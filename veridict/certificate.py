"""Certificate issuance (§4.2) + offline replay verification (§7.3 m3).

verify_certificate imports core modules ONLY — never jury/verifiers/audit.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .keys import KeyStore
from .ladder import adjudicate
from .ledger import ChainError, Ledger
from .policy import PolicyDeclaration, Thresholds
from .schemas import ActorRef, Claim, EvidenceItem, SCHEMA_VERSION
from .utils import canonical_json, payload_digest, sha256_hex

ADJUDICATOR = ActorRef(kind="adjudicator", identity="veridict-issuer", version="0.1.0")

# A standalone verifier (no ledger) rejects a certificate whose clock reads
# this far ahead of the verifier's own clock. Large on purpose: it is a
# sanity bound against a grossly forged ts, not a precision claim — the
# signed timestamp is provenance, and distributed clock skew is normal.
_STANDALONE_SKEW_S = 60.0 * 60.0 * 24.0   # 24h


def _parse_iso8601(ts) -> datetime | None:
    """Parse an ISO-8601 string as UTC; None when unparseable (skip, not fail)."""
    if not isinstance(ts, str):
        return None
    try:
        d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d


def _risk_level(values: list[str]) -> str:
    if any(v in ("REFUTED", "ESCALATED") for v in values):
        return "high"
    if any(v == "INCONCLUSIVE" for v in values):
        return "medium"
    return "low"


def _risk_level_for(claims: list[Claim], per_claim: dict) -> str:
    """Risk reflects TOP-LEVEL claim verdicts only.

    A REFUTED coverage meta-claim is a juror declining to answer a question
    the ladder asked because that juror had already dissented — it carries
    no independent finding about the artifact. Counting it as high risk
    would let the same dissent §5.3 rule 2 refuses to honor at the gate come
    back in through the certificate's risk field. Meta-claim refusals are
    surfaced as `meta-coverage-unconfirmed` flags in the certificate; risk
    stays tied to claims about the artifact itself.
    """
    top = [c for c in claims
           if c.verifiability != "DOCTRINAL"
           or not c.predicate.startswith("coverage-of-")]
    values = []
    for c in top:
        a = per_claim[c.claim_id]
        values.append(a["value"] if isinstance(a, dict) else a.value)
    return _risk_level(values)


class CertificateIssuer:
    def __init__(self, ledger: Ledger, keystore: KeyStore, key_id: str) -> None:
        self.ledger = ledger
        self.keystore = keystore
        self.key_id = key_id

    def issue(self, task, artifact_digest: str, policy: PolicyDeclaration,
              claims: list[Claim], adjudications: list, evidence_by_claim: dict,
              jury_families: list[str], disclosure_level: str,
              scope_limits: list[str], issued_at: str | None = None) -> dict:
        adj_by_id = {a.claim_id: a for a in adjudications}
        cert = {
            "schema_version": SCHEMA_VERSION,
            "cert_id": sha256_hex(f"{task.task_id}|{artifact_digest}")[:24],
            "subject": {"artifact_digest": artifact_digest, "task_id": task.task_id,
                        "actor_identity": task.actor_identity},
            "policy_mode": policy.mode,
            "policy_ref": {"policy_id": policy.policy_id,                      # reconciled
                           "mode": policy.mode,
                           "criticality": list(policy.criticality),
                           "thresholds": {
                               "min_jury_families": policy.thresholds.min_jury_families,
                               "divergence_tolerance": policy.divergence_tolerance,
                               "min_w1_coverage": policy.thresholds.min_w1_coverage,
                               "meta_claim_depth_budget": policy.thresholds.meta_claim_depth_budget}},
            "claims": [{"claim_id": c.claim_id,
                        "predicate": c.predicate,
                        "verdict_value": adj_by_id[c.claim_id].value,
                        "divergence": adj_by_id[c.claim_id].divergence,
                        "evidence_ids": [e.evidence_id
                                         for e in evidence_by_claim.get(c.claim_id, [])]}
                       for c in claims],
            "jury_composition": {"families": jury_families},
            "disclosure_level": disclosure_level,
            "divergence_summary": {c.claim_id: adj_by_id[c.claim_id].divergence
                                   for c in claims},
            "risk_level": _risk_level_for(claims, adj_by_id),
            "score": round(sum(1 for c in claims
                               if adj_by_id[c.claim_id].value == "VERIFIED")
                           / len(claims), 3) if claims else 0.0,
            "ledger_anchor": {},          # filled after checkpoint below
            "signatures": [],
            "verify_instructions": "veridict verify --ledger <ledger.jsonl> --cert <cert.json>",
            # Self-containment (the property a third party needs): the signing
            # key's PUBLIC half and a wall-clock issuance time travel INSIDE
            # the certificate, both covered by the signature above. Without
            # them, `veridict verify cert.json` alone cannot check the
            # signature or the issuance order — it would have to trust the
            # issuer's say-so, which is exactly the claim-versus-proof gap the
            # certificate exists to close. The PRIVATE key never leaves the
            # issuer; only its public verifier does.
            # issued_at is injectable so deterministic builds (the conformance
            # test vectors) can pin it — a live clock would make the signed
            # vectors non-reproducible byte-for-byte.
            "public_key": {"key_id": self.key_id, "algorithm": "ed25519",
                           "public_pem": self.keystore.public_pem(self.key_id)},
            "issued_at": issued_at or datetime.now(timezone.utc).isoformat(),
            "scope_limits": ["claim coverage is heuristic, not exhaustive",
                             *scope_limits],
            "issued_at_task": task.task_id,
        }
        checkpoint = self.ledger.append("checkpoint.anchored", ActorRef(
            kind="system", identity="veridict-core", version="0.1.0"),
            {"chain_hash": self.ledger.entries[-1]["entry_hash"] if self.ledger.entries else None,
             "upto_seq": len(self.ledger.entries)})
        cert["ledger_anchor"] = {"checkpoint_seq": checkpoint["seq"],
                                 "chain_hash": checkpoint["payload"]["chain_hash"]}
        body = dict(cert)
        body.pop("signatures")
        cert["signatures"] = [{"key_id": self.key_id, "algorithm": "ed25519",
                               "sig_b64": self.keystore.sign(
                                   self.key_id, canonical_json(body).encode("utf-8"))}]
        self.ledger.append("certificate.issued", ADJUDICATOR, cert)
        return cert


def verify_certificate(ledger_path: str, cert_path: str) -> dict:
    errors: list[str] = []
    with open(cert_path, encoding="utf-8") as f:
        cert = json.load(f)
    try:
        led = Ledger.load(ledger_path)
    except ChainError as exc:
        return {"valid": False, "chain_valid": False, "signature_valid": False,
                "verdicts_match": False, "errors": [f"chain: {exc}"]}
    chain_ok, chain_msg = led.verify_chain()
    if not chain_ok:
        errors.append(f"chain: {chain_msg}")

    # Signature over the unsigned body, verified against the enrolled key.
    # The key.enrolled lookup is scoped to the anchored prefix (seq <= cp_seq):
    # a key enrolled AFTER the checkpoint can re-sign an unchanged body and
    # would otherwise produce signature_valid=true, and a relying party cannot
    # tell an issuer-time signature from a later rogue key's. Append-only means
    # next() still takes the original enrollment for an honest key; the guard
    # only forbids time travel.
    body = dict(cert)
    sigs = body.pop("signatures", [])
    anchor = cert.get("ledger_anchor", {})
    cp_seq_raw = anchor.get("checkpoint_seq")
    cp_seq = cp_seq_raw if isinstance(cp_seq_raw, int) else None
    sig_ok = False
    for s in sigs:
        pub_pem = next((e["payload"]["public_pem"]
                        for e in led.query("key.enrolled")
                        if e["payload"]["key_id"] == s["key_id"]
                        and (cp_seq is None or e["seq"] <= cp_seq)), None)
        if pub_pem and KeyStore.verify_signature(
                pub_pem, canonical_json(body).encode("utf-8"), s["sig_b64"]):
            sig_ok = True
            break
    if not sig_ok:
        errors.append("signature: no enrolled key verifies the certificate body")

    # Anchor check: the checkpoint entry must exist and match the cert anchor.
    # The pinned chain_hash is compared against the REAL chain, not the
    # checkpoint entry's self-attested payload. Comparing payload to payload
    # is a no-op when an attacker with ledger write access rewrites the pinned
    # prefix and recomputes every hash — the checkpoint's stored chain_hash is
    # just more attacker-controlled bytes in the same file. The entry at
    # cp_seq - 1 is the last entry the checkpoint covered, and its recomputed
    # entry_hash IS the chain_hash a honest issue() pinned (certificate.py:97
    # sets chain_hash = entries[-1].entry_hash at append time). Binding it here
    # makes the prefix tamper-evident rather than tamper-visible.
    anchor = cert.get("ledger_anchor", {})
    cp_seq = anchor.get("checkpoint_seq")
    anchor_ok = False
    if isinstance(cp_seq, int) and cp_seq >= 1 and cp_seq < len(led.entries):
        if led.entries[cp_seq]["entry_type"] == "checkpoint.anchored":
            prev_hash = led.entries[cp_seq - 1]["entry_hash"]
            anchor_ok = (
                prev_hash == anchor.get("chain_hash")
                and led.entries[cp_seq]["payload"].get("chain_hash")
                == anchor.get("chain_hash"))
    if not anchor_ok:
        errors.append("anchor: checkpoint does not match ledger")

    # Issuance check: the ledger must contain the certificate.issued entry the
    # anchor claims to cover — a checkpoint without its issuance entry means
    # the certificate was never actually issued into this chain.
    if isinstance(cp_seq, int):
        issued_ok = any(
            e["entry_type"] == "certificate.issued"
            and e["payload"].get("cert_id") == cert.get("cert_id")
            and e["seq"] >= cp_seq
            for e in led.entries)
        if not issued_ok:
            errors.append("certificate: no matching certificate.issued entry in ledger")

    # Recompute verdicts from ledger evidence and compare.
    verdicts_match = True
    if chain_ok:
        pr = cert.get("policy_ref", {})
        pol = PolicyDeclaration(
            policy_id=pr.get("policy_id", "replay"),                       # reconciled
            mode=pr.get("mode", "CERTIFICATE"),
            criticality=tuple(pr.get("criticality", [])),
            thresholds=Thresholds(**pr.get("thresholds", {})),
            # divergence_tolerance is a PolicyDeclaration field (audit F5):
            # asdict serializes it at policy_ref top level, so read it there
            # first and fall back to under-thresholds for pre-F5 certs.
            divergence_tolerance=pr.get(
                "divergence_tolerance", pr.get("thresholds", {}).get(
                    "divergence_tolerance", 1 / 3)))
        # Policy provenance (D17 class, members four and five). The cert's
        # `policy_ref` is used to BUILD the replay policy, so unlike a
        # summary field it is an INPUT to the verdicts, not a consequence of
        # them: a verifier reading the policy from the certificate replays
        # under whatever policy the issuer claims to have used. The ledger
        # records the policy the run actually used — policy.decision carries
        # policy_digest — so policy_ref is reconciled against it rather than
        # trusted. If no recorded policy matches the claimed policy_id, the
        # claim is unfalsifiable and the replay would run under an
        # unattested policy; that must fail closed, not skip the check.
        # Scope guard (D4, same as deliberation below): only a policy.decision
        # INSIDE the anchored prefix (seq <= checkpoint) attests the policy
        # the run used. The cert's signed anchor pins that prefix's
        # chain_hash; a post-issuance entry is outside it, so an attacker
        # cannot retroactively attest a policy that was never run — and
        # equally cannot append a mismatched entry to engineer a spurious
        # rejection. Taking the LAST in-prefix match keeps the run's own
        # decision when a policy_id legitimately appears twice (e.g. a
        # blocked-then-passed retry under the same declaration). When the
        # anchor itself is bad the anchor check above already rejects, so
        # this guard only narrows the view of an otherwise-anchored prefix.
        in_prefix = (lambda e: isinstance(cp_seq, int) and e["seq"] <= cp_seq)
        recorded = next((e["payload"] for e in reversed(led.query("policy.decision"))
                         if in_prefix(e)
                         and e["payload"].get("policy_id") == pol.policy_id), None)
        if recorded is None:
            errors.append("policy: cert policy_ref names a policy_id the "
                          "ledger does not record — replay would adjudicate "
                          "under an unattested policy")
            verdicts_match = False
        elif recorded.get("policy_digest") != payload_digest(pol.to_dict()):
            errors.append("policy mismatch: cert policy_ref does not match "
                          "the policy the ledger records the run used — "
                          "replay would adjudicate under the issuer's "
                          "claimed policy, not the real one")
            verdicts_match = False
        if cert.get("policy_mode") != pr.get("mode"):
            errors.append(f"policy_mode mismatch: cert={cert.get('policy_mode')}"
                          f" policy_ref.mode={pr.get('mode')} — the mode is "
                          f"stored twice and the two copies disagree")
            verdicts_match = False
        # Replay scope (D20): every entry the replay trusts must come from
        # INSIDE the anchored prefix (seq <= checkpoint). The cert's signed
        # anchor pins that prefix's chain_hash, so pre-issuance entries are
        # tamper-evident; a post-issuance entry is outside the pin and must
        # not reach the replay. Measured before this fix: an attacker with
        # ledger write access appends either (a) a claim.registered with a
        # claim_id the cert already names — the dict comprehension below
        # OVERWRITES the real claim with the attacker's text while the cert
        # still verifies valid — or (b) an evidence.recorded SUPPORTS item,
        # which flips a refuted/inconclusive verdict to VERIFIED. Both are
        # the same class as the D19 policy.decision gap: an unscoped query.
        # cp_seq is int-checked by the anchor gate above; when it is not,
        # the cert is already rejected, so this only narrows a good anchor.
        in_prefix = (lambda e: isinstance(cp_seq, int) and e["seq"] <= cp_seq)
        claims_by_id = {e["payload"]["claim_id"]: Claim.from_dict(e["payload"])
                        for e in led.query("claim.registered") if in_prefix(e)}
        ev_by_claim: dict[str, list[EvidenceItem]] = {}
        # Deliberation parity (§4.4.3): when a claim went through a revision
        # round, the deliberation.rounded entry names the SUPERSEDED first-round
        # item ids. Replay must adjudicate on the post-deliberation evidence set
        # (first-round items stay in the ledger, but they no longer decide).
        # Scope guard (D4, audit round 4): only deliberation entries INSIDE the
        # anchored prefix count (seq <= checkpoint). The cert's signed anchor
        # pins that prefix's chain_hash, so entries committed pre-issuance are
        # tamper-evident; a post-issuance fake deliberation entry must NOT be
        # able to erase refuting evidence from the replay.
        superseded: set[str] = set()
        if isinstance(cp_seq, int):
            for e in led.query("deliberation.rounded"):
                if e["seq"] > cp_seq:
                    continue
                superseded.update(x["evidence_id"]
                                  for x in e["payload"].get("first_round", []))
        for e in led.query("evidence.recorded"):
            if not in_prefix(e) or e["payload"]["evidence_id"] in superseded:
                continue
            ev_by_claim.setdefault(e["payload"]["claim_id"], []).append(
                EvidenceItem.from_dict(e["payload"]))
        known_evidence_ids = {e["payload"]["evidence_id"]
                              for e in led.query("evidence.recorded") if in_prefix(e)}
        for c in cert["claims"]:
            claim = claims_by_id.get(c["claim_id"])
            if claim is None:
                errors.append(f"claims: {c['claim_id']} not registered in ledger")
                verdicts_match = False
                continue
            # T25.2 defense-in-depth: the cert's evidence references are part of
            # the certification claim — a signed cert citing evidence the ledger
            # does not contain must not verify, even when the recomputed verdict
            # happens to agree (the anchor pin already binds the prefix; this is
            # the independent, human-auditable check).
            for eid in c.get("evidence_ids", []):
                if eid not in known_evidence_ids:
                    errors.append(f"evidence: cert references unknown evidence {eid}")
                    verdicts_match = False
            recomputed = adjudicate(claim, ev_by_claim.get(c["claim_id"], []), pol)
            if recomputed.value != c["verdict_value"]:
                errors.append(f"verdict mismatch for {c['claim_id']}: "
                              f"cert={c['verdict_value']} recomputed={recomputed.value}")
                verdicts_match = False
        # Derived-field consistency (Tamga ERRATUM-A2 class): a certificate
        # carries summary fields that FOLLOW from the verdicts — risk_level
        # and score. The verdicts themselves are recomputed above, so they
        # cannot be lied about. But a verifier that stops at the verdicts
        # leaves the summaries unconstrained: an attacker who cannot touch
        # the verdicts can still rewrite risk_level to 'low' while a claim
        # verdict says REFUTED, hiding a bad result behind a green summary —
        # or to 'high' while verdicts say VERIFIED, inflating it. A consumer
        # that reads risk_level to decide (the settlement policy does exactly
        # this) would then decide on a forged field.
        #
        # Scope: only the claims THIS certificate adjudicates. A shared ledger
        # carries claims from other audits (segments, other tasks); scoring
        # those would measure the ledger, not the certificate.
        cert_claims = [claims_by_id[c["claim_id"]] for c in cert["claims"]
                       if c["claim_id"] in claims_by_id]
        replay = {c.claim_id: adjudicate(c, ev_by_claim.get(c.claim_id, []), pol)
                  for c in cert_claims}
        recomputed_risk = _risk_level_for(cert_claims, replay)
        if cert.get("risk_level") != recomputed_risk:
            errors.append(f"risk_level mismatch: cert={cert.get('risk_level')} "
                          f"recomputed={recomputed_risk} — summary field does "
                          f"not follow from the claim verdicts")
            verdicts_match = False
        n = len(cert_claims)
        recomputed_score = round(sum(1 for a in replay.values()
                                     if a.value == "VERIFIED") / n, 3) if n else 0.0
        if cert.get("score") != recomputed_score:
            errors.append(f"score mismatch: cert={cert.get('score')} "
                          f"recomputed={recomputed_score} — does not follow "
                          f"from the claim verdicts")
            verdicts_match = False
        # Same class, second member: `divergence_summary` maps each claim to
        # its adjudication divergence (UNANIMOUS / SPLIT / ...). It is a
        # per-claim summary that follows from the same replay, and a verifier
        # that checks only the verdict value leaves it unconstrained. Forging
        # it cannot manufacture a REFUTED verdict — the verdict check above
        # still fires — but it can hide a SPLIT the same way risk_level can
        # hide a high one, which matters because a SPLIT is the trigger for
        # deliberation (§9.1) and the honest disagreement the certificate
        # exists to surface. Forging jury_composition is the third member:
        # a certificate whose real panel was one family can claim two.
        recomputed_div = {cid: a.divergence for cid, a in replay.items()}
        if cert.get("divergence_summary") != recomputed_div:
            errors.append("divergence_summary mismatch — does not follow from "
                          "the claim adjudications")
            verdicts_match = False
    # Revocation (§6.6 class, applied to certificates): an append-only
    # certificate.revoked entry naming this cert_id makes the certificate
    # worthless, and a verifier that ignores it keeps honoring a receipt the
    # issuer already disavowed. Checked on the WHOLE chain, not the anchored
    # prefix — revocation is by definition a post-issuance event, so scoping
    # it to the prefix would make revocation impossible. Any matching entry
    # wins; the revocation entry itself is chain-protected like every other.
    revoked = _revocation_status(led, cert.get("cert_id"))
    if revoked:
        errors.append(f"revoked: {revoked}")
    # Revocation is reported through `errors` (and drives `valid`) rather than
    # as a new top-level key: this report's schema is a byte-for-byte contract
    # with the spec-only verifier (examples/spec_verifier.py) — the two must
    # agree exactly (tests/test_spec_verifier_parity.py, test_fuzz_e2e.py) —
    # and a caller learns everything it needs from `valid` + the error line.
    # The receipt path (verify_receipt) has no parity contract and reports a
    # top-level `revoked`.
    return {"valid": not errors, "chain_valid": chain_ok, "signature_valid": sig_ok,
            "verdicts_match": verdicts_match, "errors": errors}


def _revocation_status(ledger: Ledger, cert_id) -> str | None:
    """Return the revocation reason if the ledger revokes this cert_id."""
    if not cert_id:
        return None
    for e in ledger.query("certificate.revoked"):
        if e["payload"].get("cert_id") == cert_id:
            reason = e["payload"].get("reason", "").strip()
            return reason or "revoked by issuer (no reason recorded)"
    return None


def revoke_certificate(ledger: Ledger, cert_id: str, reason: str) -> dict:
    """Append a certificate.revoked entry. Returns the ledger entry.

    Revocation is append-only: the certificate is never rewritten, so its
    signature stays intact and the revocation is independently auditable in
    the same chain that issued it. Idempotent in status — revoking an
    already-revoked cert appends a second entry and keeps the first (the
    ledger is a log, not a table), but the observable status is unchanged.

    The ledger's own hash chain is the integrity mechanism, so revocation
    needs no separate signing step: like every other entry, it is bound by
    the entry_hash of every entry that follows it.
    """
    payload = {"cert_id": cert_id, "reason": reason,
               "revoked_at": datetime.now(timezone.utc).isoformat()}
    author = ActorRef(kind="system", identity="veridict-issuer", version="0.1.0")
    return ledger.append("certificate.revoked", author, payload)


def verify_certificate_standalone(cert_path: str) -> dict:
    """Verify a certificate from the file ALONE — no ledger, no network.

    This is the property a third party actually has: someone hands them a
    certificate, and nothing else. It checks exactly what a self-contained
    certificate can prove on its own:

      1. the content hash (cert_id) recomputes from the certificate's own
         subject fields — the binding between the certificate and what it
         certifies is recomputable by anyone;
      2. the signature verifies against the public key embedded in the
         certificate, so the issuer cannot deny having signed this exact
         body;
      3. the issuance timestamp is well-formed and not in the future.

    What it deliberately CANNOT check, and says so: verdict replay (needs
    the ledger's evidence) and revocation (needs the issuer's record). Both
    are reported as ``unknown`` rather than silently assumed good — the
    alternative is a verifier that advertises more assurance than the file
    can deliver, which is the failure mode this whole project exists to
    prevent. Pass a ledger to verify_certificate for the full replay.
    """
    errors: list[str] = []
    with open(cert_path, encoding="utf-8") as f:
        cert = json.load(f)

    cert_id = cert.get("cert_id")
    if not isinstance(cert_id, str) or not cert_id:
        errors.append("cert_id missing — the certificate names nothing")
    subject = cert.get("subject", {})
    if not isinstance(subject, dict):
        errors.append("subject is not an object")
        subject = {}
    # 1. Content hash — recomputable by anyone with the file.
    expected_id = sha256_hex(
        f"{subject.get('task_id')}|{subject.get('artifact_digest')}")[:24]
    if cert_id and cert_id != expected_id:
        errors.append(
            f"cert_id mismatch: certificate claims {cert_id!r} but its own "
            f"subject recomputes to {expected_id!r} — the certificate no "
            f"longer binds to what it certifies")

    # 2. Signature against the embedded public key.
    body = dict(cert)
    sigs = body.pop("signatures", [])
    embedded = cert.get("public_key", {})
    if not isinstance(embedded, dict) or not embedded.get("public_pem"):
        errors.append(
            "signature: no public key embedded in the certificate — this "
            "certificate predates embedded keys (or was stripped); the "
            "signature cannot be checked without the issuer's ledger "
            "(verify_certificate with --ledger)")
    elif not isinstance(sigs, list) or not sigs:
        errors.append("signature: certificate carries no signature")
    else:
        pem = embedded["public_pem"]
        sig_ok = False
        for s in sigs:
            if not isinstance(s, dict):
                continue
            if KeyStore.verify_signature(pem, canonical_json(body).encode("utf-8"),
                                         s.get("sig_b64", "")):
                sig_ok = True
                break
        if not sig_ok:
            errors.append("signature: no signature on this body verifies "
                          "against the certificate's embedded public key")

    # 3. Timestamp — well-formed and not manufactured in the future.
    issued_at = cert.get("issued_at")
    ts_ok = False
    if not isinstance(issued_at, str):
        errors.append("timestamp: issued_at missing or not a string")
    else:
        parsed = _parse_iso8601(issued_at)
        if parsed is None:
            errors.append(f"timestamp: issued_at {issued_at!r} is not ISO-8601")
        else:
            ts_ok = True
            skew = parsed.timestamp() - datetime.now(timezone.utc).timestamp()
            if skew > _STANDALONE_SKEW_S:
                errors.append(
                    f"timestamp: issued_at is {skew / 3600:.1f}h ahead of the "
                    f"verifier's clock — beyond the {_STANDALONE_SKEW_S / 3600:.0f}h "
                    f"sanity bound")

    return {
        "valid": not errors,
        "standalone": True,
        "cert_id": cert_id,
        "signature_valid": not any(e.startswith("signature:") for e in errors),
        "content_hash_valid": not any(e.startswith("cert_id") for e in errors),
        "timestamp_valid": ts_ok and not any(
            e.startswith("timestamp:") for e in errors),
        "issued_at": issued_at if isinstance(issued_at, str) else None,
        # Explicitly NOT claimed: these need the issuer's ledger.
        "verdicts_match": None,
        "revoked": None,
        "errors": errors,
    }
