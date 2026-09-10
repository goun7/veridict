"""Certificate issuance (§4.2) + offline replay verification (§7.3 m3).

verify_certificate imports core modules ONLY — never jury/verifiers/audit.
"""
from __future__ import annotations

import json

from .keys import KeyStore
from .ladder import adjudicate
from .ledger import ChainError, Ledger
from .policy import PolicyDeclaration, Thresholds
from .schemas import ActorRef, Claim, EvidenceItem, SCHEMA_VERSION
from .utils import canonical_json, sha256_hex

ADJUDICATOR = ActorRef(kind="adjudicator", identity="veridict-issuer", version="0.1.0")


def _risk_level(values: list[str]) -> str:
    if any(v in ("REFUTED", "ESCALATED") for v in values):
        return "high"
    if any(v == "INCONCLUSIVE" for v in values):
        return "medium"
    return "low"


class CertificateIssuer:
    def __init__(self, ledger: Ledger, keystore: KeyStore, key_id: str) -> None:
        self.ledger = ledger
        self.keystore = keystore
        self.key_id = key_id

    def issue(self, task, artifact_digest: str, policy: PolicyDeclaration,
              claims: list[Claim], adjudications: list, evidence_by_claim: dict,
              jury_families: list[str], disclosure_level: str,
              scope_limits: list[str]) -> dict:
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
                        "verdict_value": adj_by_id[c.claim_id].value,
                        "divergence": adj_by_id[c.claim_id].divergence,
                        "evidence_ids": [e.evidence_id
                                         for e in evidence_by_claim.get(c.claim_id, [])]}
                       for c in claims],
            "jury_composition": {"families": jury_families},
            "disclosure_level": disclosure_level,
            "divergence_summary": {c.claim_id: adj_by_id[c.claim_id].divergence
                                   for c in claims},
            "risk_level": _risk_level([adj_by_id[c.claim_id].value for c in claims]),
            "score": round(sum(1 for c in claims
                               if adj_by_id[c.claim_id].value == "VERIFIED")
                           / len(claims), 3) if claims else 0.0,
            "ledger_anchor": {},          # filled after checkpoint below
            "signatures": [],
            "verify_instructions": "veridict verify --ledger <ledger.jsonl> --cert <cert.json>",
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
    body = dict(cert)
    sigs = body.pop("signatures", [])
    sig_ok = False
    for s in sigs:
        pub_pem = next((e["payload"]["public_pem"]
                        for e in led.query("key.enrolled")
                        if e["payload"]["key_id"] == s["key_id"]), None)
        if pub_pem and KeyStore.verify_signature(
                pub_pem, canonical_json(body).encode("utf-8"), s["sig_b64"]):
            sig_ok = True
            break
    if not sig_ok:
        errors.append("signature: no enrolled key verifies the certificate body")

    # Anchor check: the checkpoint entry must exist and match the cert anchor.
    anchor = cert.get("ledger_anchor", {})
    cp_seq = anchor.get("checkpoint_seq")
    if not isinstance(cp_seq, int) or cp_seq >= len(led.entries) or \
            led.entries[cp_seq]["entry_type"] != "checkpoint.anchored" or \
            led.entries[cp_seq]["payload"]["chain_hash"] != anchor.get("chain_hash"):
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
            divergence_tolerance=pr.get("thresholds", {}).get(
                "divergence_tolerance", 1 / 3))
        claims_by_id = {e["payload"]["claim_id"]: Claim.from_dict(e["payload"])
                        for e in led.query("claim.registered")}
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
            if e["payload"]["evidence_id"] in superseded:
                continue
            ev_by_claim.setdefault(e["payload"]["claim_id"], []).append(
                EvidenceItem.from_dict(e["payload"]))
        for c in cert["claims"]:
            claim = claims_by_id.get(c["claim_id"])
            if claim is None:
                errors.append(f"claims: {c['claim_id']} not registered in ledger")
                verdicts_match = False
                continue
            recomputed = adjudicate(claim, ev_by_claim.get(c["claim_id"], []), pol)
            if recomputed.value != c["verdict_value"]:
                errors.append(f"verdict mismatch for {c['claim_id']}: "
                              f"cert={c['verdict_value']} recomputed={recomputed.value}")
                verdicts_match = False
    return {"valid": not errors, "chain_valid": chain_ok, "signature_valid": sig_ok,
            "verdicts_match": verdicts_match, "errors": errors}
