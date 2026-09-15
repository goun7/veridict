"""SLSA VSA projection of a Veridict certificate.

SLSA v1.2's Verification Summary Attestation is the approved, widely-
consumed format for "some trusted verifier evaluated this artifact against
this policy and here is the result" — which is exactly what a Veridict
certificate asserts, about AI-produced artifacts. Exporting a VSA lets
existing supply-chain tooling (policy engines, VSA collectors) consume a
Veridict verdict without learning a new format, while the certificate
stays the authoritative object: a VSA is a lossy projection (it carries
no claims, evidence tiers, or divergence detail), so every projection
embeds the full cert binding as a spec-sanctioned URI extension field
("producers MAY add extension fields using field names that are URIs").

Mapping rules (all honest, none inflated):
  * verificationResult PASSED  <=> the certificate's risk_level is "low"
    — i.e. it would survive GATE mode. medium/high risk => FAILED.
    Veridict does NOT certify SLSA build levels: verifiedLevels is always
    empty (our policy makes no such claim) even though the VSA format
    could carry them.
  * subject/resourceUri carry the artifact digest the certificate was
    issued over; the ledger's certificate.issued entry provides
    timeVerified (the issuance timestamp, not the export timestamp).
  * inputAttestations names the exact certificate (digest of its
    canonical JSON) so a consumer can demand the authoritative object.

DSSE envelope (in-toto signing layer) is optional: `--sign KEYFILE`
wraps the statement with the Ed25519 key that issued the certificate;
without a key the export is an unsigned statement — documented, not
silently half-signed.
"""
from __future__ import annotations

import base64
import json

from .utils import sha256_hex

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
VSA_PREDICATE_TYPE = "https://slsa.dev/verification_summary/v1"
CERT_EXTENSION_FIELD = "https://veridict.dev/cert/v1"
VERIFIER_ID = "https://github.com/goun7/veridict"


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def _veridict_version() -> str:
    """Single honest version probe. The PyPI distribution is
    `veridict-standard` (bare `veridict` belongs to another project);
    querying the wrong name silently shipped the fallback forever —
    caught by the 0.5.0 UX sweep, now probed under both spellings."""
    from importlib.metadata import PackageNotFoundError, version
    for dist in ("veridict-standard", "veridict"):
        try:
            return version(dist)
        except PackageNotFoundError:
            continue
    return "0.5.0+source"               # running from an uninstalled checkout


def to_vsa(cert: dict, ledger_entries: list[dict], *,
           verifier_version: str | None = None) -> dict:
    """Project a certificate onto an in-toto Statement with a SLSA VSA
    predicate. Raises ValueError for material that cannot support an
    honest projection (no issuance record, missing artifact digest)."""
    subject = cert.get("subject") or {}
    digest = subject.get("artifact_digest")
    if not digest:
        raise ValueError("certificate subject carries no artifact_digest — "
                         "a VSA must name a digested artifact, not a guess")
    issued = next((e for e in ledger_entries
                   if e.get("entry_type") == "certificate.issued"
                   and e.get("payload", {}).get("cert_id") == cert.get("cert_id")),
                  None)
    if issued is None:
        raise ValueError(f"no certificate.issued ledger entry for cert_id "
                         f"{cert.get('cert_id')} — refusing to project a "
                         f"certificate the ledger does not carry")
    policy_ref = cert.get("policy_ref") or {}
    result = "PASSED" if cert.get("risk_level") == "low" else "FAILED"
    predicate = {
        "verifier": {"id": VERIFIER_ID,
                     "version": {"veridict": verifier_version
                                 or _veridict_version()}},
        "timeVerified": issued["ts"],
        "resourceUri": f"veridict:artifact/sha256:{digest}",
        "policy": {"uri": f"veridict:policy/{policy_ref.get('policy_id', 'default')}",
                   "digest": {"sha256": sha256_hex(_canonical(policy_ref))}},
        "inputAttestations": [
            {"uri": f"veridict:cert/{cert.get('cert_id')}",
             "digest": {"sha256": sha256_hex(_canonical(cert))}}],
        "verificationResult": result,
        "verifiedLevels": [],           # Veridict asserts no SLSA level
        "dependencyLevels": {},
        "slsaVersion": "1.2",
        CERT_EXTENSION_FIELD: {
            "cert_id": cert.get("cert_id"),
            "task_id": subject.get("task_id"),
            "actor_identity": subject.get("actor_identity"),
            "risk_level": cert.get("risk_level"),
            "score": cert.get("score"),
            "policy_mode": cert.get("policy_mode"),
            "disclosure_level": cert.get("disclosure_level"),
            "divergence_summary": cert.get("divergence_summary"),
            "jury_composition": cert.get("jury_composition"),
            "scope_limits": cert.get("scope_limits"),
            "ledger_anchor": cert.get("ledger_anchor"),
            "verify_instructions": cert.get("verify_instructions")},
    }
    return {"_type": STATEMENT_TYPE,
            "subject": [{"name": f"veridict:task/{subject.get('task_id', 'unknown')}",
                         "digest": {"sha256": digest}}],
            "predicateType": VSA_PREDICATE_TYPE,
            "predicate": predicate}


def dsse_envelope(statement: dict, private_key_pem: str, key_id: str) -> dict:
    """Sign a statement into a DSSE envelope (in-toto v1 PAE encoding).
    private_key_pem: Ed25519 PEM, the certificate's issuing key."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    payload_type = "application/vnd.in-toto+json"
    body = _canonical(statement)
    pae = (f"DSSEv1 {len(payload_type)} {payload_type} "
           f"{len(body)} ").encode() + body
    key = load_pem_private_key(private_key_pem.encode(), password=None)
    return {"payloadType": payload_type,
            "payload": base64.b64encode(body).decode(),
            "signatures": [{"keyid": key_id,
                            "sig": base64.b64encode(key.sign(pae)).decode()}]}


def dsse_verify(envelope: dict, public_key_pem: str) -> bool:
    """Offline check of a DSSE envelope's first signature against a key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    try:
        body = base64.b64decode(envelope["payload"])
        pt = envelope["payloadType"]
        pae = (f"DSSEv1 {len(pt)} {pt} {len(body)} ").encode() + body
        pub = load_pem_public_key(public_key_pem.encode())
        pub.verify(base64.b64decode(envelope["signatures"][0]["sig"]), pae)
        return True
    except (InvalidSignature, KeyError, IndexError):
        return False


# --------------------------------------------------------------------------
# SPDX 3.0.1 AI profile projection (JSON-LD)
# --------------------------------------------------------------------------
#
# Reality check (verified against the official 3.0.1 model, 2026-09-15):
# the SPDX AI profile documents AI *systems* — models, training data,
# hyperparameters, energy. It has NO class for "audit verdict about an
# AI-generated work product". Pretending otherwise (e.g. dumping our
# risk_level into ai_safetyRiskAssessment, whose semantics are the AI
# system's EU-AI-Act-style safety risk) would be exactly the kind of
# inflated interop claim this project exists to refute.
#
# So the projection is an ENVELOPE: the audited artifact as an
# ai_AIPackage (identity + digest + supplier), and every audit semantic
# (claims, evidence tiers, jury, risk, anchor) as core Annotation /
# Relationship / ExternalRef elements — real SPDX vocabulary, no invented
# fields, no ai_* property carrying a meaning it does not have. Consumers
# that want the authoritative object follow the certificationReport
# externalRef to the certificate itself (digest-bound).
#
# profileConformance declares ["core","software","simpleLicensing","ai"]
# — the "ai" claim is only that an ai_AIPackage element is present,
# which is true. Validation: tests/test_export_spdx.py checks every
# export against the official JSON schema (docs/data/, sha256-pinned).

SPDX_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
SPDX_SPEC_VERSION = "3.0.1"


def _spdx_ts(iso: str) -> str:
    """SPDX 3.0.1 `created` demands second precision and a Z/offset zone;
    ledger timestamps carry microseconds. Same instant, valid rendering."""
    from datetime import datetime, timezone
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_spdx(cert: dict, ledger_entries: list[dict], *,
            anchor: dict | None = None) -> dict:
    """Project a certificate onto an SPDX 3.0.1 JSON-LD document.
    Same refusal rules as to_vsa: no issuance record or no artifact
    digest => no projection. `anchor` (the Rekor sidecar dict, optional)
    is attached as an ExternalRef, never as a trust claim."""
    subject = cert.get("subject") or {}
    digest = subject.get("artifact_digest")
    if not digest:
        raise ValueError("certificate subject carries no artifact_digest — "
                         "an SPDX package must name a digested artifact")
    issued = next((e for e in ledger_entries
                   if e.get("entry_type") == "certificate.issued"
                   and e.get("payload", {}).get("cert_id") == cert.get("cert_id")),
                  None)
    if issued is None:
        raise ValueError(f"no certificate.issued ledger entry for cert_id "
                         f"{cert.get('cert_id')} — refusing to project a "
                         f"certificate the ledger does not carry")
    cid = cert.get("cert_id")
    base = f"https://veridict.dev/spdx/{cid}"
    task_id = subject.get("task_id", "unknown")
    actor = subject.get("actor_identity") or "unknown-actor"
    policy_ref = cert.get("policy_ref") or {}

    ext_refs = [
        {"type": "ExternalRef",
         "externalRefType": "certificationReport",
         "locator": [f"veridict:cert/{cid}"],
         "comment": ("Authoritative Veridict certificate (sha256:"
                     + sha256_hex(_canonical(cert))
                     + ") — this document is a lossy projection; verify "
                       "offline against the ledger.")},
        {"type": "ExternalRef",
         "externalRefType": "other",
         "locator": [f"veridict:policy/{policy_ref.get('policy_id', 'default')}"],
         "comment": ("Policy declaration the audit adjudicated against "
                     "(sha256:" + sha256_hex(_canonical(policy_ref)) + ").")}]
    if anchor:
        rek = anchor.get("rekor") or {}
        entry = rek.get("entry") or {}
        ext_refs.append(
            {"type": "ExternalRef",
             "externalRefType": "other",
             "locator": [f"{rek.get('server', 'https://rekor.sigstore.io')}"
                         f"/api/v1/log/entries/{rek.get('uuid', '')}"],
             "comment": ("Public transparency-log entry anchoring the audit "
                         f"checkpoint (logIndex {entry.get('logIndex', '?')}; "
                         "existence-at-time proof — verify offline: "
                         "veridict verify --anchor).")})

    def el(suffix, etype, extra):
        out = {"type": etype, "spdxId": f"{base}#{suffix}",
               "creationInfo": "_:ci"}
        out.update(extra)
        return out

    graph = [
        {"@id": "_:ci", "type": "CreationInfo", "specVersion": SPDX_SPEC_VERSION,
         "created": _spdx_ts(issued["ts"]),
         "createdBy": [f"{base}#veridict-agent", f"{base}#actor"],
         "comment": "Document generated by veridict export --format spdx; "
                    "created timestamp is the certificate's ledger issuance "
                    "time (deterministic projection, not export time)."},
        el("veridict-agent", "SoftwareAgent",
           {"name": f"veridict {_veridict_version()}"}),
        el("actor", "Organization",
           {"name": actor,
            "comment": "Actor identity as declared in the task manifest — "
                       "self-reported, not verified."}),
        el("license", "simplelicensing_LicenseExpression",
           {"name": "NOASSERTION",
            "simplelicensing_licenseExpression": "NOASSERTION",
            "comment": "Veridict audits work product, not licensing; the "
                       "3.0.1 AI profile requires declared/concluded "
                       "license links, so NOASSERTION states the honest "
                       "absence."}),
        el("pkg", "ai_AIPackage",
           {"name": f"veridict-audit:{task_id}",
            "software_downloadLocation": "NOASSERTION",
            "software_packageVersion": "NOASSERTION",
            "software_primaryPurpose": "other",
            "releaseTime": _spdx_ts(issued["ts"]),
            "suppliedBy": f"{base}#actor",
            "verifiedUsing": [{"type": "Hash", "algorithm": "sha256",
                               "hashValue": digest}],
            "externalRef": ext_refs,
            "ai_informationAboutApplication":
                "AI-generated work product audited by Veridict. The SPDX "
                "AI profile models AI systems, not audit verdicts about "
                "outputs; all audit semantics ride on the Annotations and "
                "Relationships in this document, none on ai_* fields.",
            "ai_limitation": "; ".join(cert.get("scope_limits") or [])
                             or "no scope limits recorded"}),
    ]

    annotations, rels = [], []

    def annotate(suffix, statement):
        uri = f"{base}#ann-{suffix}"
        annotations.append(el(f"ann-{suffix}", "Annotation",
                              {"name": f"veridict-{suffix}",
                               "annotationType": "review",
                               "statement": statement,
                               "subject": f"{base}#pkg"}))
        rels.append(el(f"rel-{suffix}", "Relationship",
                       {"from": f"{base}#pkg", "to": [uri],
                        "relationshipType": "hasEvidence",
                        "name": f"evidence-{suffix}"}))

    annotate("verdict", f"risk_level={cert.get('risk_level')} "
                        f"score={cert.get('score')} mode={cert.get('policy_mode')}")
    for i, cl in enumerate(cert.get("claims") or []):
        annotate(f"claim{i}", f"claim {cl.get('claim_id')}: "
                              f"{cl.get('verdict_value')} "
                              f"(divergence {cl.get('divergence')})")
    evidence = {}
    for e in ledger_entries:
        if e.get("entry_type") == "evidence.recorded":
            pl = e.get("payload", {})
            evidence[pl.get("evidence_id")] = pl
    for i, cl in enumerate(cert.get("claims") or []):
        for j, eid in enumerate(cl.get("evidence_ids") or []):
            ev = evidence.get(eid)
            if ev is None:
                continue          # evidence lives in the full ledger; an
            prod = ev.get("producer")  # export may see a trimmed copy
            if isinstance(prod, dict):
                prod = prod.get("identity", "?")
            annotate(f"ev{i}-{j}", f"{ev.get('tier')} {ev.get('stance')} "
                                   f"producer={prod} class={ev.get('evidence_class')}")
    if cert.get("jury_composition"):
        fams = cert["jury_composition"].get("families") \
             or cert["jury_composition"]
        annotate("jury", "jury families: " + ", ".join(str(x) for x in fams))

    for lic in ("hasDeclaredLicense", "hasConcludedLicense"):
        rels.append(el(lic, "Relationship",
                       {"from": f"{base}#pkg",
                        "to": [f"{base}#license"],
                        "relationshipType": lic, "name": lic}))

    all_elements = [f"{base}#{s}" for s in
                    ("pkg", "license", "veridict-agent", "actor")] + \
                   [a["spdxId"] for a in annotations] + [r["spdxId"] for r in rels]
    graph.append(el("doc", "SpdxDocument",
                    {"name": f"Veridict audit certificate {cid}",
                     "profileConformance": ["core", "software",
                                            "simpleLicensing", "ai"],
                     "rootElement": [f"{base}#pkg"],
                     "element": all_elements}))
    graph.extend(annotations)
    graph.extend(rels)
    return {"@context": SPDX_CONTEXT, "@graph": graph}
