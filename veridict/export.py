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
    try:
        from importlib.metadata import version
        return version("veridict")
    except Exception:
        return "0.3.3+source"          # running from a checkout


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
