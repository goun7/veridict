#!/usr/bin/env python
"""Build the Standard v1.0.0 conformance test vectors (docs/standard-test-vectors).

Determinism contract: the generated ledger/certificate/expected-verify triple
is byte-stable across runs. Every entry ts is a FIXED ISO-8601 string and the
signing key is a FIXED ed25519 seed — clearly marked TEST-ONLY, never use it
for real signing. An independent implementation of the standard must be able
to reproduce the chain hashes and reach the same verify verdict from these
files alone (docs/specs/2026-09-10-veridict-standard-v1.0.md §11.3).
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from veridict.certificate import CertificateIssuer, verify_certificate
from veridict.claim_extractor import ClaimExtractor
from veridict.keys import KeyStore, SYSTEM_AUTHOR
from veridict.ladder import adjudicate
from veridict.ledger import Ledger
from veridict.policy import PolicyDeclaration, PolicyEngine, Thresholds
from veridict.schemas import ActorRef, SCHEMA_VERSION
from veridict.schemas import ActorRef, EvidenceItem, TaskManifest
from veridict.utils import canonical_json, payload_digest, sha256_hex

OUT = os.environ.get(
    "VECTOR_OUT",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "docs", "standard-test-vectors"))

# TEST-ONLY seed — published on purpose so anyone can reproduce the vectors.
VECTOR_SEED = bytes(range(32))
FIXED_TS = [f"2026-09-10T09:00:{s:02d}+00:00" for s in range(32)]


def _fixed_keystore(ledger: Ledger) -> tuple[KeyStore, str]:
    """A KeyStore whose key is derived from VECTOR_SEED (deterministic)."""
    ks = KeyStore(ledger)
    priv = Ed25519PrivateKey.from_private_bytes(VECTOR_SEED)
    pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key_id = sha256_hex(pub_bytes)[:16]
    pub_pem = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
    ledger.append("key.enrolled", SYSTEM_AUTHOR, {
        "key_id": key_id, "algorithm": "ed25519",
        "purpose": "certificate-signing", "identity": "vector-signer",
        "public_pem": pub_pem})
    ks._keys[key_id] = priv          # inject the fixed key
    return ks, key_id


def _pin_timestamps(ledger: Ledger, ks: KeyStore, cert: dict) -> None:
    """Overwrite every entry ts with a fixed value and rebuild the chain.

    The checkpoint's payload chain_hash and the certificate's signed anchor
    both embed the live-time chain state — they must be re-derived in the
    same forward pass, and the certificate re-signed (fixed key =>
    deterministic signature), or the "pinned" triple is internally
    inconsistent and nondeterministic.
    """
    for i, e in enumerate(ledger.entries):
        e["ts"] = FIXED_TS[i]
    prev = "0" * 64
    last_checkpoint_chain = None
    for e in ledger.entries:
        if e["entry_type"] == "checkpoint.anchored":
            e["payload"]["chain_hash"] = prev          # re-derive the pin
            e["payload_hash"] = payload_digest(e["payload"])
            last_checkpoint_chain = prev
        if e["entry_type"] == "certificate.issued":
            cert["ledger_anchor"]["chain_hash"] = last_checkpoint_chain
            body = dict(cert)
            body.pop("signatures")
            cert["signatures"] = [{
                "key_id": cert["signatures"][0]["key_id"],
                "algorithm": "ed25519",
                "sig_b64": ks.sign(cert["signatures"][0]["key_id"],
                                   canonical_json(body).encode("utf-8"))}]
            e["payload_hash"] = payload_digest(e["payload"])
        e["prev_hash"] = prev
        e["entry_hash"] = sha256_hex("|".join([
            prev, e["payload_hash"], e["entry_type"], str(e["seq"]),
            canonical_json(e["author"]), canonical_json(e["ts"]),
            e["schema_version"]]))
        prev = e["entry_hash"]


def build() -> None:
    os.makedirs(OUT, exist_ok=True)
    led = Ledger()
    ks, key_id = _fixed_keystore(led)

    task = TaskManifest(task_id="vector-1", artifact_path="/nonexistent",
                        actor_identity="ai-dev",
                        intent_lines=("MACHINE: add computes the sum of two numbers",),
                        criticality=(), has_existing_tests=True, pytest_args=())
    claim = ClaimExtractor().extract(task, "vector-digest")[0]
    led.append("claim.registered", SYSTEM_AUTHOR, claim.to_dict())

    items = [
        EvidenceItem(evidence_id=sha256_hex("vector|w1a")[:24],
                     claim_id=claim.claim_id, evidence_class="TEST_EXECUTION",
                     tier="W1a",
                     producer={"kind": "verifier", "identity": "test-executor",
                               "version": "0.1.0", "family": "pytest"},
                     artifact_ref="vector-digest",
                     reproducibility={"deterministic": True,
                                      "rerun_recipe": {"cmd": "pytest -q"}},
                     stance="SUPPORTS", confidence=1.0,
                     rationale="pytest exited with exit code 0"),
        EvidenceItem(evidence_id=sha256_hex("vector|w2a")[:24],
                     claim_id=claim.claim_id, evidence_class="JURY_OPINION",
                     tier="W2",
                     producer={"kind": "jury", "identity": "juror-a",
                               "version": "0.1.0", "family": "model-family-1"},
                     artifact_ref="vector-digest",
                     reproducibility={"deterministic": False,
                                      "rerun_recipe": None},
                     stance="SUPPORTS", confidence=0.8,
                     rationale="implementation matches the claim"),
        EvidenceItem(evidence_id=sha256_hex("vector|w2b")[:24],
                     claim_id=claim.claim_id, evidence_class="JURY_OPINION",
                     tier="W2",
                     producer={"kind": "jury", "identity": "juror-b",
                               "version": "0.1.0", "family": "model-family-2"},
                     artifact_ref="vector-digest",
                     reproducibility={"deterministic": False,
                                      "rerun_recipe": None},
                     stance="SUPPORTS", confidence=0.8,
                     rationale="implementation matches the claim"),
    ]
    for it in items:
        led.append("evidence.recorded",
                   ActorRef(kind=it.producer["kind"],
                            identity=it.producer["identity"],
                            version=it.producer["version"]), it.to_dict())

    pol = PolicyDeclaration(policy_id="vector-policy", mode="GATE",
                            criticality=(), thresholds=Thresholds(),
                            divergence_tolerance=1 / 3)
    # D19: a verifier reconciles the cert's policy against the policy the
    # ledger records the run actually used. A vector without this entry
    # fails closed on an unattested policy, which is correct behaviour but
    # would make the expected output unachievable.
    PolicyEngine(led).apply([claim], {claim.claim_id: items}, pol,
                           ActorRef(kind="system", identity="vector-builder",
                                    version=SCHEMA_VERSION))
    adj = adjudicate(claim, items, pol)
    assert adj.value == "VERIFIED", adj.value
    cert = CertificateIssuer(led, ks, key_id).issue(
        task=task, artifact_digest="vector-digest", policy=pol,
        claims=[claim], adjudications=[adj],
        evidence_by_claim={claim.claim_id: items},
        jury_families=["model-family-1", "model-family-2"],
        disclosure_level="REDACTED",
        scope_limits=["claim coverage is heuristic, not exhaustive"])

    _pin_timestamps(led, ks, cert)

    ledger_path = os.path.join(OUT, "ledger.jsonl")
    cert_path = os.path.join(OUT, "certificate.json")
    expected_path = os.path.join(OUT, "expected_verify.json")
    led.save(ledger_path)
    with open(cert_path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2, sort_keys=True)
    report = verify_certificate(ledger_path, cert_path)
    assert report["valid"] is True, report
    with open(expected_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)

    readme = os.path.join(OUT, "README.md")
    with open(readme, "w", encoding="utf-8") as f:
        f.write("""# Standard v1.0.0 — conformance test vectors

Generated by `scripts/build_test_vectors.py` (deterministic: fixed ts values,
fixed ed25519 seed `bytes(range(32))` — TEST-ONLY, never sign anything real
with it).

An independent implementation of the standard (§11.3) MUST, from
`ledger.jsonl` + `certificate.json` alone:

1. recompute every `entry_hash` (preimage binds seq, prev_hash, payload
   digest, entry_type, author, ts, schema_version — §2.3),
2. validate the chain, the certificate signature against the enrolled
   `key.enrolled` entry, the anchor, and the `certificate.issued` entry,
3. recompute the claim verdict from the ledger evidence (R0: W1a SUPPORTS +
   unanimous W2 ⇒ VERIFIED),
4. reach exactly the verdict in `expected_verify.json`
   (`{valid: true, chain_valid: true, signature_valid: true,
   verdicts_match: true, errors: []}`).

`tests/test_standard_vectors.py` pins these files against the reference
implementation, including byte-determinism of regeneration.
""")
    print("vectors written:", OUT)


if __name__ == "__main__":
    build()
