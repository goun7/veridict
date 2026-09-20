"""Signature-format interop (the external verifier's actual first task).

A stranger implementing the standard will NOT import our KeyStore. The real
§11 flow: load the cert JSON, pop `signatures`, reconstruct the body,
canonicalize per §4, fetch the `key.enrolled` public PEM for the signing
key_id from the ledger, and verify with ANY standard ed25519 library. This
test does exactly that through the `cryptography` public API — no veridict
verification code on the verify side — proving the on-the-wire format is
interoperable. Dependency CVE scan: `pip-audit` runs in CI.
"""
import base64
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from veridict.certificate import CertificateIssuer, verify_certificate
from veridict.claim_extractor import ClaimExtractor
from veridict.keys import KeyStore
from veridict.ladder import adjudicate
from veridict.ledger import Ledger
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import ActorRef, TaskManifest
from veridict.utils import canonical_json


def _issue(artifact_digest):
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("interop")
    pol = PolicyDeclaration(policy_id="interop", mode="GATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    task = TaskManifest(task_id=f"interop-{abs(hash(artifact_digest)) % 10**6}",
                        artifact_path="/x", actor_identity="ai-dev",
                        intent_lines=("MACHINE: add computes the sum of two numbers",),
                        criticality=(), has_existing_tests=True, pytest_args=())
    claim = ClaimExtractor().extract(task, artifact_digest)[0]
    led.append("claim.registered",
               ActorRef(kind="system", identity="c", version="1"),
               claim.to_dict())
    adj = adjudicate(claim, [], pol)   # R4-first: no evidence ⇒ INCONCLUSIVE
    # D19: verifier reconciles policy_ref against the ledger's recorded policy
    from veridict.policy import PolicyEngine
    PolicyEngine(led).apply([claim], {}, pol,
                           ActorRef(kind="system", identity="interop", version="1"))
    cert = CertificateIssuer(led, ks, kid).issue(
        task=task, artifact_digest=artifact_digest, policy=pol, claims=[claim],
        adjudications=[adj], evidence_by_claim={claim.claim_id: []},
        jury_families=[], disclosure_level="REDACTED",
        scope_limits=["claim coverage is heuristic, not exhaustive"])
    return led, ks, cert


def test_certificate_signature_verifiable_with_plain_ed25519(tmp_path):
    """The stranger's path: cert JSON + ledger JSONL + a stock ed25519
    verifier. No veridict verification code on the verification side."""
    led, ks, cert = _issue("digest-interop")
    assert cert["signatures"][0]["algorithm"] == "ed25519"

    # 1. reconstruct the signed body: the cert minus its `signatures` array
    body = dict(cert)
    sigs = body.pop("signatures")
    message = canonical_json(body).encode("utf-8")

    # 2. fetch the enrolled public key for the signing key_id — from the
    #    ledger entries alone (key.enrolled → payload.public_pem)
    key_id = sigs[0]["key_id"]
    pub_pem = next(e["payload"]["public_pem"]
                   for e in led.entries
                   if e["entry_type"] == "key.enrolled"
                   and e["payload"]["key_id"] == key_id)
    public_key = serialization.load_pem_public_key(pub_pem.encode())
    assert isinstance(public_key, Ed25519PublicKey)

    # 3. verify — raises InvalidSignature on any mismatch
    public_key.verify(base64.b64decode(sigs[0]["sig_b64"]), message)

    # sanity: our reference verifier agrees the certificate is valid too
    lp = str(tmp_path / "led.jsonl")
    cp = str(tmp_path / "cert.json")
    led.save(lp)
    json.dump(cert, open(cp, "w"))
    assert verify_certificate(lp, cp)["valid"]


def test_tampered_body_fails_plain_verification():
    led, _, cert = _issue("digest-tamper")
    body = dict(cert)
    sigs = body.pop("signatures")
    body["score"] = 100.0            # one field flipped — a lying certificate
    message = canonical_json(body).encode("utf-8")
    pub_pem = next(e["payload"]["public_pem"] for e in led.entries
                   if e["entry_type"] == "key.enrolled"
                   and e["payload"]["key_id"] == sigs[0]["key_id"])
    public_key = serialization.load_pem_public_key(pub_pem.encode())
    with pytest.raises(Exception):
        public_key.verify(base64.b64decode(sigs[0]["sig_b64"]), message)
