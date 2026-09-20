"""Multi-signer federation (P4-T9): two independent KeyStores, one ledger.

The enrollment rule (§11.2) is what makes this work: a signing key must be
enrolled into the SAME ledger that will later verify its signatures. Two
auditors each enroll their own key; each certificate verifies against its
own enrollment — and against NOTHING when that enrollment is absent.
"""
import sys, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.certificate import CertificateIssuer, verify_certificate
from veridict.claim_extractor import ClaimExtractor
from veridict.jury import Opinion, ScriptedProvider
from veridict.keys import KeyStore, SYSTEM_AUTHOR
from veridict.ladder import adjudicate
from veridict.ledger import Ledger
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import ActorRef, EvidenceItem, TaskManifest


def _policy() -> PolicyDeclaration:
    return PolicyDeclaration(policy_id="fed", mode="GATE", criticality=(),
                             thresholds=Thresholds(), divergence_tolerance=1 / 3)


def _task(tid: str) -> TaskManifest:
    return TaskManifest(task_id=tid, artifact_path="/nonexistent",
                        actor_identity="ai-dev",
                        intent_lines=("MACHINE: add computes the sum of two numbers",),
                        criticality=(), has_existing_tests=True, pytest_args=())


def _audit_one(led, ks, kid, tid):
    claim = ClaimExtractor().extract(_task(tid), f"digest-{tid}")[0]
    led.append("claim.registered", SYSTEM_AUTHOR, claim.to_dict())
    item = EvidenceItem(
        evidence_id=sha_hex(tid), claim_id=claim.claim_id,
        evidence_class="TEST_EXECUTION", tier="W1a",
        producer={"kind": "verifier", "identity": "test-executor",
                  "version": "0.1.0", "family": "pytest"},
        artifact_ref=f"digest-{tid}",
        reproducibility={"deterministic": True, "rerun_recipe": {"cmd": "pytest -q"}},
        stance="SUPPORTS", confidence=1.0, rationale="pytest exited with exit code 0")
    led.append("evidence.recorded",
               ActorRef(kind="verifier", identity="test-executor", version="0.1.0"),
               item.to_dict())
    pol = _policy()
    adj = adjudicate(claim, [item], pol)
    # D19: verifier reconciles policy_ref against the ledger's recorded policy
    from veridict.policy import PolicyEngine
    PolicyEngine(led).apply([claim], {claim.claim_id: [item]}, pol,
                           ActorRef(kind="system", identity="federation", version="1"))
    cert = CertificateIssuer(led, ks, kid).issue(
        task=_task(tid), artifact_digest=f"digest-{tid}", policy=pol,
        claims=[claim], adjudications=[adj],
        evidence_by_claim={claim.claim_id: [item]},
        jury_families=[], disclosure_level="REDACTED",
        scope_limits=["claim coverage is heuristic, not exhaustive"])
    return cert


def sha_hex(s: str) -> str:
    from veridict.utils import sha256_hex
    return sha256_hex(f"fed|{s}")[:24]


def _write(led, tmp_path, name):
    lp = str(tmp_path / f"{name}.jsonl")
    led.save(lp)
    return lp


def test_two_auditors_one_ledger_both_verify(tmp_path):
    led = Ledger()
    ks1, ks2 = KeyStore(led), KeyStore(led)     # independent private keys,
    kid1 = ks1.generate_and_enroll("auditor-a")  # SAME ledger enrollments
    kid2 = ks2.generate_and_enroll("auditor-b")
    cert_a = _audit_one(led, ks1, kid1, "task-a")
    cert_b = _audit_one(led, ks2, kid2, "task-b")
    assert cert_a["signatures"][0]["key_id"] == kid1
    assert cert_b["signatures"][0]["key_id"] == kid2
    lp = _write(led, tmp_path, "fed")
    for name, cert in (("a", cert_a), ("b", cert_b)):
        cp = str(tmp_path / f"cert_{name}.json")
        import json
        json.dump(cert, open(cp, "w"))
        report = verify_certificate(lp, cp)
        assert report["valid"], (name, report)


def test_certificate_fails_without_its_own_key_enrollment(tmp_path):
    """Auditor B's certificate must NOT verify against a ledger that only
    carries auditor A's enrollment — signatures are enrollment-bound."""
    led = Ledger()
    ks1, ks2 = KeyStore(led), KeyStore(led)
    kid1 = ks1.generate_and_enroll("auditor-a")
    kid2 = ks2.generate_and_enroll("auditor-b")
    cert_b = _audit_one(led, ks2, kid2, "task-b")
    # rebuild WITHOUT auditor-b's enrollment: a fresh ledger carrying only A
    lone = Ledger()
    ks_lone = KeyStore(lone)
    ks_lone._keys[kid1] = ks1._keys[kid1]
    lone.append("key.enrolled", SYSTEM_AUTHOR, dict(
        next(e["payload"] for e in led.query("key.enrolled")
             if e["payload"]["key_id"] == kid1)))
    import json
    lp = _write(lone, tmp_path, "lone")
    cp = str(tmp_path / "cert_b.json")
    json.dump(cert_b, open(cp, "w"))
    report = verify_certificate(lp, cp)
    assert report["valid"] is False and not report["signature_valid"], report
