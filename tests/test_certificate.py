import json

from veridict.certificate import CertificateIssuer, verify_certificate
from veridict.claim_extractor import ClaimExtractor
from veridict.keys import SYSTEM_AUTHOR, KeyStore
from veridict.ladder import adjudicate
from veridict.ledger import Ledger
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import TaskManifest


def _fixture(tmp_path, code, test):
    (tmp_path / "calc.py").write_text(code)
    (tmp_path / "test_calc.py").write_text(test)
    return TaskManifest(task_id="t1", artifact_path=str(tmp_path),
                        actor_identity="ai-dev", intent_lines=(), criticality=(),
                        has_existing_tests=True, pytest_args=())


def _run(tmp_path):
    task = _fixture(tmp_path, "def add(a, b):\n    return a + b\n",
                    "def test_add():\n    assert add(1, 1) == 2\n")
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("veridict-core")
    pol = PolicyDeclaration(policy_id="p1", mode="CERTIFICATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    claims = ClaimExtractor().extract(task, "digest")
    for c in claims:
        led.append("claim.registered", SYSTEM_AUTHOR, c.to_dict())
    ev = {c.claim_id: [] for c in claims}          # unit fixture: no evidence recorded
    adjs = [adjudicate(c, ev[c.claim_id], pol) for c in claims]
    cert = CertificateIssuer(led, ks, kid).issue(
        task=task, artifact_digest="digest", policy=pol, claims=claims,
        adjudications=adjs, evidence_by_claim=ev, jury_families=["stub-a", "stub-b"],
        disclosure_level="REDACTED",
        scope_limits=["claim coverage is heuristic, not exhaustive"])
    ledger_path = str(tmp_path / "ledger.jsonl")
    cert_path = str(tmp_path / "cert.json")
    led.save(ledger_path)
    with open(cert_path, "w") as f:
        json.dump(cert, f)
    return cert, ledger_path, cert_path


def test_issue_produces_signed_certificate(tmp_path):
    cert, _, _ = _run(tmp_path)
    assert cert["policy_mode"] == "CERTIFICATE"
    assert cert["disclosure_level"] == "REDACTED"
    assert cert["signatures"][0]["algorithm"] == "ed25519"
    assert cert["ledger_anchor"]["chain_hash"]
    assert "claim coverage is heuristic" in " ".join(cert["scope_limits"])


def test_verify_accepts_honest_certificate(tmp_path):
    cert, lp, cp = _run(tmp_path)
    report = verify_certificate(lp, cp)
    assert report["valid"] is True, report["errors"]
    assert report["chain_valid"] and report["signature_valid"] and report["verdicts_match"]


def test_verify_rejects_tampered_ledger(tmp_path):
    cert, lp, cp = _run(tmp_path)
    with open(lp) as f:
        lines = f.read().splitlines()
    entry = json.loads(lines[0])
    entry["payload"]["tampered"] = True            # retroactive edit
    lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    with open(lp, "w") as f:
        f.write("\n".join(lines) + "\n")
    assert verify_certificate(lp, cp)["valid"] is False


def test_verify_rejects_tampered_certificate(tmp_path):
    cert, lp, cp = _run(tmp_path)
    cert["claims"][0]["verdict_value"] = "REFUTED"   # tamper after signing
    with open(cp, "w") as f:
        json.dump(cert, f)
    assert verify_certificate(lp, cp)["valid"] is False


def test_verify_rejects_missing_certificate_entry(tmp_path):
    cert, lp, cp = _run(tmp_path)
    with open(lp) as f:
        lines = [l for l in f.read().splitlines()
                 if '"certificate.issued"' not in l]
    with open(lp, "w") as f:
        f.write("\n".join(lines) + "\n")
    assert verify_certificate(lp, cp)["valid"] is False


def test_verify_invalid_on_garbled_ledger(tmp_path):
    cert, lp, cp = _run(tmp_path)
    with open(lp, "a") as f:
        f.write('{"seq": 99, "trunc\n')
    report = verify_certificate(lp, cp)
    assert report["valid"] is False
    assert report["chain_valid"] is False
