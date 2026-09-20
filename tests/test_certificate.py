import json

from veridict.certificate import CertificateIssuer, verify_certificate
from veridict.claim_extractor import ClaimExtractor
from veridict.keys import SYSTEM_AUTHOR, KeyStore
from veridict.ladder import adjudicate
from veridict.ledger import Ledger
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import TaskManifest
from veridict.utils import canonical_json


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


def test_verify_rejects_unknown_evidence_reference(tmp_path):
    """T25.2: a validly-signed, chain-consistent cert that references evidence
    ids absent from the ledger must NOT verify — evidence references are part
    of the certification claim (defense-in-depth over the anchor pin)."""
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
    adjs = [adjudicate(c, [], pol) for c in claims]          # no evidence -> INCONCLUSIVE
    cert = CertificateIssuer(led, ks, kid).issue(
        task=task, artifact_digest="digest", policy=pol, claims=claims,
        adjudications=adjs, evidence_by_claim={c.claim_id: [] for c in claims},
        jury_families=["stub-a", "stub-b"], disclosure_level="REDACTED",
        scope_limits=["claim coverage is heuristic, not exhaustive"])
    cert = json.loads(json.dumps(cert))          # detach from the ledger's stored copy
    cert["claims"][0]["evidence_ids"] = ["does-not-exist-000000"]
    body = dict(cert)
    body.pop("signatures")
    cert["signatures"] = [{"key_id": kid, "algorithm": "ed25519",
                           "sig_b64": ks.sign(kid, canonical_json(body).encode("utf-8"))}]
    lp, cp = str(tmp_path / "ledger.jsonl"), str(tmp_path / "cert.json")
    led.save(lp)
    with open(cp, "w") as f:
        json.dump(cert, f)
    report = verify_certificate(lp, cp)
    assert report["valid"] is False, report
    assert any("unknown evidence" in e for e in report["errors"]), report["errors"]
    assert report["signature_valid"] is True    # isolate: signature fine, reference missing


def test_forged_risk_level_is_caught(tmp_path):
    """Tamga ERRATUM-A2 class: a summary field that follows from the verdicts
    must not be independently forgeable.

    The verdicts are recomputed, so they cannot be lied about. But a verifier
    that stops at the verdicts leaves risk_level free — an attacker rewrites
    it to 'low' while a claim verdict says REFUTED, or to 'high' while they
    say VERIFIED. A consumer that reads risk_level to decide (the settlement
    policy gates on exactly this field) would then decide on a forged value.
    The verifier must recompute it from the same verdicts it just checked.
    """
    from veridict.audit import AuditOrchestrator
    from veridict.jury import Jury, ScriptedProvider, Opinion
    from veridict.keys import KeyStore
    from veridict.ledger import Ledger
    from veridict.policy import PolicyDeclaration, Thresholds
    from veridict.schemas import TaskManifest
    import os, json, copy
    pkg = tmp_path / "pkg"; pkg.mkdir()
    (pkg / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (pkg / "test_calc.py").write_text(
        "def test_add():\n    from calc import add\n    assert add(1, 2) == 3\n")
    led = Ledger(); ks = KeyStore(led); kid = ks.generate_and_enroll("t")
    jury = Jury([ScriptedProvider(family="a", identity="a-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok")),
                 ScriptedProvider(family="b", identity="b-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok"))])
    pol = PolicyDeclaration(policy_id="t", mode="CERTIFICATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    task = TaskManifest(task_id="t", artifact_path=str(pkg), actor_identity="a",
                        intent_lines=("MACHINE: add computes the sum",),
                        criticality=(), has_existing_tests=True, pytest_args=[])
    out = AuditOrchestrator(led, pol, jury, ks, kid).run(task, "REDACTED")
    led.save(str(tmp_path / "ledger.jsonl"))
    cp = tmp_path / "cert.json"
    cp.write_text(json.dumps(out["cert"], indent=2, sort_keys=True))
    base = json.loads(cp.read_text())

    # baseline: the honest certificate verifies
    assert verify_certificate(str(tmp_path / "ledger.jsonl"), str(cp))["valid"]

    def probe(mutate):
        c = copy.deepcopy(base)
        mutate(c)
        cp.write_text(json.dumps(c, indent=2, sort_keys=True))
        return verify_certificate(str(tmp_path / "ledger.jsonl"), str(cp))

    # inflated risk: verdicts are all VERIFIED but risk says high
    r = probe(lambda c: c.__setitem__("risk_level", "high"))
    assert not r["valid"], "inflated risk_level must not verify"
    assert any("risk_level mismatch" in e for e in r["errors"])

    # deflated score
    r = probe(lambda c: c.__setitem__("score", 0.0))
    assert not r["valid"], "forged score must not verify"
    assert any("score mismatch" in e for e in r["errors"])

    # D18: divergence_summary is the second member of the same class — a
    # per-claim summary that follows from the same adjudications. Forging it
    # to UNANIMOUS presents a contested finding as settled, which is the
    # framing direction of A2-prime. (The honest certificate here is all
    # UNANIMOUS, so forge in the other direction: claim a SPLIT that did
    # not happen.)
    if base.get("divergence_summary"):
        r = probe(lambda c: c.__setitem__(
            "divergence_summary",
            {k: "SPLIT" for k in c["divergence_summary"]}))
        assert not r["valid"], "forged divergence_summary must not verify"

    # restore, then hide a bad result: flip a verdict to REFUTED and keep
    # risk_level 'low'. This is the dangerous direction — the verdict itself
    # is now inconsistent with the ledger, so the verdict check fires; the
    # risk check is defense in depth, not the only guard.
    cp.write_text(json.dumps(base, indent=2, sort_keys=True))
    r = probe(lambda c: (c["claims"].__setitem__(
        0, {**c["claims"][0], "verdict_value": "REFUTED"}),
        c.__setitem__("risk_level", "low")))
    assert not r["valid"], "a hidden REFUTED verdict must not verify"
