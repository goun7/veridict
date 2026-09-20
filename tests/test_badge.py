"""Badge protocol: the SVG is a CLAIM, not a decoration.

- a valid all-VERIFIED certificate yields a green badge mentioning its cert id
- a certificate with a REFUTED claim yields a RED badge (worst-verdict-wins)
- an INVALID certificate yields NO badge (exit 1) — a badge that cannot be
  refused is marketing, not audit

Fixtures are SELF-CONTAINED (a fresh cert is issued per test) — the badge
tests deliberately do NOT depend on dogfood_ledger.jsonl, which is a
gitignored artifact produced by a LATER CI step than this suite.
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "make_badge.py")


def _issue_cert(tmp_path, verdict_item_tier="W1a"):
    """Issue a fresh, valid certificate for a single MACHINE_CHECKABLE claim
    backed by one W1a SUPPORTS item → R0 VERIFIED. Returns (ledger_path,
    cert_path, cert_dict)."""
    from veridict.certificate import CertificateIssuer
    from veridict.claim_extractor import ClaimExtractor
    from veridict.keys import KeyStore
    from veridict.ladder import adjudicate
    from veridict.ledger import Ledger
    from veridict.policy import PolicyDeclaration, Thresholds
    from veridict.schemas import ActorRef, EvidenceItem, TaskManifest

    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("badge-test")
    pol = PolicyDeclaration(policy_id="badge", mode="GATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    task = TaskManifest(task_id="badge-e2e", artifact_path="/x",
                        actor_identity="ai-dev",
                        intent_lines=("MACHINE: add computes the sum of two numbers",),
                        criticality=(), has_existing_tests=True, pytest_args=())
    claim = ClaimExtractor().extract(task, "digest-badge")[0]
    led.append("claim.registered",
               ActorRef(kind="system", identity="c", version="1"),
               claim.to_dict())
    item = EvidenceItem(
        evidence_id="veridict-evidence-v1-" + claim.claim_id + "-testexec",
        claim_id=claim.claim_id, evidence_class="TEST_EXECUTION", tier="W1a",
        producer={"kind": "verifier", "identity": "test-executor", "version": "0.1.0"},
        artifact_ref="digest-badge",
        reproducibility={"deterministic": True, "rerun_recipe": {"cmd": ["pytest"]}},
        stance="SUPPORTS", confidence=1.0, rationale="tests pass")
    led.append("evidence.recorded",
               ActorRef(kind="verifier", identity="test-executor", version="0.1.0"),
               item.to_dict())
    adj = adjudicate(claim, [item], pol)   # R0: machine evidence univocal
    assert adj.value == "VERIFIED"
    # D19: the verifier reconciles the cert's policy against the policy the
    # ledger records the run used, so the ledger must record one.
    from veridict.policy import PolicyEngine
    PolicyEngine(led).apply(
        [claim], {claim.claim_id: [item]}, pol,
        ActorRef(kind="system", identity="badge-builder", version="1"))
    cert = CertificateIssuer(led, ks, kid).issue(
        task=task, artifact_digest="digest-badge", policy=pol, claims=[claim],
        adjudications=[adj], evidence_by_claim={claim.claim_id: [item]},
        jury_families=[], disclosure_level="REDACTED",
        scope_limits=["claim coverage is heuristic, not exhaustive"])
    lp = str(tmp_path / "led.jsonl")
    cp = str(tmp_path / "cert.json")
    led.save(lp)
    json.dump(cert, open(cp, "w"))
    return lp, cp, cert


def _run(cert_path, ledger_path, out_path, label="test-repo"):
    return subprocess.run(
        [sys.executable, SCRIPT, "--cert", cert_path, "--ledger", ledger_path,
         "--out", out_path, "--label", label],
        capture_output=True, text=True, cwd=REPO, timeout=120)


def test_valid_cert_yields_verified_badge(tmp_path):
    lp, cp, cert = _issue_cert(tmp_path)
    out = str(tmp_path / "badge.svg")
    r = _run(cp, lp, out)
    assert r.returncode == 0, r.stderr
    svg = open(out, encoding="utf-8").read()
    assert 'aria-label="test-repo: VERIFIED"' in svg
    assert 'fill="#2da44e"' in svg
    assert cert["cert_id"][:12] in svg
    assert "goun7.github.io/veridict/standard.html" in svg
    # Receipt, not narrative: the emitted SVG must parse as XML. The 0.3.x
    # badge shipped with "--" inside an XML comment (illegal per XML 1.0) —
    # every browser showed a broken image while CI stayed green for a day.
    import xml.etree.ElementTree as ET
    ET.fromstring(svg)  # raises ParseError → test fails


def test_badge_status_worst_verdict_wins():
    """The color a badge carries is decided by the WORST verdict only —
    one REFUTED/ESCALATED/INCONCLUSIVE claim taints the whole badge, even
    alongside many VERIFIED ones (no silent pass in the badge either)."""
    from scripts.make_badge import badge_status
    assert badge_status({"claims": [{"verdict_value": "VERIFIED"}]}) == "VERIFIED"
    assert badge_status(
        {"claims": [{"verdict_value": "VERIFIED"},
                    {"verdict_value": "REFUTED"}]}) == "REFUTED"
    assert badge_status(
        {"claims": [{"verdict_value": "ESCALATED"}]}) == "ESCALATED"
    assert badge_status(
        {"claims": [{"verdict_value": "VERIFIED"},
                    {"verdict_value": "INCONCLUSIVE"}]}) == "INCONCLUSIVE"
    assert badge_status({"claims": []}) == "INCONCLUSIVE"


def test_recomputed_mismatch_is_refused(tmp_path):
    """Flip one claim verdict without re-signing: the offline recomputation
    disagrees → the cert is invalid → NO badge (rc 1)."""
    lp, cp, cert = _issue_cert(tmp_path)
    cert["claims"][0]["verdict_value"] = "REFUTED"
    json.dump(cert, open(cp, "w"))
    r = _run(cp, lp, str(tmp_path / "badge.svg"))
    assert r.returncode == 1
    assert "INVALID" in r.stderr