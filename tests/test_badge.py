"""Badge protocol: the SVG is a CLAIM, not a decoration.

- a valid all-VERIFIED certificate yields a green badge mentioning its cert id
- a certificate with a REFUTED claim yields a RED badge (worst-verdict-wins)
- an INVALID certificate yields NO badge (exit 1) — a badge that cannot be
  refused is marketing, not audit
"""
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO, "scripts", "make_badge.py")


def _run(cert_path, ledger_path, out_path, label="test-repo"):
    return subprocess.run(
        [sys.executable, SCRIPT, "--cert", cert_path, "--ledger", ledger_path,
         "--out", out_path, "--label", label],
        capture_output=True, text=True, cwd=REPO, timeout=120)


def test_valid_cert_yields_verified_badge(tmp_path):
    from veridict.ledger import Ledger
    led = Ledger.load(os.path.join(REPO, "dogfood_ledger.jsonl"))
    with open(os.path.join(REPO, "dogfood_cert.json"), encoding="utf-8") as f:
        cert = json.load(f)
    lp = str(tmp_path / "led.jsonl")
    cp = str(tmp_path / "cert.json")
    led.save(lp)
    json.dump(cert, open(cp, "w"))
    out = str(tmp_path / "badge.svg")
    r = _run(cp, lp, out)
    assert r.returncode == 0, r.stderr
    svg = open(out, encoding="utf-8").read()
    assert 'aria-label="test-repo: VERIFIED"' in svg
    assert 'fill="#2da44e"' in svg
    assert cert["cert_id"][:12] in svg
    assert "goun7.github.io/veridict/standard.html" in svg


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
    from veridict.ledger import Ledger
    led = Ledger.load(os.path.join(REPO, "dogfood_ledger.jsonl"))
    with open(os.path.join(REPO, "dogfood_cert.json"), encoding="utf-8") as f:
        cert = json.load(f)
    cert["claims"][0]["verdict_value"] = "REFUTED"
    lp = str(tmp_path / "led.jsonl")
    cp = str(tmp_path / "bad.json")
    led.save(lp)
    json.dump(cert, open(cp, "w"))
    r = _run(cp, lp, str(tmp_path / "badge.svg"))
    assert r.returncode == 1
    assert "INVALID" in r.stderr
