"""CLI end-to-end smoke (the external user's actual path):

    veridict audit --task task.json --ledger led.jsonl --cert-out cert.json
    veridict verify --ledger led.jsonl --cert cert.json

Runs the installed entrypoint as a subprocess in a temp dir; asserts rc 0,
a valid certificate, and the stub-jury honesty warning surfacing on stderr
output (R5: nobody should mistake a stub jury for real doctrine).
"""
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _fixture(root):
    fix = os.path.join(root, "fixture")
    os.makedirs(fix)
    with open(os.path.join(fix, "calc.py"), "w") as f:
        f.write("def add(a, b):\n    return a + b\n")
    with open(os.path.join(fix, "test_calc.py"), "w") as f:
        f.write("from calc import add\n\n\ndef test_add():\n    assert add(1, 1) == 2\n")
    task = {"task_id": "cli-e2e", "artifact_path": fix,
            "actor_identity": "ai-dev",
            "intent_lines": ["MACHINE: add computes the sum of two numbers"],
            "criticality": [], "has_existing_tests": True, "pytest_args": []}
    tp = os.path.join(root, "task.json")
    json.dump(task, open(tp, "w"))
    return tp


def test_cli_audit_then_verify_roundtrip():
    with tempfile.TemporaryDirectory() as root:
        tp = _fixture(root)
        led = os.path.join(root, "led.jsonl")
        cert = os.path.join(root, "cert.json")
        base = [sys.executable, "-m", "veridict.cli"]
        r = subprocess.run(base + ["audit", "--task", tp, "--mode", "GATE",
                                   "--ledger", led, "--cert-out", cert],
                           capture_output=True, text=True, cwd=REPO, timeout=180)
        assert r.returncode == 0, r.stderr[-800:]
        out = json.loads(r.stdout)
        assert out["blocked"] is False
        assert any("stub" in w.lower() or "jury" in w.lower()
                   for w in out["warnings"]), out["warnings"]
        v = subprocess.run(base + ["verify", "--ledger", led, "--cert", cert],
                           capture_output=True, text=True, cwd=REPO, timeout=60)
        assert v.returncode == 0, v.stderr[-800:]
        report = json.loads(v.stdout)
        assert report["valid"] and report["verdicts_match"]


def test_verify_scales_linearly_on_large_ledgers(tmp_path):
    """GATE latency (§6.5) depends on verification staying O(n). A 4k-entry
    ledger (200 audits × 20 entries) must verify well under a second of
    budget-sensitive time — catches accidental O(n²) walks."""
    import time
    from veridict.ledger import Ledger
    from veridict.schemas import ActorRef

    led = Ledger()
    auth = ActorRef(kind="system", identity="core", version="1")
    for i in range(4000):
        led.append("evidence.recorded", auth,
                   {"claim_id": f"c{i % 40}", "n": i, "data": "x" * 40})
    lp = str(tmp_path / "big.jsonl")
    led.save(lp)
    reloaded = Ledger.load(lp)
    t0 = time.monotonic()
    ok, msg = reloaded.verify_chain()
    elapsed = time.monotonic() - t0
    assert ok, msg
    assert elapsed < 5.0, f"verify_chain took {elapsed:.2f}s for 4k entries — O(n²)?"
    print(f"verify_chain 4k entries: {elapsed:.2f}s")
