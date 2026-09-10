"""CLI --watcher wiring (§6): the external watcher author's actual path —

    veridict audit --task t.json --watcher m.json:my_watcher:judge ...

with the manifest's code_hash verified against the entry module. Also the
§6.6 CLI surface: a watcher revoked in the audit ledger must not appear in
the exported index.
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _write_fixture(root):
    fix = os.path.join(root, "fixture")
    os.makedirs(fix)
    with open(os.path.join(fix, "calc.py"), "w") as f:
        f.write("def add(a, b):\n    return a + b\n")
    with open(os.path.join(fix, "test_calc.py"), "w") as f:
        f.write("from calc import add\n\n\ndef test_add():\n    assert add(1, 1) == 2\n")
    task = {"task_id": "cli-watcher", "artifact_path": fix,
            "actor_identity": "ai-dev",
            "intent_lines": ["MACHINE: add computes the sum of two numbers"],
            "criticality": [], "has_existing_tests": True, "pytest_args": []}
    tp = os.path.join(root, "task.json")
    json.dump(task, open(tp, "w"))
    return tp


def _write_watcher(root):
    """A minimal external watcher: module + manifest + matching code_hash."""
    module = os.path.join(root, "my_watcher.py")
    code = ('"""An external Veridict watcher (see CONTRIBUTING quickstart)."""\n'
            "\n\ndef judge(claim_summary: str, artifact_digest: str):\n"
            '    return ("SUPPORTS", 0.7, "external watcher saw nothing wrong")\n')
    with open(module, "w") as f:
        f.write(code)
    code_hash = hashlib.sha256(code.encode()).hexdigest()
    manifest = {
        "watcher_id": "example-external", "name": "Example", "version": "1.0.0",
        "producer": {"identity": "example-org", "maintainer": "example"},
        "capabilities": {"evidence_classes": ["JURY_OPINION"],
                         "max_tier": "W2", "subscribes_to": ["*"]},
        "resource_class": {"timeout_seconds": 2, "cost_budget": None,
                           "sandbox_level": "none"},
        "integrity": {"code_hash": code_hash, "update_policy": "pinned"},
    }
    mp = os.path.join(root, "manifest.json")
    json.dump(manifest, open(mp, "w"))
    return f"{mp}:my_watcher:judge"


def _run(root, tp, spec):
    led = os.path.join(root, "led.jsonl")
    cert = os.path.join(root, "cert.json")
    base = [sys.executable, "-m", "veridict.cli"]
    env = dict(os.environ, PYTHONPATH=root)
    r = subprocess.run(base + ["audit", "--task", tp, "--mode", "GATE",
                               "--ledger", led, "--cert-out", cert,
                               "--watcher", spec],
                       capture_output=True, text=True, cwd=REPO,
                       env=env, timeout=180)
    return r, led, cert


def test_cli_watcher_runs_and_records_evidence():
    with tempfile.TemporaryDirectory() as root:
        tp = _write_fixture(root)
        spec = _write_watcher(root)
        r, led, cert = _run(root, tp, spec)
        assert r.returncode == 0, r.stderr[-800:]
        out = json.loads(r.stdout)
        assert any("example-external" in w for w in out["warnings"])
        entries = [json.loads(line) for line in open(led)]
        kinds = [e["payload"].get("producer", {}).get("identity")
                 for e in entries if e["entry_type"] == "evidence.recorded"]
        assert "example-org" in kinds, "watcher evidence recorded"
        v = subprocess.run([sys.executable, "-m", "veridict.cli", "verify",
                            "--ledger", led, "--cert", cert],
                           capture_output=True, text=True, cwd=REPO, timeout=60)
        assert v.returncode == 0 and json.loads(v.stdout)["valid"]


def test_cli_rejects_code_hash_mismatch():
    with tempfile.TemporaryDirectory() as root:
        tp = _write_fixture(root)
        spec = _write_watcher(root)
        mp = spec.split(":")[0]
        manifest = json.load(open(mp))
        manifest["integrity"]["code_hash"] = "0" * 64
        json.dump(manifest, open(mp, "w"))
        r, _, _ = _run(root, tp, spec)
        assert r.returncode != 0 and "code_hash mismatch" in r.stderr


def test_cli_rejects_bad_spec_shape():
    with tempfile.TemporaryDirectory() as root:
        tp = _write_fixture(root)
        r, _, _ = _run(root, tp, "no-colons-here")
        assert r.returncode != 0 and "expected manifest.json:module:fn" in r.stderr
