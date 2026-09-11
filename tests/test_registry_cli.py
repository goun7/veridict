"""`veridict registry` subcommands + `audit --registry` (§6.6 at the CLI).

The marketplace owner's path: init a registry ledger → register watcher
manifests → revoke on compromise → export the index. The auditor's path:
`audit --registry r.jsonl` enforces that wired watchers are registered AND
active there — self-registration cannot bypass the owner's revocation.
"""
import json
import os
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV = dict(os.environ, PYTHONPATH=REPO)


def _cli(*argv, root=None):
    env = dict(ENV)
    if root:
        env["PYTHONPATH"] = f"{root}{os.pathsep}{ENV['PYTHONPATH']}"
    return subprocess.run([sys.executable, "-m", "veridict.cli", *argv],
                          capture_output=True, text=True, cwd=REPO,
                          env=env, timeout=120)


def _write_manifest(root, watcher_id="cli-reg-w", code_hash=None):
    module = os.path.join(root, f"{watcher_id.replace('-', '_')}.py")
    code = (f"def judge(claim_summary: str, artifact_digest: str):\n"
            f'    return ("SUPPORTS", 0.6, "ok")\n')
    with open(module, "w") as f:
        f.write(code)
    import hashlib
    manifest = {
        "watcher_id": watcher_id, "name": "CLI Watcher", "version": "1.0.0",
        "producer": {"identity": "cli-test-org", "maintainer": "cli"},
        "capabilities": {"evidence_classes": ["WATCHER_REPORT"],
                         "max_tier": "W2", "subscribes_to": ["*"]},
        "resource_class": {"timeout_seconds": 2, "cost_budget": None,
                           "sandbox_level": "inprocess"},
        "integrity": {"code_hash": code_hash or hashlib.sha256(
            code.encode()).hexdigest(), "update_policy": "pinned"},
    }
    mp = os.path.join(root, f"{watcher_id}.manifest.json")
    json.dump(manifest, open(mp, "w"))
    return mp, module


def _write_task(root):
    fix = os.path.join(root, "fixture")
    os.makedirs(fix, exist_ok=True)
    with open(os.path.join(fix, "calc.py"), "w") as f:
        f.write("def add(a, b):\n    return a + b\n")
    with open(os.path.join(fix, "test_calc.py"), "w") as f:
        f.write("from calc import add\n\n\ndef test_add():\n    assert add(1, 1) == 2\n")
    tp = os.path.join(root, "task.json")
    json.dump({"task_id": "reg-cli", "artifact_path": fix,
               "actor_identity": "ai-dev",
               "intent_lines": ["MACHINE: add computes the sum of two numbers"],
               "criticality": [], "has_existing_tests": True,
               "pytest_args": []}, open(tp, "w"))
    return tp


def test_registry_lifecycle_via_cli():
    with tempfile.TemporaryDirectory() as root:
        mp, _ = _write_manifest(root, "lifecycle-w")
        reg = os.path.join(root, "registry.jsonl")
        kf = os.path.join(root, "registry.key.json")
        r = _cli("registry", "init", "--registry", reg, "--key-out", kf)
        assert r.returncode == 0, r.stderr
        r = _cli("registry", "register", "--registry", reg,
                 "--manifest", mp, "--key-file", kf)
        assert r.returncode == 0, r.stderr
        r = _cli("registry", "list", "--registry", reg)
        assert r.returncode == 0 and "lifecycle-w\tactive" in r.stdout
        r = _cli("registry", "revoke", "--registry", reg,
                 "--watcher-id", "lifecycle-w", "--reason", "key compromise",
                 "--key-file", kf)
        assert r.returncode == 0, r.stderr
        r = _cli("registry", "list", "--registry", reg)
        assert "lifecycle-w\trevoked" in r.stdout
        # index refuses to list the revoked watcher
        idx_path = os.path.join(root, "index.json")
        r = _cli("registry", "index", "--registry", reg, "--out", idx_path)
        assert r.returncode == 0, r.stderr
        assert json.load(open(idx_path))["watchers"] == []


def test_audit_requires_external_registry_membership():
    with tempfile.TemporaryDirectory() as root:
        mp, module = _write_manifest(root, "member-w")
        reg = os.path.join(root, "registry.jsonl")
        kf = os.path.join(root, "registry.key.json")
        _cli("registry", "init", "--registry", reg, "--key-out", kf)
        _cli("registry", "register", "--registry", reg, "--manifest", mp,
             "--key-file", kf)
        tp = _write_task(root)
        spec = f"{mp}:member_w:judge"
        led = os.path.join(root, "led.jsonl")

        # WITH membership: audit wires the watcher via the external registry
        r = _cli("audit", "--task", tp, "--mode", "GATE", "--ledger", led,
                 "--cert-out", os.path.join(root, "cert.json"),
                 "--watcher", spec, "--registry", reg, root=root)
        assert r.returncode == 0, r.stderr[-600:]
        out = json.loads(r.stdout)
        assert any("active in external registry" in w for w in out["warnings"])

        # AFTER revocation: the audit REFUSES to wire the watcher
        _cli("registry", "revoke", "--registry", reg,
             "--watcher-id", "member-w", "--reason", "rot", "--key-file", kf)
        led2 = os.path.join(root, "led2.jsonl")
        r = _cli("audit", "--task", tp, "--mode", "GATE", "--ledger", led2,
                 "--cert-out", os.path.join(root, "c2.json"),
                 "--watcher", spec, "--registry", reg, root=root)
        assert r.returncode != 0
        assert "not registered/active" in r.stderr


def test_audit_without_registry_still_self_registers():
    """Back-compat: no --registry ⇒ the watcher self-registers in the audit
    ledger (the pre-registry CLI behavior, honest to §6's open registry)."""
    with tempfile.TemporaryDirectory() as root:
        mp, module = _write_manifest(root, "solo-w")
        tp = _write_task(root)
        led = os.path.join(root, "led.jsonl")
        r = _cli("audit", "--task", tp, "--mode", "GATE", "--ledger", led,
                 "--cert-out", os.path.join(root, "cert.json"),
                 "--watcher", f"{mp}:solo_w:judge", root=root)
        assert r.returncode == 0, r.stderr[-600:]
        assert any("registered and wired" in w
                   for w in json.loads(r.stdout)["warnings"])
