import json

from veridict.cli import main


def _task_json(tmp_path, mode):
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "test_calc.py").write_text(
        "from calc import add\n\ndef test_add():\n    assert add(1, 1) == 2\n")
    return {"task_id": "cli-t", "artifact_path": str(tmp_path),
            "actor_identity": "ai-dev", "intent_lines": [], "criticality": [],
            "has_existing_tests": True, "pytest_args": []}


def test_audit_then_verify_roundtrip(tmp_path):
    tj = tmp_path / "task.json"
    with open(tj, "w") as f:
        json.dump(_task_json(tmp_path, "CERTIFICATE"), f)
    rc = main(["audit", "--task", str(tj), "--mode", "CERTIFICATE",
               "--ledger", str(tmp_path / "led.jsonl"),
               "--cert-out", str(tmp_path / "cert.json")])
    assert rc == 0
    rc = main(["verify", "--ledger", str(tmp_path / "led.jsonl"),
               "--cert", str(tmp_path / "cert.json")])
    assert rc == 0


def test_verify_detects_corruption(tmp_path):
    tj = tmp_path / "task.json"
    with open(tj, "w") as f:
        json.dump(_task_json(tmp_path, "CERTIFICATE"), f)
    main(["audit", "--task", str(tj), "--mode", "CERTIFICATE",
          "--ledger", str(tmp_path / "led.jsonl"),
          "--cert-out", str(tmp_path / "cert.json")])
    with open(tmp_path / "led.jsonl") as f:
        lines = f.read().splitlines()
    e = json.loads(lines[0])
    e["payload"]["x"] = 1
    lines[0] = json.dumps(e, sort_keys=True, separators=(",", ":"))
    with open(tmp_path / "led.jsonl", "w") as f:
        f.write("\n".join(lines) + "\n")
    rc = main(["verify", "--ledger", str(tmp_path / "led.jsonl"),
               "--cert", str(tmp_path / "cert.json")])
    assert rc == 1


def test_audit_gate_blocked_exits_2(tmp_path):
    tj = tmp_path / "task.json"
    # failing test suite + MACHINE(payments) intent → REFUTED claims → GATE blocks
    d = _task_json(tmp_path, "GATE")
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    d["intent_lines"] = ["MACHINE(payments): add computes sums"]
    with open(tj, "w") as f:
        json.dump(d, f)
    rc = main(["audit", "--task", str(tj), "--mode", "GATE",
               "--ledger", str(tmp_path / "led2.jsonl"),
               "--cert-out", str(tmp_path / "cert2.json")])
    assert rc == 2


def test_usage_error_exits_1(capsys):
    assert main(["bogus-subcommand"]) == 1


def test_verify_missing_files_exits_1(tmp_path, capsys):
    rc = main(["verify", "--ledger", str(tmp_path / "nope.jsonl"),
               "--cert", str(tmp_path / "nope.json")])
    assert rc == 1
    assert "error" in capsys.readouterr().err
