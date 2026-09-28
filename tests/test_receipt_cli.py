"""CLI surface for the new standalone verification + receipt commands.

The external-wrapper contract (test_cli_surface.py) pins `verify --ledger
--cert`; this file pins the ADDITIVE surface that closes the independent-
verification gap: a positional certificate that needs nothing else.
"""
from __future__ import annotations

import json
import os

from veridict.cli import main


def _audit_cert(tmp_path):
    """Build a real audit certificate via the orchestrator, like the wrappers do."""
    from veridict.audit import AuditOrchestrator
    from veridict.jury import Jury, Opinion, ScriptedProvider
    from veridict.keys import KeyStore
    from veridict.ledger import Ledger
    from veridict.policy import PolicyDeclaration, Thresholds
    from veridict.schemas import TaskManifest

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("cli-test")
    jury = Jury([
        ScriptedProvider(family="stub-a", identity="a", default=Opinion("SUPPORTS", 0.8, "s")),
        ScriptedProvider(family="stub-b", identity="b", default=Opinion("SUPPORTS", 0.8, "s")),
    ])
    pol = PolicyDeclaration(policy_id="t", mode="CERTIFICATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    task = TaskManifest(task_id="t1", artifact_path=str(pkg), actor_identity="actor",
                        intent_lines=["MACHINE: add computes the sum"],
                        criticality=(), has_existing_tests=False, pytest_args=[])
    cert = AuditOrchestrator(led, pol, jury, ks, kid).run(task)["cert"]
    led.save(str(tmp_path / "led.jsonl"))
    p = tmp_path / "cert.json"
    p.write_text(json.dumps(cert, default=str))
    return str(tmp_path / "led.jsonl"), str(p)


def test_verify_positional_standalone(tmp_path, monkeypatch):
    """`veridict verify cert.json` — no ledger argument at all."""
    _, cert = _audit_cert(tmp_path)
    monkeypatch.chdir(tmp_path)
    rc = main(["verify", cert])
    assert rc == 0


def test_verify_cert_flag_without_ledger(tmp_path):
    _, cert = _audit_cert(tmp_path)
    rc = main(["verify", "--cert", cert])
    assert rc == 0


def test_standalone_rejects_tampered_body(tmp_path):
    _, cert = _audit_cert(tmp_path)
    with open(cert, encoding="utf-8") as f:
        c = json.load(f)
    c["risk_level"] = "high" if c["risk_level"] != "high" else "low"
    with open(cert, "w", encoding="utf-8") as f:
        json.dump(c, f)
    rc = main(["verify", cert])
    assert rc == 1


def test_audit_cert_revoke_then_verify_invalid(tmp_path):
    """The audit-certificate revoke path: append-only, file untouched."""
    ledger, cert = _audit_cert(tmp_path)
    rc = main(["verify", "--ledger", ledger, "--cert", cert])
    assert rc == 0
    rc = main(["revoke", "--ledger", ledger, "--cert", cert, "--reason", "superseded"])
    assert rc == 0
    rc = main(["verify", "--ledger", ledger, "--cert", cert])
    assert rc == 1
    # the receipt/cert file itself is untouched by revocation


def test_receipt_cli_full_lifecycle(tmp_path, monkeypatch):
    ws = tmp_path / "ws"
    monkeypatch.setenv("VERIDICT_HOME", str(ws))

    rc = main(["receipt", "issue", "--achievement", "deployed api v2 to staging",
               "--actor", "agent-7", "--evidence", "gh run 8812 passed"])
    assert rc == 0
    receipts_dir = ws / "receipts"
    cert_file = next(receipts_dir.glob("*.json"))
    cert_id = cert_file.stem

    # standalone verify of the issued receipt
    rc = main(["verify", str(cert_file)])
    assert rc == 0

    # full verify with the ledger
    rc = main(["receipt", "verify", "--cert", str(cert_file),
               "--ledger", str(ws / "ledger.jsonl")])
    assert rc == 0

    # list
    rc = main(["receipt", "list"])
    assert rc == 0

    # revoke, then verify must fail
    rc = main(["receipt", "revoke", "--cert-id", cert_id,
               "--reason", "canary regressed"])
    assert rc == 0
    rc = main(["receipt", "verify", "--cert", str(cert_file),
               "--ledger", str(ws / "ledger.jsonl")])
    assert rc == 1
    # standalone still good — the file was never edited
    rc = main(["verify", str(cert_file)])
    assert rc == 0
    # active-only listing drops the revoked receipt
    rc = main(["receipt", "list", "--active-only"])
    assert rc == 0


def test_receipt_issue_writes_to_explicit_out(tmp_path):
    ws = tmp_path / "ws"
    out = tmp_path / "nested" / "receipt.json"
    rc = main(["receipt", "issue", "--achievement", "paid invoice 1042",
               "--actor", "agent-pay", "--workspace", str(ws),
               "--out", str(out)])
    assert rc == 0
    assert out.exists()
    rc = main(["verify", str(out)])
    assert rc == 0


def test_receipt_rejects_empty_achievement(tmp_path, capsys):
    ws = tmp_path / "ws"
    rc = main(["receipt", "issue", "--achievement", "   ",
               "--workspace", str(ws)])
    assert rc == 1
    assert "achievement" in capsys.readouterr().err
