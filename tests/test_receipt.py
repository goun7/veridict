"""Receipt layer (proof-of-done): signed, self-contained, revocable.

The property under test is the one a third party cares about: someone hands
you a file, nothing else, and you can confirm it binds to what it claims and
was signed by the key it names — then, if you also have the issuer's ledger,
that it was really issued and not later disavowed.
"""
from __future__ import annotations

import json
import os
import stat

import pytest

from veridict.certificate import verify_certificate_standalone
from veridict.receipt import (RECEIPT_TYPE, ReceiptError, ReceiptWorkspace,
                              content_digest, issue_receipt, list_receipts,
                              revoke_receipt, verify_receipt)


def _ws(tmp_path, name="ws") -> ReceiptWorkspace:
    return ReceiptWorkspace(str(tmp_path / name))


def test_issue_then_standalone_verify(tmp_path):
    ws = _ws(tmp_path)
    r = issue_receipt(ws, "deployed api v2 to staging", "agent-7",
                      evidence=["gh run 8812 passed"])
    assert r["certificate_type"] == RECEIPT_TYPE
    assert r["subject"]["actor_identity"] == "agent-7"
    # the content hash recomputes from the receipt's own fields
    assert r["subject"]["artifact_digest"] == content_digest(
        r["achievement"], r["evidence"])
    p = str(tmp_path / "r.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(r, f, sort_keys=True)
    rep = verify_receipt(p)
    assert rep["valid"] is True, rep["errors"]
    assert rep["signature_valid"] is True
    assert rep["content_hash_valid"] is True
    assert rep["timestamp_valid"] is True
    # standalone cannot know revocation: it says so, never assumes good
    assert rep["revoked"] is None


def test_cert_id_recomputes_like_an_audit_certificate(tmp_path):
    """cert_id derives from the subject fields exactly the way an audit
    certificate's does — one standalone verifier serves both document kinds."""
    ws = _ws(tmp_path)
    r = issue_receipt(ws, "paid invoice 1042", "agent-pay")
    p = str(tmp_path / "r.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(r, f, sort_keys=True)
    rep = verify_certificate_standalone(p)
    assert rep["valid"] is True, rep["errors"]


def test_verify_with_ledger_checks_chain_and_issuance(tmp_path):
    ws = _ws(tmp_path)
    r = issue_receipt(ws, "shipped feature flag F9", "agent-1")
    p = str(tmp_path / "r.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(r, f, sort_keys=True)
    rep = verify_receipt(p, ws.ledger_path)
    assert rep["valid"] is True, rep["errors"]
    assert rep["chain_valid"] is True
    assert rep["revoked"] is False


def test_verify_against_wrong_ledger_is_rejected(tmp_path):
    """A receipt presented against a ledger it was never issued into must
    fail closed — otherwise any ledger vouches for any receipt."""
    ws_a = _ws(tmp_path, "a")
    r = issue_receipt(ws_a, "did the work", "agent-1")
    p = str(tmp_path / "r.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(r, f, sort_keys=True)

    ws_b = _ws(tmp_path, "b")
    issue_receipt(ws_b, "unrelated work", "agent-2")   # a different ledger

    rep = verify_receipt(p, ws_b.ledger_path)
    assert rep["valid"] is False
    assert any("receipt.issued" in e for e in rep["errors"]), rep["errors"]


def test_revoke_makes_receipt_invalid_with_ledger(tmp_path):
    ws = _ws(tmp_path)
    r = issue_receipt(ws, "deployed v2", "agent-7")
    p = str(tmp_path / "r.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(r, f, sort_keys=True)
    assert verify_receipt(p, ws.ledger_path)["valid"] is True

    res = revoke_receipt(ws, r["cert_id"], "rollback: canary regressed")
    assert res["cert_id"] == r["cert_id"]
    assert res["reason"] == "rollback: canary regressed"

    rep = verify_receipt(p, ws.ledger_path)
    assert rep["valid"] is False
    assert rep["revoked"] is True
    assert any("revoked: rollback" in e for e in rep["errors"])

    # standalone verification is unaffected: revocation is a ledger fact, and
    # the receipt's own signature is still intact (the file was never edited)
    alone = verify_receipt(p)
    assert alone["valid"] is True
    assert alone["signature_valid"] is True


def test_receipt_file_is_not_modified_by_revoke(tmp_path):
    ws = _ws(tmp_path)
    r = issue_receipt(ws, "deployed v2", "agent-7")
    p = str(tmp_path / "r.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(r, f, sort_keys=True)
    before = open(p, encoding="utf-8").read()
    revoke_receipt(ws, r["cert_id"], "superseded")
    after = open(p, encoding="utf-8").read()
    assert before == after, "revocation must be append-only on the ledger"


def test_list_marks_revoked_and_filters(tmp_path):
    ws = _ws(tmp_path)
    a = issue_receipt(ws, "task a", "agent-1")
    b = issue_receipt(ws, "task b", "agent-1")
    revoke_receipt(ws, a["cert_id"], "bad")
    rows = list_receipts(ws)
    assert {x["cert_id"] for x in rows} == {a["cert_id"], b["cert_id"]}
    status = {x["cert_id"]: x["revoked"] for x in rows}
    assert status[a["cert_id"]] is True
    assert status[b["cert_id"]] is False
    active = list_receipts(ws, include_revoked=False)
    assert [x["cert_id"] for x in active] == [b["cert_id"]]
    # newest first
    assert rows[0]["issued_at"] >= rows[1]["issued_at"]


def test_issuer_identity_survives_a_process_boundary(tmp_path):
    """A workspace keeps ONE issuer identity: reloading it must reuse the
    same key, so receipts from two sessions share one verifiable signer."""
    ws = _ws(tmp_path)
    r1 = issue_receipt(ws, "first session", "agent-1")
    key_id_1 = r1["issuer"]["key_id"]
    assert r1["public_key"]["public_pem"]

    # a fresh object over the same directory simulates a restart
    ws2 = ReceiptWorkspace(ws.home)
    r2 = issue_receipt(ws2, "second session", "agent-1")
    assert r2["issuer"]["key_id"] == key_id_1, "issuer identity must persist"
    assert r2["public_key"]["public_pem"] == r1["public_key"]["public_pem"]
    assert stat.S_IMODE(os.stat(ws2._key_path).st_mode) == 0o600


def test_workspace_key_from_another_ledger_is_refused(tmp_path):
    """A key file that does not match this ledger must not silently sign
    with a key the chain cannot vouch for."""
    ws_a = _ws(tmp_path, "a")
    ws_b = _ws(tmp_path, "b")
    issue_receipt(ws_a, "work", "agent-1")          # key written under a/
    # copy a's key into b's workspace, where it is not enrolled
    os.makedirs(os.path.join(ws_b.home, "keys"), exist_ok=True)
    src, dst = ws_a._key_path, ws_b._key_path
    with open(src, encoding="utf-8") as f:
        key = f.read()
    with open(dst, "w", encoding="utf-8") as f:
        f.write(key)
    with pytest.raises(ReceiptError, match="not enrolled"):
        issue_receipt(ws_b, "forged", "agent-1")


def test_tampered_body_breaks_signature(tmp_path):
    ws = _ws(tmp_path)
    r = issue_receipt(ws, "deployed v2", "agent-7")
    r["evidence"].append(" lie: never actually verified")
    p = str(tmp_path / "r.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(r, f, sort_keys=True)
    rep = verify_receipt(p)
    assert rep["valid"] is False
    assert rep["signature_valid"] is False


def test_stripped_public_key_is_reported_not_assumed(tmp_path):
    ws = _ws(tmp_path)
    r = issue_receipt(ws, "deployed v2", "agent-7")
    del r["public_key"]
    p = str(tmp_path / "r.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(r, f, sort_keys=True)
    rep = verify_receipt(p)
    assert rep["valid"] is False
    assert any("no public key embedded" in e for e in rep["errors"])


def test_missing_achievement_is_rejected(tmp_path):
    ws = _ws(tmp_path)
    with pytest.raises(ReceiptError, match="achievement is required"):
        issue_receipt(ws, "   ", "agent-1")
    with pytest.raises(ReceiptError):
        issue_receipt(ws, "x" * 5000, "agent-1")


def test_revoke_requires_cert_id(tmp_path):
    ws = _ws(tmp_path)
    with pytest.raises(ReceiptError, match="cert_id is required"):
        revoke_receipt(ws, "", "reason")


def test_corrupt_ledger_is_reported_not_crashed(tmp_path):
    ws = _ws(tmp_path)
    r = issue_receipt(ws, "work", "agent-1")
    p = str(tmp_path / "r.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(r, f, sort_keys=True)
    with open(ws.ledger_path, "w", encoding="utf-8") as f:
        f.write("{not json\n")
    rep = verify_receipt(p, ws.ledger_path)
    assert rep["valid"] is False
    assert any("ledger:" in e for e in rep["errors"])


def test_workspace_resolution_prefers_explicit_then_env(tmp_path, monkeypatch):
    explicit = ReceiptWorkspace.resolve(str(tmp_path / "explicit"))
    assert explicit.home == str(tmp_path / "explicit")

    monkeypatch.setenv("VERIDICT_HOME", str(tmp_path / "fromenv"))
    assert ReceiptWorkspace.resolve(None).home == str(tmp_path / "fromenv")

    monkeypatch.delenv("VERIDICT_HOME", raising=False)
    monkeypatch.chdir(tmp_path)
    assert ReceiptWorkspace.resolve(None).home == str(tmp_path / ".veridict")
