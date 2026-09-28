"""veridict-receipt-mcp — the four certificate tools over the protocol.

Two regimes, exactly like the audit adapter tests:

  - a stub FastMCP (the SDK is optional in CI) exercises the tool LOGIC,
    since a @mcp.tool-decorated function is a plain function underneath;
  - when the real SDK is installed, tool REGISTRATION and invocation go
    through the actual protocol surface — the test that catches a rename
    like the v1 -> v2 FastMCP -> MCPServer move.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import sys
import types

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MCP_DIR = os.path.join(ROOT, "mcp")
_SERVER = os.path.join(MCP_DIR, "veridict_receipt_mcp", "server.py")


def _mcp_module(monkeypatch):
    """Import the server with a stub FastMCP so the SDK is not required.

    Registered under unique sys.modules keys and monkeypatch-scoped, so the
    fake `mcp` can never shadow the real SDK for the real-SDK tests below."""
    class _FakeMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            def deco(fn):
                fn._is_tool = True      # visible to the registry test
                return fn
            return deco

        def run(self, *a, **k):
            raise SystemExit(0)

    stub = types.ModuleType("mcp")
    server_mod = types.ModuleType("mcp.server")
    fastmcp = types.ModuleType("mcp.server.fastmcp")
    fastmcp.FastMCP = _FakeMCP
    server_mod.fastmcp = fastmcp
    stub.server = server_mod
    for key, mod in (("mcp", stub), ("mcp.server", server_mod),
                     ("mcp.server.fastmcp", fastmcp)):
        monkeypatch.setitem(sys.modules, key, mod)

    spec = importlib.util.spec_from_file_location(
        "_stub_veridict_receipt_mcp_server", _SERVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_four_tools_are_registered(monkeypatch):
    server = _mcp_module(monkeypatch)
    # FastMCP derives tool names from function names; the documented surface
    # is issue / verify / revoke / list and nothing else.
    registered = {name for name, fn in vars(server).items()
                  if callable(fn) and getattr(fn, "_is_tool", False)}
    assert registered == {"issue", "verify", "revoke", "list"}


def test_issue_then_verify_roundtrip(monkeypatch, tmp_path):
    server = _mcp_module(monkeypatch)
    monkeypatch.setenv("VERIDICT_HOME", str(tmp_path / "ws"))

    out = json.loads(server.issue("deployed api v2 to staging", "agent-7",
                                  evidence=["gh run 8812 passed"]))
    assert out["ok"] is True
    assert out["cert_id"]
    assert out["verify"].startswith("veridict verify ")

    rep = json.loads(server.verify(out["receipt_path"]))
    assert rep["valid"] is True, rep["errors"]
    assert rep["signature_valid"] is True
    assert rep["content_hash_valid"] is True


def test_verify_accepts_inline_json(monkeypatch, tmp_path):
    """An agent often holds the receipt content rather than a path; the
    verifier meets it where it is without dropping the standalone property."""
    server = _mcp_module(monkeypatch)
    monkeypatch.setenv("VERIDICT_HOME", str(tmp_path / "ws"))
    out = json.loads(server.issue("ran migrations", "agent-9"))

    as_json_string = json.dumps(json.load(open(out["receipt_path"])))
    rep = json.loads(server.verify(as_json_string))
    assert rep["valid"] is True, rep["errors"]

    import json as _j
    as_object = _j.loads(as_json_string)
    rep2 = json.loads(server.verify(as_object))
    assert rep2["valid"] is True, rep2["errors"]


def test_revoke_then_verify_invalid(monkeypatch, tmp_path):
    server = _mcp_module(monkeypatch)
    monkeypatch.setenv("VERIDICT_HOME", str(tmp_path / "ws"))
    out = json.loads(server.issue("deployed v2", "agent-7"))
    ledger = str(tmp_path / "ws" / "ledger.jsonl")

    assert json.loads(server.verify(out["receipt_path"], ledger))["valid"] is True

    rev = json.loads(server.revoke(out["cert_id"], "canary regressed"))
    assert rev["ok"] is True and rev["reason"] == "canary regressed"

    rep = json.loads(server.verify(out["receipt_path"], ledger))
    assert rep["valid"] is False
    assert rep["revoked"] is True


def test_list_marks_revoked(monkeypatch, tmp_path):
    server = _mcp_module(monkeypatch)
    monkeypatch.setenv("VERIDICT_HOME", str(tmp_path / "ws"))
    a = json.loads(server.issue("task a", "agent-1"))
    json.loads(server.issue("task b", "agent-1"))
    json.loads(server.revoke(a["cert_id"], "bad"))

    rows = json.loads(server.list())
    assert rows["count"] == 2
    assert any(r["cert_id"] == a["cert_id"] and r["revoked"] for r in rows["receipts"])
    active = json.loads(server.list(active_only=True))
    assert active["count"] == 1
    assert active["receipts"][0]["cert_id"] != a["cert_id"]


def test_tools_never_raise(monkeypatch, tmp_path):
    """Over the protocol an exception is a session-wide event; every tool
    reports as JSON instead."""
    server = _mcp_module(monkeypatch)
    monkeypatch.setenv("VERIDICT_HOME", str(tmp_path / "ws"))
    out = json.loads(server.issue("ok", "agent-1"))
    assert json.loads(server.verify(str(tmp_path / "nope.json")))["valid"] is False
    assert json.loads(server.verify("{not json"))["valid"] is False
    assert json.loads(server.revoke("", "why"))["ok"] is False
    assert json.loads(server.issue("", "agent-1"))["ok"] is False
    # a receipt verified against a ledger it was never issued into
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.setenv("VERIDICT_HOME", str(other))
    json.loads(server.issue("other", "agent-2"))
    rep = json.loads(server.verify(out["receipt_path"], str(other / "ledger.jsonl")))
    assert rep["valid"] is False


def test_mcp_json_is_valid_and_publishable():
    """The registry definition must parse and name the real launcher."""
    with open(os.path.join(MCP_DIR, "mcp.json"), encoding="utf-8") as f:
        d = json.load(f)
    assert d["name"] == "veridict-receipt"
    assert d["transport"] == "stdio"
    assert {t["name"] for t in d["tools"]} == {"issue", "verify", "revoke", "list"}
    assert d["install"]["args"] == ["-m", "veridict_receipt_mcp.server"]
    # the launcher must resolve to a real module on disk
    assert os.path.exists(_SERVER)


# ---- against the REAL SDK ----------------------------------------------
def _real():
    pytest.importorskip("mcp")
    for k in [k for k in sys.modules if k.startswith("veridict_receipt_mcp")]:
        del sys.modules[k]
    if MCP_DIR not in sys.path:
        sys.path.insert(0, MCP_DIR)
    import veridict_receipt_mcp.server as server
    return server


def _call(server, name, **kw):
    r = asyncio.run(server.mcp.call_tool(name, kw))
    return json.loads(r.content[0].text)


def test_real_sdk_registers_four_tools():
    server = _real()
    tools = asyncio.run(server.mcp.list_tools())
    assert {t.name for t in tools} == {"issue", "verify", "revoke", "list"}


def test_real_sdk_issue_verify_revoke_roundtrip(tmp_path, monkeypatch):
    server = _real()
    monkeypatch.setenv("VERIDICT_HOME", str(tmp_path / "real"))
    out = _call(server, "issue", achievement="deployed api v3 to prod",
                actor_identity="agent-9", evidence=["gh run 9001 passed"])
    assert out["ok"] is True
    ledger = str(tmp_path / "real" / "ledger.jsonl")

    rep = _call(server, "verify", cert=out["receipt_path"])
    assert rep["valid"] is True, rep["errors"]

    rep2 = _call(server, "verify", cert=out["receipt_path"], ledger=ledger)
    assert rep2["valid"] is True and rep2["chain_valid"] is True

    _call(server, "revoke", cert_id=out["cert_id"], reason="rolled back")
    rep3 = _call(server, "verify", cert=out["receipt_path"], ledger=ledger)
    assert rep3["valid"] is False and rep3["revoked"] is True

    rows = _call(server, "list")
    assert rows["count"] == 1 and rows["receipts"][0]["revoked"] is True


def test_real_sdk_rejects_w1a_style_nonsense_over_protocol(tmp_path, monkeypatch):
    """The protocol boundary rejects a receipt with no achievement — the
    fail-closed rule from the core, visible over the wire."""
    server = _real()
    monkeypatch.setenv("VERIDICT_HOME", str(tmp_path / "real2"))
    out = _call(server, "issue", achievement="")
    assert out["ok"] is False
    assert "achievement" in out["error"]
