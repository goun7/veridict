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
import subprocess
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
    # the launcher is the standalone runner (it resolves veridict_receipt_mcp
    # without putting the repo root on sys.path, which would shadow the SDK)
    assert d["install"]["args"] == ["mcp/run_server.py"]
    assert os.path.exists(os.path.join(MCP_DIR, "run_server.py")), \
        "the declared launcher must exist"
    assert os.path.exists(_SERVER)


def _sdk_present() -> bool:
    """Hangi MCP SDK jenerasyonu yukluysa o kabul edilir (v1 FastMCP ya da
    v2 MCPServer — server.py'nin kendisi ikisini de deniyor; testlerin
    gate'i v2'de de acilmali, yoksa EN degerli real-SDK testleri v2 ile
    gizlice SKIP olup 'yesil-orman' uretiyor). 2026-10-19 gece turu:
    pip show mcp = 2.2.0 -> 4 test skip'te idi, simdi v2 ile calisir."""
    try:
        import mcp.server.fastmcp  # noqa: F401 - v1
        return True
    except ImportError:
        pass
    try:
        import mcp.server.mcpserver  # noqa: F401 - v2
        return True
    except ImportError:
        return False


def _skip_if_no_sdk():
    if not _sdk_present():
        pytest.skip("MCP SDK yuklu degil (v1 fastmcp ya da v2 mcpserver)")


def test_runner_does_not_shadow_the_mcp_sdk():
    """`python mcp/run_server.py` must import the installed MCP SDK, not the
    repo's own mcp/ directory. A launcher that put the repo root on sys.path
    would resolve `mcp` to this directory and break the server's import —
    the runner adds only mcp/ itself."""
    # Fix-2026-10-03 (CI #166): bu kontrolün ÖNERMESİ yüklenen SDK'dır —
    # SDK YOKSA runner doğruca "needs the MCP SDK" fail-closed mesajını
    # yazar ve assert onu ARADIĞI için yeşil-boyanamaz. SDK opsiyonel bir
    # bağımlılıktır (CI kurulumunda yoktur), bu yüzden _real()'in (L188)
    # yerleşik-deseniyle aynı importorskip ile İNDETERMİNE der.
    _skip_if_no_sdk()
    import subprocess
    r = subprocess.run([sys.executable, "-c",
                        "import sys, runpy; "
                        "sys.path.insert(0, 'mcp'); "
                        "runpy.run_path('mcp/run_server.py', run_name='__main__')"],
                       capture_output=True, text=True, timeout=30,
                       cwd=ROOT)
    # the server starts and blocks reading stdio; a broken SDK import instead
    # exits with 2 and a message naming the SDK.
    assert "needs the MCP SDK" not in r.stderr, r.stderr


# ---- against the REAL SDK ----------------------------------------------
def _real():
    _skip_if_no_sdk()
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


# ---- stdio-protocol surface (2026-10-19 gece turu: G15) -------------------
# Both regimes below drive the REAL wire, not in-process handlers. They exist
# because the handler-level "never raises" contract was green while the SDK's
# pre-handler argument validation was surfacing raw pydantic errors over the
# wire (`isError: true` + "1 validation error for issueArguments" instead of
# the mesh's structured Green/RED JSON). The mesh contract (tamga/swarmax/
# kredent/sester/veridrome/fleksa MCP servers) is: a missing argument is a
# structured RED, never a traceback-flavoured error object.


def _stdio_session(tmp_path):
    """Start the real server over stdio; returns (send, read, stop)."""
    import select
    server_path = os.path.join(MCP_DIR, "run_server.py")
    env = dict(os.environ)
    env["VERIDICT_HOME"] = str(tmp_path / "stdio-ws")
    proc = subprocess.Popen(
        [sys.executable, server_path],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env, cwd=str(tmp_path), bufsize=1)

    def send(line):
        proc.stdin.write(line + "\n")
        proc.stdin.flush()

    def read(timeout=10.0):
        ready, _, _ = select.select([proc.stdout], [], [], timeout)
        return proc.stdout.readline() if ready else None

    def stop():
        try:
            proc.stdin.close()
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    send(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18",
                                "capabilities": {},
                                "clientInfo": {"name": "pin", "version": "1"}}}))
    read()
    send(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized",
                     "params": {}}))
    return send, read, stop


def _call_tool_line(rid, name, args):
    return json.dumps({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                       "params": {"name": name, "arguments": args}})


def _result_of(read, rid):
    while True:
        line = read()
        if line is None:
            raise AssertionError(f"no response for id={rid} (server silent)")
        doc = json.loads(line)
        if doc.get("id") == rid:
            return doc


def test_stdio_missing_args_are_structured_red_not_traceback(tmp_path):
    """Every required argument missing must come back as structured JSON with
    ok:false (+ valid:false for verify), NOT `isError: true` with a raw
    pydantic message. This is the mesh-wide never-exception contract."""
    send, read, stop = _stdio_session(tmp_path)
    try:
        send(_call_tool_line(10, "issue", {}))
        res = _result_of(read, 10)["result"]
        assert res.get("isError") is not True, res
        body = json.loads(res["content"][0]["text"])
        assert body["ok"] is False
        assert "achievement" in body["error"]

        send(_call_tool_line(11, "verify", {}))
        res = _result_of(read, 11)["result"]
        assert res.get("isError") is not True, res
        body = json.loads(res["content"][0]["text"])
        assert body["ok"] is False and body["valid"] is False
        assert "cert" in body["error"]

        send(_call_tool_line(12, "revoke", {}))
        res = _result_of(read, 12)["result"]
        body = json.loads(res["content"][0]["text"])
        assert body["ok"] is False and "cert_id" in body["error"]
    finally:
        stop()


def test_stdio_unknown_tool_is_structured_error(tmp_path):
    """An unknown tool must be a structured protocol-level error, not a
    crash and not silent. The SDK version decides the exact envelope: v1/v2
    expose it as a JSON-RPC -32601 error OR as a tool result with
    isError:true and a plain-text message (both spec-valid; the stdib
    mesh servers use -32601). The pin accepts either, and rejects silence."""
    send, read, stop = _stdio_session(tmp_path)
    try:
        send(_call_tool_line(20, "no_such_tool", {}))
        doc = _result_of(read, 20)
        if "error" in doc:
            assert doc["error"]["code"] == -32601
        else:
            res = doc["result"]
            assert res.get("isError") is True
            assert "no_such_tool" in res["content"][0]["text"]
    finally:
        stop()


def test_stdio_list_limit_clamps(tmp_path):
    """limit=0 clamps to 1 and limit=5000 clamps to 1000; the schema stays
    optional so a missing limit is the default, never a validation error."""
    send, read, stop = _stdio_session(tmp_path)
    try:
        send(_call_tool_line(30, "issue", {"achievement": "clamp-a"}))
        out = json.loads(_result_of(read, 30)["result"]["content"][0]["text"])
        assert out["ok"] is True
        send(_call_tool_line(31, "issue", {"achievement": "clamp-b"}))
        out = json.loads(_result_of(read, 31)["result"]["content"][0]["text"])
        assert out["ok"] is True

        send(_call_tool_line(32, "list", {"limit": 0}))
        body = json.loads(_result_of(read, 32)["result"]["content"][0]["text"])
        assert body["ok"] is True and body["count"] == 1

        send(_call_tool_line(33, "list", {"limit": 5000}))
        body = json.loads(_result_of(read, 33)["result"]["content"][0]["text"])
        assert body["ok"] is True and body["count"] == 2

        send(_call_tool_line(34, "list", {}))
        body = json.loads(_result_of(read, 34)["result"]["content"][0]["text"])
        assert body["ok"] is True and body["count"] == 2
    finally:
        stop()


def test_stdio_receipt_roundtrip_and_revoke(tmp_path):
    """issue -> verify -> revoke -> verify again, all over the real wire; the
    receipt verifies standalone (no ledger), then invalid once revoked."""
    send, read, stop = _stdio_session(tmp_path)
    try:
        send(_call_tool_line(40, "issue",
                             {"achievement": "deployed api v4 to staging",
                              "actor_identity": "agent-pin",
                              "evidence": ["gh run 9002 passed"]}))
        out = json.loads(_result_of(read, 40)["result"]["content"][0]["text"])
        assert out["ok"] is True, out
        path = out["receipt_path"]

        send(_call_tool_line(41, "verify", {"cert": path}))
        rep = json.loads(_result_of(read, 41)["result"]["content"][0]["text"])
        assert rep["valid"] is True, rep

        send(_call_tool_line(42, "revoke", {"cert_id": out["cert_id"],
                                            "reason": "rolled back"}))
        rev = json.loads(_result_of(read, 42)["result"]["content"][0]["text"])
        assert rev["ok"] is True, rev

        ledger = str(tmp_path / "stdio-ws" / "ledger.jsonl")
        send(_call_tool_line(43, "verify", {"cert": path, "ledger": ledger}))
        rep2 = json.loads(_result_of(read, 43)["result"]["content"][0]["text"])
        assert rep2["valid"] is False and rep2["revoked"] is True, rep2
    finally:
        stop()
