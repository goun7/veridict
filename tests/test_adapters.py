"""Adapter tests — LangChain / LlamaIndex / MCP.

Each test is skipped when its framework is absent, so the suite stays
green in the minimal CI image. When the framework IS installed the test
exercises the adapter end-to-end against the real Veridict ledger.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from veridict.ledger import Ledger  # noqa: E402


# ---- LangChain --------------------------------------------------------
# Skipped as a block when langchain-core is absent; the importorskip is
# INSIDE the first test (not module level) so the MCP tests below still run.
def _lc():
    pytest.importorskip("langchain_core")
    from adapters.langchain.veridict_langchain import VeridictCallback
    return VeridictCallback


class _FakeLLMResult:
    """Minimal stand-in for langchain_core.outputs.LLMResult."""

    def __init__(self, text: str):
        gen = type("Gen", (), {"text": text})()
        self.generations = [[gen]]


def test_langchain_records_llm_pair(tmp_path):
    VeridictCallback = _lc()
    ledger = str(tmp_path / "lc.jsonl")
    cb = VeridictCallback(ledger, actor_identity="lc-test")
    cb.on_llm_start({"name": "fake-model"}, ["hello"], run_id="r1")
    cb.on_llm_end(_FakeLLMResult("world"), run_id="r1")
    path = cb.flush()

    led = Ledger.load(path)
    stages = [e["payload"]["stage"] for e in led.entries]
    assert stages == ["llm.start", "llm.end"]
    ok, reason = led.verify_chain()
    assert ok, reason


def test_langchain_digests_not_contents_by_default(tmp_path):
    ledger = str(tmp_path / "lc.jsonl")
    cb = _lc()(ledger)
    cb.on_llm_start({"name": "m"}, ["secret-prompt"], run_id="r1")
    cb.on_llm_end(_FakeLLMResult("secret-response"), run_id="r1")
    cb.flush()
    raw = open(ledger).read()
    assert "secret-prompt" not in raw          # contents never stored by default
    assert "secret-response" not in raw


def test_langchain_store_contents_opt_in(tmp_path):
    ledger = str(tmp_path / "lc.jsonl")
    cb = _lc()(ledger, store_contents=True)
    cb.on_llm_start({"name": "m"}, ["keep-me"], run_id="r1")
    cb.on_llm_end(_FakeLLMResult("keep-too"), run_id="r1")
    cb.flush()
    raw = open(ledger).read()
    assert "keep-me" in raw and "keep-too" in raw


def test_langchain_appends_to_existing_ledger(tmp_path):
    """Re-attaching resumes an existing ledger (append-only, never clobber)."""
    ledger = str(tmp_path / "lc.jsonl")
    cb = _lc()(ledger)
    cb.on_llm_start({"name": "m"}, ["a"], run_id="r1")
    cb.on_llm_end(_FakeLLMResult("b"), run_id="r1")
    cb.flush()
    first = sum(1 for _ in open(ledger))

    cb2 = _lc()(ledger)
    cb2.on_llm_start({"name": "m"}, ["c"], run_id="r2")
    cb2.on_llm_end(_FakeLLMResult("d"), run_id="r2")
    cb2.flush()
    second = sum(1 for _ in open(ledger))
    assert second == first + 2


def test_langchain_tool_events(tmp_path):
    ledger = str(tmp_path / "lc.jsonl")
    cb = _lc()(ledger)
    cb.on_tool_start({"name": "search"}, "query", run_id="t1")
    cb.on_tool_end("result", run_id="t1")
    path = cb.flush()
    led = Ledger.load(path)
    stages = [e["payload"]["stage"] for e in led.entries]
    assert stages == ["tool.start", "tool.end"]


def test_langchain_error_event(tmp_path):
    ledger = str(tmp_path / "lc.jsonl")
    cb = _lc()(ledger)
    cb.on_llm_start({"name": "m"}, ["x"], run_id="r1")
    cb.on_chain_error(RuntimeError("boom"), run_id="r1")
    cb.flush()
    led = Ledger.load(ledger)
    assert led.entries[-1]["payload"]["stage"] == "chain.error"
    assert led.entries[-1]["payload"]["error_type"] == "RuntimeError"


# ---- MCP server -------------------------------------------------------
# The MCP SDK is optional; the two ledger-touching tools are exercised
# directly (they are plain functions over the veridict runtime core).

def _mcp_module():
    """Import the server module's tools without the MCP SDK.

    The module top-level imports FastMCP and exits when the SDK is
    absent. The @mcp.tool-decorated functions are plain functions
    underneath, so a minimal FastMCP stub (whose .tool() returns the
    function unchanged) is enough to load and exercise them."""
    import importlib.util
    import types

    class _FakeMCP:
        def __init__(self, *a, **k):
            pass

        def tool(self, *a, **k):
            def deco(fn):
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
    sys.modules["mcp"] = stub
    sys.modules["mcp.server"] = server_mod
    sys.modules["mcp.server.fastmcp"] = fastmcp

    mcp_path = os.path.join(os.path.dirname(__file__), "..",
                            "adapters", "mcp", "veridict_mcp", "server.py")
    spec = importlib.util.spec_from_file_location("veridict_mcp_server", mcp_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_mcp_record_evidence_and_verify(tmp_path):
    server = _mcp_module()
    ledger = str(tmp_path / "mcp.jsonl")

    out = json.loads(server.record_evidence(
        ledger, "mcp-test", "JURY_OPINION", "W2", "SUPPORTS", 0.6,
        rationale="probe"))
    assert out["ok"] is True
    assert out["entries"] == 1

    rep = json.loads(server.verify_ledger(ledger))
    assert rep["ok"] is True and rep["entries"] == 1


def test_mcp_rejects_w1a_from_watcher(tmp_path):
    """The MCP surface mirrors the conformance-kit C2 rule: watchers can
    never emit W1a evidence, even over the protocol boundary."""
    server = _mcp_module()
    out = json.loads(server.record_evidence(
        str(tmp_path / "mcp.jsonl"), "mcp-test", "JURY_OPINION", "W1a",
        "SUPPORTS", 0.9))
    assert out["ok"] is False
    assert "W1a" in out["error"]


def test_mcp_rejects_bad_stance(tmp_path):
    server = _mcp_module()
    out = json.loads(server.record_evidence(
        str(tmp_path / "mcp.jsonl"), "mcp-test", "JURY_OPINION", "W2",
        "MAYBE", 0.5))
    assert out["ok"] is False and "stance" in out["error"]
