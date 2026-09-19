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


# ---- LangChain with REAL SDK objects (not fakes) ---------------------
# The tests above pass hand-built objects. These exercise the adapter
# against the actual langchain_core types a real chain emits, which is
# the only way to catch signature drift in the framework.
def _lc_real():
    pytest.importorskip("langchain_core")
    from langchain_core.outputs import ChatGenerationChunk, GenerationChunk
    from langchain_core.messages import AIMessageChunk
    from adapters.langchain.veridict_langchain import VeridictCallback
    return VeridictCallback, GenerationChunk, ChatGenerationChunk, AIMessageChunk


def test_langchain_real_generation_chunk(tmp_path):
    """A real GenerationChunk (non-chat model path) must be recorded."""
    cb, GenerationChunk, _, _ = _lc_real()
    ledger = str(tmp_path / "lc.jsonl")
    cb = cb(ledger)
    run = "r-" + str(object.__hash__(ledger))[-6:]
    cb.on_llm_start({"name": "gpt-oss"}, ["hello"], run_id=run)
    cb.on_llm_end(
        type("R", (), {"generations": [[GenerationChunk(text="world")]]})(),
        run_id=run)
    cb.flush()
    led = Ledger.load(ledger)
    stages = [e["payload"]["stage"] for e in led.entries]
    assert stages == ["llm.start", "llm.end"]


def test_langchain_real_chat_generation_chunk(tmp_path):
    """Chat models emit ChatGenerationChunk, whose text comes from a
    message object — not a flat .text attribute."""
    cb, _, ChatGenerationChunk, AIMessageChunk = _lc_real()
    ledger = str(tmp_path / "lc.jsonl")
    cb = cb(ledger)
    run = "r-" + str(object.__hash__(ledger))[-6:]
    cb.on_llm_start({"name": "gpt-4o"}, ["hi"], run_id=run)
    chunk = ChatGenerationChunk(
        message=AIMessageChunk(content="hello there"),
        generation_info={"finish_reason": "stop"})
    cb.on_llm_end(
        type("R", (), {"generations": [[chunk]]})(), run_id=run)
    cb.flush()
    led = Ledger.load(ledger)
    end = led.entries[-1]["payload"]
    assert end["stage"] == "llm.end"
    assert len(end["response_digest"]) == 64
    assert "hello there" not in open(ledger).read()


def test_langchain_subclass_of_base_handler():
    """The adapter must remain a real BaseCallbackHandler — if it stops
    being one, LangChain will silently never call any hook."""
    pytest.importorskip("langchain_core")
    from langchain_core.callbacks import BaseCallbackHandler
    from adapters.langchain.veridict_langchain import VeridictCallback
    assert issubclass(VeridictCallback, BaseCallbackHandler)


def test_langchain_every_hook_round_trips(tmp_path):
    """All implemented hooks must produce a chain-verified ledger."""
    cb, GenerationChunk, _, _ = _lc_real()
    ledger = str(tmp_path / "lc.jsonl")
    cb = cb(ledger)
    for i, stage in enumerate(["llm", "tool"]):
        rid = f"run-{i}"
        cb.on_llm_start({"name": "m"}, ["q"], run_id=rid)
        cb.on_tool_start({"name": f"tool-{i}"}, "in", run_id=rid)
        cb.on_tool_end("out", run_id=rid)
        cb.on_llm_end(
            type("R", (), {"generations": [[GenerationChunk(text="a")]]})(),
            run_id=rid)
    cb.on_chain_error(RuntimeError("boom"), run_id="run-0")
    cb.flush()
    led = Ledger.load(ledger)
    ok, reason = led.verify_chain()
    assert ok, reason
    assert len(led.entries) == 9


# ---- MCP server -------------------------------------------------------

# The MCP SDK is optional; the two ledger-touching tools are exercised
# directly (they are plain functions over the veridict runtime core).

def _mcp_module(monkeypatch):
    """Import the server module's tools without the MCP SDK.

    The module top-level imports FastMCP and exits when the SDK is
    absent. The @mcp.tool-decorated functions are plain functions
    underneath, so a minimal FastMCP stub (whose .tool() returns the
    function unchanged) is enough to load and exercise them.

    Registered under unique sys.modules keys and monkeypatch-scoped, so
    the fake `mcp` can never shadow the real SDK for the tests below."""
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
    # Unique keys + monkeypatch: the fake is removed at test teardown and
    # never collides with the real `mcp` import in _real_mcp().
    for key, mod in (("mcp", stub), ("mcp.server", server_mod),
                     ("mcp.server.fastmcp", fastmcp)):
        monkeypatch.setitem(sys.modules, key, mod)

    mcp_path = os.path.join(os.path.dirname(__file__), "..",
                            "adapters", "mcp", "veridict_mcp", "server.py")
    spec = importlib.util.spec_from_file_location("_stub_veridict_mcp_server", mcp_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_mcp_record_evidence_and_verify(tmp_path, monkeypatch):
    server = _mcp_module(monkeypatch)
    ledger = str(tmp_path / "mcp.jsonl")

    out = json.loads(server.record_evidence(
        ledger, "mcp-test", "JURY_OPINION", "W2", "SUPPORTS", 0.6,
        rationale="probe"))
    assert out["ok"] is True
    assert out["entries"] == 1

    rep = json.loads(server.verify_ledger(ledger))
    assert rep["ok"] is True and rep["entries"] == 1


def test_mcp_rejects_w1a_from_watcher(tmp_path, monkeypatch):
    """The MCP surface mirrors the conformance-kit C2 rule: watchers can
    never emit W1a evidence, even over the protocol boundary."""
    server = _mcp_module(monkeypatch)
    out = json.loads(server.record_evidence(
        str(tmp_path / "mcp.jsonl"), "mcp-test", "JURY_OPINION", "W1a",
        "SUPPORTS", 0.9))
    assert out["ok"] is False
    assert "W1a" in out["error"]


def test_mcp_rejects_bad_stance(tmp_path, monkeypatch):
    server = _mcp_module(monkeypatch)
    out = json.loads(server.record_evidence(
        str(tmp_path / "mcp.jsonl"), "mcp-test", "JURY_OPINION", "W2",
        "MAYBE", 0.5))
    assert out["ok"] is False and "stance" in out["error"]


# ---- MCP against the REAL SDK -----------------------------------------
# The three tests above run against a stub so CI stays green without the
# SDK. This one runs only when `mcp` is actually installed and exercises
# the real protocol surface — tool registration AND tool invocation,
# which the stub cannot check. This is the test that caught the v1→v2
# FastMCP→MCPServer rename.
def _real_mcp():
    pytest.importorskip("mcp")
    # The stub tests above inject a fake `veridict_mcp.server` into
    # sys.modules; drop it so this path resolves the real module.
    for k in [k for k in sys.modules if k.startswith("veridict_mcp")]:
        del sys.modules[k]
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                    "adapters", "mcp"))
    import veridict_mcp.server as server
    return server


def test_real_mcp_registers_three_tools():
    server = _real_mcp()
    import asyncio
    tools = asyncio.run(server.mcp.list_tools())
    names = {t.name for t in tools}
    assert names == {"record_evidence", "verify_ledger", "audit_artifact"}


def test_real_mcp_record_and_verify_roundtrip(tmp_path):
    server = _real_mcp()
    import asyncio
    ledger = str(tmp_path / "real.jsonl")

    def call(name, **kw):
        return json.loads(asyncio.run(server.mcp.call_tool(name, kw)).content[0].text)

    out = call("record_evidence", ledger_path=ledger, producer_identity="w",
               evidence_class="TEST_EXECUTION", tier="W1b",
               stance="SUPPORTS", confidence=0.9)
    assert out["ok"] is True and out["entries"] == 1

    rep = call("verify_ledger", ledger_path=ledger)
    assert rep["ok"] is True and rep["entries"] == 1


def test_real_mcp_rejects_w1a_over_protocol(tmp_path):
    """C2 enforced at the real protocol boundary, not just in-process."""
    server = _real_mcp()
    import asyncio
    r = asyncio.run(server.mcp.call_tool("record_evidence", {
        "ledger_path": str(tmp_path / "real.jsonl"), "producer_identity": "w",
        "evidence_class": "TEST_EXECUTION", "tier": "W1a",
        "stance": "SUPPORTS", "confidence": 0.9}))
    out = json.loads(r.content[0].text)
    assert out["ok"] is False and "W1a" in out["error"]


# ---- LlamaIndex with REAL SDK objects ---------------------------------
def _li():
    pytest.importorskip("llama_index.core")
    from llama_index.core.callbacks import CBEventType
    from adapters.llamaindex.veridict_llamaindex import VeridictCallback
    return VeridictCallback, CBEventType


def test_llamaindex_subclasses_real_handler():
    """If the adapter stops subclassing the framework's handler,
    LlamaIndex will silently never call any hook."""
    pytest.importorskip("llama_index.core")
    from llama_index.core.callbacks import PythonicallyPrintingBaseHandler
    from adapters.llamaindex.veridict_llamaindex import VeridictCallback
    assert issubclass(VeridictCallback, PythonicallyPrintingBaseHandler)


def test_llamaindex_event_pair(tmp_path):
    cb, CBEventType = _li()
    ledger = str(tmp_path / "li.jsonl")
    cb = cb(ledger)
    cb.start_trace()
    eid = cb.on_event_start(CBEventType.LLM, {"key": "value"}, event_id="e1")
    assert isinstance(eid, str)          # base contract: must return an id
    cb.on_event_end(CBEventType.LLM, {"key": "value"}, event_id="e1")
    cb.end_trace()
    cb.flush()
    led = Ledger.load(ledger)
    stages = [e["payload"]["stage"] for e in led.entries]
    assert stages == ["llm.start", "llm.end"]
    ok, reason = led.verify_chain()
    assert ok, reason


def test_llamaindex_digests_not_contents(tmp_path):
    cb, CBEventType = _li()
    ledger = str(tmp_path / "li.jsonl")
    cb = cb(ledger)
    cb.on_event_start(CBEventType.EMBEDDING, {"secret": "prompt"})
    cb.on_event_end(CBEventType.EMBEDDING, {"secret": "prompt"})
    cb.flush()
    assert "secret" not in open(ledger).read()


def test_llamaindex_store_contents_opt_in(tmp_path):
    cb, CBEventType = _li()
    ledger = str(tmp_path / "li.jsonl")
    cb = cb(ledger, store_contents=True)
    cb.on_event_start(CBEventType.QUERY, {"q": "keep-me"})
    cb.on_event_end(CBEventType.QUERY, {"q": "keep-me"})
    cb.flush()
    assert "keep-me" in open(ledger).read()


def test_llamaindex_multiple_event_types(tmp_path):
    cb, CBEventType = _li()
    ledger = str(tmp_path / "li.jsonl")
    cb = cb(ledger)
    for et in (CBEventType.QUERY, CBEventType.RETRIEVE, CBEventType.SYNTHESIZE):
        cb.on_event_start(et, {"k": "v"}, event_id=f"id-{et.value}")
        cb.on_event_end(et, {"k": "v"}, event_id=f"id-{et.value}")
    cb.flush()
    led = Ledger.load(ledger)
    ok, reason = led.verify_chain()
    assert ok, reason
    assert len(led.entries) == 6
