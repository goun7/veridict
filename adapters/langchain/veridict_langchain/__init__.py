"""veridict-langchain — LangChain BaseCallbackHandler for evidence capture.

Drop-in: attach to any LangChain chain/agent and every LLM interaction
becomes an append-only ledger entry. The ledger is the machine evidence
that later feeds a Veridict audit certificate.

Install: pip install veridict-standard  (runtime core stays stdlib-only;
this adapter only needs veridict + langchain-core, which you already have)

Usage:
    from veridict_langchain import VeridictCallback
    cb = VeridictCallback(ledger_path="veridict-ledger.jsonl",
                          actor_identity="my-agent")
    chain.invoke({"q": "..."}, config={"callbacks": [cb]})
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, Optional

from langchain_core.callbacks import BaseCallbackHandler  # type: ignore


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


class VeridictCallback(BaseCallbackHandler):
    """Records LLM/chain interactions into a Veridict evidence ledger.

    Every interaction is one ledger entry (entry_type 'evidence.recorded',
    an existing type — no schema change). Payloads carry the invocation
    digest, not the raw prompt/response contents (configurable: pass
    store_contents=True to keep them).
    """

    def __init__(
        self,
        ledger_path: str,
        actor_identity: str = "langchain-agent",
        *,
        store_contents: bool = False,
    ) -> None:
        from veridict.ledger import Ledger
        from veridict.schemas import ActorRef

        self.ledger_path = ledger_path
        self.actor_identity = actor_identity
        self.store_contents = store_contents
        self._ledger = Ledger()
        self._producer = ActorRef(kind="watcher", identity=actor_identity,
                                  version="0.1.0")
        # resume an existing ledger if present (append-only, never clobber)
        if os.path.exists(ledger_path):
            self._ledger = Ledger.load(ledger_path)
        self._starts: Dict[str, Dict[str, Any]] = {}

    # -- private ---------------------------------------------------------

    def _append(self, stage: str, payload: Dict[str, Any]) -> None:
        payload = {"adapter": "langchain", "stage": stage, **payload}
        self._ledger.append("evidence.recorded", self._producer, payload)

    @staticmethod
    def _digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    # -- LangChain hooks -------------------------------------------------

    def on_llm_start(self, serialized, prompts, *, run_id, **kwargs):
        model = (serialized or {}).get("name", "unknown-model") \
            if isinstance(serialized, dict) else "unknown-model"
        self._starts[str(run_id)] = {"model": model, "started": time.time()}
        self._append("llm.start", {
            "run_id": str(run_id),
            "model": model,
            "prompt_digests": [self._digest(p) for p in (prompts or [])],
            **({"prompts": list(prompts)} if self.store_contents else {}),
        })

    def on_llm_end(self, response, *, run_id, **kwargs):
        start = self._starts.pop(str(run_id), {})
        texts = []
        generations = getattr(response, "generations", []) or []
        for batch in generations:
            for gen in batch:
                text = getattr(gen, "text", None)
                if text is not None:
                    texts.append(text)
        joined = "\n".join(texts)
        self._append("llm.end", {
            "run_id": str(run_id),
            "model": start.get("model", "unknown"),
            "duration_s": round(time.time() - start.get("started", time.time()), 3),
            "response_digest": self._digest(joined),
            **({"response": joined} if self.store_contents else {}),
        })

    def on_chain_error(self, error, *, run_id, **kwargs):
        self._starts.pop(str(run_id), None)
        self._append("chain.error", {
            "run_id": str(run_id),
            "error_type": type(error).__name__,
            "error_message": str(error)[:200],
        })

    def on_tool_start(self, serialized, input_str, *, run_id, **kwargs):
        name = (serialized or {}).get("name", "unknown-tool") \
            if isinstance(serialized, dict) else "unknown-tool"
        self._append("tool.start", {
            "run_id": str(run_id),
            "tool": name,
            "input_digest": self._digest(input_str or ""),
        })

    def on_tool_end(self, output, *, run_id, **kwargs):
        out = str(output)
        self._append("tool.end", {
            "run_id": str(run_id),
            "output_digest": self._digest(out),
            **({"output": out} if self.store_contents else {}),
        })

    # -- lifecycle -------------------------------------------------------

    def flush(self) -> str:
        """Persist the ledger and return its path. Chain-verified first —
        a ledger that fails verification is never written (fail-closed)."""
        ok, reason = self._ledger.verify_chain()
        if not ok:
            raise RuntimeError(f"refusing to flush a broken ledger: {reason}")
        d = os.path.dirname(os.path.abspath(self.ledger_path))
        if d:
            os.makedirs(d, exist_ok=True)
        self._ledger.save(self.ledger_path)
        return self.ledger_path

    def __enter__(self) -> "VeridictCallback":
        return self

    def __exit__(self, *exc) -> None:
        self.flush()
