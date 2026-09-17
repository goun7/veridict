"""veridict-llamaindex — LlamaIndex callback for Veridict evidence capture.

Usage:
    from veridict_llamaindex import VeridictCallback
    from llama_index.core import Settings
    Settings.callback_manager.add_callback(VeridictCallback("ledger.jsonl"))
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict

from llama_index.core.callbacks import CBEventType, BaseCallbackHandler  # type: ignore


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


class VeridictCallback(BaseCallbackHandler):
    """Records LlamaIndex events into a Veridict evidence ledger.

    One ledger entry per event pair (start/end) using the existing
    'evidence.recorded' entry type — no schema change. Payloads bind
    digests by default; pass store_contents=True to keep raw text.
    """

    def __init__(self, ledger_path: str, actor_identity: str = "llamaindex-agent",
                 *, store_contents: bool = False) -> None:
        from veridict.ledger import Ledger
        from veridict.schemas import ActorRef

        self.ledger_path = ledger_path
        self.actor_identity = actor_identity
        self.store_contents = store_contents
        self._ledger = Ledger() if not os.path.exists(ledger_path) \
            else Ledger.load(ledger_path)
        self._producer = ActorRef(kind="watcher", identity=actor_identity,
                                  version="0.1.0")
        self._starts: Dict[str, float] = {}

    def _append(self, stage: str, payload: Dict[str, Any]) -> None:
        payload = {"adapter": "llamaindex", "stage": stage, **payload}
        self._ledger.append("evidence.recorded", self._producer, payload)

    @staticmethod
    def _digest(text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def on_event_start(self, event_type: CBEventType, payload, **kwargs):
        self._starts[str(event_type)] = time.time()
        self._append(f"{event_type.value}.start", {
            "event_type": event_type.value,
            "payload_digest": self._digest(_canonical(payload or {})),
            **({"payload": payload} if self.store_contents else {}),
        })

    def on_event_end(self, event_type: CBEventType, payload, **kwargs):
        started = self._starts.pop(str(event_type), time.time())
        self._append(f"{event_type.value}.end", {
            "event_type": event_type.value,
            "duration_s": round(time.time() - started, 3),
            "payload_digest": self._digest(_canonical(payload or {})),
            **({"payload": payload} if self.store_contents else {}),
        })

    def start_trace(self, trace_id: str | None = None) -> None:
        pass   # trace boundaries are not evidence; event pairs are

    def end_trace(self, trace_id: str | None = None) -> None:
        pass

    def flush(self) -> str:
        """Persist + verify. Broken chains are refused (fail-closed)."""
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
