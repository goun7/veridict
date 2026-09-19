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

from llama_index.core.callbacks import (  # type: ignore
    CBEvent,
    CBEventType,
    PythonicallyPrintingBaseHandler,
)


def _canonical(payload: Any) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


class VeridictCallback(PythonicallyPrintingBaseHandler):
    """Records LlamaIndex events into a Veridict evidence ledger.

    One ledger entry per event pair (start/end) using the existing
    'evidence.recorded' entry type — no schema change. Payloads bind
    digests by default; pass store_contents=True to keep raw text.

    Note on the base class: llama_index renamed its callback base several
    times (BaseCallbackHandler → CBHandler → PythonicallyPrintingBaseHandler
    across releases). The adapter subclasses the name that exists in the
    installed version; if your version has a different one, the import
    error names the exact missing symbol.
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

    def on_event_start(self, event_type: CBEventType, payload=None,
                       event_id: str = "", parent_id: str = "", **kwargs) -> str:
        """Must return an event id (the base class contract)."""
        self._starts[event_id or event_type.value] = time.time()
        self._append(f"{event_type.value}.start", {
            "event_id": event_id,
            "parent_id": parent_id,
            "event_type": event_type.value,
            "payload_digest": self._digest(_canonical(payload or {})),
            **({"payload": payload} if self.store_contents else {}),
        })
        return event_id or f"{event_type.value}-{time.time()}"

    def on_event_end(self, event_type: CBEventType, payload=None,
                     event_id: str = "", **kwargs) -> None:
        key = event_id or event_type.value
        started = self._starts.pop(key, time.time())
        self._append(f"{event_type.value}.end", {
            "event_id": event_id,
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
