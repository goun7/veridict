"""Append-only, hash-chained ledger (§4.1). Small-core: stdlib only."""
from __future__ import annotations

import json
import os
import time

from .schemas import ActorRef, SCHEMA_VERSION
from .utils import canonical_json, payload_digest, sha256_hex

GENESIS = "0" * 64


class ChainError(Exception):
    pass


def _entry_hash(prev_hash: str, payload: dict, entry_type: str, seq: int,
                author: dict) -> str:
    return sha256_hex("|".join([
        prev_hash, payload_digest(payload), entry_type, str(seq),
        canonical_json(author),
    ]))


class Ledger:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    def append(self, entry_type: str, author: ActorRef, payload: dict) -> dict:
        seq = len(self.entries)
        prev_hash = self.entries[-1]["entry_hash"] if self.entries else GENESIS
        author_d = author.to_dict()
        entry = {
            "schema_version": SCHEMA_VERSION,
            "seq": seq,
            "prev_hash": prev_hash,
            "entry_type": entry_type,
            "author": author_d,
            "payload": payload,
            "ts": time.time(),
            "payload_hash": payload_digest(payload),
            "entry_hash": _entry_hash(prev_hash, payload, entry_type, seq, author_d),
        }
        self.entries.append(entry)
        return entry

    def verify_chain(self) -> tuple[bool, str]:
        prev = GENESIS
        for e in self.entries:
            # A retroactive payload edit stales BOTH stored hashes; report both
            # so the message names every invalidated invariant at this seq.
            payload_ok = e["payload_hash"] == payload_digest(e["payload"])
            expect = _entry_hash(prev, e["payload"], e["entry_type"], e["seq"], e["author"])
            entry_ok = e["entry_hash"] == expect
            if not payload_ok and not entry_ok:
                return False, (f"payload hash mismatch and entry hash mismatch "
                               f"at seq {e['seq']}")
            if not payload_ok:
                return False, f"payload hash mismatch at seq {e['seq']}"
            if not entry_ok:
                return False, f"entry hash mismatch at seq {e['seq']}"
            if e["prev_hash"] != prev:
                return False, f"prev_hash mismatch at seq {e['seq']}"
            prev = e["entry_hash"]
        return True, "ok"

    def query(self, entry_type: str | None = None) -> list[dict]:
        return [e for e in self.entries
                if entry_type is None or e["entry_type"] == entry_type]

    def save(self, path: str) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for e in self.entries:
                f.write(canonical_json(e) + "\n")
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> "Ledger":
        led = cls()
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    led.entries.append(json.loads(line))
        return led
