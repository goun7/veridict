"""Append-only, hash-chained ledger (§4.1). Small-core: stdlib only."""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .schemas import ActorRef, SCHEMA_VERSION
from .utils import canonical_json, payload_digest, sha256_hex

GENESIS = "0" * 64


class ChainError(Exception):
    pass


def _reject_dupes(pairs: list) -> dict:
    """Reject duplicate JSON keys: last-wins dedup makes two semantically
    different documents share one digest, so the hash cannot tell an honest
    task_id from a smuggled one (parser-differential at the digest level)."""
    seen = set()
    for k, _ in pairs:
        if k in seen:
            raise ValueError(f"duplicate JSON key: {k!r}")
        seen.add(k)
    return dict(pairs)


def _entry_hash(prev_hash: str, payload: dict, entry_type: str, seq: int,
                author: dict, ts: float, schema_version: str) -> str:
    # The preimage binds EVERY stored field (standard §2.3): payload (via its
    # digest), routing, ordering, authorship, timestamp, and format version.
    # The fuzz property (tests/test_fuzz_ledger.py) caught v0's unbound ts —
    # a retroactive timestamp edit used to leave the chain "valid"; an audit
    # ledger whose timestamps are editable is not one.
    return sha256_hex("|".join([
        prev_hash, payload_digest(payload), entry_type, str(seq),
        canonical_json(author), canonical_json(ts), schema_version,
    ]))


class Ledger:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    def append(self, entry_type: str, author: ActorRef, payload: dict) -> dict:
        seq = len(self.entries)
        prev_hash = self.entries[-1]["entry_hash"] if self.entries else GENESIS
        author_d = author.to_dict()
        ts = datetime.now(timezone.utc).isoformat()
        entry = {
            "schema_version": SCHEMA_VERSION,
            "seq": seq,
            "prev_hash": prev_hash,
            "entry_type": entry_type,
            "author": author_d,
            "payload": payload,
            # ISO-8601 UTC string (§2.3): floats must not occupy hashed
            # positions — canonical float formatting is language-fragile,
            # strings are not. seq carries the ordering; ts is provenance.
            "ts": ts,
            "payload_hash": payload_digest(payload),
            "entry_hash": _entry_hash(prev_hash, payload, entry_type, seq,
                                      author_d, ts, SCHEMA_VERSION),
        }
        self.entries.append(entry)
        return entry

    def query(self, entry_type: str | None = None) -> list[dict]:
        return [e for e in self.entries
                if entry_type is None or e["entry_type"] == entry_type]

    def save(self, path: str) -> None:
        """Atomic save that refuses to follow a symlinked .tmp and refuses to
        shrink an existing ledger.

        The .tmp name is predictable, so an attacker with directory write
        access could pre-create it as a symlink to a victim file and have this
        write clobber the victim. O_NOFOLLOW refuses that. fsync before the
        rename so a crash does not leave the rename durable but the bytes not.
        Append-only is enforced too: a Ledger that lost its in-memory entries
        used to silently truncate a 4-entry file to zero lines on save —
        accepted as "ok" by verify_chain. A shrink is a data-loss event, not
        a save.
        """
        loaded = getattr(self, "_loaded_len", None)
        if loaded is not None and len(self.entries) < loaded:
            raise ChainError(
                "refusing to shrink ledger: "
                f"{len(self.entries)} entries < {loaded} loaded")
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for e in self.entries:
                    f.write(canonical_json(e) + "\n")
                f.flush()
                os.fsync(f.fileno())
        except BaseException:
            # Do not leave a stale .tmp behind for the next save to clobber.
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        os.replace(tmp, path)

    @staticmethod
    def _validate_entry(entry: object, lineno: int) -> None:
        """Fail closed on any shape the chain cannot faithfully replay.

        The anchored-prefix scope (§9.5(c), D20) treats `seq` as a position
        token: certificate.py scopes replay to `e["seq"] <= checkpoint_seq`
        and anchor.py locates the checkpoint by that field. A stored seq that
        does not equal its list position is therefore a forgery primitive,
        not a style violation — an entry appended at the END of the file can
        claim `seq: 0`, keep the pinned prefix byte-identical, and replay as
        though it preceded the checkpoint. Same for a duplicated or negative
        seq. `append()` guarantees the invariant; the readers enforce it,
        because the producer is not the threat. Type confusion is the same
        class: `str(seq)` in the preimage makes `0` and `"0"` hash-identical,
        so a no-recompute edit passes verify_chain and then crashes the audit
        path with a TypeError instead of rejecting.
        """
        if not isinstance(entry, dict):
            raise ChainError(f"malformed ledger line {lineno}: entry is not "
                             "an object")
        required = ("schema_version", "seq", "prev_hash", "entry_type",
                    "author", "payload", "ts", "payload_hash", "entry_hash")
        missing = [k for k in required if k not in entry]
        if missing:
            raise ChainError(f"malformed ledger line {lineno}: missing "
                             f"required keys {sorted(missing)}")
        # bool is an int subclass; True would silently collide with 1.
        if isinstance(entry["seq"], bool) or not isinstance(entry["seq"], int):
            raise ChainError(f"malformed ledger line {lineno}: seq is not an "
                             "integer")
        if not isinstance(entry["payload"], dict):
            raise ChainError(f"malformed ledger line {lineno}: payload is not "
                             "an object")
        if not isinstance(entry["author"], dict):
            raise ChainError(f"malformed ledger line {lineno}: author is not "
                             "an object")
        if not isinstance(entry["ts"], str):
            raise ChainError(f"malformed ledger line {lineno}: ts is not a "
                             "string")
        for k in ("schema_version", "entry_type", "prev_hash", "payload_hash",
                  "entry_hash"):
            if not isinstance(entry[k], str):
                raise ChainError(f"malformed ledger line {lineno}: {k} is not "
                                 "a string")

    @classmethod
    def load(cls, path: str) -> "Ledger":
        led = cls()
        with open(path, encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line, object_pairs_hook=_reject_dupes)
                except json.JSONDecodeError as exc:
                    raise ChainError(f"malformed ledger line {lineno}: "
                                     "line is not valid JSON") from exc
                except ValueError as exc:
                    raise ChainError(f"malformed ledger line {lineno}: "
                                     f"{exc}") from exc
                led._validate_entry(entry, lineno)
                led.entries.append(entry)
        led._loaded_len = len(led.entries)
        return led

    def verify_chain(self, expected_height: int | None = None,
                     anchor_hash: str | None = None) -> tuple[bool, str]:
        prev = GENESIS
        for i, e in enumerate(self.entries):
            # The producer guarantees seq == position; the readers must too, or
            # every seq-keyed scope (the D20 replay window above) is trust in
            # an attacker-writable field. Rejected here, at the boundary.
            if e["seq"] != i:
                return False, (f"seq field {e['seq']} != position {i}")
            # A retroactive payload edit stales BOTH stored hashes; report both
            # so the message names every invalidated invariant at this seq.
            payload_ok = e["payload_hash"] == payload_digest(e["payload"])
            expect = _entry_hash(prev, e["payload"], e["entry_type"], e["seq"],
                                 e["author"], e["ts"], e["schema_version"])
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
        # A truncated or emptied ledger used to verify "ok" on its own; the
        # signed cert catches it one layer up, but the ledger should not
        # outsource its own height check. Callers with an anchor pass it in.
        if expected_height is not None and len(self.entries) != expected_height:
            return False, (f"truncated or grown chain: height "
                           f"{len(self.entries)} != expected {expected_height}")
        if anchor_hash is not None and prev != anchor_hash:
            return False, "chain head does not match the pinned anchor hash"
        return True, "ok"
