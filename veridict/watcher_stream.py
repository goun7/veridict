"""WATCH-mode streaming transport (issue #3, v1.1 candidate over §10.3).

v1.0.0 WATCH was a policy mode over an evidence ledger with no realtime
transport (errata §14.2). This module is the transport candidate:

    LedgerStream.subscribe(ledger_path) → yields Observation events

A conforming stream, per the issue text: subscribes to a ledger file,
detects appended entries, recomputes the policy flags on the new suffix,
and emits `watch.observed` notifications with the SAME flag semantics as
the batch engine — WATCH never blocks, it only reports.

Design constraints honored here:
- The stream is a READ-ONLY observer of the ledger file. It appends
  nothing itself: §2's append-only chain stays owned by the writer, and
  obviating concurrent writes to one file is the WRITER's contract.
- Verdict/flag recomputation reuses the SAME `adjudicate` ladder and the
  SAME flag logic as PolicyEngine.apply — byte-identical semantics, no
  second implementation to drift. Where the standard is ambiguous the
  batch engine holds the only truth.
- Detect latency is bounded by a poll interval (no inotify dependency —
  the standard's vector format must stay platform-neutral); §10.3's
  normative latency sentence lands in the spec as annotations + this
  docstring, NOT as a compliance claim until v1.1 ratifies it.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

from .ladder import adjudicate
from .policy import PolicyDeclaration
from .schemas import Claim, EvidenceItem


@dataclass(frozen=True)
class Observation:
    """One `watch.observed` notification. WATCH never blocks; `flags`
    carry exactly the batch semantics (§10.2) so a feed consumer can mix
    stream and batch decisions without reconciliation rules."""
    kind: str                      # always "watch.observed"
    seq_from: int                  # first new entry seq in this batch
    seq_to: int                    # last new entry seq in this batch
    flags: tuple[str, ...]         # §10.2 flag set over the new suffix
    coverage: float                # W1 coverage over ALL claims seen so far
    per_claim: dict                # claim_id -> {value, rung, divergence}
    ts: float                      # detection timestamp (epoch seconds)
    detection_latency: float       # seconds between last entry ts and now


class LedgerStream:
    """Poll-based append detector over a JSONL ledger file.

    Only integration points claimed by v1.0.0 are used: the file format
    (`ledger.save` output) and the ladder. The stream tolerates a ledger
    that does not exist yet (waits for the writer's first append) and a
    ledger whose entries arrive in partial lines (appends are detected by
    counting COMPLETE lines — a torn last line is the writer's, held back
    until it completes).
    """

    def __init__(self, ledger_path: str, policy: PolicyDeclaration,
                 poll_interval: float = 0.05) -> None:
        self.ledger_path = ledger_path
        self.policy = policy
        self.poll_interval = poll_interval
        self._claims: dict[str, Claim] = {}
        self._evidence: dict[str, list] = {}

    # -- entry ingestion ---------------------------------------------------

    def _ingest_range(self, entries: list[dict], seq_from: int,
                      seq_to: int) -> Observation:
        """Index new claims/evidence, then recompute flags with the batch
        ladder. per-claim values come from `adjudicate` — the same function
        the batch PolicyEngine calls; flag assembly mirrors §10.2 exactly:
        coverage-below-threshold, divergence-split:{id},
        inconclusive-unresolved:{id}."""
        for e in entries:
            p = e.get("payload", {})
            et = e["entry_type"]
            if et == "claim.registered":
                self._claims[p["claim_id"]] = Claim.from_dict(p)
            elif et == "evidence.recorded":
                self._evidence.setdefault(p["claim_id"], []).append(p)

        claims = list(self._claims.values())
        # Evidence binding and jury-family visibility must mirror
        # PolicyEngine.apply exactly (F7, F8) — §10.2 parity is the contract
        # that the stream verdict and the batch verdict are the same verdict,
        # and a stream that skips either check diverges on the same ledger.
        def bound_ev(claim: "Claim") -> list:
            items = self._evidence.get(claim.claim_id, [])
            if claim.derived_from is None:
                return items
            return [p for p in items
                    if p.get("artifact_ref") == claim.derived_from]
        mc = [c for c in claims if c.verifiability == "MACHINE_CHECKABLE"]
        covered = [c for c in mc
                   if any(e.get("tier") in ("W1a", "W1b")
                          for e in bound_ev(c))]
        coverage = (len(covered) / len(mc)) if mc else 1.0

        per_claim, flags = {}, []
        # Flag order must match PolicyEngine.apply exactly: mismatch, family,
        # coverage, split, inconclusive. §10.2 parity is asserted as an exact
        # tuple, so a different order would read as a divergence even when
        # both sides flag the same facts.
        for c in claims:
            raw = self._evidence.get(c.claim_id, [])
            if c.derived_from is not None:
                for p in raw:
                    if p.get("artifact_ref") != c.derived_from:
                        flags.append("evidence-artifact-mismatch:"
                                     f"{c.claim_id}:{p.get('evidence_id')}")
        jury_families = {
            p.get("producer", {}).get("family")
            for items in self._evidence.values() for p in items
            if p.get("tier") in ("W2", "W3")
            and p.get("producer", {}).get("family")}
        if jury_families and len(jury_families) < self.policy.thresholds.min_jury_families:
            flags.append("jury-single-family:" + ",".join(sorted(jury_families)))
        if coverage < self.policy.thresholds.min_w1_coverage:
            flags.append("coverage-below-threshold")
        for c in claims:
            items = bound_ev(c)
            evs = [EvidenceItem.from_dict(p) for p in items]
            adj = adjudicate(c, evs, self.policy)
            per_claim[c.claim_id] = {"value": adj.value, "rung": adj.rung,
                                     "divergence": adj.divergence}
            if adj.divergence == "SPLIT":
                flags.append(f"divergence-split:{c.claim_id}")
        for c in claims:
            if (c.verifiability == "MACHINE_CHECKABLE"
                    and per_claim[c.claim_id]["value"] == "INCONCLUSIVE"):
                flags.append(f"inconclusive-unresolved:{c.claim_id}")

        # §2.3: ts is an ISO-8601 string (floats never occupy hashed
        # positions) — parse for the latency measure, not for ordering.
        from datetime import datetime
        last_ts = entries[-1].get("ts", "")
        try:
            appended_at = datetime.fromisoformat(last_ts).timestamp()
        except (ValueError, TypeError):
            appended_at = time.time()
        now = time.time()
        return Observation(kind="watch.observed", seq_from=seq_from,
                           seq_to=seq_to, flags=tuple(flags), coverage=coverage,
                           per_claim=per_claim, ts=now,
                           detection_latency=max(0.0, now - appended_at))

    # -- stream ------------------------------------------------------------

    def observations(self, max_batches: int | None = None,
                     idle_timeout: float | None = None):
        """Yield Observation batches as the ledger grows.

        Ends when: `max_batches` observations were emitted (bounded runs —
        tests, CI receipts), or when `idle_timeout` seconds pass with no
        new append (poll loops hand the caller back control; a None means
        never idle-stop). An unreadable/incomplete last line is skipped
        until complete: torn writes are the writer's, not the stream's.
        """
        seen_lines = 0
        batches = 0
        last_append_ts = time.time()
        while max_batches is None or batches < max_batches:
            entries = self._read_complete_entries()
            new = entries[seen_lines:]
            if new:
                seen_lines = len(entries)
                obs = self._ingest_range(new, new[0]["seq"], new[-1]["seq"])
                last_append_ts = time.time()
                batches += 1
                yield obs
            elif (idle_timeout is not None
                  and time.time() - last_append_ts > idle_timeout):
                return
            else:
                time.sleep(self.poll_interval)

    def _read_complete_entries(self) -> list[dict]:
        if not os.path.exists(self.ledger_path):
            return []
        out = []
        with open(self.ledger_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    return out          # torn trailing line: hold back
        return out


def stream_summary(obs: Observation) -> dict:
    """Ledger-appendable serialization of an Observation (the notification
    payload a recording consumer would append as `watch.observed`)."""
    return {"kind": obs.kind, "seq_from": obs.seq_from, "seq_to": obs.seq_to,
            "flags": list(obs.flags), "coverage": obs.coverage,
            "detection_latency": obs.detection_latency}
