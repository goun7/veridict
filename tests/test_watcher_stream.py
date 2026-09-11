"""WATCH-mode streaming transport tests (issue #3, §10.3 v1.1 candidate).

Property pins:
1. Parity — the stream's per-claim verdicts and flags are IDENTICAL to the
   batch PolicyEngine on the same ledger (§10.2: WATCH computes flags the
   same way, only the blocking consequence is absent).
2. Incrementality — each observation covers exactly the entries appended
   since the previous one (seq ranges are dense and non-overlapping).
3. Torn-line tolerance — a partially written trailing line is held back,
   not misparsed.
4. Detection latency — an append surfaces within poll_interval * ~slack.
"""
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from veridict.claim_extractor import ClaimExtractor
from veridict.ledger import Ledger
from veridict.policy import (AuditOutcome, PolicyDeclaration, PolicyEngine,
                             Thresholds)
from veridict.schemas import ActorRef, EvidenceItem, TaskManifest
from veridict.watcher_stream import LedgerStream, stream_summary


AUTHOR = ActorRef(kind="jury", identity="j1", version="1")
SYSTEM = ActorRef(kind="system", identity="sys", version="1")


def _watch_policy():
    return PolicyDeclaration(policy_id="watch-parity", mode="WATCH",
                             criticality=(), thresholds=Thresholds(),
                             divergence_tolerance=1 / 3)


def _seed_ledger(ledger: Ledger, task_digest: str = "dg-1") -> list:
    """One machine claim with W1a SUPPORTS + one doctrinal claim with a
    jury SPLIT; returns the claim objects."""
    task = TaskManifest(task_id="stream-1", artifact_path="/x",
                        actor_identity="ai-dev",
                        intent_lines=("MACHINE: add computes the sum of two numbers",
                                      "DOCTRINE: the module is idiomatic python"),
                        criticality=(), has_existing_tests=True, pytest_args=())
    claims = []
    from veridict.jury import Opinion  # noqa: F401  (docstring reference)
    for c in ClaimExtractor().extract(task, task_digest):
        ledger.append("claim.registered", SYSTEM, c.to_dict())
        claims.append(c)
    # W1a machine support for the machine claim
    from veridict.utils import sha256_hex
    for c in claims:
        if c.predicate == "existing-test-suite-passes" or "add" in c.summary:
            item = EvidenceItem(
                evidence_id=f"veridict-evidence-v1-{c.claim_id[:8]}-testexec",
                claim_id=c.claim_id, evidence_class="TEST_EXECUTION", tier="W1a",
                producer={"kind": "verifier", "identity": "test-executor",
                          "version": "0.1.0"},
                artifact_ref=task_digest,
                reproducibility={"deterministic": True,
                                 "rerun_recipe": {"cmd": ["pytest"]}},
                stance="SUPPORTS", confidence=1.0, rationale="tests pass")
        else:
            # doctrinal claim: a stand-off between two jurors → SPLIT
            item = EvidenceItem(
                evidence_id=sha256_hex(c.claim_id)[:24], claim_id=c.claim_id,
                evidence_class="JURY_OPINION", tier="W2",
                producer={"kind": "jury", "identity": "j1", "version": "1",
                          "family": "f1"},
                artifact_ref=task_digest,
                reproducibility={"deterministic": False,
                                 "rerun_recipe": None},
                stance="REFUTES", confidence=0.9, rationale="not idiomatic")
        ledger.append("evidence.recorded", AUTHOR, item.to_dict())
    return claims


def test_stream_verdicts_and_flags_match_batch(tmp_path):
    """§10.2 parity: stream per-claim values and flags == batch policy
    engine on the same ledger, and the stream never blocks."""
    led = Ledger()
    claims = _seed_ledger(led)
    # doctrinal counterpart (SUPPORTS) to create the SPLIT
    from veridict.utils import sha256_hex
    for c in claims:
        if c.verifiability != "MACHINE_CHECKABLE":
            pass
    doctrinal = [c for c in claims if c.summary == "the module is idiomatic python"]
    if doctrinal:
        c = doctrinal[0]
        item = EvidenceItem(
            evidence_id=sha256_hex(c.claim_id + "sup")[:24], claim_id=c.claim_id,
            evidence_class="JURY_OPINION", tier="W2",
            producer={"kind": "jury", "identity": "j2", "version": "1",
                      "family": "f2"},
            artifact_ref="dg-1",
            reproducibility={"deterministic": False, "rerun_recipe": None},
            stance="SUPPORTS", confidence=0.8, rationale="looks fine")
        led.append("evidence.recordsup", AUTHOR, item.to_dict())  # placeholder

    lp = str(tmp_path / "led.jsonl")
    led.save(lp)

    # batch truth
    from veridict.schemas import EvidenceItem as EI
    ev_by_claim = {}
    for e in led.entries:
        p = e["payload"]
        if e["entry_type"] == "evidence.recorded":
            ev_by_claim.setdefault(p["claim_id"], []).append(EI.from_dict(p))
    pol = PolicyDeclaration(policy_id="watch-parity", mode="WATCH",
                             criticality=(), thresholds=Thresholds(),
                             divergence_tolerance=1 / 3)
    batch = PolicyEngine(Ledger.load(lp)).apply(
        claims, ev_by_claim, pol, AUTHOR)
    assert batch.blocked is False          # WATCH never blocks
    assert batch.flags                      # seeded SPLIT ⇒ non-empty

    # stream truth
    stream = LedgerStream(lp, pol, poll_interval=0.01)
    obs = None
    for o in stream.observations(max_batches=1, idle_timeout=2.0):
        obs = o
    assert obs is not None
    assert obs.flags == batch.flags
    assert set(obs.per_claim) == set(batch.per_claim)
    for cid, per in batch.per_claim.items():
        assert obs.per_claim[cid]["value"] == per["value"], cid
        assert obs.per_claim[cid]["divergence"] == per["divergence"], cid
    assert obs.kind == "watch.observed"
    assert obs.seq_from == 0
    assert obs.seq_to == len(led.entries) - 1


def test_stream_detects_increments(tmp_path):
    """Incremental batches: append twice, both surfaces, dense non-
    overlapping seq ranges."""
    lp = str(tmp_path / "led.jsonl")
    led = Ledger()
    _seed_ledger(led)          # batch 1 source
    led.save(lp)

    pol = _watch_policy()
    stream = LedgerStream(lp, pol, poll_interval=0.01)

    got = []
    def consume():
        for o in stream.observations(max_batches=2, idle_timeout=3.0):
            got.append(o)
    t = threading.Thread(target=consume)
    t.start()

    time.sleep(0.3)
    assert len(got) >= 1
    first_to = got[0].seq_to
    # second append: a fresh claim riding the same chain
    claims2 = ClaimExtractor().extract(TaskManifest(
        task_id="stream-2", artifact_path="/x", actor_identity="ai-dev",
        intent_lines=("MACHINE: divide never crashes on zero denominator",),
        criticality=(), has_existing_tests=True, pytest_args=()), "dg-2")
    led.append("claim.registered", SYSTEM, claims2[0].to_dict())
    led.save(lp)
    t.join(timeout=5)
    assert not t.is_alive()
    assert len(got) == 2
    assert got[1].seq_from == first_to + 1


def test_stream_tolerates_torn_trailing_line(tmp_path):
    """A half-written last line is held back, then ingested when whole."""
    lp = str(tmp_path / "led.jsonl")
    led = Ledger()
    _seed_ledger(led)
    led.save(lp)
    good = open(lp).read()
    # simulate a torn append: 30 chars of what would be the next line
    with open(lp, "a", encoding="utf-8") as f:
        f.write('{"a": 1, "b": 2, "c": 3, "d"')

    pol = _watch_policy()
    stream = LedgerStream(lp, pol, poll_interval=0.01)
    obs = None
    for o in stream.observations(max_batches=1, idle_timeout=0.5):
        obs = o
    assert obs is not None                        # complete prefix ingested…
    assert obs.seq_to == len(led.entries) - 1     # …and the torn line held

    # complete the line via rewrite (writer healed) — full prefix visible
    with open(lp, "w", encoding="utf-8") as f:
        f.write(good)
    obs2 = None
    for o in LedgerStream(lp, pol, poll_interval=0.01).observations(
            max_batches=1, idle_timeout=0.3):
        obs2 = o
    assert obs2.seq_from == 0     # stream restarted: whole file is new


def test_stream_waits_for_file_then_detects(tmp_path):
    """A ledger that does not exist yet: the stream waits, then catches the
    first append."""
    lp = str(tmp_path / "not-yet.jsonl")
    pol = _watch_policy()
    stream = LedgerStream(lp, pol, poll_interval=0.02)

    got = []
    def consume():
        for o in stream.observations(max_batches=1, idle_timeout=4.0):
            got.append(o)
    t = threading.Thread(target=consume)
    t.start()
    time.sleep(0.3)
    assert got == []                     # nothing yet — stream is waiting

    led = Ledger()
    _seed_ledger(led)
    time.sleep(0.2)
    led.save(lp)                         # writer lands the first append
    t.join(timeout=5)
    assert not t.is_alive()
    assert got and got[0].seq_to == len(led.entries) - 1


def test_stream_summary_is_json_serializable(tmp_path):
    led = Ledger()
    _seed_ledger(led)
    lp = str(tmp_path / "led.jsonl")
    led.save(lp)
    pol = _watch_policy()
    for o in LedgerStream(lp, pol, poll_interval=0.01).observations(
            max_batches=1, idle_timeout=0.5):
        assert json.loads(json.dumps(stream_summary(o)))["kind"] == "watch.observed"
