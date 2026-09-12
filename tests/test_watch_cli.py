"""CLI `veridict watch` — the WATCH transport surface (§10.3, v1.1 A1).

These tests run the REAL CLI in a subprocess against a ledger that grows
underneath it: the writer appends, the stream observes, the printed JSON
batches carry §10.2 flags with batch-identical semantics, and the process
never writes to the ledger (read-only observer — the transport MUST NOT
append, A1).
"""
import json
import os
import subprocess
import sys
import time

import pytest

from veridict.ledger import Ledger
from veridict.ladder import adjudicate  # noqa: F401  (import surface sanity)
from veridict.keys import KeyStore
from veridict.schemas import ActorRef, Claim, EvidenceItem
from veridict.policy import PolicyDeclaration, PolicyEngine, Thresholds

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = [sys.executable, "-m", "veridict.cli"]

_VERIFIER = ActorRef(kind="verifier", identity="watch-test", version="0")
_JUROR = ActorRef(kind="jury", identity="watch-juror", version="0")


def _emit(led: Ledger, path: str) -> None:
    led.save(path)


def _machine_claim(led, claim_id, covered=True):
    c = Claim(claim_id=claim_id, task_id="t", subject="s", predicate="p",
              scope="r", summary="machine claim", derived_from="d",
              verifiability="MACHINE_CHECKABLE", falsifiable_by=("verifier",),
              critical_class=None)
    led.append("claim.registered", _VERIFIER, c.to_dict())
    if covered:
        led.append("evidence.recorded", _VERIFIER, EvidenceItem(
            evidence_id=f"ev-{claim_id}", claim_id=claim_id,
            evidence_class="MACHINE_CHECK", tier="W1a",
            producer={"kind": "verifier", "identity": "watch-test",
                     "version": "0", "family": "core"},
            artifact_ref="d", reproducibility={"deterministic": True,
                                               "rerun_recipe": None},
            stance="SUPPORTS", confidence=0.9,
            rationale="probe").to_dict())


def _watch(tmp_path, ledger_path, extra=()):
    return subprocess.Popen(
        CLI + ["watch", "--ledger", ledger_path,
               "--poll-interval", "0.02", "--idle-timeout", "3", *extra],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def test_watch_emits_batches_and_flags(tmp_path):
    """A growing ledger yields JSON observation batches; an uncovered
    machine claim produces the §10.2 coverage/inconclusive flags; a fully
    covered one clears them."""
    path = str(tmp_path / "grows.jsonl")
    led = Ledger()
    ks = KeyStore(led)
    ks.generate_and_enroll("watch-test")
    _machine_claim(led, "c-uncovered", covered=False)   # coverage hole
    _emit(led, path)

    proc = _watch(tmp_path, path)
    try:
        # batch 1: the coverage hole is visible immediately
        first_line = proc.stdout.readline()
        first = json.loads(first_line)
        assert first["kind"] == "watch.observed"
        assert first["seq_from"] >= 0
        assert "coverage-below-threshold" in first["flags"]
        assert any(f.startswith("inconclusive-unresolved:c-uncovered")
                   for f in first["flags"])

        # the writer covers the hole (READ-ONLY stream: writer keeps the pen)
        _machine_claim(led, "c-uncovered", covered=True)
        _emit(led, path)
        second = json.loads(proc.stdout.readline())
        assert second["seq_from"] > first["seq_to"]
        assert "coverage-below-threshold" not in second["flags"]
        assert not any(f.startswith("inconclusive-unresolved")
                       for f in second["flags"])
    finally:
        proc.kill()
        proc.wait(timeout=5)

    # read-only invariant: the stream never appended to the ledger
    after = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    led_after = Ledger.load(path)
    assert len(led_after.entries) == len(after) == len(led.entries)
    kinds = {e["entry_type"] for e in led_after.entries}
    assert "watch.observed" not in kinds     # A1: transport MUST NOT append


def test_watch_max_batches_bounds_the_run(tmp_path):
    path = str(tmp_path / "one.jsonl")
    led = Ledger()
    ks = KeyStore(led)
    ks.generate_and_enroll("watch-test")
    _machine_claim(led, "c1", covered=True)
    _emit(led, path)
    out = subprocess.run(
        CLI + ["watch", "--ledger", path, "--poll-interval", "0.02",
               "--max-batches", "1", "--idle-timeout", "5"],
        cwd=REPO, capture_output=True, text=True, timeout=30)
    assert out.returncode == 0
    lines = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
    assert len(lines) == 1
    assert lines[0]["kind"] == "watch.observed"


def test_watch_exits_clean_on_idle(tmp_path):
    path = str(tmp_path / "quiet.jsonl")
    led = Ledger()
    ks = KeyStore(led)
    ks.generate_and_enroll("watch-test")
    _machine_claim(led, "c1", covered=True)
    _emit(led, path)
    t0 = time.time()
    out = subprocess.run(
        CLI + ["watch", "--ledger", path, "--poll-interval", "0.02",
               "--idle-timeout", "1"],
        cwd=REPO, capture_output=True, text=True, timeout=30)
    elapsed = time.time() - t0
    assert out.returncode == 0
    assert 0.5 < elapsed < 20          # observed the batch, then idled out
    lines = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
    assert len(lines) == 1 and lines[0]["kind"] == "watch.observed"


def test_watch_flags_match_batch_engine(tmp_path):
    """A1 parity: flags printed by the stream equal the batch PolicyEngine's
    §10.2 flags for the same ledger suffix (no second semantics)."""
    pol = PolicyDeclaration(policy_id="p", mode="WATCH", criticality=(),
                            thresholds=Thresholds(),
                            divergence_tolerance=1 / 3)
    path = str(tmp_path / "parity.jsonl")
    led = Ledger()
    ks = KeyStore(led)
    ks.generate_and_enroll("watch-test")
    _machine_claim(led, "c-par", covered=False)
    _emit(led, path)
    out = subprocess.run(
        CLI + ["watch", "--ledger", path, "--poll-interval", "0.02",
               "--max-batches", "1", "--idle-timeout", "5"],
        cwd=REPO, capture_output=True, text=True, timeout=30)
    streamed = json.loads(out.stdout.splitlines()[0])
    # batch engine over a FRESH ledger (its policy.decision append must not
    # leak into the streamed ledger — read-only transport, A1)
    batch_led = Ledger()
    ks2 = KeyStore(batch_led)
    ks2.generate_and_enroll("watch-test")
    _machine_claim(batch_led, "c-par", covered=False)
    claims = [Claim.from_dict(e["payload"])
              for e in batch_led.query("claim.registered")]
    evidence_by_claim: dict = {}
    for e in batch_led.query("evidence.recorded"):
        item = EvidenceItem.from_dict(e["payload"])
        evidence_by_claim.setdefault(item.claim_id, []).append(item)
    outcome = PolicyEngine(batch_led).apply(claims, evidence_by_claim, pol,
                                            _VERIFIER)
    batch_flags = set(outcome.flags)
    stream_flags = set(streamed["flags"])
    # the coverage/inconclusive flag families must agree exactly
    cov_batch = {f for f in batch_flags if "coverage" in f}
    cov_stream = {f for f in stream_flags if "coverage" in f}
    inc_batch = {f for f in batch_flags if f.startswith("inconclusive")}
    inc_stream = {f for f in stream_flags if f.startswith("inconclusive")}
    assert cov_batch == cov_stream
    assert inc_batch == inc_stream
