"""Pugio watch-feed bridge (K0 §6 / K3) receiver — tamper class pins.

The bridge is Veridict's ingestion point for PUGIO metering decisions
(watch_manifest → watch_event* → watch_close). These tests pin the
fail-loud contract across tamper classes, including the v1 KNOWN
LIMIT (manifest VALUES are not chained — documented in the module
docstring, fixing it needs producer-side changes / bridge_version=2).
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "scripts"))

from pugio_watch_receiver import (BRIDGE_VERSION, GENESIS, entry_sha,  # noqa: E402
                                  verify_watch_feed)


def _make_feed() -> list[str]:
    """A clean 3-event feed (same shape as the module selftest)."""
    prev = GENESIS
    lines = [json.dumps({
        "type": "watch_manifest", "bridge_version": BRIDGE_VERSION,
        "source": "pugio", "watcher_id": "pin-test",
        "bundle_head": "a" * 64, "bundle_merkle_root": "b" * 64,
        "bundle_event_count": 3,
    }, sort_keys=True, separators=(",", ":"))]
    for i, (rule, dec) in enumerate(
            [("quota", "deny"), ("replay", "deny"), ("ok", "allow")], 1):
        sha = entry_sha(prev, i, "1726100000.000000", "0xag", "/api", rule, dec)
        lines.append(json.dumps({
            "type": "watch_event", "bridge_version": BRIDGE_VERSION, "seq": i,
            "ts": "1726100000.000000", "agent": "0xag", "host": "/api",
            "rule_id": rule, "decision": dec,
            "prev_entry_sha": prev, "entry_sha": sha,
        }, sort_keys=True, separators=(",", ":")))
        prev = sha
    lines.append(json.dumps({
        "type": "watch_close", "bridge_version": BRIDGE_VERSION,
        "entries": 3, "watch_head": prev,
    }, sort_keys=True, separators=(",", ":")))
    return lines


def _rewrite(lines: list[str], idx: int, **changes) -> list[str]:
    obj = json.loads(lines[idx])
    obj.update(changes)
    lines = list(lines)
    lines[idx] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return lines


def test_clean_feed_passes_with_tally():
    ok, msg, tally = verify_watch_feed(_make_feed())
    assert ok, msg
    assert sum(tally.values()) == 3
    assert tally["quota/deny"] == 1 and tally["ok/allow"] == 1


def test_decision_tamper_breaks_chain():
    feed = _rewrite(_make_feed(), 1, decision="allow")     # was deny
    ok, msg, _ = verify_watch_feed(feed)
    assert not ok and "entry_sha" in msg


def test_truncated_feed_without_close_fails():
    ok, msg, _ = verify_watch_feed(_make_feed()[:-1])
    assert not ok and "watch_close yok" in msg


def test_swapped_events_fail_on_seq():
    feed = _make_feed()
    feed[1], feed[2] = feed[2], feed[1]
    ok, msg, _ = verify_watch_feed(feed)
    assert not ok and "seq" in msg


def test_seq_skip_fails():
    feed = _rewrite(_make_feed(), 3, seq=9)
    ok, msg, _ = verify_watch_feed(feed)
    assert not ok and "seq" in msg


def test_hash_exogenous_field_is_rejected():
    """A field outside the hash preimage must not ride along silently —
    the standard's D5 lesson, applied to the bridge."""
    feed = _rewrite(_make_feed(), 1, note="invisible to the chain")
    ok, msg, _ = verify_watch_feed(feed)
    assert not ok and "bilinmeyen alan" in msg


def test_count_mismatch_between_manifest_and_close_is_rejected():
    feed = _rewrite(_make_feed(), 0, bundle_event_count=99)
    ok, msg, _ = verify_watch_feed(feed)
    assert not ok and "bundle_event_count" in msg


def test_close_entries_lie_is_rejected():
    feed = _rewrite(_make_feed(), 4, entries=5)
    ok, msg, _ = verify_watch_feed(feed)
    assert not ok and "close.entries" in msg


def test_empty_feed_fails():
    ok, msg, _ = verify_watch_feed([])
    assert not ok


def test_manifest_value_tamper_is_the_documented_v1_limit():
    """KNOWN LIMIT (pinned honestly): manifest VALUES (bundle_head etc.)
    are not chained in v1 — the tamper PASSES today. When producer-side
    binding lands (bridge_version=2), flip this test to assert failure;
    until then this pin keeps the limitation visible instead of silent."""
    feed = _rewrite(_make_feed(), 0, bundle_head="f" * 64)
    ok, msg, _ = verify_watch_feed(feed)
    assert ok, "v1 documented limitation changed — update bridge to v2 " \
               "and flip this pin to `not ok`"
