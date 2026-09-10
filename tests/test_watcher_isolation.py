"""Watcher isolation limits — pinned honestly, per the fresh-eyes audit (F1b)."""
import sys, threading, time, os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.watchers import WatcherSession, WatcherManifest, run_session
from veridict.schemas import Claim


def _manifest():
    return WatcherManifest(
        watcher_id="slow-w", name="Slow", version="1.0.0",
        producer={"identity": "w", "maintainer": "m"},
        capabilities={"evidence_classes": ("JURY_OPINION",), "max_tier": "W2",
                      "subscribes_to": ("*",)},
        resource_class={"timeout_seconds": 0.05, "cost_budget": None,
                        "sandbox_level": "none"},
        integrity={"code_hash": "0" * 64, "update_policy": "pinned"})


def _claim():
    return Claim(claim_id="c", task_id="t", subject="s", predicate="p",
                 scope="s", summary="x", derived_from="d",
                 verifiability="DOCTRINAL", falsifiable_by=("x",),
                 critical_class=None)


def test_timeout_abstains_and_threads_are_reclaimed_after_fn_completes():
    """Deadline expiry → abstain. The worker thread outlives the deadline
    (shutdown(wait=False)) but is RECLAIMED once the fn completes — the leak
    is bounded by fn runtime, and the audit is never blocked by a slow
    watcher (documented honest limit; host isolation is the other control)."""
    def slow_fn(summary, ref):
        time.sleep(0.4)
        return ("SUPPORTS", 1.0, "late")

    session = WatcherSession(_manifest(), slow_fn)
    base = threading.active_count()
    results = [run_session(session, _claim(), "d", timeout_seconds=0.05)
               for _ in range(20)]
    assert all(r is None for r in results), "timed-out watcher must abstain"
    # wait past the fn runtime: workers finish their item, find the executor
    # shut down, and exit — the leak is bounded, not permanent
    deadline = time.time() + 5
    while threading.active_count() > base and time.time() < deadline:
        time.sleep(0.05)
    assert threading.active_count() <= base + 1, (
        f"worker threads not reclaimed: {threading.active_count()} > {base}+1")
