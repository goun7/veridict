import time

from veridict.conformance import run_conformance_suite
from veridict.schemas import Claim
from veridict.watchers import WatcherManifest, WatcherSession

from watchers.compliance_watcher import SESSION as COMP_SESSION
from watchers.cost_watcher import SESSION as COST_SESSION
from watchers.security_watcher import SESSION as SEC_SESSION


def _manifest(**over):
    base = dict(
        watcher_id="conf-probe", name="Conformance Probe", version="0.1.0",
        producer={"identity": "conf-probe", "maintainer": "test-org"},
        capabilities={"evidence_classes": ("WATCHER_REPORT",), "max_tier": "W1b",
                      "subscribes_to": ("*",)},
        resource_class={"timeout_seconds": 0, "cost_budget": 0,
                        "sandbox_level": "none"},
        integrity={"code_hash": "c" * 64, "update_policy": "manual"})
    base.update(over)
    return WatcherManifest(**base)


def test_all_example_watchers_conform():
    for session in (SEC_SESSION, COST_SESSION, COMP_SESSION):
        report = run_conformance_suite(session)
        assert report["conformant"], report["checks"]
        assert {c["id"] for c in report["checks"]} == {
            f"C{i}" for i in range(1, 14)}


def test_always_failing_session_is_nonconformant():
    def always_down(summary, ref):
        raise RuntimeError("watcher down")

    report = run_conformance_suite(WatcherSession(_manifest(), always_down))
    assert report["conformant"] is False
    failing = {c["id"] for c in report["checks"] if not c["passed"]}
    assert "C8" in failing            # no well-formed evidence item produced


def test_always_bad_stance_session_is_nonconformant():
    report = run_conformance_suite(WatcherSession(
        _manifest(), lambda summary, ref: ("MAYBE", 0.5, "eh")))
    assert report["conformant"] is False
    failing = {c["id"] for c in report["checks"] if not c["passed"]}
    # C6 probes the RUNTIME's abstention on bad stance (wrapper fn) and passes;
    # the session's own always-MAYBE fn cannot produce a well-formed item, so
    # the observable-contract failure surfaces at C8.
    assert "C8" in failing and "C6" not in failing


def test_report_checks_never_raise():
    # a pathological fn that returns garbage of the wrong arity must yield a
    # failing report, not an exception out of the suite
    report = run_conformance_suite(WatcherSession(
        _manifest(), lambda summary, ref: ("SUPPORTS",)))
    assert report["conformant"] is False


def test_c10_deadline_check_exercises_timeout():
    started = time.time()
    report = run_conformance_suite(WatcherSession(_manifest(), lambda s, r: None))
    elapsed = time.time() - started
    c10 = next(c for c in report["checks"] if c["id"] == "C10")
    assert c10["passed"] is True
    assert elapsed < 10               # deadline check actually bounded


def test_c13_rejects_lying_sandbox_budget():
    # L2-3: an inprocess manifest with a nonzero cost_budget contradicts
    # itself — an in-process fn cannot spend money. The kit must refuse to
    # certify such a manifest.
    lying = _manifest(resource_class={"timeout_seconds": 10, "cost_budget": 5.0,
                                      "sandbox_level": "inprocess"})
    report = run_conformance_suite(WatcherSession(
        lying, lambda s, r: ("SUPPORTS", 0.8, "probe")))
    c13 = next(c for c in report["checks"] if c["id"] == "C13")
    assert c13["passed"] is False
    assert "cost_budget" in c13["detail"]


def test_c13_passes_coherent_manifest():
    coherent = _manifest(resource_class={"timeout_seconds": 10, "cost_budget": 0.0,
                                         "sandbox_level": "inprocess"})
    report = run_conformance_suite(WatcherSession(
        coherent, lambda s, r: ("SUPPORTS", 0.8, "probe")))
    c13 = next(c for c in report["checks"] if c["id"] == "C13")
    assert c13["passed"] is True
