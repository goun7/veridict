import pytest

from veridict.jury import Opinion
from veridict.ledger import Ledger
from veridict.keys import KeyStore
from veridict.watchers import (ManifestRegistry, WatcherManifest, WatcherSession,
                               run_session)


def _manifest(**over):
    base = dict(
        watcher_id="sec-1", name="Security Watcher", version="0.1.0",
        producer={"identity": "sec-watcher", "maintainer": "example-org"},
        capabilities={"evidence_classes": ("STATIC_ANALYSIS",), "max_tier": "W1b",
                      "subscribes_to": ("payments", "security")},
        resource_class={"timeout_seconds": 30, "cost_budget": 1.0,
                        "sandbox_level": "none"},
        integrity={"code_hash": "a" * 64, "update_policy": "manual"})
    base.update(over)
    return WatcherManifest(**base)


def _registry(ledger=None):
    led = ledger or Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("watcher-registry")
    return ManifestRegistry(led, ks, kid), led


def test_manifest_roundtrip():
    m = _manifest()
    assert WatcherManifest.from_dict(m.to_dict()) == m
    assert len(m.manifest_digest()) == 64


def test_w1a_ceiling_forbidden():
    with pytest.raises(ValueError):
        _manifest(capabilities={"evidence_classes": ("TEST_EXECUTION",),
                                "max_tier": "W1a", "subscribes_to": ("*",)})


def test_bad_evidence_class_rejected():
    with pytest.raises(ValueError):
        _manifest(capabilities={"evidence_classes": ("TELEPATHY",),
                                "max_tier": "W2", "subscribes_to": ("*",)})


def test_anonymous_producer_rejected():
    with pytest.raises(ValueError):
        _manifest(producer={"identity": "", "maintainer": ""})


def test_register_and_verify(tmp_path=None):
    reg, led = _registry()
    entry = reg.register(_manifest())
    assert entry["entry_type"] == "watcher.registered"
    report = ManifestRegistry.verify_manifest(led, "sec-1")
    assert report["valid"] is True, report["errors"]
    assert report["signature_valid"] is True
    got = ManifestRegistry.get_manifest(led, "sec-1")
    assert got == _manifest()


def test_tampered_manifest_fails_verification():
    reg, led = _registry()
    reg.register(_manifest())
    led.entries[-1]["payload"]["name"] = "Evil Watcher"   # retroactive edit
    report = ManifestRegistry.verify_manifest(led, "sec-1")
    assert report["valid"] is False


def test_unknown_watcher_verify_fails():
    reg, led = _registry()
    report = ManifestRegistry.verify_manifest(led, "ghost")
    assert report["valid"] is False
    assert ManifestRegistry.get_manifest(led, "ghost") is None


def _session_manifest(max_tier="W1b", evidence_class="STATIC_ANALYSIS"):
    return _manifest(capabilities={"evidence_classes": (evidence_class,),
                                   "max_tier": max_tier, "subscribes_to": ("*",)})


def test_session_produces_ceiling_respecting_evidence():
    m = _session_manifest(max_tier="W1b")
    s = WatcherSession(m, lambda summary, digest: ("REFUTES", 0.9, "shell=True found"))
    ev = run_session(s, _claim_stub("x is safe"), "digest")
    assert ev is not None
    assert ev.tier == "W1b" and ev.stance == "REFUTES"
    assert ev.producer["kind"] == "watcher" and ev.producer["family"] == "sec-1"
    assert ev.evidence_class == "STATIC_ANALYSIS"
    assert ev.reproducibility["deterministic"] is True


def test_w3_doctrinal_watcher():
    m = _session_manifest(max_tier="W3", evidence_class="WATCHER_REPORT")
    s = WatcherSession(m, lambda summary, digest: ("SUPPORTS", 0.6, "compliant"))
    ev = run_session(s, _claim_stub("api usage is idiomatic"), "digest")
    assert ev.tier == "W3" and ev.evidence_class == "WATCHER_REPORT"
    assert ev.reproducibility["deterministic"] is False


def test_session_blind_input_only():
    seen = []
    s = WatcherSession(_session_manifest(), lambda summary, digest: seen.append((summary, digest)) or ("SUPPORTS", 0.8, "ok"))
    run_session(s, _claim_stub("some claim"), "digest")
    assert seen == [("some claim", "digest")]


def test_session_error_is_abstain():
    def boom(summary, digest):
        raise RuntimeError("watcher crashed")
    s = WatcherSession(_session_manifest(), boom)
    assert run_session(s, _claim_stub("x"), "digest") is None


def test_session_none_is_abstain():
    s = WatcherSession(_session_manifest(), lambda summary, digest: None)
    assert run_session(s, _claim_stub("x"), "digest") is None


def test_session_bad_stance_is_abstain():
    s = WatcherSession(_session_manifest(), lambda summary, digest: ("MAYBE", 0.5, "eh"))
    assert run_session(s, _claim_stub("x"), "digest") is None


def test_w2_ceiling_mapping():
    m = _session_manifest(max_tier="W2", evidence_class="WATCHER_REPORT")
    s = WatcherSession(m, lambda summary, digest: ("SUPPORTS", 0.8, "ok"))
    ev = run_session(s, _claim_stub("x"), "d")
    assert ev.tier == "W2" and ev.reproducibility["deterministic"] is False


def test_body_tamper_fails_all_checks():
    reg, led = _registry()
    reg.register(_manifest())
    led.entries[-1]["payload"]["manifest"]["name"] = "Evil"
    report = ManifestRegistry.verify_manifest(led, "sec-1")
    assert report["valid"] is False
    assert not report["signature_valid"]      # body tamper breaks the signature


def test_confidence_clamped():
    s = WatcherSession(_session_manifest(), lambda summary, digest: ("SUPPORTS", 7.3, "wild"))
    ev = run_session(s, _claim_stub("x"), "d")
    assert ev.confidence == 1.0
    s2 = WatcherSession(_session_manifest(), lambda summary, digest: ("SUPPORTS", -2, "low"))
    assert run_session(s2, _claim_stub("x"), "d").confidence == 0.0


def test_reregistration_latest_wins():
    reg, led = _registry()
    reg.register(_manifest(name="First"))
    reg.register(_manifest(name="Second"))
    assert ManifestRegistry.get_manifest(led, "sec-1").name == "Second"


def test_malformed_fn_output_is_abstain():
    # Hardening: unpack + float() live inside the try — a malformed fn return
    # must abstain, not crash the audit (§5.4).
    short = WatcherSession(_session_manifest(), lambda summary, digest: ("SUPPORTS", 0.8))
    assert run_session(short, _claim_stub("x"), "d") is None
    non_numeric = WatcherSession(_session_manifest(),
                                 lambda summary, digest: ("SUPPORTS", "high", "r"))
    assert run_session(non_numeric, _claim_stub("x"), "d") is None


def test_malformed_manifest_body_reports_error():
    # Hardening: a structurally malformed (not merely tampered) body must
    # surface as an error line, not a KeyError crash.
    reg, led = _registry()
    reg.register(_manifest())
    led.entries[-1]["payload"]["manifest"].pop("capabilities")
    report = ManifestRegistry.verify_manifest(led, "sec-1")
    assert report["valid"] is False
    assert any("invalid manifest" in e for e in report["errors"])


def test_run_session_passes_artifact_path_reference():
    # §5.3: "claim + artifact references" — an artifact REFERENCE (the path) is
    # legitimate session input; blindness means no other producers' outputs.
    seen = []
    s = WatcherSession(_session_manifest(),
                       lambda summary, ref: seen.append(ref) or ("SUPPORTS", 0.8, "ok"))
    run_session(s, _claim_stub("x"), "d", artifact_path="/artifacts/repo")
    assert seen == ["/artifacts/repo"]


def test_watcher_evidence_persists_doctrine_rationale():
    # The doctrine fn's rationale (3rd tuple element) was accepted-but-dropped;
    # it must persist on the evidence item (dossier risk_frame input, §6.3).
    s = WatcherSession(_session_manifest(),
                       lambda summary, ref: ("REFUTES", 0.9, "billing path flips signs"))
    ev = run_session(s, _claim_stub("x"), "digest")
    assert ev.rationale == "billing path flips signs"


def _claim_stub(summary):
    from veridict.schemas import Claim
    return Claim(claim_id="cx", task_id="t", subject="s", predicate="p", scope="r",
                 summary=summary, derived_from="digest", verifiability="DOCTRINAL",
                 falsifiable_by=("watcher",), critical_class=None)


def _manifest_with_timeout(seconds):
    m = _session_manifest()
    return WatcherManifest(**{**m.to_dict(), "resource_class": {
        "timeout_seconds": seconds, "cost_budget": 0, "sandbox_level": "none"}})


def test_session_timeout_abstains():
    import time

    def slow(summary, ref):
        time.sleep(2.0)
        return ("SUPPORTS", 0.8, "late")

    s = WatcherSession(_manifest_with_timeout(1), slow)
    assert run_session(s, _claim_stub("x"), "d") is None


def test_session_without_timeout_runs_inline():
    import threading

    seen = {}

    def note_thread(summary, ref):
        seen["thread"] = threading.current_thread()
        return ("SUPPORTS", 0.8, "ok")

    s = WatcherSession(_manifest_with_timeout(0), note_thread)
    assert run_session(s, _claim_stub("x"), "d") is not None
    assert seen["thread"] is threading.current_thread()


def test_session_manifest_timeout_used_when_caller_omits():
    import time

    def slow(summary, ref):
        time.sleep(2.0)
        return ("SUPPORTS", 0.8, "late")

    s = WatcherSession(_manifest_with_timeout(1), slow)
    # no explicit timeout_seconds argument — manifest deadline applies
    assert run_session(s, _claim_stub("x"), "d") is None
