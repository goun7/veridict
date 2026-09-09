from veridict.audit import AuditOrchestrator
from veridict.jury import Jury, Opinion, ScriptedProvider
from veridict.ledger import Ledger
from veridict.keys import KeyStore
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import TaskManifest
from veridict.watchers import WatcherManifest, WatcherSession


def _watcher(watcher_id="w1", max_tier="W1b", evidence_class="STATIC_ANALYSIS",
             subscribes_to=("*",), fn=None):
    m = WatcherManifest(
        watcher_id=watcher_id, name=f"W {watcher_id}", version="0.1.0",
        producer={"identity": watcher_id, "maintainer": "test-org"},
        capabilities={"evidence_classes": (evidence_class,), "max_tier": max_tier,
                      "subscribes_to": subscribes_to},
        resource_class={"timeout_seconds": 10, "cost_budget": 0, "sandbox_level": "none"},
        integrity={"code_hash": "b" * 64, "update_policy": "manual"})
    return WatcherSession(m, fn or (lambda summary, ref: ("SUPPORTS", 0.8, "watcher ok")))


def _task(tmp_path):
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "test_calc.py").write_text(
        "from calc import add\n\ndef test_add():\n    assert add(1, 1) == 2\n")
    return TaskManifest(task_id="tw", artifact_path=str(tmp_path),
                        actor_identity="ai-dev", intent_lines=(), criticality=(),
                        has_existing_tests=True, pytest_args=())


def _orch(ledger, watchers=()):
    ks = KeyStore(Ledger())          # scratch: keep audit ledger's types[0] == task.started
    kid = ks.generate_and_enroll("core")
    jury = Jury([ScriptedProvider(family="a", identity="a-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok")),
                 ScriptedProvider(family="b", identity="b-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok"))])
    pol = PolicyDeclaration(policy_id="pw", mode="GATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    return AuditOrchestrator(ledger, pol, jury, ks, kid, watchers=watchers)


def test_watcher_evidence_recorded_with_authority(tmp_path):
    led = Ledger()
    result = _orch(led, watchers=(_watcher(),)).run(_task(tmp_path))
    watcher_ev = [e for e in led.entries if e["entry_type"] == "evidence.recorded"
                  and e["payload"]["producer"]["kind"] == "watcher"]
    assert watcher_ev, "watcher evidence missing"
    assert all(e["author"]["kind"] == "watcher" for e in watcher_ev)
    assert all(e["payload"]["tier"] == "W1b" for e in watcher_ev)


def test_watcher_subscribes_to_filtering(tmp_path):
    led = Ledger()
    selective = _watcher(watcher_id="cost", subscribes_to=("cost", "performance"))
    result = _orch(led, watchers=(selective,)).run(_task(tmp_path))
    watcher_ev = [e for e in led.entries if e["entry_type"] == "evidence.recorded"
                  and e["payload"]["producer"].get("family") == "cost"]
    assert watcher_ev == []          # nothing subscribed → session never ran


def test_watcher_abstention_reported(tmp_path):
    led = Ledger()
    crashy = _watcher(watcher_id="crashy",
                      fn=lambda summary, ref: (_ for _ in ()).throw(RuntimeError("down")))
    result = _orch(led, watchers=(crashy,)).run(_task(tmp_path))
    assert "crashy" in result["report"]["abstentions"]
    assert result["outcome"].blocked is False      # abstain ≠ refute (§5.4)


def test_watchers_blind_to_jury_output(tmp_path):
    seen = []
    recording = _watcher(watcher_id="rec",
                         fn=lambda summary, ref: seen.append(summary) or ("SUPPORTS", 0.8, "ok"))
    _orch(Ledger(), watchers=(recording,)).run(_task(tmp_path))
    assert all("jury" not in s and "opinion" not in s for s in seen)
