from veridict.audit import AuditOrchestrator, artifact_digest
from veridict.jury import Jury, Opinion, ScriptedProvider
from veridict.ledger import Ledger
from veridict.keys import KeyStore
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import TaskManifest


def _orchestrator(ledger, responses=None):
    # Reconciled: committed KeyStore contract appends key.enrolled to its ledger;
    # enrolling into the audit ledger would put key.enrolled at entries[0] ahead
    # of the audit flow. Signing is in-memory, so a scratch ledger keeps every
    # assertion below exact (types[0] == "task.started").
    ks = KeyStore(Ledger())
    kid = ks.generate_and_enroll("veridict-core")
    jury = Jury([ScriptedProvider(family="stub-a", identity="stub-a-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok"),
                                  responses=responses or {}),
                 ScriptedProvider(family="stub-b", identity="stub-b-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok"),
                                  responses=responses or {})])
    pol = PolicyDeclaration(policy_id="p1", mode="GATE", criticality=("payments",),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    return AuditOrchestrator(ledger, pol, jury, ks, kid), pol


def _task(tmp_path, intent=(), crit=()):
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "test_calc.py").write_text(
        "from calc import add\n\ndef test_add():\n    assert add(1, 1) == 2\n")
    return TaskManifest(task_id="t1", artifact_path=str(tmp_path),
                        actor_identity="ai-dev", intent_lines=tuple(intent),
                        criticality=tuple(crit), has_existing_tests=True, pytest_args=())


def test_artifact_digest_is_stable_and_order_independent(tmp_path):
    (tmp_path / "a.py").write_text("x = 1")
    (tmp_path / "b.py").write_text("y = 2")
    d1 = artifact_digest(str(tmp_path))
    (tmp_path / "a.py").write_text("x = 1")   # rewrite same content
    assert artifact_digest(str(tmp_path)) == d1


def test_full_pipeline_happy_path(tmp_path):
    task = _task(tmp_path)
    led = Ledger()
    orch, _ = _orchestrator(led)
    result = orch.run(task)
    types = [e["entry_type"] for e in led.entries]
    assert types[0] == "task.started"
    assert "actor.output" in types
    assert types.count("claim.registered") >= 3
    assert types.count("evidence.recorded") >= 5      # tests + static + jury(>=2)
    assert "policy.decision" in types and "certificate.issued" in types
    assert result["outcome"].blocked is False
    assert result["cert"]["risk_level"] == "low"


def test_actor_output_pins_digest(tmp_path):
    task = _task(tmp_path)
    led = Ledger()
    orch, _ = _orchestrator(led)
    orch.run(task)
    actor_entries = [e for e in led.entries if e["entry_type"] == "actor.output"]
    assert actor_entries[0]["author"]["kind"] == "actor"
    assert actor_entries[0]["payload"]["artifact_digest"] == artifact_digest(task.artifact_path)


def test_jury_split_flags_divergence(tmp_path):
    task = _task(tmp_path)
    split_responses = {"existing test suite passes": Opinion("REFUTES", 0.9, "suspicious")}
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("core")
    jury = Jury([ScriptedProvider(family="stub-a", identity="a-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok")),
                 ScriptedProvider(family="stub-b", identity="b-1",
                                  default=Opinion("REFUTES", 0.9, "doubt"),
                                  responses=split_responses)])
    pol = PolicyDeclaration(policy_id="p2", mode="CERTIFICATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    orch = AuditOrchestrator(led, pol, jury, ks, kid)
    result = orch.run(task)
    assert any(e["entry_type"] == "divergence.flagged" for e in led.entries)
    assert any("divergence-split" in f for f in result["outcome"].flags)


def test_meta_claim_registered_when_budget_allows(tmp_path):
    task = _task(tmp_path)
    led = Ledger()
    responses = {"existing test suite passes": Opinion("REFUTES", 0.9, "uncovered case")}
    orch, _ = _orchestrator(led, responses=responses)
    result = orch.run(task)
    preds = [e["payload"]["predicate"] for e in led.entries
             if e["entry_type"] == "claim.registered"]
    assert any(p.startswith("coverage-of") for p in preds)
