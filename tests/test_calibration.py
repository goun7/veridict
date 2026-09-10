from veridict.audit import AuditOrchestrator
from veridict.calibration import calibration_factor, update_calibration
from veridict.jury import Jury, Opinion, ScriptedProvider
from veridict.ledger import Ledger
from veridict.keys import KeyStore
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import ActorRef, Claim, EvidenceItem, TaskManifest


def _claim(cid="c1"):
    return Claim(claim_id=cid, task_id="t", subject="s", predicate="p", scope="r",
                 summary="sum", derived_from="d", verifiability="MACHINE_CHECKABLE",
                 falsifiable_by=("test",), critical_class=None)


def _ev(eid, tier, stance, identity="juror-1", family="fam"):
    return EvidenceItem(
        evidence_id=eid, claim_id="c1", evidence_class="JURY_OPINION", tier=tier,
        producer={"kind": "watcher" if tier != "W2" else "jury",
                  "identity": identity, "version": "0", "family": family},
        artifact_ref="d",
        reproducibility={"deterministic": tier in ("W1a", "W1b"), "rerun_recipe": None},
        stance=stance, confidence=0.8)


def _actor():
    return ActorRef(kind="adjudicator", identity="veridict-ladder", version="0.2.0")


def test_w1a_contradiction_discounts_doctrine():
    led = Ledger()
    evs = [_ev("m1", "W1a", "SUPPORTS"), _ev("d1", "W2", "REFUTES", identity="juror-1")]
    entries = update_calibration(led, _actor(), [_claim()], {"c1": evs})
    assert len(entries) == 1 and entries[0]["payload"]["delta"] == -0.1
    assert calibration_factor(led, "juror-1") == 0.9


def test_factor_floors_at_half():
    led = Ledger()
    for i in range(10):
        update_calibration(led, _actor(), [_claim()],
                           {"c1": [_ev(f"m{i}", "W1a", "SUPPORTS"),
                                   _ev(f"d{i}", "W2", "REFUTES", identity="j")]})
    assert calibration_factor(led, "j") == 0.5


def test_rehabilitation_raises_factor():
    led = Ledger()
    update_calibration(led, _actor(), [_claim()],
                       {"c1": [_ev("m1", "W1a", "SUPPORTS"),
                               _ev("d1", "W2", "REFUTES", identity="j")]})
    update_calibration(led, _actor(), [_claim()],
                       {"c1": [_ev("m2", "W1a", "SUPPORTS"),
                               _ev("d2", "W2", "SUPPORTS", identity="j")]})
    assert calibration_factor(led, "j") == 0.95    # -0.1 then +0.05


def test_no_w1a_no_updates():
    led = Ledger()
    assert update_calibration(led, _actor(), [_claim()],
                              {"c1": [_ev("d1", "W2", "REFUTES")]}) == []
    assert calibration_factor(led, "juror-1") == 1.0


def test_unknown_identity_neutral():
    assert calibration_factor(Ledger(), "nobody") == 1.0


def _task(tmp_path):
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "test_calc.py").write_text(
        "from calc import add\n\ndef test_add():\n    assert add(1, 1) == 2\n")
    return TaskManifest(task_id="tw", artifact_path=str(tmp_path),
                        actor_identity="ai-dev", intent_lines=(), criticality=(),
                        has_existing_tests=True, pytest_args=())


def _orch(ledger):
    # Scratch keystore ledger (existing test style): keeps the audit ledger's
    # entry types clean of key.enrolled noise.
    ks = KeyStore(Ledger())
    kid = ks.generate_and_enroll("core")
    jury = Jury([ScriptedProvider(family="a", identity="a-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok")),
                 ScriptedProvider(family="b", identity="b-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok"))])
    pol = PolicyDeclaration(policy_id="pw", mode="GATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    return AuditOrchestrator(ledger, pol, jury, ks, kid)


def test_factor_discounts_recorded_jury_confidence(tmp_path):
    # seed: a-1 previously contradicted W1a machine evidence
    # (evidence_by_claim is keyed by claim_id — same shape the orchestrator passes)
    led = Ledger()
    update_calibration(led, _actor(), [_claim()],
                       {"c1": [_ev("m0", "W1a", "SUPPORTS"),
                               _ev("d0", "W2", "REFUTES", identity="a-1")]})
    assert calibration_factor(led, "a-1") == 0.9
    _orch(led).run(_task(tmp_path))                # helpers from test_audit_watchers
    rows = [e for e in led.entries if e["entry_type"] == "evidence.recorded"
            and e["payload"]["producer"].get("identity") == "a-1"]
    assert rows and all(abs(r["payload"]["confidence"] - 0.72) < 1e-9 for r in rows)
    assert all(r["payload"]["tier"] == "W2" for r in rows)      # tier untouched
    assert all(r["payload"]["stance"] == "SUPPORTS" for r in rows)  # stance untouched
    assert any(e["entry_type"] == "calibration.updated" for e in led.entries)  # this run re-discounts
