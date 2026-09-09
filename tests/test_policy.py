import json
from veridict.policy import (PolicyEngine, PolicyDeclaration, Thresholds, load_policy)
from veridict.ledger import Ledger
from veridict.schemas import ActorRef, Claim, EvidenceItem

def _claim(cid="c1", ver="MACHINE_CHECKABLE"):
    return Claim(claim_id=cid, task_id="t", subject="s", predicate="p", scope="r",
                 summary="x", derived_from="d", verifiability=ver,
                 falsifiable_by=("test_execution",), critical_class="payments")

def _ev(cid="c1", tier="W1a", stance="SUPPORTS"):
    return EvidenceItem(evidence_id=f"e-{cid}-{tier}-{stance}", claim_id=cid,
                        evidence_class="TEST_EXECUTION" if tier.startswith("W1") else "JURY_OPINION",
                        tier=tier, producer={"kind": "verifier", "identity": "v",
                                             "version": "0.1.0"},
                        artifact_ref="d", reproducibility={"deterministic": True,
                        "rerun_recipe": {"cmd": ["pytest"]}}, stance=stance, confidence=1.0)

DECL = PolicyDeclaration(policy_id="p1", mode="GATE", criticality=("payments",),
                         thresholds=Thresholds(), divergence_tolerance=1/3)

def test_gate_blocks_on_critical_refuted():
    led = Ledger()
    out = PolicyEngine(led).apply([_claim()], {"c1": [_ev(stance="REFUTES")]}, DECL,
                                  ActorRef(kind="system", identity="core", version="0"))
    assert out.blocked is True and out.mode == "GATE"
    kinds = [e["payload"]["decision_kind"] for e in led.query("policy.decision")]
    assert kinds == ["gate.blocked"]

def test_gate_blocks_on_low_coverage():
    led = Ledger()
    out = PolicyEngine(led).apply([_claim()], {"c1": []}, DECL,
                                  ActorRef(kind="system", identity="core", version="0"))
    assert out.blocked and out.coverage == 0.0

def test_watch_never_blocks_but_records():
    led = Ledger()
    decl = PolicyDeclaration(policy_id="p2", mode="WATCH", criticality=("payments",),
                             thresholds=Thresholds(), divergence_tolerance=1/3)
    out = PolicyEngine(led).apply([_claim()], {"c1": [_ev(stance="REFUTES")]}, decl,
                                  ActorRef(kind="system", identity="core", version="0"))
    assert out.blocked is False and out.mode == "WATCH"
    kinds = [e["payload"]["decision_kind"] for e in led.query("policy.decision")]
    assert kinds == ["watch.observed"]

def test_policy_is_data_decision_recorded_with_digest():
    led = Ledger()
    PolicyEngine(led).apply([_claim()], {"c1": [_ev()]}, DECL,
                            ActorRef(kind="system", identity="core", version="0"))
    e = led.query("policy.decision")[0]
    assert e["payload"]["policy_digest"] and e["payload"]["policy_id"] == "p1"

def test_load_policy_from_json_roundtrip(tmp_path):
    d = DECL.to_dict()
    p = tmp_path / "pol.json"
    p.write_text(json.dumps(d))
    decl = load_policy(str(p))
    assert decl == DECL

def test_hybrid_blocks_like_gate():
    led = Ledger()
    decl = PolicyDeclaration(policy_id="p3", mode="HYBRID", criticality=("payments",),
                             thresholds=Thresholds(), divergence_tolerance=1/3)
    out = PolicyEngine(led).apply([_claim()], {"c1": [_ev(stance="REFUTES")]}, decl,
                                  ActorRef(kind="system", identity="core", version="0"))
    assert out.blocked is True
