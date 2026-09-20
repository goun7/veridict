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

def test_inconclusive_machine_claim_flags_gate():
    led = Ledger()
    out = PolicyEngine(led).apply([_claim()], {"c1": [_ev(tier="W1b", stance="REFUTES")]},
                                  DECL, ActorRef(kind="system", identity="core", version="0"))
    assert out.blocked is True
    assert any(f.startswith("inconclusive-unresolved:") for f in out.flags)


def _mc_claim(cid, predicate, ver):
    """Claim is frozen — build with the right predicate directly."""
    return Claim(claim_id=cid, task_id="t", subject="intent", predicate=predicate,
                 scope="module", summary="x", derived_from=None, verifiability=ver,
                 falsifiable_by=("test_execution",), critical_class=None)


def test_meta_coverage_flag_does_not_block_gate(tmp_path):
    """D15's second half: a meta-coverage flag is advisory, not a verdict.

    The flag exists so a juror's refusal of its own coverage question stays
    visible. But a flag that blocks IS a verdict — and this one would hand
    the deciding vote to the dissenter §5.3 rule 2 refuses to honor. D15
    excluded meta-claims from `any_refuted` but left them in `flags`, and
    GATE/HYBRID block on any flag, so the exclusion only held in CERTIFICATE
    mode. Measured before the fix: 3/3 clean cases blocked under HYBRID with
    a jury that refutes everything.
    """
    led = Ledger()
    engine = PolicyEngine(led)
    dec = PolicyDeclaration(policy_id="p1", mode="HYBRID", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1/3)
    top = _mc_claim("top", "existing-test-suite-passes", "MACHINE_CHECKABLE")
    meta = _mc_claim("meta", "coverage-of-existing-test-suite-passes", "DOCTRINAL")
    # top-level SUPPORTS (W1a); the meta-claim gets a W2 REFUTES — a jury
    # refusing to answer its own coverage question
    r = engine.apply([top, meta], {"top": [_ev("top", "W1a", "SUPPORTS")],
                                  "meta": [_ev("meta", "W2", "REFUTES")]},
                     dec, ActorRef(kind="system", identity="a", version="1"))
    assert r.per_claim["top"]["value"] == "VERIFIED"
    assert not r.blocked, "a meta-coverage refusal must not block the gate"
    assert any(f.startswith("meta-coverage-unconfirmed:") for f in r.flags), \
        "the refusal must stay visible even though it does not decide"


def test_fail_closed_survives_the_d15_second_half(tmp_path):
    """The fix above must not widen the fail-closed hole: a refuted
    top-level machine claim still blocks, with no meta-claim involved."""
    led = Ledger()
    engine = PolicyEngine(led)
    dec = PolicyDeclaration(policy_id="p1", mode="HYBRID", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1/3)
    top = _mc_claim("top", "existing-test-suite-passes", "MACHINE_CHECKABLE")
    r = engine.apply([top], {"top": [_ev("top", "W1a", "REFUTES")]},
                     dec, ActorRef(kind="system", identity="a", version="1"))
    assert r.per_claim["top"]["value"] == "REFUTED"
    assert r.blocked, "a refuted top-level claim must still block the gate"
