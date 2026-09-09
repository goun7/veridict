from veridict.divergence import compute_divergence
from veridict.ladder import adjudicate
from veridict.schemas import Claim, EvidenceItem

class StubPolicy:
    mode = "CERTIFICATE"
    criticality = ("payments",)
    meta_claim_depth_budget = 2
    divergence_tolerance = 1 / 3

def _claim(ver="MACHINE_CHECKABLE", crit="payments", pred="x-equals-y"):
    return Claim(claim_id="c1", task_id="t1", subject="s", predicate=pred, scope="r",
                 summary="x equals y", derived_from="digest", verifiability=ver,
                 falsifiable_by=("test_execution",), critical_class=crit)

def _ev(tier, stance, n=1):
    return [EvidenceItem(evidence_id=f"e{i}-{tier}-{stance}", claim_id="c1",
                         evidence_class="TEST_EXECUTION" if tier.startswith("W1") else "JURY_OPINION",
                         tier=tier, producer={"kind": "verifier", "identity": f"v{i}",
                                              "version": "0.1.0"},
                         artifact_ref="digest", reproducibility={"deterministic": True,
                         "rerun_recipe": {"cmd": ["pytest"]}}, stance=stance, confidence=1.0)
            for i in range(n)]

def test_r0_machine_supported_by_w1a():
    a = adjudicate(_claim(), _ev("W1a", "SUPPORTS", 2), StubPolicy())
    assert a.value == "VERIFIED" and a.rung == "R0" and a.meta_claims

def test_r1_doctrine_cannot_overturn_w1a():
    ev = _ev("W1a", "SUPPORTS", 1) + _ev("W2", "REFUTES", 1) + _ev("W2", "REFUTES", 1)
    a = adjudicate(_claim(), ev, StubPolicy())
    assert a.value == "VERIFIED" and a.rung == "R1"
    assert any("cannot overturn" in n for n in a.risk_notes)

def test_r2_w1b_refute_opens_meta_claim_not_refutation():
    ev = _ev("W1a", "SUPPORTS", 2) + _ev("W1b", "REFUTES", 1)
    a = adjudicate(_claim(crit="payments"), ev, StubPolicy())
    assert a.value == "VERIFIED" and a.rung == "R2"
    assert a.meta_claims and a.meta_claims[0]["subject"].startswith("coverage-of:")

def test_r3_critical_split_escalates():
    ev = _ev("W2", "SUPPORTS", 2) + _ev("W2", "REFUTES", 2)
    a = adjudicate(_claim(crit="payments"), ev, StubPolicy())
    assert a.value == "ESCALATED" and a.rung == "R3"

def test_r4_no_evidence_is_never_silent_pass():
    a = adjudicate(_claim(), [], StubPolicy())
    assert a.value == "INCONCLUSIVE" and a.rung == "R4"
    assert any("no evidence" in n for n in a.risk_notes)
