from veridict.divergence import compute_divergence
from veridict.schemas import EvidenceItem

def _ev(tier, stance, n=1, family="fam"):
    out = []
    for i in range(n):
        out.append(EvidenceItem(
            evidence_id=f"e-{tier}-{stance}-{i}", claim_id="c1",
            evidence_class="JURY_OPINION", tier=tier,
            producer={"kind": "jury", "identity": f"{family}-{i}",
                      "version": "0.1.0", "family": family},
            artifact_ref="d", reproducibility={"deterministic": False,
            "rerun_recipe": None}, stance=stance, confidence=0.9))
    return out

def test_no_doctrinal_evidence_is_unanimous():
    assert compute_divergence(_ev("W1a", "SUPPORTS", 2)) == "UNANIMOUS"

def test_all_same_is_unanimous():
    ev = _ev("W2", "SUPPORTS", 3)
    assert compute_divergence(ev) == "UNANIMOUS"

def test_minority_within_tolerance_is_majority():
    ev = _ev("W2", "SUPPORTS", 2) + _ev("W2", "REFUTES", 1, family="g")
    assert compute_divergence(ev) == "MAJORITY"

def test_even_split_is_split():
    ev = _ev("W2", "SUPPORTS", 1) + _ev("W2", "REFUTES", 1, family="g")
    assert compute_divergence(ev) == "SPLIT"
