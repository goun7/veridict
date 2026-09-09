import pytest
from veridict.claim_extractor import ClaimExtractor
from veridict.schemas import TaskManifest

def _task(intent=(), crit=(), has_tests=True):
    return TaskManifest(task_id="t1", artifact_path=".", actor_identity="ai-dev",
                        intent_lines=tuple(intent), criticality=tuple(crit),
                        has_existing_tests=has_tests, pytest_args=())

def test_machine_and_doctrine_lines_parsed():
    claims = ClaimExtractor().extract(
        _task(["MACHINE: refund equals subtotal",
               "MACHINE(payments): invoice total is stable",
               "DOCTRINE: api usage is idiomatic"]), "digest")
    ver = {c.predicate: c.verifiability for c in claims}
    assert ver["refund-equals-subtotal"] == "MACHINE_CHECKABLE"
    assert ver["invoice-total-is-stable"] == "MACHINE_CHECKABLE"
    assert ver["api-usage-is-idiomatic"] == "DOCTRINAL"

def test_critical_class_attached():
    claims = ClaimExtractor().extract(
        _task(["MACHINE(payments): invoice total is stable"], crit=("payments",)), "digest")
    c = next(c for c in claims if c.predicate == "invoice-total-is-stable")
    assert c.critical_class == "payments"

def test_auto_claims_present():
    claims = ClaimExtractor().extract(_task(), "digest")
    preds = {c.predicate for c in claims}
    assert "existing-test-suite-passes" in preds
    assert "forbidden-constructs-absent" in preds

def test_auto_claim_verifiability_and_falsifiers():
    claims = ClaimExtractor().extract(_task(), "digest")
    by = {c.predicate: c for c in claims}
    assert by["existing-test-suite-passes"].falsifiable_by == ("test_execution",)
    assert by["forbidden-constructs-absent"].falsifiable_by == ("static_analysis",)
    assert all(c.verifiability == "MACHINE_CHECKABLE"
               for c in (by["existing-test-suite-passes"],
                         by["forbidden-constructs-absent"]))

def test_claim_ids_deterministic():
    a = ClaimExtractor().extract(_task(["MACHINE: x equals y"]), "digest")
    b = ClaimExtractor().extract(_task(["MACHINE: x equals y"]), "digest")
    assert [c.claim_id for c in a] == [c.claim_id for c in b]

def test_invalid_line_raises():
    with pytest.raises(ValueError):
        ClaimExtractor().extract(_task(["FREEFORM: no tag"]), "digest")
