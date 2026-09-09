from veridict.schemas import (ActorRef, Claim, EvidenceItem, TaskManifest,
                              TIER_RANK, SCHEMA_VERSION)

def test_actor_ref_to_dict():
    a = ActorRef(kind="verifier", identity="test-executor", version="0.1.0")
    assert a.to_dict() == {"kind": "verifier", "identity": "test-executor", "version": "0.1.0"}

def test_claim_roundtrip():
    c = Claim(claim_id="c1", task_id="t1", subject="artifact", predicate="tests-pass",
              scope="repo", summary="existing tests pass", derived_from="digest",
              verifiability="MACHINE_CHECKABLE", falsifiable_by=("test_execution",),
              critical_class=None)
    d = c.to_dict()
    assert d["schema_version"] == SCHEMA_VERSION
    c2 = Claim.from_dict(d)
    assert c2 == c

def test_claim_is_frozen():
    import dataclasses, pytest
    c = Claim(claim_id="c", task_id="t", subject="s", predicate="p", scope="r",
              summary="m", derived_from="d", verifiability="DOCTRINAL",
              falsifiable_by=("jury",), critical_class=None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.status = "VERIFIED"

def test_evidence_item_shape():
    e = EvidenceItem(evidence_id="e1", claim_id="c1", evidence_class="TEST_EXECUTION",
                     tier="W1a", producer={"kind": "verifier", "identity": "test-executor",
                                           "version": "0.1.0"},
                     artifact_ref="digest", reproducibility={"deterministic": True,
                     "rerun_recipe": {"cmd": ["pytest"]}}, stance="SUPPORTS", confidence=1.0)
    assert e.tier == "W1a" and e.stance == "SUPPORTS"

def test_tier_rank_strict_order():
    assert TIER_RANK["W1a"] > TIER_RANK["W1b"] > TIER_RANK["W2"] > TIER_RANK["W3"]

def test_task_manifest_holds_intent():
    t = TaskManifest(task_id="t1", artifact_path=".", actor_identity="ai-dev",
                     intent_lines=("MACHINE: existing tests pass",),
                     criticality=("payments",), has_existing_tests=True,
                     pytest_args=())
    assert t.actor_identity == "ai-dev"
