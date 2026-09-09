import pytest
from veridict.claim_extractor import ClaimExtractor
from veridict.jury import Jury, Opinion, ScriptedProvider, ProviderError
from veridict.schemas import TaskManifest

CLAIM = ClaimExtractor().extract(
    TaskManifest(task_id="t", artifact_path=".", actor_identity="a",
                 intent_lines=("DOCTRINE: api usage is idiomatic",), criticality=(),
                 has_existing_tests=False, pytest_args=()), "d")[0]

def _jury(fam_a="stub-a", op_a="SUPPORTS", fam_b="stub-b", op_b="SUPPORTS"):
    return Jury([
        ScriptedProvider(family=fam_a, identity=f"{fam_a}-1",
                         default=Opinion(op_a, 0.8, "looks fine")),
        ScriptedProvider(family=fam_b, identity=f"{fam_b}-1",
                         default=Opinion(op_b, 0.8, "agrees")),
    ])

def test_requires_two_distinct_families():
    with pytest.raises(ValueError):
        _jury(fam_a="same", fam_b="same")

def test_evaluate_produces_blind_w2_evidence():
    items, abstained = _jury().evaluate(CLAIM, "digest")
    assert abstained == []
    assert len(items) == 2
    assert all(e.tier == "W2" and e.evidence_class == "JURY_OPINION"
               and e.stance == "SUPPORTS" for e in items)
    assert {e.producer["family"] for e in items} == {"stub-a", "stub-b"}
    assert all(e.reproducibility["deterministic"] is False for e in items)

def test_provider_error_is_recorded_as_abstain_not_evidence():
    class Boom(ScriptedProvider):
        def doctrine(self, claim_summary, artifact_digest):
            raise ProviderError("simulated outage")
    j = Jury([Boom(family="boom", identity="boom-1",
                   default=Opinion("SUPPORTS", 0.5, "")),
              ScriptedProvider(family="stub-b", identity="stub-b-1",
                               default=Opinion("SUPPORTS", 0.8, ""))])
    items, abstained = j.evaluate(CLAIM, "digest")
    assert items and len(items) == 1          # only the healthy provider
    assert abstained == ["boom-1"]            # abstention reported, never evidence

def test_blindness_providers_receive_no_cross_context():
    seen = []
    class Recorder(ScriptedProvider):
        def doctrine(self, claim_summary, artifact_digest):
            seen.append(claim_summary)
            return super().doctrine(claim_summary, artifact_digest)
    rec = Recorder(family="rec", identity="rec-1", default=Opinion("SUPPORTS", 0.8, ""))
    j = Jury([rec, ScriptedProvider(family="stub-b", identity="stub-b-1",
                                    default=Opinion("SUPPORTS", 0.8, ""))])
    j.evaluate(CLAIM, "digest")
    assert len(seen) == 1
    assert "other opinions" not in seen[0]
