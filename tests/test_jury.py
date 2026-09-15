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

def test_evidence_item_carries_opinion_rationale():
    items, _ = _jury().evaluate(CLAIM, "digest")
    assert [e.rationale for e in items] == ["looks fine", "agrees"]


def test_deliberate_without_revise_keeps_first_round_rationale():
    # A provider with no revise hook keeps its first-round OPINION — its
    # rationale is that same first-round opinion's rationale (already computed;
    # the revised item must not silently drop it).
    j = Jury([ScriptedProvider(family="a", identity="a-1",
                               default=Opinion("SUPPORTS", 0.8, "machine truth holds")),
              ScriptedProvider(family="b", identity="b-1",
                               default=Opinion("REFUTES", 0.9, "rounding drops cents"))])
    items, _ = j.evaluate(CLAIM, "digest")
    revised, _ = j.deliberate(CLAIM, "digest", items, 1 / 3)
    b = next(e for e in revised if e.producer["identity"] == "b-1")
    assert b.stance == "REFUTES" and b.rationale == "rounding drops cents"


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


# ---------------------------------------------------------------------------
# Self-preference guard (0.4.0): an AI from the audited author's own model
# family cannot rate the author's work (Zheng et al. arXiv:2306.05685
# self-enhancement; Watai et al. arXiv:2410.21819 self-preference).

def _jury3():
    return Jury([
        ScriptedProvider(family="famA", identity="a1",
                         default=Opinion("SUPPORTS", 0.9, "kin says ok")),
        ScriptedProvider(family="famB", identity="b1",
                         default=Opinion("SUPPORTS", 0.8, "independent")),
        ScriptedProvider(family="famC", identity="c1",
                         default=Opinion("SUPPORTS", 0.8, "independent")),
    ])

def test_author_family_juror_is_excluded_and_abstains():
    jury = Jury([
        ScriptedProvider(family="famA", identity="a1",
                         default=Opinion("SUPPORTS", 0.9, "kin says ok")),
        ScriptedProvider(family="famB", identity="b1",
                         default=Opinion("SUPPORTS", 0.8, "independent")),
        ScriptedProvider(family="famC", identity="c1",
                         default=Opinion("REFUTES", 0.8, "independent")),
    ], author_family="famA")
    items, abstained = jury.evaluate(CLAIM, "digest")
    assert {i.producer["identity"] for i in items} == {"b1", "c1"}
    assert abstained == ["a1 (self-preference: author family 'famA')"]

def test_exclusion_is_case_insensitive():
    jury = Jury([
        ScriptedProvider(family="FamA", identity="a1",
                         default=Opinion("SUPPORTS", 0.9, "x")),
        ScriptedProvider(family="famB", identity="b1",
                         default=Opinion("SUPPORTS", 0.8, "x")),
        ScriptedProvider(family="famC", identity="c1",
                         default=Opinion("SUPPORTS", 0.8, "x")),
    ], author_family="  faMA ")
    _, abstained = jury.evaluate(CLAIM, "digest")
    assert any(ab.startswith("a1 (self-preference") for ab in abstained)

def test_jury_fails_closed_when_author_family_would_gut_it():
    # Excluding the author's kin must never leave a single-family jury:
    # validation runs AFTER the filter.
    with pytest.raises(ValueError):
        Jury([
            ScriptedProvider(family="famA", identity="a1",
                             default=Opinion("SUPPORTS", 0.9, "x")),
            ScriptedProvider(family="famB", identity="b1",
                             default=Opinion("SUPPORTS", 0.8, "x")),
        ], author_family="famA")

def test_no_author_family_keeps_legacy_behavior():
    items, abstained = _jury3().evaluate(CLAIM, "digest")
    assert len(items) == 3 and abstained == []

def test_deliberation_cannot_revive_an_excluded_juror():
    jury = Jury([
        ScriptedProvider(family="famA", identity="a1",
                         default=Opinion("SUPPORTS", 0.9, "x")),
        ScriptedProvider(family="famB", identity="b1",
                         default=Opinion("SUPPORTS", 0.8, "x")),
        ScriptedProvider(family="famC", identity="c1",
                         default=Opinion("REFUTES", 0.9, "x")),
    ], author_family="famA")
    first, _ = jury.evaluate(CLAIM, "digest")
    revised, _abst = jury.deliberate(CLAIM, "digest", first, 1 / 3)
    assert {i.producer["identity"] for i in revised} == {"b1", "c1"}
