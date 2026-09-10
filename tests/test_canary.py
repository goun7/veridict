import json

from veridict.canary import CanaryRunner, build_orchestrator
from veridict.jury import Opinion
from veridict.policy import PolicyDeclaration, Thresholds


def _pol():
    return PolicyDeclaration(policy_id="canary-gate", mode="GATE", criticality=(),
                             thresholds=Thresholds(), divergence_tolerance=1 / 3)


def _audit_fn():
    refutable = {"add computes the sum of two numbers",
                 "divide never crashes on zero denominator",
                 "sum_to sums 1..n inclusive",
                 "top_scores returns scores sorted descending",
                 "set_age rejects ages outside 0..130"}
    overrides = {
        "stub-a": lambda summary: Opinion("REFUTES", 0.9, "defect spotted")
        if summary in refutable else Opinion("SUPPORTS", 0.8, "ok"),
        "stub-b": lambda summary: Opinion("SUPPORTS", 0.8, "ok"),
    }

    def audit_fn(task, disclosure):
        return build_orchestrator(
            _pol(), provider_overrides=overrides).run(task, disclosure)

    return audit_fn


def test_quality_sheet_counts_catches_and_false_positives():
    sheet = CanaryRunner(_audit_fn()).run("corpus/corpus.jsonl")
    by_id = {c["id"]: c["caught"] for c in sheet["cases"]}
    assert by_id["canary-sign-error"] is True
    assert by_id["canary-uncovered-edge"] is True
    assert by_id["canary-uncovered-edge-uncatchable"] is False   # honest miss
    assert by_id["canary-clean"] is False                        # no false positive
    assert by_id["canary-off-by-one"] is True
    assert by_id["canary-contract-violation"] is True
    assert by_id["canary-missing-validation"] is True
    assert by_id["canary-clean-normalize"] is False              # no false positive
    assert by_id["canary-parse-date-miss"] is False              # honest miss
    assert sheet["per_class"]["uncovered-edge"] == {"caught": 1, "total": 2}
    assert sheet["per_class"]["logic-error"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["contract-violation"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["missing-validation"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["parse-date"] == {"caught": 0, "total": 1}
    assert sheet["false_positives"] == 0
    assert sheet["caught_total"] == 5


def test_quality_sheet_persists(tmp_path):
    sheet = CanaryRunner(_audit_fn()).run("corpus/corpus.jsonl")
    out = tmp_path / "sheet.json"
    out.write_text(json.dumps(sheet))
    assert json.loads(out.read_text())["caught_total"] == 5
