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
                 "set_age rejects ages outside 0..130",
                 "increment is safe under concurrent callers",
                 "read_config closes the file handle it opens",
                 "find_user never interpolates raw input into SQL",
                 "parse_strict never ignores malformed input",
                 "no hardcoded credentials are present",
                 # L2-2 security expansion (2026-09-16): 7 new defect classes.
                 # Intent lines are the MACHINE evidence the audit_fn must
                 # refute; each ships with its own artifact + test.
                 "parse_count clamps to the documented 1..1000 range",
                 "read_report rejects names that escape base_dir",
                 "load_profile rejects pickle on untrusted input",
                 "safe_compare is constant-time (no short-circuit)",
                 "make_token uses a cryptographically secure generator",
                 "get_cached closes the check-then-use race",
                 "login failure paths return one indistinguishable reason"}
    # deliberately NOT refutable: hash_password (crypto-misuse honest miss),
    # parse_iso_utc (offset-stomp honest miss), and both clean summaries
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
    assert by_id["canary-race-condition"] is True
    assert by_id["canary-resource-leak"] is True
    assert by_id["canary-sql-injection"] is True
    assert by_id["canary-exception-swallowing"] is True
    assert by_id["canary-crypto-misuse"] is False                # honest miss
    assert by_id["canary-clean-uuid"] is False                   # no false positive
    assert by_id["canary-secrets-leak"] is True
    # L2-2 security expansion — all 7 new classes are caught
    assert by_id["canary-integer-overflow"] is True
    assert by_id["canary-path-traversal"] is True
    assert by_id["canary-insecure-deserialization"] is True
    assert by_id["canary-timing-attack"] is True
    assert by_id["canary-weak-random"] is True
    assert by_id["canary-toctou"] is True
    assert by_id["canary-error-message-leak"] is True
    assert sheet["per_class"]["uncovered-edge"] == {"caught": 1, "total": 2}
    assert sheet["per_class"]["logic-error"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["contract-violation"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["missing-validation"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["parse-date"] == {"caught": 0, "total": 1}
    assert sheet["false_positives"] == 0
    assert sheet["per_class"]["race-condition"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["crypto-misuse"] == {"caught": 0, "total": 1}
    assert sheet["per_class"]["secrets-leak"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["integer-overflow"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["path-traversal"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["insecure-deserialization"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["timing-attack"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["weak-random"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["toctou"] == {"caught": 1, "total": 1}
    assert sheet["per_class"]["error-message-leak"] == {"caught": 1, "total": 1}
    assert sheet["caught_total"] == 17


def test_quality_sheet_persists(tmp_path):
    sheet = CanaryRunner(_audit_fn()).run("corpus/corpus.jsonl")
    out = tmp_path / "sheet.json"
    out.write_text(json.dumps(sheet))
    assert json.loads(out.read_text())["caught_total"] == 17
