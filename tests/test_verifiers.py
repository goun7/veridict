import subprocess, sys
from veridict.claim_extractor import ClaimExtractor
from veridict.schemas import TaskManifest
from veridict.verifiers import TestExecutorVerifier, StaticAnalyzerVerifier

def _task(tmp_path, code, test_code):
    (tmp_path / "calc.py").write_text(code)
    (tmp_path / "test_calc.py").write_text(test_code)
    return TaskManifest(task_id="t", artifact_path=str(tmp_path),
                        actor_identity="ai-dev", intent_lines=(), criticality=(),
                        has_existing_tests=True, pytest_args=())

def _claims(task, digest="d"):
    return {c.predicate: c for c in ClaimExtractor().extract(task, digest)}

def test_executor_supports_passing_suite(tmp_path):
    task = _task(tmp_path, "def add(a, b):\n    return a + b\n",
                 "from calc import add\ndef test_add():\n    assert add(1, 1) == 2\n")
    ev = TestExecutorVerifier().produce(_claims(task)["existing-test-suite-passes"], task)
    assert ev is not None
    assert ev.tier == "W1a" and ev.stance == "SUPPORTS" and ev.confidence == 1.0
    assert ev.evidence_class == "TEST_EXECUTION"
    assert ev.reproducibility["deterministic"] is True
    assert ev.reproducibility["rerun_recipe"]["cmd"]

def test_executor_refutes_failing_suite(tmp_path):
    task = _task(tmp_path, "def add(a, b):\n    return a - b\n",
                 "from calc import add\ndef test_add():\n    assert add(1, 1) == 2\n")
    ev = TestExecutorVerifier().produce(_claims(task)["existing-test-suite-passes"], task)
    assert ev.tier == "W1a" and ev.stance == "REFUTES"

def test_executor_abstains_on_wrong_claim(tmp_path):
    task = _task(tmp_path, "def add(a, b):\n    return a + b\n",
                 "from calc import add\ndef test_add():\n    assert add(1, 1) == 2\n")
    ev = TestExecutorVerifier().produce(_claims(task)["forbidden-constructs-absent"], task)
    assert ev is None  # abstain — claim not falsifiable by test_execution

def test_static_refutes_bare_except_and_eval(tmp_path):
    task = _task(tmp_path, "def f(x):\n    try:\n        eval(x)\n    except:\n        pass\n",
                 "def test_f():\n    assert f('1+1') == 2\n")
    ev = StaticAnalyzerVerifier().produce(_claims(task)["forbidden-constructs-absent"], task)
    assert ev.tier == "W1b" and ev.stance == "REFUTES"
    assert ev.reproducibility["rerun_recipe"] is not None

def test_static_supports_clean_artifact(tmp_path):
    task = _task(tmp_path, "def add(a, b):\n    return a + b\n",
                 "def test_add():\n    assert add(1, 1) == 2\n")
    ev = StaticAnalyzerVerifier().produce(_claims(task)["forbidden-constructs-absent"], task)
    assert ev.tier == "W1b" and ev.stance == "SUPPORTS"

def test_executor_rationale_records_exit_code(tmp_path):
    task = _task(tmp_path, "def add(a, b):\n    return a - b\n",
                 "from calc import add\ndef test_add():\n    assert add(1, 1) == 2\n")
    ev = TestExecutorVerifier().produce(_claims(task)["existing-test-suite-passes"], task)
    assert "exit code 1" in ev.rationale

def test_static_rationale_carries_findings(tmp_path):
    task = _task(tmp_path, "def f(x):\n    try:\n        eval(x)\n    except:\n        pass\n",
                 "def test_f():\n    assert f('1+1') == 2\n")
    ev = StaticAnalyzerVerifier().produce(_claims(task)["forbidden-constructs-absent"], task)
    assert "forbidden-call" in ev.rationale and "bare-except" in ev.rationale


def test_static_analyzer_ignores_hidden_dirs(tmp_path):
    """Errata D9: a non-hidden venv inside the artifact (.venv312 etc.) used
    to be walked — third-party eval/exec findings then REFUTES'd the claim
    and the fail-closed gate blocked the release. The walk now skips every
    dotted directory; the venv's forbidden calls are invisible."""
    import hashlib
    from veridict.claim_extractor import ClaimExtractor
    from veridict.schemas import TaskManifest
    from veridict.verifiers import StaticAnalyzerVerifier

    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    venv = tmp_path / ".venv312"
    (venv / "lib" / "site-packages").mkdir(parents=True)
    (venv / "lib" / "site-packages" / "evil.py").write_text(
        "def boom(x):\n    return eval(x)   # third-party code — NOT our artifact\n")
    task = TaskManifest(task_id="d9", artifact_path=str(tmp_path),
                        actor_identity="ai-dev", intent_lines=(),
                        criticality=(), has_existing_tests=False, pytest_args=())
    claim = next(c for c in ClaimExtractor().extract(task, "d9")
                 if c.predicate == "forbidden-constructs-absent")
    item = StaticAnalyzerVerifier().produce(claim, task)
    assert item is not None and item.stance == "SUPPORTS", item.rationale
    # and a REAL forbidden call at the top level is still caught
    (tmp_path / "oops.py").write_text("def go(s):\n    return eval(s)\n")
    item = StaticAnalyzerVerifier().produce(claim, task)
    assert item.stance == "REFUTES" and "oops.py" in item.rationale
