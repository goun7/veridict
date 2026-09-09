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
