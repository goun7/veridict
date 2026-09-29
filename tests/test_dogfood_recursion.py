"""Anti-recursion + hard-budget contract for dogfood() (v0.3 fix).

dogfood() uses the repository's own pytest suite as its W1a evidence, and
tests/test_dogfood.py exercises dogfood() — so a nested run that collected
test_dogfood.py re-entered the audit while it ran, and tests/test_canary.py
replayed the full 25-case canary corpus inside it. dogfood() now ignores
both files in its nested pytest run by default, and runs its whole audit in
a worker subprocess under a hard wall-clock budget: exceeding it fails
CLOSED (blocked=True, no certificate reissued) instead of hanging (§6).

Guard hygiene: VERIDICT_DOGFOOD_ACTIVE is set while dogfood() runs, and this
file is itself collected by the nested suite — scrub it before every call.
"""
import os
import time

from scripts.dogfood import (
    DEFAULT_EXCLUDE,
    DOGFOOD_TIMEOUT_SECONDS,
    _ignore_args,
    _main_task,
    dogfood,
)

CALC = "def add(a, b):\n    return a + b\n"
CALC_TEST = ("from calc import add\n\n\n"
             "def test_add():\n    assert add(1, 1) == 2\n")


def _scrub_guard(monkeypatch) -> None:
    monkeypatch.delenv("VERIDICT_DOGFOOD_ACTIVE", raising=False)


def test_default_exclude_and_budget_pin_the_contract():
    # v0.3.1: the slow CLI e2e (replays the canary corpus through the CLI,
    # ~141 s alone) is excluded too — the W1a claim is about the core audit
    # modules and outer CI already covers that CLI path. The remaining nested
    # run measures 300-342 s, so the budget is 420 s with headroom.
    assert set(DEFAULT_EXCLUDE) == {
        "tests/test_dogfood.py",
        "tests/test_canary.py",
        "tests/test_cli.py::test_quality_sheet_reports_stub_jury_context",
    }
    assert DOGFOOD_TIMEOUT_SECONDS == 420


def test_nested_pytest_command_ignores_self_and_canary():
    # TestExecutorVerifier builds the nested command as
    # [python, -m, pytest, -q, --tb=no, *task.pytest_args] — the task's
    # pytest_args ARE the nested collection, so pinning them pins what the
    # audit re-runs: never itself, never the canary corpus.
    args = _ignore_args(DEFAULT_EXCLUDE)
    assert "--ignore=tests/test_dogfood.py" in args
    assert "--ignore=tests/test_canary.py" in args
    task = _main_task("/does/not/matter", DEFAULT_EXCLUDE)
    assert task.pytest_args == args


def test_hard_timeout_fails_closed(tmp_path, monkeypatch):
    _scrub_guard(monkeypatch)
    out = dogfood(run_root=str(tmp_path), timeout_seconds=2)
    assert out["timeout"] is True
    assert out["outcome"].blocked is True          # fail-closed, never hang-open
    assert out["verification"]["valid"] is False
    assert out["verification"]["errors"]
    # a fail-closed run must not leave a half-written certificate behind
    assert not os.path.exists(out["cert_path"])


def test_hard_timeout_returns_promptly(tmp_path, monkeypatch):
    _scrub_guard(monkeypatch)
    started = time.time()
    out = dogfood(run_root=str(tmp_path), timeout_seconds=3)
    assert out["outcome"].blocked is True
    # the process-group kill returns control well under any sane budget
    assert time.time() - started < 90


def test_dogfood_completes_under_budget_on_a_tiny_artifact(tmp_path, monkeypatch):
    _scrub_guard(monkeypatch)
    (tmp_path / "calc.py").write_text(CALC)
    (tmp_path / "test_calc.py").write_text(CALC_TEST)
    started = time.time()
    out = dogfood(run_root=str(tmp_path))          # the default 420 s budget
    assert time.time() - started < DOGFOOD_TIMEOUT_SECONDS
    assert out["timeout"] is False
    assert out["outcome"].blocked is False
    assert out["verification"]["valid"] is True, out["verification"]["errors"]
    assert os.path.exists(out["ledger_path"])
    assert os.path.exists(out["cert_path"])
    assert os.path.exists(out["index_path"])
