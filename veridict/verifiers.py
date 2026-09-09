"""Built-in verifiers (§5.1): TestExecutor (W1a), StaticAnalyzer (W1b).

Both return None on abstain — no evidence item is produced (§5.4).
Every W1a item carries a rerun_recipe (§5.1 invariant).
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys

from .schemas import ActorRef, Claim, EvidenceItem, TaskManifest
from .utils import iter_python_files

TEST_ACTOR = ActorRef(kind="verifier", identity="test-executor", version="0.1.0")
STATIC_ACTOR = ActorRef(kind="verifier", identity="static-analyzer", version="0.1.0")
EID_SALT = "veridict-evidence-v1"


class TestExecutorVerifier:
    def produce(self, claim: Claim, task: TaskManifest,
                timeout_seconds: int = 600) -> EvidenceItem | None:
        if "test_execution" not in claim.falsifiable_by:
            return None
        cmd = [sys.executable, "-m", "pytest", "-q", "--tb=no",
               *task.pytest_args]
        recipe = {"cmd": cmd, "cwd": task.artifact_path,
                  "timeout_seconds": timeout_seconds}
        try:
            proc = subprocess.run(cmd, cwd=task.artifact_path, timeout=timeout_seconds,
                                  capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            return None
        if proc.returncode in (2, 3, 4, 5):   # usage/internal/no-tests → abstain
            return None
        stance = "SUPPORTS" if proc.returncode == 0 else "REFUTES"
        return EvidenceItem(
            evidence_id=f"{EID_SALT}-" + claim.claim_id + "-testexec",
            claim_id=claim.claim_id, evidence_class="TEST_EXECUTION", tier="W1a",
            producer=TEST_ACTOR.to_dict(), artifact_ref=claim.derived_from,
            reproducibility={"deterministic": True, "rerun_recipe": recipe},
            stance=stance, confidence=1.0)


FORBIDDEN_CALLS = {"eval", "exec", "compile"}


class StaticAnalyzerVerifier:
    """AST rules v0 (W1b statistical signal, §5.1 #3): bare-except, eval/exec/compile."""

    def produce(self, claim: Claim, task: TaskManifest,
                timeout_seconds: int = 120) -> EvidenceItem | None:
        if "static_analysis" not in claim.falsifiable_by:
            return None
        findings: list[str] = []
        for rel in iter_python_files(task.artifact_path):
            path = os.path.join(task.artifact_path, rel)
            try:
                with open(path, encoding="utf-8") as fh:
                    source = fh.read()
                tree = ast.parse(source, filename=rel)
            except SyntaxError as exc:
                findings.append(f"syntax-error:{rel}:{exc.lineno}")
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    findings.append(f"bare-except:{rel}:{node.lineno}")
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id in FORBIDDEN_CALLS):
                    findings.append(f"forbidden-call:{rel}:{node.lineno}:{node.func.id}")
        stance = "REFUTES" if findings else "SUPPORTS"
        recipe = {"cmd": [sys.executable, "-m", "veridict.cli", "audit",
                          "--task", "<task.json>", "--mode", "CERTIFICATE"],
                  "cwd": task.artifact_path, "timeout_seconds": timeout_seconds}
        return EvidenceItem(
            evidence_id=f"{EID_SALT}-" + claim.claim_id + "-static",
            claim_id=claim.claim_id, evidence_class="STATIC_ANALYSIS", tier="W1b",
            producer=STATIC_ACTOR.to_dict(), artifact_ref=claim.derived_from,
            reproducibility={"deterministic": False, "rerun_recipe": recipe},
            stance=stance, confidence=0.9 if stance == "REFUTES" else 0.7)
