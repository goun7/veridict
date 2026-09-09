"""Example security watcher — a THIRD-PARTY producer living outside the core.

This module is the platform-gate proof (§5.3): the core has no special-case
for it; it participates purely through a signed manifest + a blind session.
"""
import ast
import hashlib
import os
import re

from veridict.utils import iter_python_files
from veridict.watchers import WatcherManifest, WatcherSession

_CODE_HASH = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()

MANIFEST = WatcherManifest(
    watcher_id="example-security",
    name="Example Security Watcher",
    version="0.1.0",
    producer={"identity": "example-security", "maintainer": "veridict-examples"},
    capabilities={"evidence_classes": ("STATIC_ANALYSIS",), "max_tier": "W1b",
                  "subscribes_to": ("payments", "security")},
    resource_class={"timeout_seconds": 60, "cost_budget": 0.0,
                    "sandbox_level": "inprocess"},
    integrity={"code_hash": _CODE_HASH, "update_policy": "manual"})

SECRET_RE = re.compile(r"(api_key|password|secret)\s*=\s*[\"'][^\"']{8,}",
                       re.IGNORECASE)
_SENSITIVE_MODULES = ("subprocess", "pickle", "yaml")


def _import_roots(tree: ast.AST) -> dict[str, str]:
    """Local name -> real module, for the modules this doctrine watches."""
    roots: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _SENSITIVE_MODULES:
                    roots[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module in _SENSITIVE_MODULES:
            for alias in node.names:
                roots[alias.asname or alias.name] = node.module
    return roots


def _call_root(call: ast.Call, roots: dict[str, str]) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return roots.get(func.id)                    # `from subprocess import run`
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return roots.get(func.value.id)              # `subprocess.run(...)`
    return None


def _scan_ast(tree: ast.AST, rel: str) -> list[str]:
    findings: list[str] = []
    roots = _import_roots(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        root = _call_root(node, roots)
        if root is None:
            continue
        tail = (node.func.attr if isinstance(node.func, ast.Attribute)
                else node.func.id if isinstance(node.func, ast.Name) else "")
        kws = {k.arg: k.value for k in node.keywords if k.arg}
        shell_true = (isinstance(kws.get("shell"), ast.Constant)
                      and kws["shell"].value is True)
        if root == "subprocess" and shell_true:
            findings.append(f"{rel}:{node.lineno}: subprocess call with shell=True")
        elif root == "pickle" and tail == "loads":
            findings.append(f"{rel}:{node.lineno}: pickle.loads call")
        elif root == "yaml" and tail == "load" and "Loader" not in kws:
            findings.append(f"{rel}:{node.lineno}: yaml.load without Loader")
    return findings


def _doctrine(summary: str, artifact_ref: str) -> tuple[str, float, str] | None:
    if not os.path.isdir(artifact_ref):
        return None                       # unreadable reference → abstain (§5.4)
    findings: list[str] = []
    for rel in iter_python_files(artifact_ref):
        with open(os.path.join(artifact_ref, rel), encoding="utf-8",
                  errors="replace") as f:
            src = f.read()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue                      # not this watcher's rule to judge
        findings.extend(_scan_ast(tree, rel))
        for lineno, line in enumerate(src.splitlines(), start=1):
            if SECRET_RE.search(line):
                findings.append(f"{rel}:{lineno}: hardcoded secret literal")
    if findings:
        return ("REFUTES", 0.9, "dangerous patterns: " + "; ".join(findings))
    return ("SUPPORTS", 0.85, "no dangerous patterns")


SESSION = WatcherSession(MANIFEST, _doctrine)
