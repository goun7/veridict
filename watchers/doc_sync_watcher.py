"""Example doc-sync watcher — a THIRD-PARTY producer living outside the core.

This module is the platform-gate proof (§5.3): the core has no special-case
for it; it participates purely through a signed manifest + a blind session.
Its doctrine is a W3 judgment (documentation claims about counts staying in
sync with reality — the class of staleness this project itself hit with its
own "190 tests" receipt line).
"""
import ast
import hashlib
import os
import re

from veridict.utils import iter_python_files
from veridict.watchers import WatcherManifest, WatcherSession

_CODE_HASH = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()

MANIFEST = WatcherManifest(
    watcher_id="example-doc-sync",
    name="Example Doc Sync Watcher",
    version="0.1.0",
    producer={"identity": "example-doc-sync", "maintainer": "veridict-examples"},
    capabilities={"evidence_classes": ("WATCHER_REPORT",), "max_tier": "W3",
                  "subscribes_to": ("documentation", "docs", "compliance")},
    resource_class={"timeout_seconds": 60, "cost_budget": 0.0,
                    "sandbox_level": "inprocess"},
    integrity={"code_hash": _CODE_HASH, "update_policy": "manual"})

# "<N> test(s) passed" style claims in docs
_TESTCOUNT_RE = re.compile(r"\b(\d{2,4})\s+tests?\b", re.IGNORECASE)


def _count_tests(root: str) -> int | None:
    """Count `def test_` functions across the artifact (None when none)."""
    count = 0
    seen = False
    for rel in iter_python_files(root):
        path = os.path.join(root, rel)
        if os.sep + "test" not in path.lower():
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            try:
                tree = ast.parse(f.read())
            except SyntaxError:
                continue
        seen = True
        for node in ast.walk(tree):
            if (isinstance(node, ast.FunctionDef)
                    and node.name.startswith("test_")):
                count += 1
    return count if seen else None


def _markdown_files(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if not d.startswith(".") and d != "__pycache__"]
        for name in filenames:
            if name.lower().endswith(".md"):
                yield os.path.join(dirpath, name)


def _doctrine(summary: str, artifact_ref: str) -> tuple[str, float, str] | None:
    if not os.path.isdir(artifact_ref):
        return None                       # unreadable reference → abstain (§5.4)
    actual = _count_tests(artifact_ref)
    if actual is None:
        # benign/empty artifact: no tests to sync against, the sync question
        # is vacuous, not refuted
        return ("SUPPORTS", 0.6, "no test files found (doc-sync question "
                                 "vacuous)")
    claims = set()
    for path in _markdown_files(artifact_ref):
        with open(path, encoding="utf-8", errors="replace") as f:
            for m in _TESTCOUNT_RE.finditer(f.read()):
                if int(m.group(1)) != actual:
                    claims.add(f"{os.path.relpath(path, artifact_ref)} claims "
                               f"{m.group(1)} tests")
    if claims:
        return ("REFUTES", 0.6,
                f"stale test-count claims in docs (actual: {actual}): "
                + "; ".join(sorted(claims)[:5]))
    return ("SUPPORTS", 0.6, f"no stale test-count claims found (actual: {actual})")


SESSION = WatcherSession(MANIFEST, _doctrine)
