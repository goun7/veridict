"""Example import-weight watcher — a THIRD-PARTY producer living outside
the core.

This module is the platform-gate proof (§5.3): the core has no special-case
for it; it participates purely through a signed manifest + a blind session.
Its doctrine is a W1b reproduction (deterministic import-graph weight vs a
startup budget): heavy third-party import graphs are a startup-latency
regression you can read statically. It measures WEIGHT, not coverage —
coverage (undeclared deps) belongs to the sbom watcher; this one never
looks at declarations.
"""
import ast
import hashlib
import os

from veridict.utils import iter_python_files
from veridict.watchers import WatcherManifest, WatcherSession

_CODE_HASH = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()

MANIFEST = WatcherManifest(
    watcher_id="example-import-weight",
    name="Example Import Weight Watcher",
    version="0.1.0",
    producer={"identity": "example-import-weight",
              "maintainer": "veridict-examples"},
    capabilities={"evidence_classes": ("STATIC_ANALYSIS",), "max_tier": "W1b",
                  "subscribes_to": ("performance", "startup", "cost")},
    resource_class={"timeout_seconds": 60, "cost_budget": 0.0,
                    "sandbox_level": "inprocess"},
    integrity={"code_hash": _CODE_HASH, "update_policy": "manual"})

IMPORT_BUDGET = 12        # distinct third-party top-level imports

_STDLIB_HINTS = ("os", "sys", "re", "json", "hashlib", "hmac", "base64",
                 "subprocess", "tempfile", "argparse", "collections",
                 "concurrent", "datetime", "math", "random", "typing",
                 "dataclasses", "enum", "time", "pathlib", "unittest",
                 "contextlib", "functools", "itertools", "textwrap",
                 "logging", "io", "abc", "ast", "struct", "secrets",
                 "statistics", "sqlite3", "uuid", "urllib", "http",
                 "socket", "threading", "queue", "signal", "shutil",
                 "glob", "fnmatch", "string", "copy", "operator", "zipfile",
                 "tarfile", "csv", "configparser", "importlib", "inspect")


def _third_party_imports(root: str) -> set[str]:
    """Distinct top-level third-party imports (stdlib + local excluded)."""
    local = {parts[0] for rel in iter_python_files(root)
             for parts in [rel.split(os.sep)] if len(parts) > 1}
    deps: set[str] = set()
    for rel in iter_python_files(root):
        with open(os.path.join(root, rel), encoding="utf-8",
                  errors="replace") as f:
            try:
                tree = ast.parse(f.read())
            except SyntaxError:
                continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top not in _STDLIB_HINTS and top not in local:
                        deps.add(top)
            elif isinstance(node, ast.ImportFrom) and node.module:
                top = node.module.split(".")[0]
                if (node.level == 0 and top not in _STDLIB_HINTS
                        and top not in local):
                    deps.add(top)
    return deps


def _doctrine(summary: str, artifact_ref: str) -> tuple[str, float, str] | None:
    if not os.path.isdir(artifact_ref):
        return None                       # unreadable reference → abstain (§5.4)
    py_files = list(iter_python_files(artifact_ref))
    if not py_files:
        # benign/empty artifact: no python code to weigh, the question is
        # vacuous, not refuted
        return ("SUPPORTS", 0.7,
                "no python files to weigh (import-weight question vacuous)")
    deps = _third_party_imports(artifact_ref)
    if len(deps) > IMPORT_BUDGET:
        return ("REFUTES", 0.7,
                f"import weight {len(deps)} distinct third-party top-level "
                f"imports exceeds the {IMPORT_BUDGET} startup budget: "
                f"{', '.join(sorted(deps)[:8])}")
    return ("SUPPORTS", 0.7,
            f"import weight within budget ({len(deps)} distinct third-party "
            f"top-level imports)")


SESSION = WatcherSession(MANIFEST, _doctrine)
