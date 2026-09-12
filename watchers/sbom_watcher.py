"""Example SBOM/SPDX watcher — a THIRD-PARTY producer living outside the core.

This module is the platform-gate proof (§5.3): the core has no special-case
for it; it participates purely through a signed manifest + a blind session.
Its doctrine is a W3 judgment (SPDX-style software bill of materials
completeness), reading only declared facts — never inventing components.
"""
import hashlib
import json
import os
import re

from veridict.utils import iter_python_files
from veridict.watchers import WatcherManifest, WatcherSession

_CODE_HASH = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()

MANIFEST = WatcherManifest(
    watcher_id="example-sbom-spdx",
    name="Example SBOM SPDX Watcher",
    version="0.1.0",
    producer={"identity": "example-sbom-spdx", "maintainer": "veridict-examples"},
    capabilities={"evidence_classes": ("WATCHER_REPORT",), "max_tier": "W3",
                  "subscribes_to": ("sbom", "supply-chain", "compliance")},
    resource_class={"timeout_seconds": 60, "cost_budget": 0.0,
                    "sandbox_level": "inprocess"},
    integrity={"code_hash": _CODE_HASH, "update_policy": "manual"})

_IMPORT_RE = re.compile(r"^(?:from|import)\s+([A-Za-z_][A-Za-z0-9_.]*)",
                        re.MULTILINE)

# Local top-level packages of the artifact itself (detected: a directory with
# __init__.py next to the imports) are not third-party dependencies.
_STD_HINT = ("src/", "tests/", "examples/", "docs/")


def _third_party_imports(root: str) -> set[str]:
    local: set[str] = set()
    for rel in iter_python_files(root):
        parts = rel.split(os.sep)
        if len(parts) > 1:
            local.add(parts[0])
            if parts[-1] == "__init__.py" and len(parts) > 1:
                local.add(parts[0])
    deps: set[str] = set()
    for rel in iter_python_files(root):
        with open(os.path.join(root, rel), encoding="utf-8",
                  errors="replace") as f:
            for m in _IMPORT_RE.finditer(f.read()):
                top = m.group(1).split(".")[0]
                if top not in local and not top.startswith("_"):
                    deps.add(top)
    return deps


def _declared_dependencies(root: str) -> set[str] | None:
    """Names declared in pyproject.toml / requirements*.txt (None if none)."""
    declared: set[str] = set()
    pyproject = os.path.join(root, "pyproject.toml")
    if os.path.isfile(pyproject):
        with open(pyproject, encoding="utf-8", errors="replace") as f:
            text = f.read()
        for m in re.finditer(r'["\']([A-Za-z0-9_.\-]+)["\']', text):
            declared.add(m.group(1).split("[")[0].split(".")[0].lower())
    for name in os.listdir(root):
        if name.startswith("requirements") and name.endswith(".txt"):
            with open(os.path.join(root, name), encoding="utf-8",
                      errors="replace") as f:
                for line in f:
                    line = line.split("#", 1)[0].strip()
                    if line and not line.startswith(("-")):
                        declared.add(re.split(r"[<>=!\[; ]", line)[0]
                                     .split(".")[0].lower())
    return declared or None


def _doctrine(summary: str, artifact_ref: str) -> tuple[str, float, str] | None:
    if not os.path.isdir(artifact_ref):
        return None                       # unreadable reference → abstain (§5.4)
    py_files = list(iter_python_files(artifact_ref))
    if not py_files:
        # benign/empty artifact: not a python artifact, the SBOM question is
        # vacuous, not refuted
        return ("SUPPORTS", 0.6, "no python files to check (SBOM question "
                                 "vacuous)")
    declared = _declared_dependencies(artifact_ref)
    if declared is None:
        return ("REFUTES", 0.6,
                "no pyproject.toml or requirements file declares dependencies — "
                "the SBOM is empty")
    imported = _third_party_imports(artifact_ref)
    undeclared = sorted(i.lower() for i in imported
                        if i.lower() not in declared)
    if undeclared:
        return ("REFUTES", 0.6,
                f"imported but undeclared dependencies: {', '.join(undeclared)}")
    return ("SUPPORTS", 0.6,
            f"all {len(imported)} third-party imports are declared in the SBOM")


SESSION = WatcherSession(MANIFEST, _doctrine)
