"""Example compliance watcher — a THIRD-PARTY producer living outside the core.

This module is the platform-gate proof (§5.3): the core has no special-case
for it; it participates purely through a signed manifest + a blind session.
Its doctrine is a W3 judgment (license-header presence), not machine proof.
"""
import hashlib
import os

from veridict.utils import iter_python_files
from veridict.watchers import WatcherManifest, WatcherSession

_CODE_HASH = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()

MANIFEST = WatcherManifest(
    watcher_id="example-compliance",
    name="Example Compliance Watcher",
    version="0.1.0",
    producer={"identity": "example-compliance", "maintainer": "veridict-examples"},
    capabilities={"evidence_classes": ("WATCHER_REPORT",), "max_tier": "W3",
                  "subscribes_to": ("*",)},
    resource_class={"timeout_seconds": 60, "cost_budget": 0.0,
                    "sandbox_level": "inprocess"},
    integrity={"code_hash": _CODE_HASH, "update_policy": "manual"})


def _has_license_header(path: str) -> bool:
    with open(path, encoding="utf-8", errors="replace") as f:
        first = f.readline()
    if not first.lstrip().startswith("#"):
        return False
    return "SPDX-License-Identifier" in first or "Apache" in first


def _doctrine(summary: str, artifact_ref: str) -> tuple[str, float, str] | None:
    if not os.path.isdir(artifact_ref):
        return None                       # unreadable reference → abstain (§5.4)
    files = iter_python_files(artifact_ref)
    if not files:
        return ("SUPPORTS", 0.6, "no python files to check")
    has_license = any(name.upper().startswith("LICENSE")
                      for name in os.listdir(artifact_ref))
    for rel in files:
        if _has_license_header(os.path.join(artifact_ref, rel)):
            continue
        if has_license:                   # repo-level LICENSE covers the artifact
            continue
        return ("REFUTES", 0.6, f"missing license header in {rel}")
    return ("SUPPORTS", 0.6, "license headers present")


SESSION = WatcherSession(MANIFEST, _doctrine)
