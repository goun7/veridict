"""Example cost watcher — a THIRD-PARTY producer living outside the core.

This module is the platform-gate proof (§5.3): the core has no special-case
for it; it participates purely through a signed manifest + a blind session.
"""
import hashlib
import os

from veridict.utils import iter_python_files
from veridict.watchers import WatcherManifest, WatcherSession

_CODE_HASH = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()

MANIFEST = WatcherManifest(
    watcher_id="example-cost",
    name="Example Cost Watcher",
    version="0.1.0",
    producer={"identity": "example-cost", "maintainer": "veridict-examples"},
    capabilities={"evidence_classes": ("WATCHER_REPORT",), "max_tier": "W1b",
                  "subscribes_to": ("cost", "performance")},
    resource_class={"timeout_seconds": 60, "cost_budget": 0.0,
                    "sandbox_level": "inprocess"},
    integrity={"code_hash": _CODE_HASH, "update_policy": "manual"})

LOC_BUDGET = 500


def _doctrine(summary: str, artifact_ref: str) -> tuple[str, float, str] | None:
    if not os.path.isdir(artifact_ref):
        return None                       # unreadable reference → abstain (§5.4)
    total = 0
    for rel in iter_python_files(artifact_ref):
        with open(os.path.join(artifact_ref, rel), encoding="utf-8",
                  errors="replace") as f:
            total += sum(1 for _ in f)
    if total > LOC_BUDGET:
        return ("REFUTES", 0.7,
                f"artifact exceeds {LOC_BUDGET} LOC budget ({total} lines)")
    return ("SUPPORTS", 0.7, f"artifact within LOC budget ({total} lines)")


SESSION = WatcherSession(MANIFEST, _doctrine)
