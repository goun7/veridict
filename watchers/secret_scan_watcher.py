"""Example secret-scan watcher — a THIRD-PARTY producer living outside the core.

This module is the platform-gate proof (§5.3): the core has no special-case
for it; it participates purely through a signed manifest + a blind session.
Its doctrine is a W1b reproduction (regex-based detection, deterministic on
the artifact bytes), under the watcher tier ceiling.
"""
import hashlib
import os
import re

from veridict.utils import iter_python_files
from veridict.watchers import WatcherManifest, WatcherSession

_CODE_HASH = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()

MANIFEST = WatcherManifest(
    watcher_id="example-secret-scan",
    name="Example Secret Scan Watcher",
    version="0.1.0",
    producer={"identity": "example-secret-scan",
              "maintainer": "veridict-examples"},
    capabilities={"evidence_classes": ("STATIC_ANALYSIS",), "max_tier": "W1b",
                  "subscribes_to": ("secret", "security", "credentials")},
    resource_class={"timeout_seconds": 60, "cost_budget": 0.0,
                    "sandbox_level": "inprocess"},
    integrity={"code_hash": _CODE_HASH, "update_policy": "manual"})

# High-confidence secret patterns only: value length + assignment/carrier
# context. Deliberately conservative — a scanner of this size must never
# become a false-positive machine (§13 honesty lives here too).
_PATTERNS: tuple[re.Pattern, ...] = tuple(re.compile(p) for p in (
    r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)"
    r"\s*[:=]\s*[\"'][A-Za-z0-9_\-]{20,}[\"']",
    r"(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"(?i)aws[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key)\)?"
    r"[\"']?\s*[:=]\s*[\"']?[A-Z0-9]{16,}",
    r"\b(sk|pk)_(live|test)_[A-Za-z0-9]{16,}\b",            # stripe-style keys
    r"\bghp_[A-Za-z0-9]{36,}\b",                            # github PATs
))


def _doctrine(summary: str, artifact_ref: str) -> tuple[str, float, str] | None:
    if not os.path.isdir(artifact_ref):
        return None                       # unreadable reference → abstain (§5.4)
    hits: list[str] = []
    for rel in iter_python_files(artifact_ref):
        with open(os.path.join(artifact_ref, rel), encoding="utf-8",
                  errors="replace") as f:
            text = f.read()
        for pat in _PATTERNS:
            if pat.search(text):
                hits.append(rel)
                break
    if hits:
        return ("REFUTES", 0.75,
                f"secret-like material detected in {len(hits)} file(s): "
                f"{', '.join(sorted(set(hits))[:5])}")
    return ("SUPPORTS", 0.75, "no high-confidence secret patterns detected")


SESSION = WatcherSession(MANIFEST, _doctrine)
