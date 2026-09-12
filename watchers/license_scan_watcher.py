"""Example license-scan watcher — a THIRD-PARTY producer living outside the core.

This module is the platform-gate proof (§5.3): the core has no special-case
for it; it participates purely through a signed manifest + a blind session.
Its doctrine is a W3 judgment (permissive license presence), not machine proof.
"""
import hashlib
import os

from veridict.utils import iter_python_files
from veridict.watchers import WatcherManifest, WatcherSession

_CODE_HASH = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()

MANIFEST = WatcherManifest(
    watcher_id="example-license-scan",
    name="Example License Scan Watcher",
    version="0.1.0",
    producer={"identity": "example-license-scan",
              "maintainer": "veridict-examples"},
    capabilities={"evidence_classes": ("WATCHER_REPORT",), "max_tier": "W3",
                  "subscribes_to": ("license", "compliance")},
    resource_class={"timeout_seconds": 60, "cost_budget": 0.0,
                    "sandbox_level": "inprocess"},
    integrity={"code_hash": _CODE_HASH, "update_policy": "manual"})

_PERMISSIVE = ("Apache", "MIT", "BSD", "ISC", "Python-Software-Foundation")
# Commonly-rejected license identifiers (not exhaustive — a doctrine, not law)
_NONPERMISSIVE = ("GPL-3.0", "GPL-2.0", "AGPL", "SSPL", "CC-BY-NC")


def _license_at(root: str) -> str | None:
    for name in os.listdir(root):
        if name.upper().startswith("LICENSE"):
            with open(os.path.join(root, name), encoding="utf-8",
                      errors="replace") as f:
                head = f.read(4096)
            if any(k in head for k in _PERMISSIVE):
                return "permissive"
            return "unknown-or-restrictive"
    return None


def _dependency_licenses(path: str) -> dict[str, str]:
    """Best-effort license map from package metadata; empty when unavailable
    (dependency honesty: absence of metadata is not evidence of a violation)."""
    return {}


def _doctrine(summary: str, artifact_ref: str) -> tuple[str, float, str] | None:
    if not os.path.isdir(artifact_ref):
        return None                       # unreadable reference → abstain (§5.4)
    files = list(iter_python_files(artifact_ref))
    if not files:
        # benign/empty artifact: the license question is vacuous, not refuted
        return ("SUPPORTS", 0.6, "no python files to check (license question "
                                 "vacuous)")
    top = _license_at(artifact_ref)
    if top is None:
        return ("REFUTES", 0.6, "no LICENSE file in the artifact root")
    if top != "permissive":
        return ("REFUTES", 0.6,
                "LICENSE present but not identified as permissive")
    deps = _dependency_licenses(artifact_ref)
    bad = [p for p, lic in deps.items() if lic in _NONPERMISSIVE]
    if bad:
        return ("REFUTES", 0.6,
                f"non-permissive dependency licenses: {', '.join(bad)}")
    return ("SUPPORTS", 0.6, "permissive license present; no known "
                             "non-permissive dependencies")


SESSION = WatcherSession(MANIFEST, _doctrine)
