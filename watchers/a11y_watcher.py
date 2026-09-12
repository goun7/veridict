"""Example a11y watcher — a THIRD-PARTY producer living outside the core.

This module is the platform-gate proof (§5.3): the core has no special-case
for it; it participates purely through a signed manifest + a blind session.
Its doctrine is a W3 judgment (basic accessibility hygiene of shipped HTML).
"""
import hashlib
import os
import re

from veridict.watchers import WatcherManifest, WatcherSession

_CODE_HASH = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()

MANIFEST = WatcherManifest(
    watcher_id="example-a11y",
    name="Example Accessibility Watcher",
    version="0.1.0",
    producer={"identity": "example-a11y", "maintainer": "veridict-examples"},
    capabilities={"evidence_classes": ("WATCHER_REPORT",), "max_tier": "W3",
                  "subscribes_to": ("accessibility", "a11y", "compliance")},
    resource_class={"timeout_seconds": 60, "cost_budget": 0.0,
                    "sandbox_level": "inprocess"},
    integrity={"code_hash": _CODE_HASH, "update_policy": "manual"})

# Conservative, regex-level checks only — this is a doctrine, not axe-core.
_IMG_NO_ALT = re.compile(r"<img(?![^>]*\balt=)[^>]*>", re.IGNORECASE)
_ARIA_HIDDEN_FOCUSABLE = re.compile(
    r"<(?:a|button)\s+(?![^>]*\bhref=\"#\")"   # placeholder; see focusable check
    r"[^>]*aria-hidden=[\"']true[\"'][^>]*>", re.IGNORECASE)


def _html_files(root: str) -> list[str]:
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")
                       and d not in ("node_modules", "__pycache__", "_site")]
        for name in filenames:
            if name.lower().endswith((".html", ".htm")):
                out.append(os.path.join(dirpath, name))
    return out


def _doctrine(summary: str, artifact_ref: str) -> tuple[str, float, str] | None:
    if not os.path.isdir(artifact_ref):
        return None                       # unreadable reference → abstain (§5.4)
    pages = _html_files(artifact_ref)
    if not pages:
        # benign/empty artifact: no shipped HTML, the a11y question is
        # vacuous, not refuted
        return ("SUPPORTS", 0.6, "no HTML files present (accessibility "
                                 "question vacuous)")
    offenders: list[str] = []
    for path in pages:
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
        issues = []
        if _IMG_NO_ALT.search(text):
            issues.append("img without alt text")
        if _ARIA_HIDDEN_FOCUSABLE.search(text):
            issues.append("focusable element hidden from assistive tech")
        if issues:
            offenders.append(f"{os.path.relpath(path, artifact_ref)}: "
                              + "; ".join(issues))
    if offenders:
        return ("REFUTES", 0.6, " | ".join(offenders[:5]))
    return ("SUPPORTS", 0.6, f"{len(pages)} HTML page(s) pass the basic "
                             f"accessibility checks")


SESSION = WatcherSession(MANIFEST, _doctrine)
