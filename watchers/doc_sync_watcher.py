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


# Fixture/corpus-style trees an audit tool ships to be AUDITED (not run):
# their test_ functions are subjects, not the project's suite. Skipping
# these is doctrine honesty — counting them would call every docs claim
# stale while pytest collects none of them.
_SKIP_DIRS = {"corpus", "fixtures", "examples", "node_modules",
              "__pycache__", "build", "dist", "_site"}


# Counting-method tolerance: honest docs cite either pytest's collected
# count or the static definition count (they drift via parametrize/skip).
# A claim within TOLERANCE of the static count is in sync; beyond it,
# stale under every honest counting method. Tolerance is doctrine, kept
# explicit (W3 judgment, not machine truth).
_TOLERANCE = 0.10

# Live-claim documents only: top-level READMEs (the store front) and the
# docs/notes launch kit (texts pasted publicly). Plans/emails/changelogs
# are HISTORICAL RECORDS — a past count in them is not a live claim, and
# flagging history is how a watcher earns its uninstall.
_LIVE_DOC = re.compile(r"^(readme(\..*)?|docs/notes/launch-.+\.md)$",
                       re.IGNORECASE)


def _count_tests(root: str) -> tuple[int, int] | None:
    """(lo, hi) plausible test counts = static ± tolerance.

    hi/lo = static `def test_` definition count (outside fixture trees)
    scaled by ±10%. A doc claim inside that band is in sync under SOME
    honest counting method (collected vs static drift by parametrize
    and skips); a claim outside it is stale under every one. None when
    the artifact defines no tests at all."""
    static = 0
    for rel in iter_python_files(root):
        parts = [p.lower() for p in rel.split(os.sep)]
        if any(p in _SKIP_DIRS for p in parts[:-1]):
            continue                      # fixture tree: audited, not run
        path = os.path.join(root, rel)
        with open(path, encoding="utf-8", errors="replace") as f:
            try:
                tree = ast.parse(f.read())
            except SyntaxError:
                continue
        static += sum(1 for node in ast.walk(tree)
                      if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                      and node.name.startswith("test_"))
    if not static:
        return None
    lo = max(0, round(static * (1 - _TOLERANCE)))
    hi = round(static * (1 + _TOLERANCE))
    return (lo, hi)


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
    interval = _count_tests(artifact_ref)
    if interval is None:
        # benign/empty artifact: no tests to sync against, the sync question
        # is vacuous, not refuted
        return ("SUPPORTS", 0.6, "no test files found (doc-sync question "
                                 "vacuous)")
    lo, hi = interval
    stale = set()
    for path in _markdown_files(artifact_ref):
        rel = os.path.relpath(path, artifact_ref).replace(os.sep, "/")
        if not _LIVE_DOC.match(rel):
            continue         # historical record (plan/email/etc), not live
        with open(path, encoding="utf-8", errors="replace") as f:
            for m in _TESTCOUNT_RE.finditer(f.read()):
                claimed = int(m.group(1))
                if not (lo <= claimed <= hi):
                    stale.add(f"{rel} claims {m.group(1)} tests")
    if stale:
        return ("REFUTES", 0.6,
                f"stale test-count claims in docs (plausible range "
                f"{lo}-{hi}): " + "; ".join(sorted(stale)[:5]))
    return ("SUPPORTS", 0.6, f"no stale test-count claims found (plausible "
                             f"range {lo}-{hi})")


SESSION = WatcherSession(MANIFEST, _doctrine)
