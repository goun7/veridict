"""Canonical serialization and hashing. Small-core: stdlib only (§7.3)."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

# Dotted dirs are skipped wholesale (Errata D9): any non-hidden venv
# (.venv312, .tox-anything) used to be walked, and the thousands of
# eval/exec findings inside third-party packages turned the static
# analyzer into a false-positive REFUTES machine. The fail-closed gate
# then correctly BLOCKED the release — the scanner was wrong, not the gate.
IGNORED_DIRS = frozenset({".git", "__pycache__", "node_modules",
                          "build", "dist", "site-packages",
                          ".pytest_cache", ".mypy_cache", ".ruff_cache",
                          ".tox", ".venv"})


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII-escaped."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(s: str | bytes) -> str:
    if isinstance(s, str):
        s = s.encode("utf-8")
    return hashlib.sha256(s).hexdigest()


def payload_digest(payload: dict) -> str:
    return sha256_hex(canonical_json(payload))


def iter_python_files(root: str) -> list[str]:
    """Sorted relative paths of *.py files under root, skipping IGNORED_DIRS."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in IGNORED_DIRS and not d.startswith(".")]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                rel = os.path.relpath(os.path.join(dirpath, fn), root)
                out.append(rel.replace(os.sep, "/"))
    return sorted(out)
