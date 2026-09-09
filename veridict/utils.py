"""Canonical serialization and hashing. Small-core: stdlib only (§7.3)."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

IGNORED_DIRS = frozenset({".git", "__pycache__", ".venv", "node_modules", ".pytest_cache"})


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
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                rel = os.path.relpath(os.path.join(dirpath, fn), root)
                out.append(rel.replace(os.sep, "/"))
    return sorted(out)
