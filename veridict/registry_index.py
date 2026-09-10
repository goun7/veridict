"""Marketplace manifest index (T28, §5.5): the static JSON circulation format.

An index is a VIEW of registered watcher manifests exported from an
append-only ledger — never a separate truth. Offline consumers verify an
index against a ledger they trust; the validator re-checks digests and
signatures entry-by-entry.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .ledger import Ledger
from .utils import payload_digest
from .watchers import ManifestRegistry


def build_index(ledger: Ledger) -> dict:
    """Latest-registration-wins index over `watcher.registered` entries."""
    latest: dict[str, dict] = {}
    for e in ledger.query("watcher.registered"):
        latest[e["payload"]["manifest"]["watcher_id"]] = e
    watchers = []
    for wid, e in latest.items():
        p = e["payload"]
        watchers.append({
            "watcher_id": wid,
            "name": p["manifest"]["name"],
            "version": p["manifest"]["version"],
            "producer": p["manifest"]["producer"],
            "capabilities": p["manifest"]["capabilities"],
            "resource_class": p["manifest"]["resource_class"],
            "integrity": p["manifest"]["integrity"],
            "manifest_digest": p["manifest_digest"],
            "registered_seq": e["seq"],
        })
    return {"schema_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "watchers": watchers}


def validate_index(index: dict, ledger: Ledger) -> dict:
    """Index-vs-ledger consistency: completeness, digest match, signature."""
    errors: list[str] = []
    registered: dict[str, dict] = {}
    for e in ledger.query("watcher.registered"):
        registered[e["payload"]["manifest"]["watcher_id"]] = e
    listed: set[str] = set()
    for w in index.get("watchers", []):
        wid = w.get("watcher_id")
        if wid not in registered:
            errors.append(f"index lists watcher {wid} not registered in ledger")
            continue
        listed.add(wid)
        p = registered[wid]["payload"]
        if payload_digest(p["manifest"]) != w.get("manifest_digest"):
            errors.append(f"watcher {wid}: index digest does not match the "
                          "ledger manifest")
        report = ManifestRegistry.verify_manifest(ledger, wid)
        if not report["valid"]:
            errors.append(f"watcher {wid}: registry verification failed: "
                          f"{report['errors']}")
    for wid in registered:
        if wid not in listed:
            errors.append(f"ledger watcher {wid} missing from index")
    return {"valid": not errors, "errors": errors}


def export_index(ledger: Ledger, out_path: str) -> dict:
    idx = build_index(ledger)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(idx, f, indent=2, sort_keys=True)
    return idx


def load_index(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)
