"""Every shipped examples/manifests/*.json must equal its module's live
manifest — including code_hash.

This catches the drift class found by the 2026-09-15 debt sweep: a watcher
module was edited, its JSON export (what external users register) was not
re-exported, so the registry integrity check would reject the very example
we ship. The exporter (scripts/export_example_manifests.py) is the fix;
this test is the tripwire.
"""
import glob
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "watchers"))

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

MODULES = ("security_watcher", "compliance_watcher", "cost_watcher",
           "secret_scan_watcher", "license_scan_watcher", "docker_watcher",
           "doc_sync_watcher", "sbom_watcher", "a11y_watcher",
           "import_weight_watcher", "aiact_watcher")


def _load(modname):
    return __import__(modname)


def test_every_module_has_its_example_manifest():
    exported = {json.load(open(p))["watcher_id"]: os.path.basename(p)
                for p in glob.glob(os.path.join(REPO, "examples",
                                                "manifests", "*.json"))}
    for modname in MODULES:
        wid = _load(modname).MANIFEST.watcher_id
        assert wid in exported, f"{modname} ships no example manifest"
    assert len(exported) == len(MODULES), \
        f"orphan manifests: {set(exported) - {_load(m).MANIFEST.watcher_id for m in MODULES}}"


def test_manifest_json_matches_module_exactly():
    for modname in MODULES:
        mod = _load(modname)
        m = mod.MANIFEST.to_dict()
        path = os.path.join(REPO, "examples", "manifests",
                            m["watcher_id"].replace("_", "-") + ".json")
        shipped = json.load(open(path))
        assert shipped == m, modname
        live_hash = hashlib.sha256(
            open(os.path.abspath(mod.__file__), "rb").read()).hexdigest()
        assert shipped["integrity"]["code_hash"] == live_hash, \
            f"{modname}: shipped example manifest code_hash is stale"
