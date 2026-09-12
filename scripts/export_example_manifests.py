#!/usr/bin/env python
"""Export the shipped example watchers' manifests as JSON files an external
user can register directly:

    veridict registry init --registry r.jsonl --key-out k.json
    veridict registry register --registry r.jsonl \
        --manifest examples/manifests/security-watcher.json --key-file k.json

code_hash is the sha256 of the watcher's module file, so the CLI's
integrity check passes as long as the module ships unmodified.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

OUT = os.path.join(REPO, "examples", "manifests")


def main() -> int:
    sys.path.insert(0, os.path.join(REPO, "watchers"))
    import a11y_watcher
    import compliance_watcher
    import cost_watcher
    import docker_watcher
    import doc_sync_watcher
    import import_weight_watcher
    import license_scan_watcher
    import sbom_watcher
    import secret_scan_watcher
    import security_watcher

    os.makedirs(OUT, exist_ok=True)
    for mod in (security_watcher, compliance_watcher, cost_watcher,
                secret_scan_watcher, license_scan_watcher, docker_watcher,
                doc_sync_watcher, sbom_watcher, a11y_watcher,
                import_weight_watcher):
        manifest = mod.MANIFEST.to_dict()
        module_file = mod.__file__
        manifest["integrity"]["code_hash"] = hashlib.sha256(
            open(module_file, "rb").read()).hexdigest()
        name = manifest["watcher_id"].replace("_", "-") + ".json"
        path = os.path.join(OUT, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print("wrote", path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
