"""Example docker best-practices watcher — a THIRD-PARTY producer living
outside the core.

This module is the platform-gate proof (§5.3): the core has no special-case
for it; it participates purely through a signed manifest + a blind session.
Its doctrine is a W3 judgment (Dockerfile hygiene conventions).
"""
import hashlib
import os

from veridict.watchers import WatcherManifest, WatcherSession

_CODE_HASH = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()

MANIFEST = WatcherManifest(
    watcher_id="example-docker-best-practices",
    name="Example Docker Best Practices Watcher",
    version="0.1.0",
    producer={"identity": "example-docker-best-practices",
              "maintainer": "veridict-examples"},
    capabilities={"evidence_classes": ("WATCHER_REPORT",), "max_tier": "W3",
                  "subscribes_to": ("docker", "deployment", "security")},
    resource_class={"timeout_seconds": 60, "cost_budget": 0.0,
                    "sandbox_level": "inprocess"},
    integrity={"code_hash": _CODE_HASH, "update_policy": "manual"})


def _dockerfiles(root: str) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".")
                       and d not in ("node_modules", "__pycache__")]
        for name in filenames:
            if name == "Dockerfile" or name.endswith(".dockerfile"):
                out.append(os.path.join(dirpath, name))
    return out


def _issues(text: str) -> list[str]:
    found = []
    runs = [l.split("#", 1)[0].split() for l in text.splitlines()
            if l.strip().upper().startswith(("RUN",))]
    for parts in runs:
        for tok in parts[1:]:
            if not tok.startswith("-"):
                if tok in ("apt-get", "apt", "yum", "apk"):
                    found.append("package install without --no-install-recommends "
                                 f"({tok})")
                if tok == "sudo":
                    found.append("sudo in container (should not be needed)")
    if ":latest" in text:
        found.append("floating tag ':latest' pinned nowhere")
    if "USER root" in text:
        found.append("explicit USER root")
    return found


def _doctrine(summary: str, artifact_ref: str) -> tuple[str, float, str] | None:
    if not os.path.isdir(artifact_ref):
        return None                       # unreadable reference → abstain (§5.4)
    dfs = _dockerfiles(artifact_ref)
    if not dfs:
        # benign/empty artifact: no containers declared, the hygiene question
        # is vacuous, not refuted
        return ("SUPPORTS", 0.6, "no Dockerfiles present (docker hygiene "
                                 "question vacuous)")
    hits: list[str] = []
    for path in dfs:
        with open(path, encoding="utf-8", errors="replace") as f:
            issues = _issues(f.read())
        if issues:
            hits.append(f"{os.path.relpath(path, artifact_ref)}: "
                        f"{'; '.join(issues)}")
    if hits:
        return ("REFUTES", 0.6, " | ".join(hits[:5]))
    return ("SUPPORTS", 0.6, f"{len(dfs)} Dockerfile(s) pass the hygiene checks")


SESSION = WatcherSession(MANIFEST, _doctrine)
