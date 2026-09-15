"""EU AI Act transparency watcher — a THIRD-PARTY producer (§5.3).

Regulation (EU) 2024/1689 puts machine-readable transparency duties on
systems that generate synthetic content (Art. 50: outputs must be
identifiable as AI-generated, in a machine-readable form) and on general-
purpose AI providers (the GPAI Code of Practice, published 2025-07-10,
operationalizes training-data documentation). This watcher checks a repo
for the *artifacts those duties mechanically reduce to* — no legal
judgment, just existence and shape, deterministic on the bytes:

  1. DISCLOSURE: an AI-disclosure surface exists and names itself
     (MODEL_CARD*, AI_DISCLOSURE*, or an "AI-generated"/"Article 50"
     marker in README) — Article 50's labeling duty has an anchor.
  2. MACHINE-READABLE OUTPUTS: every file under ai_outputs/ carries a
     strict-suffix sidecar `<file>.provenance.json` (e.g.
     ai_outputs/render.png.provenance.json) with generated_by +
     generated_at — a Veridict certificate reference counts as
     generated_by: the protocol is one conformant way to satisfy the
     duty, and this watcher exists partly to show that.
  3. GPAI TRAINING-DATA SUMMARY: if the repo ships model weights
     (*.safetensors/*.onnx/*.gguf/*.pt/*.bin model markers), a
     training-data-summary.{md,csv,json} must exist (Code of Practice,
     training-data summary template).

Repos with no AI surface at all report VACUOUS SUPPORT (§9 semantics, same
as license-scan on an empty artifact): Article 50 genuinely does not apply
to a text renderer, and that is a truthful supports, not a bark. Only an
unreadable reference abstains (§5.4). The opinion is a W1b reproduction
(regex + file presence, deterministic), under the watcher tier ceiling.
"""
import hashlib
import json
import os
import re

from veridict.watchers import WatcherManifest, WatcherSession

_CODE_HASH = hashlib.sha256(open(os.path.abspath(__file__), "rb").read()).hexdigest()

MANIFEST = WatcherManifest(
    watcher_id="example-aiact-transparency",
    name="Example EU AI Act Transparency Watcher",
    version="0.1.0",
    producer={"identity": "example-aiact-transparency",
              "maintainer": "veridict-examples"},
    capabilities={"evidence_classes": ("STATIC_ANALYSIS",), "max_tier": "W1b",
                  "subscribes_to": ("aiact", "transparency", "disclosure",
                                    "gpai")},
    resource_class={"timeout_seconds": 60, "cost_budget": 0.0,
                    "sandbox_level": "inprocess"},
    integrity={"code_hash": _CODE_HASH, "update_policy": "manual"})

_MODEL_EXTS = (".safetensors", ".onnx", ".gguf", ".pt", ".pth", ".bin")
_DISCLOSURE_FILE = re.compile(r"(?i)^(MODEL_CARD|AI_DISCLOSURE|ai-disclosure)")
_README_MARKER = re.compile(r"(?i)\b(AI-generated|Article 50|EU AI Act)\b")


def _walk(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
        for fn in filenames:
            yield os.path.relpath(os.path.join(dirpath, fn), root)


def _doctrine(summary: str, artifact_ref: str) -> tuple[str, float, str] | None:
    if not os.path.isdir(artifact_ref):
        return None                       # unreadable reference → abstain (§5.4)
    rels = list(_walk(artifact_ref))

    def has_top(prefix_re=_DISCLOSURE_FILE):
        return any(prefix_re.match(os.path.basename(r)) for r in rels)

    def readme_marks():
        for r in rels:
            if os.path.basename(r).lower().startswith("readme"):
                try:
                    with open(os.path.join(artifact_ref, r), encoding="utf-8",
                              errors="replace") as f:
                        if _README_MARKER.search(f.read()):
                            return True
                except OSError:
                    continue
        return False

    ships_model = any(r.lower().endswith(_MODEL_EXTS) for r in rels)
    has_outputs = any(r.replace(os.sep, "/").startswith("ai_outputs/")
                      for r in rels)
    if not (has_top() or readme_marks() or ships_model or has_outputs):
        return ("SUPPORTS", 0.6, "no AI surface detected — Article 50/GPAI "
                                 "duties not applicable to this artifact "
                                 "(vacuous supports, honest nil)")

    findings: list[str] = []
    ok = True

    if not (has_top() or readme_marks()):
        ok = False
        findings.append("no AI-disclosure surface (MODEL_CARD*/AI_DISCLOSURE* "
                        "file or README Article-50 marker) — Art. 50 labeling "
                        "duty has no anchor in this repo")

    if has_outputs:
        for r in rels:
            norm = r.replace(os.sep, "/")
            if not norm.startswith("ai_outputs/") or norm.endswith(
                    ".provenance.json"):
                continue
            side = norm + ".provenance.json"       # strict-suffix convention
            if not os.path.exists(os.path.join(artifact_ref, side)):
                ok = False
                findings.append(f"{norm}: no machine-readable provenance "
                                "sidecar (Article 50 identifiability duty)")
                continue
            try:
                with open(os.path.join(artifact_ref, side), encoding="utf-8") as f:
                    meta = json.load(f)
                missing = [k for k in ("generated_by", "generated_at")
                           if not str(meta.get(k, "")).strip()]
                if missing:
                    ok = False
                    findings.append(f"{side}: missing {missing} keys")
            except (json.JSONDecodeError, OSError) as exc:
                ok = False
                findings.append(f"{side}: unreadable provenance sidecar ({exc})")

    if ships_model:
        summaries = [r for r in rels if os.path.basename(r).startswith(
            "training-data-summary")]
        if not summaries:
            ok = False
            findings.append("model weights shipped without "
                            "training-data-summary.{md,csv,json} (GPAI Code "
                            "of Practice documentation duty)")

    if not ok:
        return ("REFUTES", 0.7, "; ".join(findings[:6]))
    return ("SUPPORTS", 0.7,
            "AI-Act-checkable surfaces present: disclosure anchor"
            + (", provenance sidecars on all ai_outputs/" if has_outputs else "")
            + (", training-data summary" if ships_model else ""))


SESSION = WatcherSession(MANIFEST, _doctrine)
