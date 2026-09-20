#!/usr/bin/env python3
"""Measure the jury's raw judgment, decoupled from the ladder.

Why this exists (D16): the end-to-end canary measures the AUDIT, not the
model. Most corpus defects still pass their own tests — that is what makes
them interesting — so they carry W1a SUPPORT, and §5.3 rule 2 (doctrine
cannot overturn W1a) means a juror that correctly spots the defect cannot
turn the verdict. The canary's 2/25 catch figure is therefore a two-layer
lower bound: (1) small models as a lower bound for frontier ones, and (2)
the corpus's error space as a lower bound of real capability. Neither
layer tells you whether the MODEL can see the defect.

This script measures the middle term the canary cannot: for each case,
what does the jury itself say about the claim, given the artifact's source?
DEFECT cases should REFUTE; CLEAN cases should SUPPORT. The result
decomposes the blind spot into 'machine evidence cannot catch it' (a
product property, §5.3) versus 'the model cannot see it' (a capability
property, which better models would fix).

This is a measurement instrument, not a product path: it deliberately does
NOT go through the ladder, because the ladder's job is to be safe, and this
instrument's job is to be informative.

Env: VERIDICT_JURY_URL[/KEY/MODEL], optional URL2/KEY2/MODEL2.
    VERIDICT_CANARY_OUT=sheet.json writes the result.
"""
from __future__ import annotations

import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from veridict.audit import artifact_digest          # noqa: E402
from veridict.claim_extractor import ClaimExtractor  # noqa: E402
from veridict.jury import OpenAICompatProvider, _read_sources  # noqa: E402
from veridict.schemas import TaskManifest           # noqa: E402


def _jurors():
    out = []
    for suffix in ("", "2"):
        url = os.environ.get(f"VERIDICT_JURY_URL{suffix}")
        if not url:
            continue
        out.append(OpenAICompatProvider(
            family=os.environ.get(f"VERIDICT_JURY_MODEL{suffix}", "model"),
            identity=f"juror-{suffix or 1}",
            base_url=url,
            api_key=os.environ.get(f"VERIDICT_JURY_KEY{suffix}", ""),
            model=os.environ.get(f"VERIDICT_JURY_MODEL{suffix}", "")))
    return out


def main() -> int:
    corpus = os.environ.get("VERIDICT_CORPUS",
                            os.path.join(ROOT, "corpus", "corpus.jsonl"))
    cases = [json.loads(l) for l in open(corpus) if l.strip()]
    jurors = _jurors()
    if not jurors:
        print("no VERIDICT_JURY_URL set — nothing to measure", file=sys.stderr)
        return 2
    print(f"judgment sonde: {len(jurors)} juror(s), {len(cases)} cases")
    for j in jurors:
        print(f"  {j.identity}: {j.model}")

    per_case = []
    t0 = time.time()
    for case in cases:
        intent = case.get("intent") or []
        if not intent:
            continue                      # nothing to ask the juror
        task = TaskManifest(
            task_id=case["id"], artifact_path=case["path"],
            actor_identity="sonde",
            intent_lines=tuple(intent),
            criticality=tuple(case.get("criticality", [])),
            has_existing_tests=True, pytest_args=())
        digest = artifact_digest(case["path"])
        src = _read_sources(case["path"])
        for claim in ClaimExtractor().extract(task, digest):
            if claim.subject != "intent":
                continue                  # repo-level claims are not about intent
            for juror in jurors:
                try:
                    op = juror.doctrine(claim.summary, digest, src)
                    per_case.append({
                        "case": case["id"], "class": case["defect_class"],
                        "ground_truth": case["ground_truth"],
                        "juror": juror.identity,
                        "claim": claim.predicate,
                        "stance": op.stance, "confidence": op.confidence,
                        "correct": (op.stance == "REFUTES")
                                   if case["ground_truth"] == "DEFECT"
                                   else (op.stance == "SUPPORTS")})
                    print(f"  {case['id'][:26]:26s} {juror.identity:8s} "
                          f"{op.stance:8s} conf={op.confidence} "
                          f"({'✓' if per_case[-1]['correct'] else '✗'})",
                          flush=True)
                except Exception as exc:   # abstain ≠ wrong
                    per_case.append({
                        "case": case["id"], "class": case["defect_class"],
                        "ground_truth": case["ground_truth"],
                        "juror": juror.identity, "claim": claim.predicate,
                        "stance": "ABSTAINED", "confidence": None,
                        "correct": False})
                    print(f"  {case['id'][:26]:26s} {juror.identity:8s} "
                          f"ABSTAINED ({type(exc).__name__})", flush=True)

    n = len(per_case)
    if not n:
        print("no intent claims measured", file=sys.stderr)
        return 2
    def_ = [r for r in per_case if r["ground_truth"] == "DEFECT"]
    clean = [r for r in per_case if r["ground_truth"] == "CLEAN"]
    catches = sum(1 for r in def_ if r["correct"])
    fps = sum(1 for r in clean if not r["correct"])
    abstain = sum(1 for r in per_case if r["stance"] == "ABSTAINED")
    result = {
        "instrument": "jury-judgment-sonde",
        "note": ("Measures the jury's own verdict given the artifact source, "
                 "decoupled from the ladder. This is NOT the product's catch "
                 "rate: §5.3 rule 2 means a correct juror REFUTE on a "
                 "test-passing defect still cannot turn the verdict. This "
                 "number isolates model capability from product policy."),
        "jurors": [j.model for j in jurors],
        "measurements": n,
        "defect_measurements": len(def_),
        "clean_measurements": len(clean),
        "juror_correct_refutations": catches,
        "juror_false_refutations": fps,
        "abstentions": abstain,
        "duration_seconds": round(time.time() - t0, 1),
        "per_case": per_case,
    }
    print(f"\n=== JÜRİ KARAR SONDASI (ladder'dan bağımsız) ===")
    print(f"ölçüm        : {n} ({len(def_)} DEFECT, {len(clean)} CLEAN)")
    print(f"doğru RED    : {catches}/{len(def_)}  (model hatayı gördü mü?)")
    print(f"yanlış RED   : {fps}/{len(clean)}  (temiz kodu yanlış mı?)")
    print(f"çekimser     : {abstain}")
    print(f"süre         : {result['duration_seconds']}s")
    out = os.environ.get("VERIDICT_SONDE_OUT")
    if out:
        with open(out, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"yazıldı: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
