#!/usr/bin/env python3
"""Resilient canary runner: restarts ollama between batches.

Found the hard way: on this machine ollama 0.32.5 deadlocks in the GPU
inference path after some number of calls. The process stays alive
(api/version answers), the socket stays ESTABLISHED, and the caller sits
in do_sys_poll forever — a hung run that looks alive. No retry inside
the jury can fix it; the model server itself is wedged.

This wrapper runs the canary in batches and restarts ollama between
them, collecting partial sheets into one final result. A wedged batch
is killed, ollama is restarted, and the batch re-runs — the measurement
completes instead of hanging forever.

Usage (same env as scripts/canary_real_llm.py):
    python3 scripts/canary_resilient.py
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

BATCH = int(os.environ.get("VERIDICT_CANARY_BATCH", "3"))
CORPUS = os.path.join(ROOT, "corpus", "corpus.jsonl")


def ollama_restart():
    """Kill and restart ollama serve, wait until it answers.

    NOTE: pattern is matched against the full executable path
    (/usr/local/bin/ollama serve), not a fragment, because a fragment
    like 'ollama serve' also matches THIS script's own command line and
    would make the wrapper kill itself.
    """
    subprocess.run(["pkill", "-f", "/usr/local/bin/ollama serve"],
                   capture_output=True, timeout=30)
    time.sleep(4)
    subprocess.Popen(["/usr/local/bin/ollama", "serve"], stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    for _ in range(60):
        try:
            import httpx
            httpx.get("http://127.0.0.1:11434/api/version", timeout=3)
            return True
        except Exception:
            time.sleep(2)
    return False


def run_batch(lines, batch_no):
    """Run one batch of cases through the real-LLM canary. Returns the
    sheet, or None if the batch wedged."""
    tmp_corpus = f"/tmp/canary-batch-{batch_no}.jsonl"
    with open(tmp_corpus, "w") as f:
        for l in lines:
            f.write(json.dumps(l) + "\n")
    env = dict(os.environ)
    proc = subprocess.Popen(
        [sys.executable, "-c", f"""
import sys; sys.path.insert(0, {ROOT!r})
from veridict.canary import CanaryRunner
from scripts.canary_real_llm import _audit_fn
import json
sheet = CanaryRunner(_audit_fn()).run({tmp_corpus!r})
print(json.dumps(sheet))
"""], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, cwd=ROOT)
    try:
        out, err = proc.communicate(timeout=60 * 12)
        if proc.returncode != 0 or not out.strip():
            print(f"  batch {batch_no}: WEDGED (rc={proc.returncode})",
                  file=sys.stderr)
            return None
        return json.loads(out.strip().splitlines()[-1])
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        print(f"  batch {batch_no}: TIMEOUT — ollama wedged", file=sys.stderr)
        return None


def main():
    lines = [json.loads(l) for l in open(CORPUS) if l.strip()]
    print(f"corpus: {len(lines)} cases, batch size {BATCH}")
    all_cases, per_class, fp, retries = [], {}, 0, 0

    i = 0
    while i < len(lines):
        batch = lines[i:i + BATCH]
        batch_no = i // BATCH
        sheet = run_batch(batch, batch_no)
        if sheet is None:
            retries += 1
            print(f"  restarting ollama and retrying batch {batch_no}",
                  file=sys.stderr)
            if not ollama_restart():
                print("  ollama would not come back; aborting", file=sys.stderr)
                break
            sheet = run_batch(batch, batch_no)
            if sheet is None:
                print(f"  batch {batch_no} failed twice; skipping",
                      file=sys.stderr)
                i += len(batch)
                continue
        for c in sheet["cases"]:
            all_cases.append(c)
            cls = per_class.setdefault(c["defect_class"] if "defect_class" in c
                                       else c["id"],
                                      {"caught": 0, "total": 0})
            # per_class needs defect_class; canary sheet cases have id only,
            # so map back from the corpus
        fp += sheet.get("false_positives", 0)
        done = len(all_cases)
        print(f"  batch {batch_no}: done {done}/{len(lines)}"
              f" caught={sheet['caught_total']}")
        i += len(batch)

    # rebuild per_class from corpus + results
    by_id = {c["id"]: c for c in all_cases}
    per_class = {}
    for case in lines:
        cid = case["id"]
        cls = per_class.setdefault(case["defect_class"], {"caught": 0, "total": 0})
        cls["total"] += 1
        if cid in by_id and by_id[cid]["caught"]:
            cls["caught"] += 1

    caught = sum(1 for c in all_cases if c["caught"])
    total_defect = sum(1 for c in lines if c["ground_truth"] == "DEFECT")
    result = {
        "cases_processed": len(all_cases),
        "cases_total": len(lines),
        "caught_total": caught,
        "defect_total": total_defect,
        "false_positives": fp,
        "per_class": per_class,
        "batch_retries": retries,
    }
    print("\n=== SONUÇ (gerçek LLM jüri) ===")
    print(f"işlenen     : {result['cases_processed']}/{result['cases_total']}")
    print(f"yakalanan   : {caught}/{total_defect}")
    print(f"yanlış poz. : {fp}")
    print(f"batch retry : {retries}")
    out = os.environ.get("VERIDICT_CANARY_OUT")
    if out:
        with open(out, "w") as f:
            json.dump(result, f, indent=2)
        print(f"yazıldı: {out}")


if __name__ == "__main__":
    main()
