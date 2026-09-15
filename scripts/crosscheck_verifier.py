#!/usr/bin/env python3
"""Verifier parity harness (issue #1 kit).

Runs BOTH shipped Python verifiers over the same corpus and asserts they
agree with the pinned expectations and with each other:

  docs/standard-test-vectors/{ledger.jsonl,certificate.json}  vs expected_verify.json
  dogfood_ledger.jsonl + dogfood_cert.json                    vs valid:true

The ladder-level parity (reference `veridict.ladder` vs the spec-only
implementation on every `ladder_vectors.json` case) is already pinned at
build time by `tests/test_contract_vectors.py` and machine-checked beyond it
by `proofs/ladder` (28,080-row Lean oracle) — this script covers the
END-TO-END report: chain + signature + certificate binding + verdict
recomputation as one observable output.

External verifier implementations (issue #1) should reach the SAME report
from the spec alone: run this with --extra pointing at a module exposing
`verify_certificate(ledger_path, cert_path) -> report-dict` — the shape of
`expected_verify.json`. Exit 0 == parity proven on this corpus.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VEC = ROOT / "docs" / "standard-test-vectors"


def ref_verify(ledger: Path, cert: Path) -> dict:
    code = ("import json, sys; sys.argv = ['veridict', 'verify',"
            " '--ledger', sys.argv[1], '--cert', sys.argv[2]];"
            " from veridict.cli import main; sys.exit(main())")
    proc = subprocess.run([sys.executable, "-c", code, str(ledger), str(cert)],
                          capture_output=True, text=True, cwd=ROOT)
    # rc 1 means "invalid report", which is still a valid JSON answer
    if not proc.stdout.strip():
        raise SystemExit(f"reference verify produced no output: {proc.stderr}")
    return json.loads(proc.stdout)


def load_spec_verifier():
    path = ROOT / "examples" / "spec_verifier.py"
    spec = importlib.util.spec_from_file_location("spec_verifier", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--extra", help="external verifier module exposing verify_certificate()")
    args = ap.parse_args()

    want = json.loads((VEC / "expected_verify.json").read_text(encoding="utf-8"))
    failures: list[str] = []
    spec = load_spec_verifier()

    # 1. reference CLI on the vectors: exact match with the pinned expectation.
    rep = ref_verify(VEC / "ledger.jsonl", VEC / "certificate.json")
    if rep != want:
        failures.append(f"vectors/reference: {rep}")

    # 2. spec-only verifier on the vectors: same report, byte-for-byte.
    rep = spec.verify_certificate(str(VEC / "ledger.jsonl"), str(VEC / "certificate.json"))
    if rep != want:
        failures.append(f"vectors/spec_verifier: {rep}")

    # 3. dogfood trio: both shipped verifiers must say valid, and agree.
    dl, dc = ROOT / "dogfood_ledger.jsonl", ROOT / "dogfood_cert.json"
    r1 = ref_verify(dl, dc)
    r2 = spec.verify_certificate(str(dl), str(dc))
    if not r1.get("valid"):
        failures.append(f"dogfood/reference: invalid {r1.get('errors')}")
    if not r2.get("valid"):
        failures.append(f"dogfood/spec_verifier: invalid {r2.get('errors')}")
    if r1 != r2:
        failures.append(f"dogfood: shipped verifiers disagree:\n  ref={r1}\n  spec={r2}")

    # 4. optional: the external candidate over the same corpus.
    if args.extra:
        s = importlib.util.spec_from_file_location("external_verifier", args.extra)
        mod = importlib.util.module_from_spec(s)
        s.loader.exec_module(mod)
        rep = mod.verify_certificate(str(VEC / "ledger.jsonl"), str(VEC / "certificate.json"))
        if rep != want:
            failures.append(f"external ({args.extra}): {rep}")
        rep2 = mod.verify_certificate(str(dl), str(dc))
        if not rep2.get("valid"):
            failures.append(f"external ({args.extra}) on dogfood: invalid {rep2.get('errors')}")

    if failures:
        print("PARITY FAILED:")
        for f in failures:
            print(" -", f)
        return 1
    print("parity OK: reference CLI == spec_verifier == pinned expectations on "
          "vectors + dogfood" + (f"; external {args.extra} conforms" if args.extra else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
