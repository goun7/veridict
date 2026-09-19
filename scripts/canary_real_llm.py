"""Canary with a REAL LLM jury (not stubs).

This is the measurement the stub runs cannot give: how many of the 25
seeded defect classes does an actual model catch before the witness
refuses to sign?

Usage (you supply the credentials, the script never reads them):

    # Two different models from the same gateway count as two families
    # (jury §5.2 diversity — a one-model jury reviewing its own output
    # is the self-preference the rule exists to forbid).
    export VERIDICT_JURY_URL="https://api.openai.com/v1"
    export VERIDICT_JURY_KEY="sk-..."
    export VERIDICT_JURY_MODEL="gpt-4o-mini"
    export VERIDICT_JURY_URL2="https://api.openai.com/v1"
    export VERIDICT_JURY_KEY2="sk-..."
    export VERIDICT_JURY_MODEL2="gpt-4o"

    python3 scripts/canary_real_llm.py

Notes:
  - Uses the SAME production jury construction as `veridict audit`
    (veridict.cli._build_jury), so what you measure here is what a real
    audit would do. If only one URL is set, the second juror is a warned
    stub — the script says so loudly instead of measuring silently-hybrid.
  - Set VERIDICT_JURY_SAMPLES=3 for a multi-sample mean.
  - Writes NO ledger and issues NO certificate: the measurement itself
    is the product. A real audit run goes through `veridict audit`.
  - Set VERIDICT_CANARY_OUT=sheet.json to persist the result with model
    names, so the number is attributable rather than anecdotal.
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.canary import CanaryRunner  # noqa: E402
from veridict.policy import PolicyDeclaration, Thresholds  # noqa: E402

CORPUS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "corpus", "corpus.jsonl")


def _audit_fn():
    """Production audit path with the production jury builder.

    The stub canary (tests/test_canary.py) hardcodes scripted jurors
    because CI has no credentials. This is the real one: it delegates to
    veridict.cli._build_jury, which reads the same env vars
    `veridict audit` uses — so a catch here means a real audit would
    have caught it too.
    """
    from veridict.audit import AuditOrchestrator
    from veridict.cli import _build_jury
    from veridict.keys import KeyStore
    from veridict.ledger import Ledger

    def audit(task, disclosure):
        ledger = Ledger()
        ks = KeyStore(ledger)
        kid = ks.generate_and_enroll("canary-real-llm")
        jury, _warn = _build_jury()
        policy = PolicyDeclaration(policy_id="canary-real-llm", mode="CERTIFICATE",
                                   criticality=(), thresholds=Thresholds(),
                                   divergence_tolerance=1 / 3)
        return AuditOrchestrator(ledger, policy, jury, ks, kid).run(task, disclosure)

    return audit


def _jury_description():
    """Which jurors are real, which are stubs — said before the run."""
    real = []
    for i, (u, m) in enumerate([(os.environ.get("VERIDICT_JURY_URL"),
                                 os.environ.get("VERIDICT_JURY_MODEL", "gpt-4o-mini")),
                                (os.environ.get("VERIDICT_JURY_URL2"),
                                 os.environ.get("VERIDICT_JURY_MODEL2"))], 1):
        if u:
            real.append(f"juror {i}: {m} @ {u}")
    stubs = 2 - len(real)
    return real, stubs


def main() -> int:
    real, stubs = _jury_description()
    if not real:
        print("BU KOŞU STUB DEĞİL — gerçek LLM jüri için credential gerekli.\n",
              file=sys.stderr)
        print("  export VERIDICT_JURY_URL=https://api.openai.com/v1", file=sys.stderr)
        print("  export VERIDICT_JURY_KEY=sk-...", file=sys.stderr)
        print("  export VERIDICT_JURY_MODEL=gpt-4o-mini", file=sys.stderr)
        print("  export VERIDICT_JURY_URL2=https://api.openai.com/v1  (2. family)",
              file=sys.stderr)
        print("  export VERIDICT_JURY_KEY2=sk-...", file=sys.stderr)
        print("  export VERIDICT_JURY_MODEL2=gpt-4o\n", file=sys.stderr)
        print("A one-model jury reviewing its own output is the §5.2 self-preference",
              file=sys.stderr)
        print("the rule exists to forbid — set BOTH URLs.\n", file=sys.stderr)
        return 2

    print("gerçek LLM jüri:")
    for r in real:
        print(f"  {r}")
    if stubs:
        print(f"  UYARI: {stubs} juror hâlâ SCRIPTED STUB — sonuç hibrit,"
              " tamamen gerçek değil")
    print(f"corpus: {CORPUS}\n")

    runner = CanaryRunner(_audit_fn())
    t0 = time.time()
    sheet = runner.run(CORPUS)
    dt = time.time() - t0

    caught = sheet["caught_total"]
    total_defect = sum(1 for c in sheet["cases"] if c["ground_truth"] == "DEFECT")
    fp = sheet["false_positives"]
    print(f"\nsüre  : {dt:.1f}s")
    print(f"sonuç : {caught}/{total_defect} hata sınıfı yakalandı,"
          f" yanlış pozitif: {fp}")

    missed = [c["id"] for c in sheet["cases"]
              if c["ground_truth"] == "DEFECT" and not c["caught"]]
    if missed:
        print(f"\nKAÇIRILAN ({len(missed)}):")
        for m in missed:
            print(f"  - {m}")

    out = os.environ.get("VERIDICT_CANARY_OUT")
    if out:
        payload = {**sheet, "real_jurors": real, "stub_jurors": stubs,
                   "duration_s": round(dt, 2)}
        with open(out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"\nyazıldı: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
