"""Canary with a REAL LLM jury (not stubs).

This is the measurement the stub runs cannot give: how many of the 20
seeded defect classes does an actual model catch before the witness
refuses to sign?

Usage (you supply the credentials, the script never reads them):

    # One provider family — jury needs TWO, so this is the minimum pair.
    # Two different models from the same gateway count as two families
    # only if they are actually different models (jury §5.2 diversity).
    export VERIDICT_JURY_URL="https://api.openai.com/v1"
    export VERIDICT_JURY_KEY="sk-..."
    export VERIDICT_JURY_MODEL="gpt-4o-mini"

    # Optional second family (recommended — a one-model jury reviewing
    # its own output is the self-preference the §5.2 rule exists for).
    export VERIDICT_JURY_URL2="https://api.openai.com/v1"
    export VERIDICT_JURY_KEY2="sk-..."
    export VERIDICT_JURY_MODEL2="gpt-4o"

    python3 scripts/canary_real_llm.py

Notes:
  - Set VERIDICT_JURY_SAMPLES=3 for a multi-sample mean (slower, less
    noise). At temperature 0 repeated calls are identical, so the
    second sample is drawn at nonzero temperature by design.
  - This writes NO ledger and issues NO certificate on failure: the
    measurement itself is the product. A real audit run would go
    through the CLI (veridict audit) with the same env vars.
"""
from __future__ import annotations

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.canary import CanaryRunner, build_orchestrator
from veridict.jury import OpenAICompatProvider, ProviderError
from veridict.policy import PolicyDeclaration, Thresholds

CORPUS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "corpus", "corpus.jsonl")


def _missing() -> list[str]:
    """Credential gate: refuse to run a 'real' measurement on stubs."""
    miss = []
    if not os.environ.get("VERIDICT_JURY_URL"):
        miss.append("VERIDICT_JURY_URL")
    if not os.environ.get("VERIDICT_JURY_KEY"):
        miss.append("VERIDICT_JURY_KEY")
    if not os.environ.get("VERIDICT_JURY_URL2"):
        miss.append("VERIDICT_JURY_URL2 (second family — a one-model jury "
                    "reviewing its own output is the self-preference §5.2 forbids)")
    if not os.environ.get("VERIDICT_JURY_KEY2"):
        miss.append("VERIDICT_JURY_KEY2")
    return miss


def _audit_fn():
    """The exact production audit path the stub runs use — no shortcut."""
    from tests.test_canary import _audit_fn as prod
    return prod()


def main() -> int:
    miss = _missing()
    if miss:
        print("BU KOŞU STUB DEĞİL — gerçek LLM jüri için credential gerekli.\n",
              file=sys.stderr)
        for m in miss:
            print(f"  eksik: {m}", file=sys.stderr)
        print("\nÖrnek:\n"
              "  export VERIDICT_JURY_URL=https://api.openai.com/v1\n"
              "  export VERIDICT_JURY_KEY=sk-...\n"
              "  export VERIDICT_JURY_MODEL=gpt-4o-mini\n"
              "  export VERIDICT_JURY_URL2=https://api.openai.com/v1\n"
              "  export VERIDICT_JURY_KEY2=sk-...\n"
              "  export VERIDICT_JURY_MODEL2=gpt-4o\n",
              file=sys.stderr)
        return 2

    model1 = os.environ.get("VERIDICT_JURY_MODEL", "gpt-4o-mini")
    model2 = os.environ.get("VERIDICT_JURY_MODEL2")
    print(f"gerçek LLM jüri: [{model1} / {model2}]")
    print(f"corpus          : {CORPUS}\n")

    providers = [
        OpenAICompatProvider(family="llm-a", identity=f"llm-{model1}",
                             base_url=os.environ["VERIDICT_JURY_URL"],
                             api_key=os.environ["VERIDICT_JURY_KEY"],
                             model=model1),
        OpenAICompatProvider(family="llm-b", identity=f"llm-{model2}",
                             base_url=os.environ["VERIDICT_JURY_URL2"],
                             api_key=os.environ["VERIDICT_JURY_KEY2"],
                             model=model2),
    ]
    print(f"jüri            : {len(providers)} sağlayıcı, "
          f"{len({p.family for p in providers})} family (§5.2)\n")

    policy = PolicyDeclaration(policy_id="canary-real-llm", mode="CERTIFICATE",
                               criticality=(), thresholds=Thresholds(),
                               divergence_tolerance=1 / 3)
    orch = build_orchestrator(policy, provider_overrides=None, ledger=None)
    orch.jury.providers = providers  # swap stubs for real ones, keep the harness

    runner = CanaryRunner(_audit_fn)
    t0 = time.time()
    try:
        sheet = runner.run(CORPUS)
    except ProviderError as exc:
        print(f"\nJÜRİ HATASI (sağlayıcı yanıt vermedi): {exc}", file=sys.stderr)
        return 3
    dt = time.time() - t0

    caught = sheet["caught_total"]
    total_defect = sum(1 for c in sheet["cases"] if c["ground_truth"] == "DEFECT")
    fp = sheet["false_positives"]
    print(f"süre   : {dt:.1f}s")
    print(f"sonuç  : {caught}/{total_defect} hata sınıfı yakalandı, "
          f"yanlış pozitif: {fp}")
    print("\nsınıf bazında:")
    for cls, st in sorted(sheet["per_class"].items()):
        flag = "✓" if st["caught"] == st["total"] else "✗"
        print(f"  {flag} {cls:24s} {st['caught']}/{st['total']}")

    # Kaçırdıklarımız — bunlar gerçeğin nerede sınırı olduğunu gösterir.
    missed = [c["id"] for c in sheet["cases"]
              if c["ground_truth"] == "DEFECT" and not c["caught"]]
    if missed:
        print(f"\nKAÇIRILAN ({len(missed)}):")
        for m in missed:
            print(f"  - {m}")

    out = os.environ.get("VERIDICT_CANARY_OUT")
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump({**sheet, "models": [model1, model2],
                       "duration_s": round(dt, 2)}, f, indent=2)
        print(f"\nyazıldı: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
