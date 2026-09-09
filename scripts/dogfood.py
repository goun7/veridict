"""Self-audit: Veridict audits its own repository (§7.3 mechanism 1)."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.canary import build_orchestrator          # noqa: E402
from veridict.certificate import verify_certificate     # noqa: E402
from veridict.policy import PolicyDeclaration, Thresholds, load_policy  # noqa: E402
from veridict.schemas import TaskManifest               # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def dogfood(run_root: str = REPO_ROOT, jury_overrides: dict | None = None) -> dict:
    if os.environ.get("VERIDICT_DOGFOOD_ACTIVE"):
        raise RuntimeError("dogfood() re-entered — refusing recursive self-audit")
    os.environ["VERIDICT_DOGFOOD_ACTIVE"] = "1"
    policy_path = os.path.join(run_root, "dogfood_policy.json")
    if os.path.exists(policy_path):
        with open(policy_path, encoding="utf-8") as f:
            pol = load_policy(json.load(f))
    else:
        pol = PolicyDeclaration(
            policy_id="dogfood-fallback-hybrid", mode="HYBRID", criticality=(),
            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    task = TaskManifest(
        task_id="dogfood-v0.1", artifact_path=run_root, actor_identity="veridict-v0.1",
        intent_lines=("DOCTRINE: core modules are idiomatic python",),
        criticality=(), has_existing_tests=True,
        pytest_args=("--ignore=tests/test_dogfood.py",))
    orch = build_orchestrator(pol, provider_overrides=jury_overrides or {})
    result = orch.run(task)
    ledger_path = os.path.join(run_root, "dogfood_ledger.jsonl")
    cert_path = os.path.join(run_root, "dogfood_cert.json")
    orch.ledger.save(ledger_path)
    with open(cert_path, "w", encoding="utf-8") as f:
        json.dump(result["cert"], f, indent=2, sort_keys=True)
    verification = verify_certificate(ledger_path, cert_path)
    return {**result, "verification": verification,
            "ledger_path": ledger_path, "cert_path": cert_path}


if __name__ == "__main__":
    out = dogfood()
    print(json.dumps({"risk_level": out["cert"]["risk_level"],
                      "score": out["cert"]["score"],
                      "blocked": out["outcome"].blocked,
                      "verification": out["verification"],
                      "duration_seconds": out["report"]["duration_seconds"]}, indent=2))
