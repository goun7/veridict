"""Canary protocol v0 (§7.6): seeded defects, blind injection, Quality Sheet."""
from __future__ import annotations

import json
import time

from .audit import AuditOrchestrator
from .jury import Jury, Opinion, ScriptedProvider
from .keys import KeyStore
from .ledger import Ledger
from .policy import PolicyDeclaration
from .schemas import TaskManifest


def build_orchestrator(policy: PolicyDeclaration, provider_overrides: dict | None = None,
                       ledger: Ledger | None = None) -> AuditOrchestrator:
    overrides = provider_overrides or {}
    providers = []
    for family in ("stub-a", "stub-b"):
        ov = overrides.get(family)
        if callable(ov):
            providers.append(ScriptedProvider(family=family, identity=f"{family}-1",
                                              default=Opinion("SUPPORTS", 0.8, "ok"),
                                              fn=ov))
        elif isinstance(ov, Opinion):
            providers.append(ScriptedProvider(family=family, identity=f"{family}-1",
                                              default=ov))
        else:
            providers.append(ScriptedProvider(family=family, identity=f"{family}-1",
                                              default=Opinion("SUPPORTS", 0.8, "ok")))
    ledger = ledger or Ledger()
    keystore = KeyStore(ledger)
    key_id = keystore.generate_and_enroll("canary")
    return AuditOrchestrator(ledger, policy, Jury(providers), keystore, key_id)


class CanaryRunner:
    """Blind injection: canary cases use the exact production audit_fn (§7.6)."""

    def __init__(self, audit_fn) -> None:
        self.audit_fn = audit_fn

    def run(self, corpus_path: str) -> dict:
        cases_out: list[dict] = []
        per_class: dict[str, dict] = {}
        false_positives = 0
        with open(corpus_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                case = json.loads(line)
                task = TaskManifest(
                    task_id=case["id"], artifact_path=case["path"],
                    actor_identity="canary-actor",
                    intent_lines=tuple(case.get("intent", [])),
                    criticality=tuple(case.get("criticality", [])),
                    has_existing_tests=True, pytest_args=())
                result = self.audit_fn(task, "REDACTED")
                # Top-level refusals only. A REFUTED coverage meta-claim is a
                # juror declining to answer a question the ladder asked it,
                # not a finding about the artifact — counting it here would
                # measure the juror's willingness to answer, not whether the
                # audit flags the defect. The certificate carries each claim's
                # predicate; meta-claims are prefixed 'coverage-of-'. This
                # must match policy.py's blocking rule exactly, or the canary
                # measures something the product does not do.
                top = {c["claim_id"] for c in result["cert"].get("claims", [])
                       if not c.get("predicate", "").startswith("coverage-of-")}
                refuted = any(per["value"] == "REFUTED"
                              for cid, per in result["outcome"].per_claim.items()
                              if cid in top)
                flagged = refuted or result["outcome"].blocked
                caught = flagged if case["ground_truth"] == "DEFECT" else False
                if case["ground_truth"] == "CLEAN" and flagged:
                    false_positives += 1
                cases_out.append({"id": case["id"], "ground_truth":
                                  case["ground_truth"], "caught": caught})
                cls = per_class.setdefault(case["defect_class"], {"caught": 0, "total": 0})
                cls["total"] += 1
                cls["caught"] += 1 if caught else 0
        return {"generated_at": time.time(),
                "provider_families": ["stub-a", "stub-b"],
                "cases": cases_out, "per_class": per_class,
                "caught_total": sum(1 for c in cases_out if c["caught"]),
                "false_positives": false_positives}
