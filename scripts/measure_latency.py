#!/usr/bin/env python
"""Measure GATE-mode end-to-end audit latency (design §6.5: p95 < 30 min).

Runs N audits of a representative tiny PR fixture (source + test file) with
the standard stub jury, in fresh ledgers, and reports p50/p95 against the
budget. The stub jury keeps this a MEASUREMENT OF PLUMBING (ledger, verify,
ladder, certificate issuance + offline verify), not of LLM latency — juror
latency is a deployment property, reported separately in production.
Exit 1 if p95 exceeds the §6.5 budget.
"""
from __future__ import annotations

import os
import statistics
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.dogfood import _write_segment_fixture, _segment_task
from veridict.canary import build_orchestrator
from veridict.certificate import verify_certificate
from veridict.policy import PolicyDeclaration, Thresholds

BUDGET_SECONDS = 30 * 60        # design §6.5 GATE p95
RUNS = int(os.environ.get("LATENCY_RUNS", "5"))


def main() -> int:
    times: list[float] = []
    with tempfile.TemporaryDirectory(prefix="vd-latency-") as root:
        fixture = os.path.join(root, "fixture")
        os.makedirs(fixture)
        _write_segment_fixture(fixture)
        for i in range(RUNS):
            pol = PolicyDeclaration(policy_id="latency-gate", mode="GATE",
                                    criticality=(), thresholds=Thresholds(),
                                    divergence_tolerance=1 / 3)
            orch = build_orchestrator(pol)
            task = _segment_task(f"latency-{i}", fixture)
            import time
            t0 = time.monotonic()
            result = orch.run(task)
            ledger_path = os.path.join(root, f"led{i}.jsonl")
            cert_path = os.path.join(root, f"cert{i}.json")
            orch.ledger.save(ledger_path)
            import json
            with open(cert_path, "w", encoding="utf-8") as f:
                json.dump(result["cert"], f)
            verify_certificate(ledger_path, cert_path)
            times.append(time.monotonic() - t0)
    p50 = statistics.median(times)
    p95 = statistics.quantiles(times, n=20)[18] if len(times) > 1 else times[0]
    print(f"runs={RUNS} p50={p50:.2f}s p95={p95:.2f}s "
          f"budget={BUDGET_SECONDS}s (design §6.5)")
    ok = p95 < BUDGET_SECONDS
    print("PASS" if ok else "FAIL: p95 exceeds §6.5 GATE budget")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
