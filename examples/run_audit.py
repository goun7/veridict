#!/usr/bin/env python
"""End-to-end demo: audit a tiny artifact with Veridict, then verify the
certificate offline — the two commands an external user actually runs.

This is the runnable version of the README quickstart. It builds a small
fixture (a calculator module with a passing test), audits it with a GATE
policy and the built-in stub jury (deterministic, no network), saves the
ledger + certificate, runs the offline verifier against both, and prints
the certificate's decision summary.

Run:  python examples/run_audit.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.canary import build_orchestrator
from veridict.certificate import verify_certificate
from veridict.policy import PolicyDeclaration, Thresholds
from scripts.dogfood import _write_segment_fixture, _segment_task


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="veridict-demo-") as root:
        fixture = os.path.join(root, "fixture")
        os.makedirs(fixture)
        _write_segment_fixture(fixture)     # calc.py + test_calc.py, both green

        pol = PolicyDeclaration(policy_id="demo-gate", mode="GATE",
                                criticality=(), thresholds=Thresholds(),
                                divergence_tolerance=1 / 3)
        orch = build_orchestrator(pol)
        task = _segment_task("demo-task", fixture,
                             intent_lines=("MACHINE: add computes the sum of "
                                           "two numbers",))
        result = orch.run(task)

        ledger_path = os.path.join(root, "ledger.jsonl")
        cert_path = os.path.join(root, "certificate.json")
        orch.ledger.save(ledger_path)
        with open(cert_path, "w", encoding="utf-8") as f:
            json.dump(result["cert"], f, indent=2, sort_keys=True)

        report = verify_certificate(ledger_path, cert_path)
        oc = result["outcome"]
        print("=== audit outcome ===")
        for cid, per in oc.per_claim.items():
            print(f"  claim {cid[:10]}: {per['value']} ({per['rung']}, "
                  f"divergence={per['divergence']})")
        print(f"  blocked: {oc.blocked} | coverage: {oc.coverage}")
        print("=== offline verification (third party's view) ===")
        print(f"  valid={report['valid']} chain={report['chain_valid']} "
              f"signature={report['signature_valid']} "
              f"verdicts={report['verdicts_match']}")
        print(f"  cert_id: {result['cert']['cert_id']}")
        print(f"  risk_level: {result['cert']['risk_level']} | "
              f"score: {result['cert']['score']}")
        return 0 if report["valid"] and not oc.blocked else 1


if __name__ == "__main__":
    sys.exit(main())
