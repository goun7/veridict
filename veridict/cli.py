"""CLI (Phase 1): audit / verify / quality-sheet. Exit: 0 ok, 1 invalid, 2 blocked."""
from __future__ import annotations

import argparse
import json
import os
import sys

from .audit import AuditOrchestrator
from .certificate import verify_certificate
from .jury import Jury, OpenAICompatProvider, Opinion, ScriptedProvider
from .keys import KeyStore
from .ledger import Ledger
from .policy import PolicyDeclaration, Thresholds, load_policy
from .schemas import TaskManifest

DEFAULT_POLICY = PolicyDeclaration(
    policy_id="default-hybrid", mode="HYBRID", criticality=(),
    thresholds=Thresholds(), divergence_tolerance=1 / 3)


def _build_jury() -> tuple[Jury, list[str]]:
    """Assemble >=2-family jury from env; pad with scripted stubs (warned)."""
    warnings: list[str] = []
    providers = []
    if os.environ.get("VERIDICT_JURY_URL"):
        providers.append(OpenAICompatProvider(family="openai-compat-1", identity="http-1"))
    if os.environ.get("VERIDICT_JURY_URL2"):
        providers.append(OpenAICompatProvider(
            family="openai-compat-2", identity="http-2",
            base_url=os.environ["VERIDICT_JURY_URL2"]))
    n = 0
    while len(providers) < 2:
        n += 1
        warnings.append(f"jury provider {len(providers) + 1} is a SCRIPTED STUB — "
                        "configure VERIDICT_JURY_URL[/URL2] for real doctrine")
        providers.append(ScriptedProvider(family=f"stub-{n}", identity=f"stub-{n}-1",
                                          default=Opinion("SUPPORTS", 0.8, "stub")))
    return Jury(providers), warnings


def _cmd_audit(args) -> int:
    with open(args.task, encoding="utf-8") as f:
        raw = json.load(f)
    task = TaskManifest(
        task_id=raw["task_id"], artifact_path=raw["artifact_path"],
        actor_identity=raw["actor_identity"],
        intent_lines=tuple(raw.get("intent_lines", [])),
        criticality=tuple(raw.get("criticality", [])),
        has_existing_tests=raw.get("has_existing_tests", False),
        pytest_args=tuple(raw.get("pytest_args", [])))
    policy = load_policy(args.policy) if args.policy else DEFAULT_POLICY
    if args.mode:
        policy = PolicyDeclaration(
            policy_id=policy.policy_id, mode=args.mode,
            criticality=policy.criticality, thresholds=policy.thresholds,
            divergence_tolerance=policy.divergence_tolerance,
            disclosure_level=policy.disclosure_level)
    ledger = Ledger()
    keystore = KeyStore(ledger)
    key_id = keystore.generate_and_enroll("veridict-core")   # same ledger as saved (offline verify)
    jury, warnings = _build_jury()
    orch = AuditOrchestrator(ledger, policy, jury, keystore, key_id)
    result = orch.run(task, disclosure_level=args.disclosure)
    ledger.save(args.ledger)
    with open(args.cert_out, "w", encoding="utf-8") as f:
        json.dump(result["cert"], f, indent=2, sort_keys=True)
    print(json.dumps({"report": result["report"],
                      "blocked": result["outcome"].blocked,
                      "warnings": warnings}, indent=2))
    return 2 if result["outcome"].blocked else 0


def _cmd_verify(args) -> int:
    report = verify_certificate(args.ledger, args.cert)
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


def _cmd_quality_sheet(args) -> int:
    from .canary import CanaryRunner, build_orchestrator   # lazy: keeps `verify` offline-clean
    sheet = CanaryRunner(lambda task, disclosure: build_orchestrator(
        DEFAULT_POLICY).run(task, disclosure)).run(args.corpus)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(sheet, f, indent=2, sort_keys=True)
    print(json.dumps(sheet["per_class"], indent=2))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="veridict")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit")
    a.add_argument("--task", required=True)
    a.add_argument("--mode", choices=("CERTIFICATE", "GATE", "WATCH", "HYBRID"))
    a.add_argument("--policy")
    a.add_argument("--ledger", required=True)
    a.add_argument("--cert-out", required=True)
    a.add_argument("--disclosure", default="REDACTED",
                   choices=("LOCAL_ONLY", "REDACTED", "FULL"))
    a.set_defaults(func=_cmd_audit)
    v = sub.add_parser("verify")
    v.add_argument("--ledger", required=True)
    v.add_argument("--cert", required=True)
    v.set_defaults(func=_cmd_verify)
    q = sub.add_parser("quality-sheet")
    q.add_argument("--corpus", required=True)
    q.add_argument("--out", required=True)
    q.set_defaults(func=_cmd_quality_sheet)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
