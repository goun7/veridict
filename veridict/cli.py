"""CLI (Phase 1): audit / verify / quality-sheet. Exit: 0 ok, 1 invalid, 2 blocked."""
from __future__ import annotations

import argparse
import json
import os
import sys

from .audit import AuditOrchestrator
from .certificate import verify_certificate
from .dossier import dossier_for, render_markdown, resolve_dossier
from .jury import Jury, OpenAICompatProvider, Opinion, ScriptedProvider
from .keys import KeyStore
from .ledger import Ledger
from .policy import PolicyDeclaration, Thresholds, load_policy
from .schemas import TaskManifest

DEFAULT_POLICY = PolicyDeclaration(
    policy_id="default-hybrid", mode="HYBRID", criticality=(),
    thresholds=Thresholds(), divergence_tolerance=1 / 3)


class _Parser(argparse.ArgumentParser):
    """Usage errors exit 1 (invalid input), not argparse's 2 (which collides
    with the gate-blocked exit code)."""
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"veridict: error: {message}", file=sys.stderr)
        raise SystemExit(1)


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


def _load_watchers(specs, ledger, keystore, key_id, warnings):
    """Resolve --watcher specs ("manifest.json:your_module:judge_fn") into
    sessions registered in the audit ledger. The manifest's integrity
    code_hash is verified against the sha256 of the entry module file — a
    watcher whose code does not match its manifest is refused outright."""
    if not specs:
        return (), None
    import importlib
    import hashlib
    from veridict.watchers import ManifestRegistry, WatcherManifest, WatcherSession
    registry = ManifestRegistry(ledger, keystore, key_id)
    sessions = []
    for spec in specs:
        try:
            mpath, modname, fnname = spec.split(":", 2)
        except ValueError:
            raise SystemExit(f"--watcher {spec!r}: expected manifest.json:module:fn")
        with open(mpath, encoding="utf-8") as f:
            manifest = WatcherManifest.from_dict(json.load(f))
        mod = importlib.import_module(modname)
        fn = getattr(mod, fnname, None)
        if not callable(fn):
            raise SystemExit(f"--watcher {spec!r}: {modname}.{fnname} is not callable")
        mod_file = getattr(mod, "__file__", None)
        if mod_file and manifest.integrity.get("code_hash"):
            actual = hashlib.sha256(open(mod_file, "rb").read()).hexdigest()
            if actual != manifest.integrity["code_hash"]:
                raise SystemExit(
                    f"--watcher {spec!r}: code_hash mismatch (manifest "
                    f"{manifest.integrity['code_hash'][:16]}… vs module {actual[:16]}…)")
        registry.register(manifest)
        sessions.append(WatcherSession(
            manifest, lambda claim_summary, digest, _f=fn: _f(claim_summary, digest)))
        warnings.append(f"watcher {manifest.watcher_id} registered and wired (§6)")
    return sessions, ledger


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
            disclosure_level=policy.disclosure_level,
            response_window_hours=policy.response_window_hours,
            deliberation_rounds=policy.deliberation_rounds)
    ledger = Ledger()
    keystore = KeyStore(ledger)
    key_id = keystore.generate_and_enroll("veridict-core")   # same ledger as saved (offline verify)
    jury, warnings = _build_jury()
    sessions, registry = _load_watchers(getattr(args, "watcher", None), ledger,
                                        keystore, key_id, warnings)
    orch = AuditOrchestrator(ledger, policy, jury, keystore, key_id,
                             watchers=tuple(sessions), registry=registry)
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
    import os

    from .canary import CanaryRunner, build_orchestrator   # lazy: keeps `verify` offline-clean
    sheet = CanaryRunner(lambda task, disclosure: build_orchestrator(
        DEFAULT_POLICY).run(task, disclosure)).run(args.corpus)
    # R5 honesty note: the CLI cannot reach the seeded provider-overrides path
    # (programmatic only), so a plain-CLI sheet runs on unseeded stub jurors.
    # State that IN the sheet — caught_total: 0 from stubs is a build fact,
    # not a quality verdict.
    if not (os.environ.get("VERIDICT_JURY_URL") or os.environ.get("VERIDICT_JURY_URL2")):
        sheet["jury_context"] = ("stub jury (no VERIDICT_JURY_URL* seeded) — "
                                 "catches require seeded provider overrides; "
                                 "see tests/test_canary.py")
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(sheet, f, indent=2, sort_keys=True)
    print(json.dumps(sheet["per_class"], indent=2))
    return 0


def _cmd_dossier(args) -> int:
    ledger = Ledger.load(args.ledger)
    d = dossier_for(ledger, args.claim_id)
    if d is None:
        raise ValueError(f"no dossier issued for claim {args.claim_id}")
    md = render_markdown(d)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(md)
    else:
        print(md, end="")
    return 0


def _cmd_resolve(args) -> int:
    ledger = Ledger.load(args.ledger)
    entry = resolve_dossier(ledger, args.dossier_id, args.decision,
                            args.decided_by, risk_note=args.note or "")
    ledger.save(args.ledger)
    print(f"recorded {entry['payload']['decision']} by "
          f"{entry['payload']['decided_by']} for dossier "
          f"{entry['payload']['dossier_id']}")
    return 0


def _cmd_index(args) -> int:
    from .registry_index import build_index, validate_index   # offline-safe
    ledger = Ledger.load(args.ledger)
    idx = build_index(ledger)
    if args.validate:
        report = validate_index(idx, ledger)
        print(json.dumps(report))
        return 0 if report["valid"] else 1
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(idx, f, indent=2, sort_keys=True)
    print(json.dumps(idx, indent=2))
    return 0


def main(argv=None) -> int:
    p = _Parser(prog="veridict")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit")
    a.add_argument("--task", required=True)
    a.add_argument("--mode", choices=("CERTIFICATE", "GATE", "WATCH", "HYBRID"))
    a.add_argument("--policy")
    a.add_argument("--ledger", required=True)
    a.add_argument("--cert-out", required=True)
    a.add_argument("--watcher", action="append", metavar="MANIFEST:MODULE:FN",
                   help="wire an external watcher: manifest JSON + module:fn "
                        "entry point; code_hash is verified against the module")
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
    dos = sub.add_parser("dossier")
    dos.add_argument("--ledger", required=True)
    dos.add_argument("--claim-id", required=True)
    dos.add_argument("--out")
    dos.set_defaults(func=_cmd_dossier)
    res = sub.add_parser("resolve")
    res.add_argument("--ledger", required=True)
    res.add_argument("--dossier-id", required=True)
    res.add_argument("--decision", required=True)
    res.add_argument("--decided-by", required=True)
    res.add_argument("--note")
    res.set_defaults(func=_cmd_resolve)
    idx = sub.add_parser("index")
    idx.add_argument("--ledger", required=True)
    idx.add_argument("--out")
    idx.add_argument("--validate", action="store_true")
    idx.set_defaults(func=_cmd_index)
    # argparse raises SystemExit on usage errors / --help; convert to a return
    # code so in-process callers (and `sys.exit(main())`) see exit 1, not a
    # raised exception. Dispatch errors below never raise SystemExit.
    try:
        args = p.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0
    try:
        return args.func(args)
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"veridict: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
