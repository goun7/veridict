"""CLI (Phase 1): audit / verify / quality-sheet. Exit: 0 ok, 1 invalid, 2 blocked."""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys

from . import anchor, tamga_anchor
from .audit import AuditOrchestrator
from .certificate import (revoke_certificate, verify_certificate,
                          verify_certificate_standalone)
from .receipt import RECEIPT_TYPE, verify_receipt
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
            base_url=os.environ["VERIDICT_JURY_URL2"],
            api_key=os.environ.get("VERIDICT_JURY_KEY2"),
            model=os.environ.get("VERIDICT_JURY_MODEL2")))
    n = 0
    while len(providers) < 2:
        n += 1
        warnings.append(f"jury provider {len(providers) + 1} is a SCRIPTED STUB — "
                        "configure VERIDICT_JURY_URL[/URL2] for real doctrine")
        providers.append(ScriptedProvider(family=f"stub-{n}", identity=f"stub-{n}-1",
                                          default=Opinion("SUPPORTS", 0.8, "stub")))
    return Jury(providers, author_family=os.environ.get("VERIDICT_ACTOR_FAMILY")
                or None), warnings


def _load_watchers(specs, ledger, keystore, key_id, warnings,
                   registry_ledger=None):
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
        if registry_ledger is not None:
            # an external registry is authoritative: the watcher must already
            # be registered there and ACTIVE (§6.6) — self-registration in
            # the audit ledger would bypass the owner's revocation
            if ManifestRegistry.lifecycle_status(registry_ledger,
                                                 manifest.watcher_id) != "active":
                raise SystemExit(
                    f"--watcher {manifest.watcher_id!r}: not registered/active "
                    "in the provided registry (§6.6) — see `veridict registry register`")
            warnings.append(f"watcher {manifest.watcher_id} active in external registry")
        else:
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
    reg_ledger = None
    if getattr(args, "registry", None):
        reg_ledger = Ledger.load(args.registry)
        warnings.append(f"registry loaded: {args.registry} (§6.6 revocation enforced)")
    sessions, _ = _load_watchers(getattr(args, "watcher", None), ledger,
                                 keystore, key_id, warnings, registry_ledger=reg_ledger)
    orch = AuditOrchestrator(ledger, policy, jury, keystore, key_id,
                             watchers=tuple(sessions), registry=reg_ledger)
    result = orch.run(task, disclosure_level=args.disclosure)
    ledger.save(args.ledger)
    with open(args.cert_out, "w", encoding="utf-8") as f:
        json.dump(result["cert"], f, indent=2, sort_keys=True)
    anchor_info = None
    if getattr(args, "anchor", "none") == "rekor":
        from . import anchor as anchor_mod     # lazy: offline-first surface
        target = args.anchor_out or (args.cert_out + ".anchor.json")
        entries = [json.loads(l) for l in open(args.ledger, encoding="utf-8")
                   if l.strip()]
        try:
            sidecar = anchor_mod.publish(entries, result["cert"],
                                         rekor_url=args.rekor_url)
            with open(target, "w", encoding="utf-8") as f:
                json.dump(sidecar, f, indent=2, sort_keys=True)
            anchor_info = {"out": target, "uuid": sidecar["rekor"]["uuid"],
                           "logIndex": sidecar["rekor"]["entry"].get("logIndex")}
        except Exception as exc:               # anchor is hardening, never a
            anchor_info = {"error": str(exc)}  # silent-pass risk: it reports
            if getattr(args, "anchor_required", False):
                raise
    elif getattr(args, "anchor", "none") == "tamga":
        from . import tamga_anchor             # mesh-local anchor transport
        sidecar_target = args.anchor_out or (args.cert_out + ".anchor.json")
        ledger_target = args.anchor_ledger or (args.cert_out + ".tamga.jsonl")
        entries = [json.loads(l) for l in open(args.ledger, encoding="utf-8")
                   if l.strip()]
        try:
            sidecar = tamga_anchor.publish(
                entries, result["cert"], ledger_target,
                node_key=getattr(args, "anchor_node_key", None))
            with open(sidecar_target, "w", encoding="utf-8") as f:
                json.dump(sidecar, f, indent=2, sort_keys=True)
            anchor_info = {"out": sidecar_target, "ledger": ledger_target,
                           "seq": sidecar["tamga"]["seq"],
                           "h": sidecar["tamga"]["h"],
                           "node_signed": sidecar["tamga"]["node_signed"]}
        except Exception as exc:               # same discipline as rekor:
            anchor_info = {"error": str(exc)}  # report, never silently pass
            if getattr(args, "anchor_required", False):
                raise
    print(json.dumps({"report": result["report"],
                      "blocked": result["outcome"].blocked,
                      "anchor": anchor_info,
                      "warnings": warnings}, indent=2))
    return 2 if result["outcome"].blocked else 0


def _cmd_verify(args) -> int:
    cert_path = getattr(args, "cert", None) or getattr(args, "cert_pos", None)
    if not cert_path:
        print("veridict: error: a certificate is required (positional or --cert)",
              file=sys.stderr)
        return 1
    ledger = getattr(args, "ledger", None)
    if ledger:
        # The file may be a receipt, not an audit certificate: both share the
        # subject schema and the standalone verifier, but only an audit
        # certificate carries claims for the ladder to replay — a receipt has
        # none, so the certificate_type selects the path. A receipt over a
        # ledger still proves chain integrity, issuance and revocation.
        with open(cert_path, encoding="utf-8") as f:
            ctype = json.load(f).get("certificate_type")
        if ctype == RECEIPT_TYPE:
            report = verify_receipt(cert_path, ledger)
        else:
            report = verify_certificate(ledger, cert_path)
    else:
        # Standalone: the certificate file is the ONLY input. This is the
        # view a third party actually has — someone hands them a receipt —
        # and it proves what a self-contained certificate can prove on its
        # own (content hash, signature, timestamp), reporting the rest as
        # unknown rather than assumed.
        report = verify_certificate_standalone(cert_path)
    if getattr(args, "anchor", None):
        with open(args.anchor, encoding="utf-8") as f:
            sidecar = json.load(f)
        with open(cert_path, encoding="utf-8") as f:
            cert = json.load(f)
        a_res = _anchor_verify(sidecar, cert)
        report["anchor"] = a_res
        report["valid"] = report["valid"] and a_res["valid"]
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


def _cmd_revoke(args) -> int:
    led = Ledger.load(args.ledger)
    with open(args.cert, encoding="utf-8") as f:
        cert = json.load(f)
    cert_id = cert.get("cert_id")
    if not cert_id:
        print("veridict: error: certificate has no cert_id", file=sys.stderr)
        return 1
    entry = revoke_certificate(led, cert_id, args.reason)
    led.save(args.ledger)
    print(json.dumps({"revoked": True, "cert_id": cert_id,
                      "seq": entry["seq"], "reason": args.reason}, indent=2))
    return 0


def _cmd_receipt(args) -> int:
    """Receipt subcommands: signed proof-of-done for agent work.

    Receipts live in a workspace (a directory with an append-only ledger and
    the issuer's local signing key). --workspace selects it; the default is
    $VERIDICT_HOME or ./.veridict."""
    from .receipt import (ReceiptError, ReceiptWorkspace, issue_receipt,
                          list_receipts, revoke_receipt, verify_receipt)
    ws = ReceiptWorkspace.resolve(getattr(args, "workspace", None))
    action = args.action
    if action == "issue":
        try:
            receipt = issue_receipt(
                ws, args.achievement, args.actor, evidence=args.evidence or [],
                issuer_identity=args.issuer)
        except ReceiptError as exc:
            print(f"veridict: error: {exc}", file=sys.stderr)
            return 1
        out = args.out or os.path.join(ws.home, "receipts",
                                       receipt["cert_id"] + ".json")
        os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=2, sort_keys=True)
        print(json.dumps({"issued": True, "cert_id": receipt["cert_id"],
                          "receipt_path": out,
                          "verify": f"veridict verify {out}"}, indent=2))
        return 0
    if action == "verify":
        report = verify_receipt(args.cert, getattr(args, "ledger", None))
        print(json.dumps(report, indent=2))
        return 0 if report["valid"] else 1
    if action == "revoke":
        # You revoke the receipt you hold, not an id you memorized: accept the
        # file (--cert) and read the cert_id out of it, or an explicit --cert-id.
        cert_id = args.cert_id
        if not cert_id and args.cert:
            try:
                with open(args.cert, encoding="utf-8") as f:
                    cert_id = json.load(f).get("cert_id")
            except OSError as exc:
                print(f"veridict: error: cannot read {args.cert}: {exc}",
                      file=sys.stderr)
                return 1
        if not cert_id:
            print("veridict: error: give the receipt to revoke with --cert, "
                  "or its cert_id with --cert-id", file=sys.stderr)
            return 1
        try:
            res = revoke_receipt(ws, cert_id, args.reason,
                                 issuer_identity=getattr(args, "issuer",
                                                         "veridict-receipt"))
        except ReceiptError as exc:
            print(f"veridict: error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({"revoked": True, **res}, indent=2))
        return 0
    if action == "list":
        rows = list_receipts(ws, include_revoked=not args.active_only,
                             limit=args.limit)
        print(json.dumps({"workspace": ws.home, "count": len(rows),
                          "receipts": rows}, indent=2))
        return 0
    print(f"veridict: error: unknown receipt action {action!r}", file=sys.stderr)
    return 1


def _anchor_verify(sidecar: dict, cert: dict) -> dict:
    """Dispatch a sidecar to its transport's verifier.

    Both transports bind the SAME fields (anchor.bound_fields), so a relying
    party mixes them freely; the sidecar's anchor_version selects the
    verifier, and an unknown version is a refusal, not a fallback.
    """
    if sidecar.get("anchor_version") == tamga_anchor.TAMGA_ANCHOR_VERSION:
        return tamga_anchor.verify(sidecar, cert)
    from . import anchor as anchor_mod
    return anchor_mod.verify(sidecar, cert)


def _cmd_anchor(args) -> int:
    transport = getattr(args, "transport", "rekor")
    with open(args.cert, encoding="utf-8") as f:
        cert = json.load(f)
    if args.action == "publish":
        entries = [json.loads(l) for l in open(args.ledger, encoding="utf-8")
                   if l.strip()]
        if transport == "tamga":
            if not args.anchor_ledger:
                print("veridict: error: tamga publish requires --anchor-ledger",
                      file=sys.stderr)
                return 1
            sidecar = tamga_anchor.publish(
                entries, cert, args.anchor_ledger,
                node_key=getattr(args, "anchor_node_key", None))
        else:
            from . import anchor as anchor_mod
            sidecar = anchor_mod.publish(entries, cert,
                                         rekor_url=args.rekor_url)
        text = json.dumps(sidecar, indent=2, sort_keys=True)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        print(text)
        return 0
    with open(args.anchor, encoding="utf-8") as f:
        sidecar = json.load(f)
    res = _anchor_verify(sidecar, cert)
    print(json.dumps(res, indent=2))
    return 0 if res["valid"] else 1


def _cmd_export(args) -> int:
    from . import export as export_mod
    with open(args.cert, encoding="utf-8") as f:
        cert = json.load(f)
    entries = [json.loads(l) for l in open(args.ledger, encoding="utf-8")
               if l.strip()]
    if args.format == "spdx":
        if args.sign:
            print("error: --sign produces a DSSE/in-toto envelope, which "
                  "only wraps VSA statements; SPDX exports carry the "
                  "certificate's own signatures — export the VSA to sign.",
                  file=sys.stderr)
            return 2
        anchor = None
        if args.anchor_file:
            with open(args.anchor_file, encoding="utf-8") as f:
                anchor = json.load(f)
        doc = export_mod.to_spdx(cert, entries, anchor=anchor)
        text = json.dumps(doc, indent=2, sort_keys=True)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        print(text)
        return 0
    statement = export_mod.to_vsa(cert, entries)
    doc = statement
    if args.sign:
        with open(args.sign, encoding="utf-8") as f:
            pem = f.read()
        # Accept BOTH shapes adopters actually have on disk: a raw PEM, or
        # the JSON key file written by `registry init` (keys.export_key_file).
        # In the JSON case its key_id is the default signer — a VSA signer
        # need not be the certificate's issuer, but silently signing with a
        # key whose id we had to invent would be worse than refusing.
        key_hint = ""
        if pem.lstrip().startswith("{"):
            keydata = json.loads(pem)
            pem = keydata["private_pem"]
            key_hint = keydata.get("key_id", "")
        key_id = args.key_id or key_hint or (cert.get("signatures") or [{}])[0].get(
            "key_id", "")
        doc = {"envelope": export_mod.dsse_envelope(statement, pem, key_id),
               "statement": statement}
    text = json.dumps(doc, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text + "\n")
    print(text)
    return 0


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


def _cmd_settle(args) -> int:
    """Turn a verified certificate into a settlement claim, or reconcile one.

    A payment layer cannot take an agent's word that work was done. This
    emits a claim derived ONLY from certificate fields, then — when
    --claim is given — reconciles the presented claim against the
    certificate from scratch, so a tampered or inflated claim is caught
    instead of paid. The certificate itself must already be verified;
    this command never verifies it.
    """
    from .settlement import (SettlementPolicy, build_settlement_claim,
                             verify_settlement_claim)
    policy = SettlementPolicy(
        max_risk=args.max_risk,
        min_jury_families=args.min_jury_families,
        min_claim_coverage=args.min_coverage,
    )
    with open(args.cert, encoding="utf-8") as f:
        cert = json.load(f)
    if args.claim:
        with open(args.claim, encoding="utf-8") as f:
            presented = json.load(f)
        report = verify_settlement_claim(presented, cert, policy)
        print(json.dumps(report, indent=2, sort_keys=True))
        # rc 1 = the claim does not hold: it is internally inconsistent
        # (edited after issuance), does not follow from this certificate
        # under this policy, or the certificate itself does not qualify.
        # rc 0 only when the claim is valid — meaning the certificate was
        # verified independently AND satisfies the settlement policy.
        return 0 if report.get("valid", False) else 1
    claim = build_settlement_claim(cert, policy)
    payload = dataclasses.asdict(claim)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _cmd_registry(args) -> int:
    from veridict.registry_index import build_index, export_index, validate_index
    from veridict.watchers import ManifestRegistry, WatcherManifest
    action = args.action
    if action == "init":
        led = Ledger()
        ks = KeyStore(led)
        kid = ks.generate_and_enroll("registry-owner")
        led.save(args.registry)
        key_file = args.key_out or (args.registry + ".key.json")
        ks.export_key_file(kid, key_file)
        print(json.dumps({"registry": args.registry, "key_id": kid,
                          "key_file": key_file,
                          "note": "private key — keep secret, needed for register/revoke"}))
        return 0
    led = Ledger.load(args.registry)
    ks = KeyStore(led)
    kid = args.key_id or next(
        (e["payload"]["key_id"] for e in led.query("key.enrolled")), None)
    if kid is None:
        raise SystemExit("registry has no enrolled key — run `veridict registry init`")
    reg = None
    if action in ("register", "revoke"):
        if not args.key_file:
            raise SystemExit(
                "--key-file required for register/revoke (private key exported "
                "by `registry init`; signing power lives there, never in the ledger)")
        kid = ks.load_key_file(args.key_file)
        reg = ManifestRegistry(led, ks, kid)
    else:
        reg = ManifestRegistry(led, ks, kid)
    if action == "register":
        with open(args.manifest, encoding="utf-8") as f:
            manifest = WatcherManifest.from_dict(json.load(f))
        entry = reg.register(manifest)
        led.save(args.registry)
        print(json.dumps({"registered": manifest.watcher_id, "seq": entry["seq"]}))
    elif action == "revoke":
        entry = reg.revoke(args.watcher_id, args.reason)
        led.save(args.registry)
        print(json.dumps({"revoked": args.watcher_id, "seq": entry["seq"],
                          "reason": args.reason}))
    elif action == "list":
        seen: dict = {}
        for e in led.entries:
            if e["entry_type"] == "watcher.registered":
                wid = e["payload"]["manifest"]["watcher_id"]
                seen.setdefault(wid, []).append(
                    (e["seq"], "registered", e["payload"]["manifest"]["version"]))
            elif e["entry_type"] == "watcher.revoked":
                seen.setdefault(e["payload"]["watcher_id"], []).append(
                    (e["seq"], "revoked", e["payload"]["reason"]))
        for wid, events in sorted(seen.items()):
            status = ManifestRegistry.lifecycle_status(led, wid)
            print(f"{wid}\t{status}\t"
                  + "; ".join(f"{seq}:{what}" for seq, what, _ in events))
    elif action == "index":
        idx = build_index(led)
        report = validate_index(idx, led)
        if not report["valid"]:
            raise SystemExit(f"index does not validate: {report['errors']}")
        export_index(led, args.out)
        print(json.dumps({"out": args.out,
                          "watchers": [w["watcher_id"] for w in idx["watchers"]]}))
    else:
        raise SystemExit(f"unknown registry action: {action}")
    return 0


def _cmd_watch(args) -> int:
    """WATCH-mode streaming transport (§10.3, v1.1-draft A1): tail a growing
    ledger and print `watch.observed` batches as JSON lines. WATCH never
    blocks the writer and never appends to the ledger — read-only observer."""
    policy = load_policy(args.policy) if args.policy else DEFAULT_POLICY
    if args.mode:
        policy = PolicyDeclaration(
            policy_id=policy.policy_id, mode=args.mode,
            criticality=policy.criticality, thresholds=policy.thresholds,
            divergence_tolerance=policy.divergence_tolerance,
            disclosure_level=policy.disclosure_level,
            response_window_hours=policy.response_window_hours,
            deliberation_rounds=policy.deliberation_rounds)
    from .watcher_stream import LedgerStream, stream_summary
    stream = LedgerStream(args.ledger, policy, poll_interval=args.poll_interval)
    idle = 0.0 if args.forever else args.idle_timeout
    for obs in stream.observations(max_batches=args.max_batches,
                                   idle_timeout=(idle or None)):
        print(json.dumps(stream_summary(obs), sort_keys=True), flush=True)
    return 0


def main(argv=None) -> int:
    p = _Parser(prog="veridict")
    from .export import _veridict_version
    p.add_argument("--version", action="version",
                   version=f"veridict {_veridict_version()}")
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
    a.add_argument("--registry", metavar="REGISTRY_JSONL",
                   help="external registry ledger: watchers must be registered "
                        "and ACTIVE there (§6.6); revocation is enforced")
    a.add_argument("--disclosure", default="REDACTED",
                   choices=("LOCAL_ONLY", "REDACTED", "FULL"))
    a.add_argument("--anchor", choices=("none", "rekor", "tamga"), default="none",
                   help="pin the certificate's checkpoint to a transparency "
                        "surface: rekor = the public Sigstore log (external); "
                        "tamga = the mesh's own anchor layer, a Tamga-grammar "
                        "hash-chained ledger (offline, no third party)")
    a.add_argument("--anchor-out",
                   help="where to write the anchor sidecar JSON "
                        "(default: <cert-out>.anchor.json)")
    a.add_argument("--anchor-ledger",
                   help="tamga transport: the Tamga-grammar ledger file to "
                        "append the checkpoint into "
                        "(default: <cert-out>.tamga.jsonl)")
    a.add_argument("--anchor-node-key", metavar="HEX",
                   help="tamga transport: ed25519 node key (64-hex) cosigning "
                        "the anchor record (L1 node-cosign; optional)")
    a.add_argument("--rekor-url", default=anchor.REKOR_SERVER)
    a.add_argument("--anchor-required", action="store_true",
                   help="fail the run if the anchor cannot be published "
                        "(default: report the failure and keep the certificate)")
    a.set_defaults(func=_cmd_audit)
    an = sub.add_parser("anchor")
    an.add_argument("action", choices=("publish", "verify"))
    an.add_argument("--transport", choices=("rekor", "tamga"), default="rekor",
                    help="which anchor transport (the sidecar's "
                         "anchor_version selects the verifier on `verify`)")
    an.add_argument("--ledger", required=True)
    an.add_argument("--cert", required=True)
    an.add_argument("--out", help="publish: write the sidecar here")
    an.add_argument("--anchor", help="verify: the sidecar JSON to check")
    an.add_argument("--anchor-ledger",
                    help="tamga publish: the ledger file to append into")
    an.add_argument("--anchor-node-key", metavar="HEX",
                    help="tamga publish: ed25519 node key cosigning the record")
    an.add_argument("--rekor-url", default=anchor.REKOR_SERVER)
    an.set_defaults(func=_cmd_anchor)
    e = sub.add_parser("export")
    e.add_argument("--format", choices=("vsa", "spdx"), required=True,
                   help="vsa: SLSA v1.2 Verification Summary Attestation "
                        "(in-toto Statement); spdx: SPDX 3.0.1 AI-profile "
                        "JSON-LD document. Both lossy projections — the "
                        "certificate stays authoritative)")
    e.add_argument("--cert", required=True)
    e.add_argument("--ledger", required=True)
    e.add_argument("--anchor-file", metavar="SIDECAR",
                   help="with --format spdx: embed the anchoring receipt "
                        "(written by audit --anchor-out) as an ExternalRef")
    e.add_argument("--out")
    e.add_argument("--sign", metavar="KEYFILE",
                   help="wrap in a DSSE envelope signed with this Ed25519 "
                        "PEM private key (default: unsigned statement)")
    e.add_argument("--key-id", help="keyid for the DSSE signature "
                                     "(default: the certificate's signer key)")
    e.set_defaults(func=_cmd_export)
    r = sub.add_parser("registry")
    r.add_argument("action", choices=("init", "register", "revoke", "list", "index"))
    r.add_argument("--registry", required=True)
    r.add_argument("--manifest")
    r.add_argument("--watcher-id")
    r.add_argument("--reason", default="")
    r.add_argument("--key-id")
    r.add_argument("--key-out", help="init: where to write the private key file")
    r.add_argument("--key-file", help="register/revoke: private key file from init")
    r.add_argument("--out")
    r.set_defaults(func=_cmd_registry)
    v = sub.add_parser(
        "verify",
        help="verify a certificate. Standalone (positional cert, no ledger) "
             "checks content hash + signature + timestamp from the file "
             "alone; with --ledger it also replays verdicts and checks "
             "revocation")
    v.add_argument("cert_pos", nargs="?", metavar="CERT",
                   help="certificate JSON — positional form, standalone: "
                        "`veridict verify cert.json` needs nothing else")
    v.add_argument("--ledger",
                   help="issuer's ledger: enables full verdict replay and "
                        "revocation checking (omitting it gives standalone "
                        "verification, which reports those as unknown)")
    v.add_argument("--cert", help="certificate JSON (alternative to the "
                                  "positional form)")
    v.add_argument("--anchor", help="also verify an external anchor sidecar "
                                    "(transparency-log receipt) against the cert")
    v.set_defaults(func=_cmd_verify)
    rk = sub.add_parser(
        "revoke",
        help="append a certificate.revoked entry to the ledger — the "
             "certificate file is never modified, so its signature stays "
             "intact and the revocation is auditable in the same chain")
    rk.add_argument("--ledger", required=True)
    rk.add_argument("--cert", required=True, help="certificate JSON to revoke")
    rk.add_argument("--reason", default="")
    rk.set_defaults(func=_cmd_revoke)
    rec = sub.add_parser(
        "receipt",
        help="signed proof-of-done for agent work: issue / verify / revoke / "
             "list. A receipt is a self-contained signed document whose "
             "content hash and signature anyone can recompute from the file "
             "alone (veridict verify <receipt.json>)")
    rec.add_argument("action", choices=("issue", "verify", "revoke", "list"))
    rec.add_argument("--workspace", help="workspace dir (ledger + issuer key); "
                                          "default $VERIDICT_HOME or ./.veridict")
    rec.add_argument("--achievement", help="issue: the falsifiable statement the "
                                           "receipt certifies")
    rec.add_argument("--actor", default="", help="issue: identity of the agent "
                                                  "that did the work")
    rec.add_argument("--evidence", action="append", default=[],
                     help="issue: a ground the issuer relied on (repeatable)")
    rec.add_argument("--issuer", default="veridict-receipt",
                     help="issue/revoke: issuer identity")
    rec.add_argument("--cert", help="verify/revoke: the receipt JSON")
    rec.add_argument("--cert-id", help="revoke: the cert_id to revoke "
                                       "(alternative to --cert)")
    rec.add_argument("--reason", default="", help="revoke: why (recorded in "
                                                   "the chain, human-readable)")
    rec.add_argument("--ledger", help="verify: the issuer's ledger, enabling "
                                      "chain + revocation checks")
    rec.add_argument("--out", help="issue: where to write the receipt JSON")
    rec.add_argument("--limit", type=int, default=100, help="list: max rows")
    rec.add_argument("--active-only", action="store_true",
                     help="list: omit revoked receipts")
    rec.set_defaults(func=_cmd_receipt)
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
    st = sub.add_parser(
        "settle",
        help="derive a settlement claim from a verified certificate, or "
             "reconcile a presented claim against its certificate")
    st.add_argument("--cert", required=True,
                   help="certificate JSON (must already be verified)")
    st.add_argument("--claim",
                   help="presented settlement claim JSON to reconcile; "
                        "omit to build a fresh claim")
    st.add_argument("--out", help="write the built claim here")
    st.add_argument("--max-risk", default="low",
                   help="highest risk level willing to settle "
                        "(low < medium < high < critical; default low)")
    st.add_argument("--min-jury-families", type=int, default=2,
                   help="minimum distinct jury families (§5.2; default 2)")
    st.add_argument("--min-coverage", type=float, default=1.0,
                   help="fraction of claims that must be accepted (default 1.0)")
    st.set_defaults(func=_cmd_settle)
    w = sub.add_parser(
        "watch",
        help="WATCH-mode streaming transport: tail a growing ledger, print "
             "watch.observed JSON batches (flags per §10.2; never blocks)")
    w.add_argument("--ledger", required=True)
    w.add_argument("--policy")
    w.add_argument("--mode", choices=("CERTIFICATE", "GATE", "WATCH", "HYBRID"))
    w.add_argument("--poll-interval", type=float, default=0.05,
                   help="seconds between file polls (detection-latency bound)")
    w.add_argument("--max-batches", type=int, default=None,
                   help="stop after N observations (bounded runs, CI receipts)")
    w.add_argument("--idle-timeout", type=float, default=10.0,
                   help="stop after N seconds with no append (default 10; "
                        "ignored with --forever)")
    w.add_argument("--forever", action="store_true",
                   help="never idle-stop (Ctrl-C to end)")
    w.set_defaults(func=_cmd_watch)
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
