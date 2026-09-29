"""Self-audit: Veridict audits its own repository (§7.3 mechanism 1).

v0.2: before the main self-audit, a Phase 2 segment (§8 exit criteria) runs
against a synthetic fixture artifact in a temp dir — ① the three example
watchers register and run blind sessions, ② a critical doctrinal SPLIT goes
the full turn (escalation → dossier → simulated human decision → ledger
return), ③ calibration accumulates across two audit passes on the SAME
ledger. The main audit runs LAST so the certificate anchors the final ledger
state; verify_certificate recomputes verdicts only for the cert's own claims,
and segment claims use distinct task ids, so pre-cert segment entries cannot
disturb the main verdicts.

v0.3 anti-recursion + hard budget: the audit's W1a evidence re-runs the
repository's own pytest suite, and tests/test_dogfood.py exercises dogfood()
— so a nested suite that still collected test_dogfood.py would re-enter the
audit while it is already running, and tests/test_canary.py would replay the
whole 25-case canary corpus inside it; together they dragged one dogfood()
past 600 s. dogfood() therefore (a) ignores both files in its nested pytest
run by default (exclude=…, backward compatible — still callable with no
arguments), and (b) runs the whole audit in a worker subprocess under a hard
wall-clock budget (DOGFOOD_TIMEOUT_SECONDS = 420): exceeding it kills the
worker's process group and fails CLOSED — blocked=True, no certificate
replaces the previous one on disk — instead of hanging the suite (§6).
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.audit import AuditOrchestrator                    # noqa: E402
from veridict.canary import build_orchestrator                  # noqa: E402
from veridict.certificate import verify_certificate             # noqa: E402
from veridict.dossier import resolve_dossier                    # noqa: E402
from veridict.jury import Jury, Opinion, ScriptedProvider       # noqa: E402
from veridict.keys import KeyStore                              # noqa: E402
from veridict.ledger import Ledger                              # noqa: E402
from veridict.policy import (                                   # noqa: E402
    AuditOutcome, PolicyDeclaration, Thresholds, load_policy)
from veridict.schemas import TaskManifest                       # noqa: E402
from veridict.conformance import run_conformance_suite            # noqa: E402
from veridict.registry_index import build_index, export_index                  # noqa: E402
from veridict.watchers import ManifestRegistry                  # noqa: E402
from watchers.a11y_watcher import SESSION as A11Y_SESSION       # noqa: E402
from watchers.compliance_watcher import SESSION as COMP_SESSION  # noqa: E402
from watchers.cost_watcher import SESSION as COST_SESSION       # noqa: E402
from watchers.docker_watcher import SESSION as DOCKER_SESSION  # noqa: E402
from watchers.doc_sync_watcher import SESSION as DOCSYNC_SESSION  # noqa: E402
from watchers.import_weight_watcher import SESSION as IMPW_SESSION  # noqa: E402
from watchers.license_scan_watcher import SESSION as LICENSE_SESSION  # noqa: E402
from watchers.sbom_watcher import SESSION as SBOM_SESSION       # noqa: E402
from watchers.secret_scan_watcher import SESSION as SECRET_SESSION  # noqa: E402
from watchers.security_watcher import SESSION as SEC_SESSION    # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# v0.3 — the self-audit must never re-enter itself through the very suite it
# runs as evidence, nor pay for the canary corpus a second time inside it.
# v0.3.1 — test_quality_sheet_reports_stub_jury_context alone costs ~141s
# (it replays the canary corpus through the CLI). The W1a claim is about the
# core audit modules; outer CI already covers that CLI e2e path, so skipping
# it here keeps the nested run smaller. The remaining run still measures
# 300-342 s on this box, so the budget is 420 s (see below).
DEFAULT_EXCLUDE = (
    "tests/test_dogfood.py",
    "tests/test_canary.py",
    "tests/test_cli.py::test_quality_sheet_reports_stub_jury_context",
)
# v0.3.1 budget: measured full dogfood() runs 300-342 s on this box
# (W1a evidence = the repo's own suite minus the excludes above). The budget
# must sit ABOVE the measured wall clock with headroom, otherwise the budget
# itself is what fails. 420 s gives ~80 s headroom while still catching a
# genuine hang (the old 600 s recursion) well inside CI's tolerance.
DOGFOOD_TIMEOUT_SECONDS = 420
_WORKER_FLAG = "--dogfood-worker"
_GUARD_ENV = "VERIDICT_DOGFOOD_ACTIVE"

SEGMENT_LICENSE_HEADER = "# SPDX-License-Identifier: Apache-2.0\n"
SEGMENT_ESCALATED_PREDICATE = "payment-totals-are-computed-with-rounding"


def _write_segment_fixture(root: str) -> None:
    """Tiny clean artifact. License headers keep the compliance watcher
    (subscribes "*", refutes without headers) at SUPPORTS — the segment stays
    green; the only REFUTES in the calibration part is the scripted juror's."""
    with open(os.path.join(root, "calc.py"), "w", encoding="utf-8") as f:
        f.write(SEGMENT_LICENSE_HEADER + "def add(a, b):\n    return a + b\n")
    with open(os.path.join(root, "test_calc.py"), "w", encoding="utf-8") as f:
        f.write(SEGMENT_LICENSE_HEADER
                + "from calc import add\n\n\ndef test_add():\n    assert add(1, 1) == 2\n")


def _segment_task(task_id: str, artifact_path: str,
                  intent_lines: tuple = ()) -> TaskManifest:
    return TaskManifest(task_id=task_id, artifact_path=artifact_path,
                        actor_identity="veridict-dogfood",
                        intent_lines=intent_lines, criticality=(),
                        has_existing_tests=True, pytest_args=())


def _segment_policy(policy_id: str, mode: str,
                    criticality: tuple = ()) -> PolicyDeclaration:
    return PolicyDeclaration(policy_id=policy_id, mode=mode,
                             criticality=criticality, thresholds=Thresholds(),
                             divergence_tolerance=1 / 3)


def _calibration_jury() -> Jury:
    """cal-juror-b REFUTES exactly the machine-backed claim (W1a SUPPORTS):
    the W1a-contradiction that drives calibration (§4.4.5)."""
    return Jury([
        ScriptedProvider(family="cal-a", identity="cal-juror-a",
                         default=Opinion("SUPPORTS", 0.8, "no dispute")),
        ScriptedProvider(family="cal-b", identity="cal-juror-b",
                         default=Opinion("SUPPORTS", 0.8, "no dispute"),
                         responses={"existing test suite passes":
                                    Opinion("REFUTES", 0.8,
                                            "disputed: the suite does not "
                                            "cover this claim")}),
    ])


def _escalation_jury() -> Jury:
    """The tests/test_dossier.py escalated_run pattern: a critical-class
    doctrinal 1-vs-1 SPLIT. Distinct identities keep this run out of the
    calibration bookkeeping of the calibration passes."""
    return Jury([
        ScriptedProvider(family="esc-a", identity="esc-juror-a",
                         default=Opinion("SUPPORTS", 0.8,
                                         "totals round per doctrine")),
        ScriptedProvider(family="esc-b", identity="esc-juror-b",
                         default=Opinion("SUPPORTS", 0.8,
                                         "no dispute on machine claims"),
                         responses={"payment totals are computed with rounding":
                                    Opinion("REFUTES", 0.9,
                                            "rounding drops cents on totals")}),
    ])


def _run_phase2_segment(ledger: Ledger,
                        fixture_root: str) -> tuple[list[str], dict]:
    """Run the Phase 2 exit-criteria segment into `ledger`; return the
    registered watcher ids. Fails loudly (RuntimeError) if any receipt is
    missing — a self-audit must not silently degrade its own evidence."""
    keystore = KeyStore(ledger)            # Phase 1 key rule: SAME ledger
    key_id = keystore.generate_and_enroll("dogfood-segment")
    registry = ManifestRegistry(ledger, keystore, key_id)
    watcher_ids: list[str] = []
    conformance: dict[str, bool] = {}
    # every shipped example must pass the certification bar before listing —
    # the marketplace shipped set is now TEN manifests (G2 direction; the
    # exit criterion needs ≥10 ACTIVE on the marketplace, and shipped
    # examples advertise the surface while external ones are recruited).
    for session in (SEC_SESSION, COST_SESSION, COMP_SESSION,
                    SECRET_SESSION, LICENSE_SESSION, DOCKER_SESSION,
                    DOCSYNC_SESSION, SBOM_SESSION, A11Y_SESSION,
                    IMPW_SESSION):
        # §5.5 certification precondition: an external watcher must pass the
        # conformance kit BEFORE it can be listed — dogfood holds its own
        # examples to the same bar.
        kit = run_conformance_suite(session)
        conformance[kit["watcher_id"]] = kit["conformant"]
        if not kit["conformant"]:
            raise RuntimeError(f"phase2 segment: watcher {kit['watcher_id']} "
                               f"failed conformance: "
                               f"{[c for c in kit['checks'] if not c['passed']]}")
        entry = registry.register(session.manifest)
        wid = entry["payload"]["manifest"]["watcher_id"]
        report = ManifestRegistry.verify_manifest(ledger, wid)
        if not report["valid"]:
            raise RuntimeError(f"phase2 segment: watcher {wid} failed "
                               f"registration verification: {report['errors']}")
        watcher_ids.append(wid)

    # Receipts ① + ③: watcher blind sessions on a clean fixture, then a SECOND
    # pass on the SAME ledger so the disputed producer's factor applies. HYBRID
    # with criticality=() stays non-blocking: the single REFUTES sits against
    # W1a SUPPORTS (R1 verdict, MAJORITY divergence — no flag, no escalation).
    fixture_cal = os.path.join(fixture_root, "calibration")
    os.makedirs(fixture_cal)
    _write_segment_fixture(fixture_cal)
    cal_orch = None
    for task_id in ("dogfood-v0.2-seg-cal-1", "dogfood-v0.2-seg-cal-2"):
        cal_orch = AuditOrchestrator(
            ledger, _segment_policy("dogfood-v0.2-segment", "HYBRID"),
            _calibration_jury(), keystore, key_id,
            watchers=(SEC_SESSION, COST_SESSION, COMP_SESSION,
                      SECRET_SESSION, LICENSE_SESSION, DOCKER_SESSION,
                      DOCSYNC_SESSION, SBOM_SESSION, A11Y_SESSION,
                      IMPW_SESSION),
            registry=ledger)   # §6.6: the self-audit consults its own registry
        cal_orch.run(_segment_task(task_id, fixture_cal))

    # Receipt ②: full turn — critical SPLIT → ESCALATED → dossier.issued →
    # simulated human decision → escalation.resolved (escalated_run pattern:
    # CERTIFICATE mode so the escalation does not block the segment outcome).
    fixture_esc = os.path.join(fixture_root, "escalation")
    os.makedirs(fixture_esc)
    _write_segment_fixture(fixture_esc)
    esc_orch = AuditOrchestrator(
        ledger, _segment_policy("dogfood-v0.2-escalation", "CERTIFICATE",
                                criticality=("payments",)),
        _escalation_jury(), keystore, key_id, registry=ledger)
    esc_orch.run(_segment_task(
        "dogfood-v0.2-escalation", fixture_esc,
        intent_lines=("DOCTRINE(payments): payment totals are computed with "
                      "rounding",)))
    dossiers = [e for e in ledger.query("dossier.issued")
                if e["payload"]["claim"]["predicate"] == SEGMENT_ESCALATED_PREDICATE]
    if not dossiers:
        raise RuntimeError("phase2 segment: no dossier.issued for the "
                           "escalated claim — receipt ② broken")
    dossier = dossiers[-1]["payload"]
    resolve_dossier(ledger, dossier["dossier_id"], "demand_rerun",
                    decided_by="gokun",
                    risk_note="simulated human decision for pipeline "
                              "demonstration (autonomous dogfood)")

    # Receipt ⑥: revocation enforcement (§6.6). The self-audit revokes its
    # OWN compliance watcher and proves: (a) the next pass records no new
    # evidence from it, (b) the index refuses to list it, (c) pre-revocation
    # evidence is not deleted. Done LAST so earlier passes keep all three.
    watcher_ev_before = [e for e in ledger.query("evidence.recorded")
                         if e["payload"]["producer"]["kind"] == "watcher"]
    registry.revoke("example-compliance", "self-audit revocation demonstration")
    cal_orch.run(_segment_task("dogfood-v0.2-seg-post-revoke", fixture_cal))
    watcher_ev_after = [e for e in ledger.query("evidence.recorded")
                        if e["payload"]["producer"]["kind"] == "watcher"]
    compliance_after = [e for e in watcher_ev_after
                        if e["payload"]["producer"]["family"] == "example-compliance"]
    compliance_before = [e for e in watcher_ev_before
                         if e["payload"]["producer"]["family"] == "example-compliance"]
    revocation_ok = (
        len(compliance_after) == len(compliance_before)
        and all(w["watcher_id"] != "example-compliance"
                for w in build_index(ledger)["watchers"])
        and ManifestRegistry.lifecycle_status(ledger, "example-compliance") == "revoked")
    if not revocation_ok:
        raise RuntimeError("phase2 segment: revocation receipt broken — "
                           "a revoked watcher still contributed evidence or "
                           "still appears in the index")

    # Receipt guards — fail closed on a broken self-audit (§6 fail-closed).
    if not any(e["payload"]["producer"]["kind"] == "watcher"
               for e in ledger.query("evidence.recorded")):
        raise RuntimeError("phase2 segment: no watcher evidence recorded — "
                           "receipt ① broken")
    if not ledger.query("calibration.updated"):
        raise RuntimeError("phase2 segment: no calibration.updated entries — "
                           "receipt ③ broken")
    if not ledger.query("escalation.resolved"):
        raise RuntimeError("phase2 segment: escalation.resolved missing — "
                           "receipt ② broken")
    return watcher_ids, conformance


def _phase2_summary(ledger: Ledger, watcher_ids: list[str],
                    conformance: dict[str, bool]) -> dict:
    """Phase 2/3 receipt block over the FINAL dogfood ledger state."""
    return {
        "watchers_registered": watcher_ids,
        "watcher_evidence": sum(1 for e in ledger.query("evidence.recorded")
                                if e["payload"]["producer"]["kind"] == "watcher"),
        "calibration_entries": len(ledger.query("calibration.updated")),
        "deliberation_entries": len(ledger.query("deliberation.rounded")),
        "dossier_issued": bool(ledger.query("dossier.issued")),
        "escalation_resolved": bool(ledger.query("escalation.resolved")),
        "fail_safe_used": bool(ledger.query("policy.fail_safe")),
        "conformance": conformance,
        "revocation_enforced": True,
        "marketplace_index": True,
    }


def _ignore_args(exclude) -> tuple[str, ...]:
    """The nested pytest's --ignore flags for the given exclude list."""
    return tuple(f"--ignore={p}" for p in tuple(exclude))


def _main_task(run_root: str, exclude) -> TaskManifest:
    """The audit's own task: the whole repo as artifact, the existing suite
    as W1a evidence — minus the files that would re-enter or duplicate the
    audit (v0.3). TestExecutorVerifier builds the nested command as
    [python, -m, pytest, -q, --tb=no, *task.pytest_args], so these pytest_args
    ARE what the nested run collects (or refuses to collect)."""
    return TaskManifest(
        task_id="dogfood-v0.1", artifact_path=run_root, actor_identity="veridict-v0.1",
        intent_lines=("DOCTRINE: core modules are idiomatic python",),
        criticality=(), has_existing_tests=True,
        pytest_args=_ignore_args(exclude))


def _outcome_to_dict(outcome: AuditOutcome) -> dict:
    return {"mode": outcome.mode, "blocked": outcome.blocked,
            "coverage": outcome.coverage, "per_claim": outcome.per_claim,
            "flags": list(outcome.flags), "policy_id": outcome.policy_id,
            "policy_digest": outcome.policy_digest}


def _outcome_from_dict(data: dict) -> AuditOutcome:
    return AuditOutcome(
        mode=data["mode"], blocked=data["blocked"], coverage=data["coverage"],
        per_claim=data.get("per_claim") or {}, flags=tuple(data.get("flags") or ()),
        policy_id=data.get("policy_id", ""), policy_digest=data.get("policy_digest", ""))


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _kill_tree(proc: subprocess.Popen) -> None:
    """Kill the worker AND its own nested pytest: start_new_session made the
    worker a process-group leader, so killpg reaches the whole subtree."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _fail_closed(run_root: str, exclude, timeout_seconds: float,
                 reason: str, timeout: bool = False) -> dict:
    """A self-audit that cannot complete within its declared budget must fail
    CLOSED (§6): blocked=True, no verdicts, no certificate — it never reports
    a pass it could not earn, and it never overwrites the previous receipts."""
    flags = ("dogfood-hard-timeout" if timeout else "dogfood-worker-failed",)
    return {
        "cert": {},
        "outcome": AuditOutcome(mode="HYBRID", blocked=True, coverage=0.0,
                                per_claim={}, flags=flags,
                                policy_id="dogfood-fail-closed",
                                policy_digest=""),
        "report": {"abstentions": [], "duration_seconds": timeout_seconds,
                   "flags": flags, "task_id": "dogfood-v0.1"},
        "verification": {"valid": False, "errors": [reason]},
        "ledger_path": os.path.join(run_root, "dogfood_ledger.jsonl"),
        "cert_path": os.path.join(run_root, "dogfood_cert.json"),
        "index_path": os.path.join(run_root, "dogfood_index.json"),
        "phase2": None,
        "timeout": bool(timeout),
        "excluded": tuple(exclude),
        "pytest_args": _ignore_args(exclude),
    }


def _run_worker(run_root: str, exclude: tuple[str, ...],
                timeout_seconds: float) -> dict:
    script = os.path.abspath(__file__)
    fd, envelope_path = tempfile.mkstemp(prefix="veridict-dogfood-result-",
                                         suffix=".json")
    os.close(fd)
    cmd = [sys.executable, script, _WORKER_FLAG,
           "--root", str(run_root), "--jsonout", envelope_path]
    for path in exclude:
        cmd += ["--exclude", str(path)]
    child_env = {k: v for k, v in os.environ.items() if k != _GUARD_ENV}
    proc = subprocess.Popen(
        cmd, cwd=str(run_root), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=True, env=child_env)
    try:
        _, stderr_text = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        _unlink(envelope_path)
        return _fail_closed(
            run_root, exclude, timeout_seconds,
            f"dogfood() exceeded its {timeout_seconds}s hard timeout and its "
            f"worker was force-killed — fail-closed: blocked=True, the "
            f"certificate was not reissued", timeout=True)
    stderr_tail = (stderr_text or "")[-800:]
    if proc.returncode != 0:
        _unlink(envelope_path)
        return _fail_closed(
            run_root, exclude, timeout_seconds,
            f"dogfood worker exited with rc={proc.returncode}: {stderr_tail}")
    try:
        with open(envelope_path, encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, ValueError) as exc:
        _unlink(envelope_path)
        return _fail_closed(
            run_root, exclude, timeout_seconds,
            f"dogfood worker produced no readable result envelope: {exc!r}")
    _unlink(envelope_path)
    payload["outcome"] = _outcome_from_dict(payload["outcome"])
    report_flags = (payload.get("report") or {}).get("flags")
    if isinstance(report_flags, list):
        payload["report"]["flags"] = tuple(report_flags)
    payload["timeout"] = False
    payload["excluded"] = tuple(exclude)
    payload["pytest_args"] = _ignore_args(exclude)
    return payload


def _worker_main(argv: list[str]) -> int:
    """Worker entry: runs the whole self-audit and writes a JSON result
    envelope the parent parses. Anything that goes wrong exits non-zero and
    the parent fails closed with the reason."""
    run_root: str | None = None
    jsonout: str | None = None
    exclude: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--root" and i + 1 < len(argv):
            run_root = argv[i + 1]
            i += 2
        elif argv[i] == "--jsonout" and i + 1 < len(argv):
            jsonout = argv[i + 1]
            i += 2
        elif argv[i] == "--exclude" and i + 1 < len(argv):
            exclude.append(argv[i + 1])
            i += 2
        else:
            sys.stderr.write(f"dogfood worker: unknown argument {argv[i]!r}\n")
            return 2
    if not jsonout:
        sys.stderr.write("dogfood worker: --jsonout is required\n")
        return 2
    try:
        result = _dogfood_impl(run_root or REPO_ROOT, tuple(exclude))
    except Exception as exc:          # fail-closed with the reason, no envelope
        sys.stderr.write(f"dogfood worker failed: {exc!r}\n")
        return 1
    payload = {k: v for k, v in result.items() if k != "outcome"}
    payload["outcome"] = _outcome_to_dict(result["outcome"])
    with open(jsonout, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    return 0


def _dogfood_impl(run_root: str, exclude: tuple[str, ...]) -> dict:
    """The audit itself. Runs only inside the worker process so a budget
    overrun can kill it without orphaning its nested pytest."""
    os.environ[_GUARD_ENV] = "1"   # re-entry guard for this process tree
    policy_path = os.path.join(run_root, "dogfood_policy.json")
    if os.path.exists(policy_path):
        with open(policy_path, encoding="utf-8") as f:
            pol = load_policy(json.load(f))
    else:
        pol = PolicyDeclaration(
            policy_id="dogfood-fallback-hybrid", mode="HYBRID", criticality=(),
            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    ledger = Ledger()
    with tempfile.TemporaryDirectory(
            prefix="veridict-dogfood-phase2-") as segment_root:
        watcher_ids, conformance = _run_phase2_segment(ledger, segment_root)
    # Main self-audit LAST (same ledger, same append-only chain): the main
    # certificate anchors the final state, and its verdicts are recomputed at
    # verify time only from its own claims — segment claims/artifacts use
    # distinct task ids and can never collide with them. The nested pytest
    # ignores the files that would re-enter or duplicate the audit (v0.3).
    task = _main_task(run_root, exclude)
    orch = build_orchestrator(pol, ledger=ledger)
    result = orch.run(task)
    # Fail-closed artifact writes: stage into uniquely-named .tmp files,
    # verify, then atomically swap. A killed or unverifying run never replaces
    # the good receipts already on disk.
    ledger_path = os.path.join(run_root, "dogfood_ledger.jsonl")
    cert_path = os.path.join(run_root, "dogfood_cert.json")
    index_path = os.path.join(run_root, "dogfood_index.json")
    stage = {p: f"{p}.tmp-{uuid.uuid4().hex}"
             for p in (ledger_path, cert_path, index_path)}
    try:
        orch.ledger.save(stage[ledger_path])
        with open(stage[cert_path], "w", encoding="utf-8") as f:
            json.dump(result["cert"], f, indent=2, sort_keys=True)
        export_index(orch.ledger, stage[index_path])
        verification = verify_certificate(stage[ledger_path], stage[cert_path])
    except OSError:
        for tmp in stage.values():
            _unlink(tmp)
        raise
    if verification["valid"]:
        for final, tmp in stage.items():
            os.replace(tmp, final)
    else:
        for tmp in stage.values():
            _unlink(tmp)    # keep the previous, still-verifiable artifacts
    return {**result, "verification": verification,
            "ledger_path": ledger_path, "cert_path": cert_path,
            "index_path": index_path,
            "phase2": _phase2_summary(orch.ledger, watcher_ids, conformance)}


def dogfood(run_root: str = REPO_ROOT, jury_overrides: dict | None = None,
            exclude=DEFAULT_EXCLUDE,
            timeout_seconds: float = DOGFOOD_TIMEOUT_SECONDS) -> dict:
    """Self-audit the repository.

    exclude: files the nested pytest run must NOT collect — defaults to the
    self-audit test and the canary corpus test, whose presence made the audit
    re-enter itself and drag past 600 s (v0.3). Pass () to ignore nothing.
    timeout_seconds: hard wall-clock budget. Exceeding it kills the worker's
    process group and fails closed (blocked=True, previous cert untouched).
    """
    if os.environ.get(_GUARD_ENV):
        raise RuntimeError("dogfood() re-entered — refusing recursive self-audit")
    if jury_overrides:
        raise TypeError(
            "jury_overrides cannot cross the worker-process boundary — "
            "dogfood() runs its whole audit in a child it can hard-kill; use "
            "the default stub jury or scripts/dogfood.py --dogfood-worker")
    exclude = tuple(exclude) if exclude is not None else DEFAULT_EXCLUDE
    os.environ[_GUARD_ENV] = "1"
    try:
        return _run_worker(run_root, exclude, timeout_seconds)
    finally:
        os.environ.pop(_GUARD_ENV, None)


if __name__ == "__main__":
    if _WORKER_FLAG in sys.argv:
        argv = [a for a in sys.argv[1:] if a != _WORKER_FLAG]
        raise SystemExit(_worker_main(argv))
    out = dogfood()
    cert = out.get("cert") or {}
    print(json.dumps({"risk_level": cert.get("risk_level"),
                      "score": cert.get("score"),
                      "blocked": out["outcome"].blocked,
                      "timeout": out.get("timeout"),
                      "verification": out["verification"],
                      "duration_seconds": out["report"]["duration_seconds"],
                      "phase2": out.get("phase2")}, indent=2))
