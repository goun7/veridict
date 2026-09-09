# Veridict Phase 2 — Watcher Layer (C synthesis) Implementation Plan

Date: 2026-09-10. Status: approved for autonomous execution. Continues task numbering from Phase 1 (T16+).
Authority: docs/specs/2026-09-09-veridict-design.md §4.4 (calibration, deliberation), §5.3 (WatcherManifest/WatcherSession), §5.4 (routing, abstain≠refute), §6.3 (dossier), §6.1 (R3/R4), §8 roadmap Phase 2.

## Global Constraints

- Small-Core Principle: core stays boring; example watchers live OUTSIDE the package (`watchers/`), proving the platform gate.
- Tier ceiling: a watcher can NEVER produce W1a (§5.3). Ceiling clamp at session level.
- Authority disjointness (§5.4): watchers write ONLY evidence.recorded — orchestrator does the writing from returned items (same pattern as jury).
- Blindness: watcher/jury first rounds see only claim summary + artifact digest. Deliberation round is the ONE cross-visible exception (§4.4).
- Calibration touches ONLY confidence, never tier (§4.4.5).
- Dossier is a VIEW over the ledger, never a separate truth (§7.3); every sentence links to entry IDs.
- Policy-is-data: new policy knobs (deliberation_rounds, response_window_hours) are PolicyDeclaration fields with defaults; load_policy must tolerate their absence in old policy files.
- TDD strict per task; implementer subagents never commit; coordinator commits per task; per-task spec review + quality review.
- Verification mechanism at the end of EVERY round: full pytest suite + dogfood self-audit (valid cert) + canary Quality Sheet (2 catches, 0 FP) + `veridict verify` on dogfood artifacts.

## File Structure (new in Phase 2)

```
veridict/watchers.py        (T16/T17: WatcherManifest + ManifestRegistry + WatcherSession)
veridict/calibration.py     (T20)
veridict/dossier.py         (T22)
watchers/security_watcher.py, cost_watcher.py, compliance_watcher.py  (T19, outside package)
scripts/dogfood.py          (T24: v0.2 with watchers)
veridict/cli.py             (T23: dossier/resolve subcommands)
```

## New ledger entry types (Phase 2)

`watcher.registered` (registry, signed manifest) · `calibration.updated` (adjudicator) ·
`deliberation.rounded` (jury) · `dossier.issued` (adjudicator) · `escalation.resolved` (human) ·
`policy.fail_safe` (policy_engine).

---

### Task 16: WatcherManifest + signing + registry

**Files:** Create `veridict/watchers.py`, test `tests/test_watchers.py`.
**Interfaces:** `WatcherManifest` frozen dataclass (watcher_id, name, version, producer{identity, maintainer}, capabilities{evidence_classes tuple, max_tier, subscribes_to tuple}, resource_class{timeout_seconds, cost_budget, sandbox_level}, integrity{code_hash, update_policy}; to_dict/from_dict; `manifest_digest()`); `ManifestRegistry(ledger, keystore)`: `register(manifest) -> entry` (maintainer signature over canonical body-without-signature, key.enrolled entry for the maintainer key, `watcher.registered` entry, author kind "watcher_registry"); `verify_manifest(ledger, watcher_id) -> dict{valid, signature_valid, errors}`; `get_manifest(ledger, watcher_id) -> WatcherManifest|None`.
**Validation:** max_tier ∈ {W1b, W2, W3} (W1a forbidden by design — ValueError); evidence_classes ⊆ EVIDENCE_CLASSES; producer.identity/maintainer non-empty (no anonymous watchers).
**Tests:** roundtrip; register→verify valid; tampered manifest body rejected; W1a ceiling rejected; anonymous producer rejected; get_manifest returns None for unknown.
**Note:** maintainer key enrollment uses the SAME ledger (offline verification parity, Phase 1 lesson).

### Task 17: WatcherSession runtime (blind, ceiling-clamped, abstain≠refute)

**Files:** Extend `veridict/watchers.py`, test `tests/test_watchers.py`.
**Interfaces:** `WatcherSession(manifest, doctrine_fn)`: `doctrine(claim_summary, artifact_digest) -> (stance, confidence, rationale)|None` (user fn; None/timeout/error → abstain); session produces EvidenceItem with tier = W3 if manifest max_tier == W3 else W1b; evidence_class ∈ manifest.evidence_classes (first); confidence clamped 0..1; evidence_id salt `veridict-watcher-v1`. `run_session(session, claim, artifact_digest, timeout_seconds=None) -> EvidenceItem|None` — timeout enforced with a simple signal-free deadline check (fn is sync; if fn raises or returns None → None). Blindness: run_session passes ONLY (claim.summary, digest) to doctrine.
**Tests:** ceiling clamp (manifest claims W1b cap; session refuses to emit W1a — a doctrine_fn attempting W1a gets clamped/error); blind input; error→None (abstain); timeout param recorded; evidence item shape (producer kind "watcher", family=watcher_id).

### Task 18: Orchestrator watcher integration (routing)

**Files:** Modify `veridict/audit.py`, test `tests/test_audit_watchers.py`.
**Interfaces:** `AuditOrchestrator(ledger, policy, jury, keystore, key_id, watchers=())`; per claim: run matching sessions (subscribes_to "*" or substring match against claim.predicate or claim.critical_class), record `evidence.recorded` with author kind "watcher"; abstentions from watchers extend report.abstentions; health note: abstain count recorded in report (full health tracking is T20's calibration scope).
**Tests:** watcher evidence lands with authority-correct author; subscribes_to filter (cost watcher abstains on non-matching claim); ceiling respected in ledger payload; watchers see nothing of jury output (Recorder probe); existing 5 audit tests + full suite stay green (watchers default empty).

### Task 19: Three example watchers (outside the package)

**Files:** Create `watchers/security_watcher.py`, `watchers/cost_watcher.py`, `watchers/compliance_watcher.py`, test `tests/test_example_watchers.py`.
**Spec:** security (W1b, STATIC_ANALYSIS, subscribes_to ("payments","security","*") — AST scan for shell=True subprocess, pickle.loads, yaml.load w/o Loader, hardcoded secret regexes; REFUTES on finding, else SUPPORTS 0.85); cost (W2? no — cost is deterministic line/complexity budget → W1b, WATCHER_REPORT, subscribes_to ("cost","performance") — abstains on most claims by design, exercising the abstention path); compliance (W3 doctrinal, JURY_OPINION-class? NO — evidence_class WATCHER_REPORT, subscribes_to ("*",) — emits SUPPORTS/REFUTES with rationale from a rule list (license header present, TODO count threshold), confidence 0.6).
**Manifests:** each module exposes `MANIFEST` (built from its own `__file__` code_hash via sha256 of file content — integrity pinning) and `SESSION` (WatcherSession bound to it).
**Tests:** each manifest registers + verifies against a scratch ledger; security watcher flags a shell=True artifact (W1b REFUTES); compliance W3 never clamps above W3; cost abstains on unrelated claims (exit criterion ① evidence: external watcher runs blind session producing ledger evidence).

### Task 20: Calibration ledger (§4.4.5)

**Files:** Create `veridict/calibration.py`, test `tests/test_calibration.py`.
**Interfaces:** `update_calibration(ledger, actor, claim, evidence_by_claim) -> list[entries]`: for each claim, if any W1a item exists with stance S == the machine truth, then for each W2/W3 producer with stance != S: append `calibration.updated` {producer_identity, delta: -0.1, reason: "W1a contradicted doctrine", claim_id}; producers agreeing with W1a on previously-contradicted stances: delta +0.05 (rehabilitation). `calibration_factor(ledger, identity) -> float` = clamp(1.0 + sum(deltas), 0.5, 1.0). Orchestrator: applies factor to W2/W3 evidence confidence at record time (confidence × factor, still clamped ≤1.0); NEVER touches tier/stance.
**Tests:** refute-contradiction writes negative delta; factor floors at 0.5; tier untouched after calibration; factor flows into recorded confidence (probe); no W1a → no updates.

### Task 21: Deliberation round (§4.4.3)

**Files:** Modify `veridict/policy.py` (PolicyDeclaration + `deliberation_rounds: int = 1`, load_policy tolerant default), `veridict/audit.py`, test `tests/test_deliberation.py`.
**Spec:** only after first-round SPLIT on a claim; second round CROSS-VISIBLE: each provider receives the first-round opinions of the others (identity-labeled); providers may revise via optional `revise(opinions) -> Opinion` hook on ScriptedProvider (default: return own first opinion); first-round items KEPT in ledger; `deliberation.rounded` entry records both rounds; adjudication uses post-deliberation items; risk note records that a first-round split occurred ("first-round split never hidden": divergence_summary in cert carries first-round divergence via adjudication risk_notes + the divergence.flagged entry stays).
**Tests:** SPLIT triggers deliberation; revised consensus → final divergence UNANIMOUS while divergence.flagged entry still present; no SPLIT → no deliberation entry; old policy JSON without the new key still loads (regression).

### Task 22: Dossier generator (§6.3)

**Files:** Create `veridict/dossier.py`, test `tests/test_dossier.py`.
**Interfaces:** `generate_dossier(ledger, claim_id, policy) -> dict`: schema_version, dossier_id (sha256(claim_id|checkpoint)[:16]), claim (predicate/summary/verdict/rung), summary_page (plain-language, impact translation from risk_notes + verdicts), risk_frame ("if the REFUTES side is right: …" built from refuting evidence rationales), options (the 4 standard options from §6.3 verbatim), default ("response window expiry (N h) triggers policy.fail_safe (R4)"), evidence_links (every claim/evidence/divergence entry ID relevant), response_window_hours (policy). `render_markdown(dossier) -> str`. Orchestrator: on ESCALATED, after escalation.requested, writes `dossier.issued` (author kind "adjudicator") with the dossier.
**Tests:** escalation → dossier.issued entry; all evidence_links resolve to real entry IDs; markdown contains summary + options; non-escalated run → no dossier.

### Task 23: Human decision return + R4 fail-safe (§6.1)

**Files:** Modify `veridict/dossier.py` (resolve + fail_safe), `veridict/cli.py` (dossier/resolve subcommands), test `tests/test_resolution.py`.
**Interfaces:** `resolve_dossier(ledger, dossier_id, decision, decided_by, risk_note="") -> entry` — decision ∈ {"accept_with_risk", "demand_rerun", "narrow_claim", "reject"}; writes `escalation.resolved` {dossier_id, decision, decided_by, risk_note, ts} (author kind "human"); unknown decision → ValueError. `apply_fail_safe(ledger, dossier_id, actor)` → `policy.fail_safe` entry {dossier_id, consequence: "gate_stays_blocked_or_certificate_stamped_unresolved"}. CLI: `dossier --ledger --claim-id [--out]` prints/renders; `resolve --ledger --dossier-id --decision --decided-by [--note]` (rc 0 ok / 1 invalid).
**Tests:** full turn (exit criterion ②): critical SPLIT → ESCALATED → dossier → resolve accept_with_risk → escalation.resolved in ledger; invalid decision rc/ValueError; fail_safe entry written; GATE outcome stays blocked after fail_safe (no silent pass).

### Task 24: Phase 2 integration — dogfood v0.2 + exit receipt

**Files:** Modify `scripts/dogfood.py` (registers example watchers, runs with watchers + calibration; v0.2), `README.md` (Phase 2 status), test `tests/test_dogfood.py` extended (watcher evidence present; calibration entries present; verification still valid).
**Receipt:** ① external watcher blind session (test_example_watchers probe) ② SPLIT → dossier → human decision → ledger return (test_resolution full turn) ③ calibration accumulating (dogfood ledger contains calibration.updated entries; second dogfood run applies factor).
**Verification mechanism after this task: full suite + dogfood + canary + verify, all green.**

---

## Phase 3 preview (NOT in this plan's execution scope unless reached)

Watcher marketplace manifests are already the Phase 2 format; Phase 3 = hosted layer + spec v1.0 standard publication + governance docs (largely documentation deliverables).
