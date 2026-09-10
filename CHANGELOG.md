# Changelog

Semver applies to the LEDGER FORMAT and the standard (§14): changes to a
digest preimage, a payload schema, or a tier rule are MAJOR.

## 0.3.0 — 2026-09-10 (Phase 3 open-source substrate)

- **CHAIN FORMAT (breaking):** entry-hash preimage now binds `ts` and
  `schema_version` (fuzz-caught gap: retroactive timestamp edits were
  undetectable). Ledgers saved by ≤0.2.x must be regenerated.
- Watcher conformance kit (`veridict/conformance.py`, C1–C10) — the §5.5
  certification precondition; dogfood holds its own watchers to it.
- `run_session` enforces `resource_class.timeout_seconds` (deadline →
  abstain).
- `verify_certificate` checks cert `evidence_ids` against the ledger.
- Spec v1.0.0-draft (`docs/specs/2026-09-10-veridict-standard-v1.0.md`),
  LICENSE (Apache-2.0), CONTRIBUTING, GOVERNANCE.
- Marketplace manifest index: build/validate/export/load + CLI `index`.
- CLI quality-sheet embeds stub-jury context note (R5 honesty).
- Fresh-eyes Phase 2/3 integration audit fixes: a revision hook that is
  absent or errors now degrades to keep-opinion (was: abstain-erase — a
  flaky endpoint could silently erase a first-round REFUTES, fail-open);
  providers without a `revise` attribute no longer crash the audit; the
  ladder's R4 doctrinal-consensus semantics are normative in the standard
  (§7 + errata §14.2); `resolve_dossier`/`apply_fail_safe` refuse fabricated
  dossier ids; dossier return payloads carry ISO-8601 string timestamps.
- 177 tests.

## 0.2.0 — 2026-09-10 (Phase 2 — watcher layer)

- Signed `WatcherManifest` registry (W1a forbidden at construction, no
  anonymous producers, entry-integrity + digest + signature + invariant
  revalidation on verify, offline parity).
- `WatcherSession`: blind `(summary, artifact-ref)` input, ceiling-clamped
  tiers (structurally incapable of W1a), abstain on error/None/bad stance.
- Orchestrator routing (`watchers=()`), abstentions reported; example
  watchers (security/cost/compliance) live OUTSIDE the package.
- Calibration ledger (§4.4.5): W1a contradiction discounts producer
  confidence (−0.1, rehab +0.05, factor clamp [0.5, 1.0]); confidence only —
  never tier/stance.
- Deliberation round (§4.4.3): first-round SPLIT → one cross-visible revision
  round; first-round items stay ledgered; replay excludes superseded items
  **within the anchored prefix only** (D4: the unbounded form was exploitable
  and is forbidden — post-issuance fake `deliberation.rounded` entries must
  not erase refuting evidence from replay).
- Dossier generator (§6.3) + human decision return (`escalation.resolved`)
  + R4 fail-safe (`policy.fail_safe`); CLI `dossier`/`resolve`.
- `EvidenceItem.rationale` persisted (feeds dossier risk frames).
- Policy knobs: `deliberation_rounds`, `response_window_hours` (tolerant
  load); `--mode` override carries all knobs.
- Dogfood v0.2: phase2 receipt block (exit criteria ①②③ end-to-end).
- CLI: usage errors exit 1 (no rc-2 collision); clean rc-1 error paths;
  `Ledger.load` raises `ChainError` on malformed lines.

## 0.1.0 — 2026-09-09 (Phase 1 — core)

Evidence ledger, claim extraction, W1a/W1b verifiers, blind jury, divergence
detector, R0–R4 ladder, 4-mode policy engine, signed certificates with
offline replay verification, canary protocol v0, dogfood self-audit.
Audit-round fixes: claim_id derived from the full claim body (slug collision
closed), meta-claim verdicts feed the policy engine and certificate
(fail-closed restored), `inconclusive-unresolved` flag, issuance-entry
requirement in verify, ChainError on malformed ledger lines.
