# Veridict Phase 3 — Platform + Standard (open-source scope) Implementation Plan

Date: 2026-09-10. Status: approved for autonomous execution. Continues task numbering (T25+).
Authority: docs/specs/2026-09-09-veridict-design.md §5.5 (extractor governance), §8 Phase 3 row (line 527), D8 (open-core split).

## Scope ruling (autonomous window)

Phase 3 exit criteria ① (independent third-party verifier) ② (external production deployment) ③ (≥10 active manifests) are EXTERNAL by nature — they cannot be manufactured autonomously. What this plan delivers is the open-source substrate those criteria need: the conformance kit (what a third-party watcher/verifier must pass), the standard document (what they implement from), the governance layer (who maintains it), and the marketplace manifest format (how manifests circulate). Hosted/commercial layer (D8) is explicitly OUT of scope.

## Tasks

### Task 25: resource enforcement + verify hardening
- `run_session` honors `resource_class.timeout_seconds` (thread-based deadline; timeout → abstain None, reported like any abstention). Manifest without timeout_seconds → no deadline (explicit).
- verify_certificate: if cert lists `evidence_ids`, every listed id must exist in the ledger (subset check; missing → error). (Phase 1 deferred item.)
- CLI quality-sheet: sheet gains `jury_context` note when built from unseeded stubs (R5, honest reporting).
- Tests: timeout→abstain; subset violation → invalid; sheet note present.

### Task 26: conformance kit (`veridict/conformance.py`)
- `run_conformance_suite(session, scratch_ledger_factory) -> {conformant: bool, checks: [{id, name, passed, detail}]}`:
  C1 manifest invariants construct cleanly (incl. W1a ban) · C2 ceiling: a W1a-claiming output cannot surface (clamp/abstain) · C3 blindness: fn receives exactly (summary, artifact_ref) · C4 abstain on error · C5 abstain on None · C6 abstain on non-SUPPORTS/REFUTES stance · C7 confidence clamped to [0,1] · C8 evidence shape (producer kind watcher, family=watcher_id, evidence_class ∈ manifest) · C9 registration + signature verify against a scratch registry · C10 timeout honored (Task 25).
- dogfood phase2 block gains `conformance: {watcher_id: conformant}` for the three example watchers; README notes the kit.
- This kit IS the certification precondition (§5.5 governance): external watchers must pass it before marketplace listing.

### Task 27: spec v1.0 standard draft (`docs/specs/2026-09-10-veridict-standard-v1.0.md`)
Normative publication (the artifact a third party implements from): conformance levels (Core/Watcher/Verifier/Resolver), the entry-type registry table with payload schemas, canonical hashing + signing rules, tier ceiling + calibration + deliberation normative sections, dossier/resolution contract, known limitations stated honestly (evidence_ids subset semantics, local-jury mode), versioning policy (semver for the standard, entry-type registry append-only).

### Task 28: governance + marketplace manifest format
- `LICENSE` (Apache-2.0), `CONTRIBUTING.md`, `GOVERNANCE.md` (maintainer model, watcher onboarding per §5.5, standard-change process).
- `docs/marketplace/MANIFEST_INDEX.md` + `veridict/registry_index.py`: build/validate a static JSON index of watcher manifests (export from a ledger, validate signatures offline) — the marketplace circulation format; CLI `index` subcommand.
- Dogfood exports the example index; test validates it round-trips.

### Task 29: Phase 3 receipt + mechanism
- README final status; dogfood summary gains `conformance` + `marketplace_index` fields; full mechanism run; receipt notes which Phase 3 exit criteria remain EXTERNAL (①②③) and what substrate now exists for each.

## Verification mechanism (every round, unchanged)
Full suite (both invocations) + fresh dogfood (valid cert) + offline verify + canary Quality Sheet (2/0).
