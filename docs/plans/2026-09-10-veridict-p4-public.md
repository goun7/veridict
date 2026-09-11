# Plan — P4: public hardening (zero-capital phase)

Context: repo is public (github.com/goun7/veridict). Commercial model and
interest gates live in `docs/commercial-model.md`. Everything in THIS plan
costs $0. Capital-bearing items are gated in the commercial doc, not here.

- [x] T1 CI pipeline (`.github/workflows/ci.yml`): suite ×2, dogfood
      receipt, offline verify, canary, latency budget — Python 3.12–3.14
- [x] T2 SECURITY.md (private advisory path, §13-aligned scope list)
- [x] T3 Issue templates (bug + **standard errata** — errata proposals are
      first-class, feeding §14.2)
- [x] T4 README for externals: receipts table, quickstart, spec parity,
      commercial model pointer
- [x] T5 `docs/commercial-model.md`: revenue streams ranked by fit and
      capital need, interest gates G1–G3, anti-corruption guardrails
- [x] T6 packaging: version 0.3.0 aligned with CHANGELOG
- [x] T7 fuzz expansion: EvidenceItem schema roundtrip + orchestrator
      end-to-end property (random fixture → audit → verify → recompute)
- [x] T8 WATCH-mode honesty: standard note that v1.0.0 WATCH is a policy
      mode only (no streaming component) OR implement the stream — decide
      by effort, errata is the default
- [x] T9 multi-signer federation: two independent KeyStores on one ledger,
      cross-verify, plus test
- [x] T10 launch story: paste-ready kit in
      `docs/notes/launch-ready.md` (Show HN + Reddit + dev.to, ~10 min of
      maintainer clicks). Decision 2026-09-10/11: publish NOW (maintainer
      accounts required — no agent can post to HN/Reddit); step 4 records
      stars/comments in the G1 tracker below
      (`docs/commercial-model.md`). Status after publish: pending maintainer
      action — kit is final, see `docs/notes/launch-ready.md` §Posting
      checklist.

## Receipt (2026-09-10)

- CI run 34494198131: GREEN on 3.12/3.13/3.14 — suite ×2, dogfood receipt,
  offline verify, canary 2/0, latency budget all pass on GitHub's runners
- 190 tests green locally (both invocation styles)
- cross-implementation fuzz (T7) caught spec_verifier R4 drift on its first
  run and the fix is pinned — the property suite now guards BOTH verifiers

Exit criteria: CI green on GitHub (not just locally), T7–T9 merged,
 receipts table in README still regenerating truthfully.
