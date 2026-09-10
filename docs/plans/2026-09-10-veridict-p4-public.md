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
- [ ] T7 fuzz expansion: EvidenceItem schema roundtrip + orchestrator
      end-to-end property (random fixture → audit → verify → recompute)
- [ ] T8 WATCH-mode honesty: standard note that v1.0.0 WATCH is a policy
      mode only (no streaming component) OR implement the stream — decide
      by effort, errata is the default
- [ ] T9 multi-signer federation: two independent KeyStores on one ledger,
      cross-verify, plus test
- [ ] T10 launch story: public write-up from
      `docs/notes/2026-09-10-agent-coordination-incident.md` (draft in
      docs/notes, publish on G1 gate)

Exit criteria: CI green on GitHub (not just locally), T7–T9 merged,
 receipts table in README still regenerating truthfully.
