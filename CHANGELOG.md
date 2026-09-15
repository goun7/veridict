# Changelog

Semver applies to the LEDGER FORMAT and the standard (§14): changes to a
digest preimage, a payload schema, or a tier rule are MAJOR.

## Unreleased (post-0.4.0)

- action: `anchor` + `anchor-required` inputs on BOTH invocation surfaces
  (composite + reusable workflow), with the offline-verify step consuming
  the sidecar when present; closes the `actor-family` reusable-workflow
  parity gap it also uncovered. New `tests/test_action_surface.py` pins
  the input-SET equality so surfaces can no longer drift silently.
- ci: `action-e2e.yml` runs the repo through its own public action surface
  (`uses: ./` — exactly what Marketplace serves) on every release tag,
  anchoring the receipt in Rekor; first dispatch caught a real bug (missing
  caller checkout), first green proved input→CLI→log→verify wiring
  end-to-end (logIndex 2844439400).
- ci(test-deps): pyyaml added to the test install line (maintainer/CI
  environment skew caught red-handed by CI, not by narrative).
- repo: GitHub topics set (evidence-ledger, llm-as-a-judge, slsa,
  transparency-log, …); adoption thread updated for 0.4.0 surfaces;
  `v1` re-pointed to include the anchor inputs.
- discovery: PR open against ProjectRecon/awesome-ai-agents-security (#123).
- proofs: the adjudication ladder is machine-checked in Lean (`proofs/ladder/`,
  core-only, no mathlib): seven invariants over evidence lists of ARBITRARY
  length (fail-safe-empty, no-silent-pass, W1a-decisive, doctrine-cannot-
  topple, escalated-conditions, split-stays-visible, meta-budget-honored, +
  divergence coherence) and a generated oracle re-checking the model against
  ALL 28,080 bounded-receipt cases at build time (digest-tied to ladder.py
  and the receipt's table sha256; `native_decide` trust placement disclosed,
  general theorems never use it). The oracle's first run caught a genuine
  model/implementation divergence (R0's refute-anywhere guard) — the MODEL
  moved, the data did not. `proofs.yml` kernel-checks on every ladder touch.
- export: `--format spdx` emits an SPDX 3.0.1 AI-profile JSON-LD document
  validated against the official schema (pinned under `docs/data/`, sha256
  locked in tests). Honest envelope: audited artifact as `ai_AIPackage`,
  every audit semantic as core Annotation/Relationship/ExternalRef; no ai_*
  field carries a meaning SPDX doesn't give it (test locks the refusal to
  map risk_level into ai_safetyRiskAssessment). Deterministic — timestamps
  are ledger-issuance, not export-time. `--anchor-file` embeds the Rekor
  receipt as an ExternalRef.
- docs: §10.5 competitive landscape re-scanned with dated primary sources
  (HANSARD 2608.22512, VCT 2606.23003, IET 2603.17445, MedAgentAudit
  2510.10185, the judge-calibration cluster, microsoft/agent-governance-
  toolkit runtime-vs-posthoc positioning); an unverifiable "AegisChain"
  entry circulating in secondary surveys dropped after source hunt —
  surveys are not oracles. Regulatory lines refreshed (Art. 50 + GPAI
  enforcement live 2026-08-02; Omnibus legacy-marking grace 2026-12-02),
  mirrored in the aiact watcher docstring and re-exported manifests.
- corrections: an earlier sweep commit claimed "316 tests"; the suite was
  306 (313 now, with the SPDX additions). Receipts amended forward rather
  than rewriting pushed history.

## 0.4.0 — 2026-09-15 (research-grounded gap closure: calibrated jury, external anchoring, SLSA export, ladder proofs)

Research-grounded gap closure: every item below traces to the 2026-09-14
literature/regulatory sweep (jury-bias papers, AuditWeave, SLSA v1.2, EU
AI Act GPAI Code of Practice, patent watch) — the roadmap's "current data"
deficit, closed autonomously, receipts-first.

### Protocol & engine

- **jury calibration layer** — the three documented LLM-as-judge failure
  modes now have structural mitigations shipping in the reference jury
  (Zheng et al. arXiv:2306.05685, Wang et al. arXiv:2305.17926, Watai et
  al. arXiv:2410.21819 cited in-module): multi-sample self-consistency
  voting (`VERIDICT_JURY_SAMPLES`, temperature 0.7 for n>1, majority or
  honest abstention — a sample-split can never fabricate a stance),
  evidence-first extraction (verdict without ≥2 evidence pointers is
  flagged, not silently trusted), and **self-preference exclusion**
  (jurors of the audited actor's provider family abstain before the
  jury is validated; `VERIDICT_ACTOR_FAMILY` / new `actor-family` action
  input). Real-jury CI receipt now runs 3 samples.
- **external anchoring** (`veridict/anchor.py`) — the design doc's
  checkpoint-hardening promise, kept: `audit --anchor rekor` /
  `anchor publish` pins {cert_id, key_id, checkpoint_seq, chain_hash}
  to the Sigstore Rekor public-good log; `verify --anchor` checks
  existence-at-time fully offline against the pinned Rekor key
  (TUF-hash-verified; rotation fails CLOSED with a documented recipe).
  Existence proof, not authority transfer — the ephemeral anchor key is
  by design. v1 release's dogfood cert is anchored live
  (`docs/receipts-anchor-v1-dogfood.json`, logIndex 2843194981).
- **SLSA v1.2 VSA export** (`veridict export --format vsa`) — lossy,
  honest projection (PASSED only for risk=low; `verifiedLevels` empty —
  Veridict asserts no build level; `timeVerified` from the ledger's
  issuance entry; cert named by digest in `inputAttestations`; full
  binding as a spec-sanctioned URI extension). Optional DSSE envelope
  under the issuing key.
- **ladder bounded-exhaustive verification** (`scripts/verify_ladder.py`)
  — 28,080 cases covering the complete finite input space (evidence
  sequences ≤3 × tiers × stances × claim/policy dimensions), 10 safety
  invariants PASS incl. no-silent-pass, W1a-decisiveness, doctrine-
  cannot-topple, split-visibility; determinism double-checked per case.
  Receipt `docs/receipts-ladder-verification.json`; CI locks the truth-
  table digest, and a meta-test proves the invariants see an injected
  silent-pass bug. Issue #8 annotated (general proofs remain open).

### Ecosystem

- **11th example watcher: EU AI Act transparency**
  (`watchers/aiact_watcher.py`) — deterministic Art. 50 / GPAI CoP
  checks (disclosure anchor, `ai_outputs/` provenance sidecars,
  training-data summary for shipped weights); vacuous-SUPPORTS for
  non-AI repos; conformance-kit clean; manifest example shipped.
- **governance**: IP & prior-art watch section — US App 19/561,229
  overlap assessed against RFC 6962 + AuditWeave intervening art and
  our dated public record; defensive publication named as doctrine
  (anchored receipts as a side effect of operating). Not legal advice.
- **design doc §10.5**: AuditWeave (arXiv:2607.09682) positioned as
  closest neighbor — convergent validation of the ledger primitive and
  of mutation-testing doctrine; differentiation: adjudication-vs-
  recording, protocol-vs-tool. Niche paragraph updated honestly.

### Housekeeping

- tests: 260 → **297** (anchor 9, export 7, aiact 8, ladder 2, jury 16 —
  incl. tamper/meta/refusal cases throughout); ledger format untouched —
  every change additive-minor per §14.
- marketplace: **listing published** (2026-09-14) —
  https://github.com/marketplace/actions/veridict-audit, primary category
  **Security**. Lane 0 is fully closed; the only remaining work is external
  (Lane 1: first real auditee).
- action: description shortened under Marketplace's 125-char limit
  (5de1eba) — the listing draft rejected the 0.3.3 text.
- badge: **the self-audit badge never rendered, ever** — the SVG template's
  XML comment contained `--ledger` / `--cert`, and XML 1.0 §2.5 forbids
  double hyphens inside comments, so every browser failed to parse the SVG
  while CI stayed green for a day. Fixed in fd2bb4d: comment rewritten,
  generator now refuses to emit non-well-formed XML (`ET.fromstring` guard),
  `test_badge.py` asserts well-formedness (would have been RED on 0.3.3).
  READMEs point the badge link at v0.3.3's dogfood receipt.
- v1: **major-tracking tag re-pointed to fd2bb4d** (badge fix inside the
  tag's tree — the listing renders the README from this commit; it would
  have re-shipped the broken badge).
- v1 release: dogfood receipts (`dogfood_cert.json` + `dogfood_ledger.jsonl`
  from the fd2bb4d CI run) attached — release notes' "dogfood certificate
  attached to each release" is now literally true for v1.

## 0.3.3 — 2026-09-14 (marketplace listing + CI deprecation cleanup)

- action: **`action.yml` moved to the repository root** (`audit/` → `/`).
  GitHub Marketplace only lists actions whose `action.yml` lives at the
  repo root — the 0.3.2 layout (`audit/action.yml`) worked via
  `uses:` but could never appear on the Marketplace (verified: the
  listing URL 404'd until the move). Invocation is now
  `uses: goun7/veridict@v1`; `v1` re-tagged to this commit. This closes
  L0-2 for real (0.3.2 claimed it prematurely).
- ci: all `actions/*` steps upgraded to Node-24-native majors
  (checkout v4→v7, setup-python v5→v7, upload-artifact v4→v7,
  download-artifact v4→v8, upload-pages-artifact v3→v4,
  deploy-pages v4→v5, configure-pages v5→v6) — clears the Node-20
  deprecation warnings that appeared on every run of 0.3.2.

## 0.3.2 — 2026-09-13 (launch follow-through)

- receipts: **real-LLM jury run** — the launch texts' last honest
  limitation is closed. A live qwen3.8-flash juror produced doctrine on
  both dogfood claims (real rationales, honest low confidence where the
  digest alone can't decide), the certificate verifies offline
  (`valid/chain_valid/signature_valid/verdicts_match` all true, risk low,
  score 1.0), and the first GATE-mode attempt showed the fail-closed
  design catching real-vs-stub divergence (`divergence-split`,
  `inconclusive-unresolved`, GATE blocked). Workflow:
  `real-jury-receipt.yml` (manual dispatch, key via repo secret, never
  committed). Roadmap #10 L0-3; run 34787467296.
- action: composite audit action added — the audit as a
  Marketplace-listable GitHub Action (reusable workflows cannot be
  Marketplace-listed; only actions with action.yml metadata can). Same
  engine, same inputs as the reusable workflow. L0-2 of roadmap issue #10
  (moved to repo root in 0.3.3 — see above; the 0.3.2 `audit/` layout
  predated the Marketplace root-file rule).

- launch hygiene (roadmap v2, issue #10): `v1` major-tracking tag created
  for the audit Action's `@v1` reference (README example was broken — no
  such tag existed; the first attempt pointed at a pre-action commit and
  was retagged on main where the workflow file exists). `publish-pypi`
  trigger narrowed to semver tags (`v*.*.*`) so the moving `v1` ref can
  never fire a publish (found live: the tag push triggered a doomed
  trusted-publishing run — PyPI publisher not yet registered; manual
  0.3.1 upload remains the release of record).

- brand: project mark (the V glyph — two strokes converge to one
  verified point) added as `docs/assets/logo.svg` with favicon set
  (16/32/48/64/128/180/512 + .ico) and a 1200×640 social card; site
  pages now carry the favicon, READMEs carry the mark beside the title.
- adoption: GitHub Discussions enabled (2026-09-13) — the open inbox for
  enterprise adoption support (first revenue lane, $0). Seed thread:
  "Adopting Veridict in your CI".
- packaging: PUBLISHED — `veridict-standard` 0.3.1 is live on PyPI
  (https://pypi.org/project/veridict-standard/0.3.1/), uploaded via the
  maintainer's API token; fresh-venv install + CLI smoke test pass.
  Future releases flow through `.github/workflows/publish-pypi.yml`
  (Trusted Publishing, OIDC, no stored tokens) on `v*` tags. READMEs
  carry the PyPI badge and the launch texts now lead with
  `pip install veridict-standard`.
- docs: "Tiers, not vibes" bullet rewritten in plain language (both
  READMEs) — the evidence rank order is explained before the W-notation
  is used.
- doc-sync watcher canon sharpened (found by running it against THIS
  repo, pre-launch): (a) counting-method tolerance — honest docs cite
  either pytest's collected count or the static definition count and
  they drift (parametrize/skip); a live claim within ±10% of the static
  count is in sync, beyond it stale under every honest method; (b)
  fixture trees (corpus/-style audited artifacts, examples, build
  output) are never counted — their test_ functions are audit subjects,
  not the suite (18 phantom defs were inflating this repo's count);
  (c) live-claim documents are top-level READMEs + the launch kit —
  plans/emails are historical records of past counts, not claims
  (flagging history is how a watcher earns its uninstall). The watcher
  now passes on its own repo (dogfood honesty extended to marketplace
  examples).
- PyPI distribution name is `veridict-standard`: the bare `veridict` name
  on PyPI belongs to an UNRELATED third-party project (curagus /
  NodexisLabs — "verify an AI agent actually did what it claimed", parked
  there since 2026-06) in an eerily adjacent domain; `pip install
  veridict` installs THEIR code, not ours. Blast radius swept and fixed
  (audit-my-repo issue template, GitHub Action, READMEs) — install path
  is `pip install -e git+...#egg=veridict-standard` or, once published,
  `pip install veridict-standard`. Same package, same import, same CLI.
- `veridict watch` subcommand — the WATCH-mode streaming transport
  surface (§10.3, v1.1-draft A1): tails a growing ledger and prints
  `watch.observed` batches as JSON lines with the batch-identical §10.2
  flag set. Never blocks, never appends (read-only observer — A1's MUST
  NOT clauses pinned by test). Bounded runs via --max-batches/--idle-
  timeout; --forever for tailing. 4 e2e tests in
  `tests/test_watch_cli.py` (subprocess-runs of the real CLI, growth
  under the stream, flag parity with the batch PolicyEngine).
- Pages site gains `marketplace.html`: the watcher showcase generated
  from the SHIPPED manifests at render time (never hand-maintained — a
  hand list would be a second truth). Ten shipped examples listed with
  tier, domains, maintainer.
- Pugio watch-feed bridge receiver (`scripts/pugio_watch_receiver.py`,
  K0 §6 / K3): ingestion point for the PUGIO metering layer's decision
  stream (watch_manifest → watch_event* → watch_close), re-hashing the
  chain receiver-side, fail-loud, stdlib-only, core untouched. Hardened
  on arrival: strict field schemas (unknown fields are RED — the
  standard's D5 lesson: a field outside the hash preimage must not ride
  along silently), and the manifest's `bundle_event_count` must respect
  the subset invariant (the feed carries DECISION events ⊆ the bundle,
  so bundle_event_count < close.entries is a lie and RED — equality
  would wrongly reject legitimate bundles whose receipts stay out of
  the feed; producer-side semantics, corrected by the PUGIO agent during
  review). 11 tamper-class pins in `tests/test_pugio_bridge.py`,
  including one honest KNOWN-LIMIT pin: manifest VALUES are not chained
  in v1 (needs producer-side changes → bridge_version=2).
- Watcher marketplace reaches TEN shipped examples (G2 direction; exit
  criterion ③ needs ≥10 ACTIVE manifests on the marketplace): eight from
  the growth batch (secret-scan W1b, license-scan, docker-best-practices,
  doc-sync, sbom-spdx — all W3 except secret-scan) plus two more roadmap
  watchers — a11y (W3, HTML hygiene: img-without-alt,
  aria-hidden-focusable) and import-weight (W1b, deterministic
  import-graph weight vs a startup budget; measures WEIGHT not coverage —
  coverage stays the sbom watcher's job). All pass the conformance kit
  (C1–C10), are registered in the dogfood Phase 2 segment, and manifests
  are exported under `examples/manifests/`.
- Auditee program (launch follow-up, strategy imperative ②): the
  "Audit my repo" issue template; README gains a paste-ready
  self-serve section (task manifest → audit → offline verify); shippable
  reusable GitHub Action `.github/workflows/veridict-audit.yml`
  (workflow_call; ledger+cert artifacts; optional risk gate).
- Standard v1.1 delta DRAFT (`docs/specs/2026-09-12-...-v1.1-delta.md`):
  ratifies exactly the WATCH transport latency sentence deferred by erratum
  D10 as amendment A1; deliberately minimal, no other normative change.
  Erratum D10 in v1.0 §14.2 now links the delta and stays OPEN until
  ratified. Issue #8 opened for the formal verification of the ladder's
  tier rules (Coq/Lean; intentionally an issue, not a branch).
- WATCH-mode streaming transport (issue #3, erratum D10): new module
  `veridict/watcher_stream.py` — `LedgerStream` subscribes to a JSONL
  ledger file, detects appended entries (complete lines only; torn
  trailing lines held back), recomputes the §10.2 flag set per increment
  through the SAME §7 ladder as the batch engine, and emits
  `watch.observed` Observations that never block. Parity with the batch
  PolicyEngine is pinned by test (identical verdicts, identical flags);
  incrementality, torn-line tolerance, missing-file waiting, and
  JSON-serializable summaries are each pinned. No latency-budget
  conformance is claimed — the normative sentence is proposed as erratum
  D10 (§14.2) and deferred to v1.1.

## 0.3.1 — 2026-09-11 (adoption surface + hardening night)

- Executable contract vectors beyond certificates: `watcher_vectors.json`
  (§6.3/§6.4 session contract: ceiling, clamps, abstains, deadline) and
  `ladder_vectors.json` (§7 decision table, 11 cases) — the reference
  ladder and the spec-only ladder agree on every case, asserted at build
  time (`scripts/build_contract_vectors.py`)
- JSON Schema contracts (§4/§6/§11) under `docs/schemas/` — validated in
  CI against EVERY dogfood ledger entry, the dogfood certificate, and all
  shipped watcher manifests; schema drift from reality fails the build
- `veridict registry` subcommands: init (0600 key file), register,
  revoke, list, index — a marketplace owner's complete surface; signing
  power never lives in the ledger
- `veridict audit --registry r.jsonl`: an external registry is
  AUTHORITATIVE — wired watchers must be registered and ACTIVE there;
  self-registration cannot bypass revocation (§6.6 at the CLI)
- `veridict audit --watcher manifest.json:module:fn`: external watchers
  via CLI, with code_hash verified against the entry module
- Signature-format interop test: the certificate verifies with a STOCK
  ed25519 library from the JSON alone (the external verifier's first task)
- Certificate mutation differential: 16 one-field mutations — reference
  and spec-only verifiers agree on every verdict; erratum D8 (§14.2): the
  spec-only verifier crashed on an empty signatures array (fail-closed now)
- Real-jury provider hardened + validated end-to-end without an API key:
  an unset VERIDICT_JURY_KEY crashed the audit (uncaught LocalProtocolError)
  instead of the juror abstaining; all transport/contract failures now
  degrade to ProviderError
- Canary corpus: 15 cases / 11 defect classes — 9 catches / 3 honest
  misses / 0 false positives (issue #2 reference implementation; crypto-
  misuse is a deliberate honest miss)
- Nightly soak workflow (1500-ledger tamper, wide latency sample, 40-audit
  parity fuzz), OpenSSF Scorecard, public docs site
  (https://goun7.github.io/veridict/), dependency CVE scan in CI
- CLI e2e roundtrip test (audit → verify), verify_chain scaling pin
  (4k entries in ~0.09s), dogfood revocation receipt ⑥
- 219 tests green across Python 3.12–3.14, two invocation styles

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
- Watcher revocation (§6.6): signed `watcher.revoked` entries, latest-entry-
  wins lifecycle, orchestrator routing skips revoked watchers (not a
  participant — no evidence, no abstention), marketplace index excludes
  them, and certificates anchored before revocation stay valid
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
