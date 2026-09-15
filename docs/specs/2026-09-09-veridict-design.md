# Veridict — The Verdict That Survived Verification

**A Protocol for Auditing AI with AI, When Humans No Longer Can**

| | |
|---|---|
| Status | Design (pre-implementation) |
| Version | 0.9 (draft for founder review) |
| Date | 2026-09-09 |
| Model | Open-core (Apache-2.0 core + commercial platform layer) |
| Scope | This document is the founding paper: problem, thesis, architecture, evidence model, threat model, roadmap |

---

## 1. Manifest: The Audit Gap

A new reality is settling in across software engineering: the engineers building AI systems increasingly admit they can no longer review the code those systems produce. They ship it anyway — because the system *runs*, and running is the only review they have left. This is not a tooling gap. It is a structural inversion: for the first time, the producer of critical work product systematically outpaces the capacity of its reviewer.

Three facts frame the gap:

1. **Capability asymmetry is growing, not shrinking.** AI-generated output already exceeds human review throughput in volume, and is approaching it in subtlety. Subtle defects (a wrong sign in a billing path, a race condition that fires monthly, a security hole behind five layers of abstraction) do not announce themselves at runtime.
2. **"It runs" is not verification.** A passing demo proves existence of a happy path, not absence of harmful paths. The distance between "works" and "is correct, safe, and aligned with intent" is precisely where the risk now lives.
3. **The gap generalizes beyond code.** Autonomous agents now take actions — payments, deployments, external communications. The same inversion applies to *behavior*: decisions made at machine speed, reviewed (if at all) at human speed.

The mainstream response is human-in-the-loop review. That response assumes the human can meaningfully evaluate the artifact. As capability grows, this assumption fails on both ends: review quality degrades (rubber-stamping) and review cost scales with output volume. **Adding more humans is not a scaling answer; it is a postponement.**

**Veridict's thesis:** when machines out-audit humans, the unit of trust must shift from *human judgment of artifacts* to *machine-verifiable evidence about artifacts*, aggregated under governance that itself resists capture. Humans stop reading the work and start owning the risk. Veridict is the precursor of that system — built now, deliberately, before the gap becomes unbridgeable.

**What Veridict is not:** it is not "another AI reviewer." Single-model AI reviewers inherit the exact problem they claim to solve (who reviews the reviewer?). Veridict is a *protocol and system* in which no single intelligence — human or artificial — is the root of trust. The root of trust is a verifiable evidence chain.

**Positioning:** the winner in this space will not be the best auditor; it will be whoever standardizes the evidence/certificate format first — the way SARIF became the interchange format for security findings and Kubernetes became the reference for orchestration. Veridict aims to be that reference protocol for AI oversight.

---

## 2. Design Decisions (Founder-Approved)

Every load-bearing decision below was explicitly made during design review. They are recorded so future contributors know the decisions are intentional, not accidental.

| # | Decision | Choice | Rejected alternatives |
|---|---|---|---|
| D1 | Audit scope | End-to-end meta-system: code, agent behavior, decisions, evidence chains; starts narrow, architecture grows | Code-only; agent-behavior-only |
| D2 | Audit output | **Policy-selectable per task**: Certificate / Gate / Watch / Hybrid — the auditee (person or company) chooses intensity per job | Fixed certificate; fixed gate; fixed watcher |
| D3 | Trust foundation | Triple hybrid: machine-evidence core + heterogeneous model jury + escalation ladder to humans | Single judge model; jury-only |
| D4 | Architecture | Evidence Chain spine + Watcher ecosystem layer (B+C synthesis): proof-first core with pluggable third-party watchers | Judge-centric; watcher-market without evidence anchor |
| D5 | Document language | English (international standards ambition); working language with founder is Turkish | Turkish-only |
| D6 | Technology stance | Tech-neutral: architecture and contracts only; languages/frameworks chosen at implementation | Premature stack commitment |
| D7 | Naming | **Veridict** (*verify + verdict* — "the verdict that survived verification") | Attestor, Probatum, Kanıt, Auditum |
| D8 | Openness | Open-core: spec + ledger core + offline verifier are Apache-2.0; hosted platform, certification authority, enterprise integrations are commercial | Fully open (cloud-wrap risk); fully closed (contradicts offline-verifiability) |

---

## 3. System Architecture

```
                        ┌─────────────────────────────────────────┐
 Task/PR/Action ──────→ │  ACTOR (the executor AI under audit)    │
                        └──────────────┬──────────────────────────┘
                                       ▼
                    ┌─────────────────────────────────────────┐
                    │  EVIDENCE LEDGER  (append-only,         │
                    │  hash-chained, tamper-evident)          │
                    └──────────────┬──────────────────────────┘
                                   ▼
                    ┌─────────────────────────────────────────┐
                    │  CLAIM EXTRACTOR                        │
                    │  ("what should be true" as falsifiable  │
                    │   claims)                               │
                    └──────────────┬──────────────────────────┘
                                   ▼
              ┌────────────────────────────────────────────────┐
              │  VERIFIER FLEET                                │
              │  ├─ Built-in verifiers (W1a/W1b machine        │
              │  │  evidence: tests, reproducible runs,        │
              │  │  static analysis, formal checks)            │
              │  ├─ Heterogeneous jury (W2, ≥2 model families, │
              │  │  blind first round, rotated pool)           │
              │  └─ WATCHERS (pluggable third-party auditors,  │
              │     W1b(cert)/W3, manifest-signed, sandboxed)  │
              └──────────────────────┬─────────────────────────┘
                                     ▼
                    ┌─────────────────────────────────────────┐
                    │  DIVERGENCE DETECTOR                    │
                    │  (disagreement = information, not error)│
                    └──────────────┬──────────────────────────┘
                                   ▼
              ┌────────────────────────────────────────────────┐
              │  POLICY ENGINE (per-task selection):           │
              │  Certificate │ Gate │ Watch │ Hybrid           │
              └──────────────┬─────────────────────────────────┘
                                     ▼
              ┌────────────────────────────────────────────────┐
              │  ADJUDICATION LADDER:                          │
              │  machine evidence → jury consensus → human     │
              │  risk owner (via Dossier)                      │
              └──────────────────────┬─────────────────────────┘
                                     ▼
                    ┌─────────────────────────────────────────┐
                    │  SIGNED AUDIT CERTIFICATE               │
                    │  (evidence-weighted, offline-verifiable)│
                    └─────────────────────────────────────────┘
```

### 3.1 Component Roles (one sentence each)

1. **Actor** — the executor AI under audit; every output and tool use it produces enters the ledger as an immutable record.
2. **Evidence Ledger** — append-only, hash-chained register; the system's tamper-evident memory and the single source of proof for every downstream decision.
3. **Claim Extractor** — converts output into falsifiable claims about what should be true ("this function returns X for input Y", "this change breaks no existing test"); the Actor never writes its own claims.
4. **Verifier Fleet** — three producer classes: built-in verifiers (machine evidence), the heterogeneous jury (independent doctrine from distinct model families), and pluggable third-party watchers (domain expertise).
5. **Divergence Detector** — treats disagreement between verifiers as *information*: a split verdict is a risk signal and an escalation trigger, never a silent pass.
6. **Policy Engine** — selects audit intensity per task (Certificate / Gate / Watch / Hybrid) from signed, versioned policy declarations; policy chooses *reaction*, never *evidence*.
7. **Adjudication Ladder** — the evidence-weight hierarchy: machine-checkable evidence > jury consensus > single-model doctrine; unresolved disagreement escalates to a human risk owner with a digestible dossier.
8. **Signed Audit Certificate** — the final output: which claims were verified/refuted/inconclusive, with what evidence, at what divergence — signed and independently verifiable offline.

**Flow summary:** Actor output → ledger → claims extracted → fleet verifies in parallel → divergence measured → policy selects output mode → ladder resolves → certificate signed.

---

## 4. Evidence Model and Data Contracts

The ledger has one record unit — the **Ledger Entry**. Everything (actor output, claims, evidence, verdicts, policy decisions, certificates) flows through it as entries, giving the system a single integrity mechanism.

### 4.1 Ledger Entry

```
LedgerEntry {
  schema_version:  contract schema version (mandatory — see below)
  seq:             monotonically increasing sequence number
  entry_type:      task.started | actor.output | claim.registered |
                   evidence.recorded | verdict.computed | divergence.flagged |
                   policy.decision | escalation.requested | escalation.resolved |
                   certificate.issued | checkpoint.anchored |
                   key.enrolled | key.revoked
  author:          { kind: actor | claim_extractor | verifier | jury | watcher |
                          divergence_detector | policy_engine | adjudicator,
                     identity, version }
  payload:         type-specific content (Claim, EvidenceItem, Verdict, ...)
  ts:              timestamp
  entry_hash:      H( prev_entry_hash || H(payload) || entry_type || seq || author )
}
```

**Hash-chain semantics:**

- **`schema_version` is mandatory on every entry and every payload contract** (Claim, EvidenceItem, Verdict, PolicyDeclaration, AuditCertificate). An unverifiable schema cannot be replayed over time: readers must be able to pin which contract generation they are validating against. Rule: a contract change increments the version; a replay verifier either understands that version or reports `UNKNOWN_SCHEMA` — never guesses.

- `entry_hash[n]` includes the previous entry's hash: any single-byte retroactive edit invalidates the entire chain from that point. Verification = replaying the chain from genesis.
- **The audited artifact is pinned by hash at ingestion.** `actor.output` entries carry the hash and location of the output, not a mutable copy. "Was this really what was audited?" is structurally closed.
- Certificates bind to the ledger via `checkpoint.anchored` entries; a checkpoint hash covers the entire chain up to that point. Optional hardening: periodically publish checkpoint hashes to an external anchor (timestamping/notary service — not blockchain, just external pinning).
- **Append-only invariant:** no update or delete exists; corrections are new entries (e.g., `evidence.recorded` followed by `divergence.flagged`).

### 4.2 Core Contracts

**Claim** — what should be true:

```
Claim {
  claim_id, statement: { subject, predicate, scope } + free-text summary
  derived_from:        artifact hash + task_id
  verifiability:       MACHINE_CHECKABLE | DOCTRINAL | MIXED
  falsifiable_by:      proposed verification methods (test? run? jury doctrine?)
  status:              OPEN | VERIFIED | REFUTED | INCONCLUSIVE | ESCALATED
}
```

Rule: every Claim must be formulated as **falsifiable** ("good code" is invalid; "function F returns Y for input X" is valid). Verifiability is *inferred by the system*, never declared by the Actor.

**EvidenceItem** — one piece of evidence:

```
EvidenceItem {
  evidence_id, claim_id
  evidence_class:  TEST_EXECUTION | REPRODUCIBLE_RUN | FORMAL_PROOF |
                   STATIC_ANALYSIS | JURY_OPINION | WATCHER_REPORT
  tier:            W1a | W1b | W2 | W3                (see 4.3)
  producer:        { kind: builtin_verifier | jury_model | watcher,
                     identity, model_family, version }   // no anonymous evidence
  artifact_ref:    ledger entry ID of raw output       // evidence is located, never copied
  reproducibility: { deterministic: bool, rerun_recipe: ref }  // mandatory for W1a
  stance:          SUPPORTS | REFUTES
  confidence:      0..1   (fixed 1.0 for W1a)
}
```

**Verdict** — per-claim outcome:

```
Verdict {
  claim_id
  value:        VERIFIED | REFUTED | INCONCLUSIVE
  evidence_summary: tier × stance breakdown
  divergence:   UNANIMOUS | MAJORITY | SPLIT
  escalation:   NONE | REQUESTED | RESOLVED_BY(<who/what>)
  rationale_digest: short rationale
}
```

**AuditCertificate** — the signed deliverable:

```
AuditCertificate {
  cert_id
  schema_version: certificate contract generation
  subject:        { audited artifact hashes, task_id, actor identity }
  policy_mode:    CERTIFICATE | GATE | WATCH | HYBRID
  claims:         [ { claim_id, verdict.value, evidence_ids[] } ]
  jury_composition: participating model families + diversity statement
  disclosure_level: LOCAL_ONLY | REDACTED | FULL   (§7.7 privacy contract)
  divergence_summary + risk_level + score
  ledger_anchor:  { checkpoint entry id, chain hash }
  signatures:     system key (+ optional external notary)
  verify_instructions: "run this replay to verify independently"
  scope_limits:   what this certificate does NOT cover (the honesty clause)
}
```

The last field is deliberate: a certificate states its own limits. "This certificate does not include a security audit" is the signature of a system that sells trustworthiness by declaring boundaries, not by hiding them.

### 4.3 Evidence Weight Hierarchy — Exact Rules

```
W1a  Deterministic machine evidence  — test execution, reproducible run, formal proof
W1b  Statistical machine signal      — static analysis, fuzzer findings
W2   Heterogeneous jury consensus    — independent doctrine from ≥2 distinct model families
W3   Single-model doctrine           — an individual jury/watcher opinion
```

Five rules, no exceptions:

1. **Strict ordering.** W1a > W1b > W2 > W3. In cross-tier conflict, the higher tier wins.
2. **Doctrine cannot overturn a test, but can interrogate it.** W2/W3 evidence can never reverse a W1a outcome; it can, however, open a **meta-claim** ("does this test actually test that claim?"). Meta-claims enter the ledger as new Claims with their own evidence chains, under a depth budget (see §7, threat #2).
3. **A W2 split is information.** Jury SPLIT is not an error but a risk signal: a `divergence.flagged` entry is written and surfaced to the policy engine.
4. **W3 alone can never produce VERIFIED.** Single-model doctrine may clear a risk flag, never affirm a claim.
5. **Machine-checkable claims cannot be certified by doctrine.** A claim with `verifiability: MACHINE_CHECKABLE` cannot reach VERIFIED without any W1 evidence; at most INCONCLUSIVE (which blocks in Gate mode).

### 4.4 Worked Micro-Example

PR claim: *"the sort function correctly returns an empty list for empty input, and breaks no existing tests."*
Evidence: test execution PASS (W1a, SUPPORTS) · GPT-family jury "no concern" (W2, SUPPORTS) · Claude-family jury "NaN edge inconsistency" (W2, REFUTES).
→ Jury SPLIT → divergence flag. Because W1a tests passed, the base verdict leans VERIFIED; the Claude finding opens a **meta-claim** ("do the tests cover NaN scenarios?"). In HYBRID mode the certificate carries a **risk note**; in GATE mode human escalation triggers. One evidence chain, two behaviors — policy-selectability in action.

### 4.5 Long-Running Tasks (Watch mode)

Agents may run for weeks. The ledger grows continuously; the following contract applies:

- **Periodic checkpoints:** `checkpoint.anchored` entries at policy-defined intervals; each checkpoint hash covers the chain so far.
- **Ledger compaction without history rewriting:** older payloads may be *archived* (cold storage referenced by hash) but entries and hashes are never rewritten; verifiers replay from checkpoints + archived segments.
- **Live certificates:** Watch mode emits periodic mini-certificates ("state of the agent as of checkpoint N"), so a week-long agent produces daily-grade attestations, not a single end-of-run verdict.
- **Hot-restart safety:** a restarted monitoring process reconstructs state from the ledger alone — the ledger, not process memory, is the system of record.

---

## 5. Verifier Fleet: Jury and Watcher Interfaces

The fleet has three producer classes with distinct authority, capability, and audit regimes. The goal in one sentence: **embed the answer to "who audits the auditor" into the fleet's structure.**

```
                         CLAIM (read from ledger)
                                │
                    ┌───────────┼────────────────┐
                    ▼           ▼                ▼
          ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
          │ BUILT-IN     │ │ HETEROGENEOUS│ │ WATCHERS     │← pluggable
          │ VERIFIERS    │ │ JURY         │ │ (3rd-party)  │
          │ W1a / W1b    │ │ W2           │ │ W1b(cert)/W3 │
          ├──────────────┤ ├──────────────┤ ├──────────────┤
          │ test runs    │ │ ≥2 model     │ │ security     │
          │ reproducible │ │ families,    │ │ compliance   │
          │ runs         │ │ blind first  │ │ cost privacy │
          │ static anal. │ │ round,       │ │ domain...    │
          │ formal proof │ │ rotated pool │ │ manifest+    │
          │              │ │              │ │ sandbox      │
          └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
                 └────────────────┼────────────────┘
                                  ▼
                    evidence.recorded → ledger (append-only)
```

### 5.1 Built-in Verifiers (W1a/W1b producers)

Four core producers:

1. **Test Executor** — runs claim-linked test suites in a sandbox; output + rerun recipe enter the ledger. W1a.
2. **Reproducible Run** — executes the artifact in a pinned, deterministic environment and compares behavior against the claim. W1a.
3. **Static Analyzer** — type checks, linters, SAST scans. W1b (signal, not certainty).
4. **Formal Verifier** — where applicable (pure functions, protocol contracts): spec-vs-implementation verification. W1a; optional, not required for every claim.

Rule: **every W1a evidence item must carry a `rerun_recipe`** — evidence that cannot be independently re-produced is not W1a; it drops to W1b.

### 5.2 Heterogeneous Jury (W2) — Composition Rules

1. **Minimum diversity:** W2 status requires ≥2 distinct **model families**; target composition is 3 (majority/split distinction is meaningful only at ≥3). Family = distinct architecture and training lineage; models with known shared descent (e.g., distillation) count as the **same family**. The diversity statement is written into every certificate.
2. **Blind first round:** jury members receive the claim + artifact references; they never see each other's doctrine. This is the primary antidote to collusion.
3. **Optional second round (deliberation):** only after a SPLIT, with cross-visible opinions; the final report marks "post-deliberation consensus" honestly and separately — the first-round split is never hidden.
4. **Rotated pool:** every audit draws a seeded, ledger-logged subset from the jury pool. A fixed roster makes consensus cartels predictable; rotation makes them structurally hard.
5. **Calibration ledger:** every producer's track record lives in the same ledger — a jury member whose doctrine is later refuted by W1a evidence loses calibration score. **Important limit:** calibration touches only `confidence`, never tier — the hierarchy rules (§4.3) are invariant over time.

### 5.3 Watcher Interface — the Platform Gate (C layer)

A Watcher is a third-party specialist auditor (security, compliance, cost, privacy, domain-specific). Two contracts:

```
WatcherManifest (registration contract — signed)
  watcher_id, name, version
  producer: { identity, maintainer, signature }     // no anonymous watchers
  capabilities:
    evidence_classes: [ ... ]                        // what it may produce
    max_tier: W1b | W2 | W3                          // certification ceiling
    subscribes_to: claim types / domains
  resource_class: { timeout, cost_budget, sandbox_level }
  integrity: { code_hash, update_policy }            // the watcher's own code is pinned

WatcherSession (runtime contract)
  input:   READ-ONLY claim + artifact references from the ledger
  output:  evidence.recorded entries (stance, confidence, artifact_ref)
  blind:   cannot see other watchers'/jury outputs (same regime as jury)
  authority: may write ONLY evidence.recorded — no other entry type
```

**Tier ceiling logic:** watchers producing deterministic tool output (e.g., a SAST engine) can generate **W1b with certification**; doctrinal watchers stay at W3. Jury membership is a separate, independently granted role — watchers extend the fleet's *coverage*, not its *spine*. This distinction lets the platform grow while the trust base stays fixed.

**Scaling property:** new audit capability = new manifest. The ecosystem grows without touching the core — the technical form of the platform thesis.

### 5.4 Orchestration and Game-Theoretic Antidotes

**Routing:** the claim router dispatches each claim to fitting producers based on `verifiability` and `falsifiable_by`; runs run in parallel under per-claim time/cost budgets. Routing derives from manifests, not hardcoded rules.

| Attack vector | Antidote |
|---|---|
| Actor games the verifiers | Actor has no access to evidence/verdict producers; write authority is disjoint by entry type |
| Intra-jury collusion | Blind round + family diversity + rotation + transparent deliberation |
| Metric gaming (Goodhart) | No single score: divergence is information, not penalty; the certificate shows raw tier×stance breakdown |

**Abstain ≠ refute:** a producer that does not answer, times out, or errors contributes **no evidence** — "no evidence" is recorded honestly. Persistently silent producers are health-tracked. When the fleet falls silent, the system knows how to say "I don't know."

**Routing micro-example:** Claim `MACHINE_CHECKABLE` ("no existing test breaks") → Test Executor (W1a) + Static Analyzer (W1b) + 3-family jury (W2) + subscribed security watcher (W1b). Claim `DOCTRINAL` ("API usage is idiomatic and consistent") → jury only (W2).

### 5.5 Claim Extractor Governance

The Claim Extractor is itself a fleet producer and is governed as one (resolving design-review note):

- **Identity:** a fleet producer with `author.kind = claim_extractor`; every `claim.registered` entry is attributable and versioned.
- **Implementation (Phase 1):** hybrid — deterministic rule-based extraction (test invocations, contracts, spec deltas) plus LLM-assisted extraction for fuzzy intent; the deterministic layer guarantees coverage floors, the LLM layer adds breadth.
- **Self-audit:** sampled independent re-extraction runs in parallel; if two extractors diverge on the same artifact, a flag is raised and the extraction strategy is itself auditable from the ledger.
- **Honest bound:** claim extraction is heuristic and never exhaustive; the certificate's `scope_limits` field always carries the line "claim coverage is heuristic, not exhaustive."

---

## 6. Policy Engine and Adjudication Ladder

This section is the system's **decision-distribution constitution**. Two principles carry everything:

> **Principle 1 — Evidence and decision are disjoint.** Policy never changes what the evidence says; it only selects what happens next. Same ledger + same claims + same evidence → same verdicts. Policy chooses blocking behavior, output format, and escalation thresholds — never outcomes.
>
> **Principle 2 — Policy is data, not code.** Every policy declaration is a versioned, signed object written to the ledger (`policy.decision`). "Who relaxed which threshold for which task?" is answerable from the ledger. Policy changes are themselves audited events.

### 6.1 Policy Declaration and the Four Modes

```
PolicyDeclaration (signed, versioned, ledger-recorded)
  mode:           CERTIFICATE | GATE | WATCH | HYBRID
  criticality:    which claim classes are "critical" (security/money/liberty...)
  thresholds:     { min_jury_families, divergence_tolerance, min_w1_coverage,
                    meta_claim_depth_budget }
  escalation_route: channel + response window + fail-safe default
  budget:         per-claim time/cost ceilings
```

| Mode | When | Blocks? | Output | Typical consumer |
|---|---|---|---|---|
| **CERTIFICATE** | After work completes | No — produces a signed certificate whatever the outcome | Attestation: verified/refuted/inconclusive claims + scope limits | Compliance teams, future auditors |
| **GATE** | Before merge/deploy/action | **Yes** — no pass without W1 evidence on critical claims or with unresolved critical divergence | Gate decision + rationale references | CI/CD pipeline, agent orchestrator |
| **WATCH** | While the agent runs | No — live stream | Anomaly/divergence flags, periodic mini-certificates | Operations screens, webhooks |
| **HYBRID** | Across the lifecycle | Partial — critical claims GATE, rest CERTIFICATE, WATCH during execution | All three under one certificate | Enterprise default |

**Modes are lifecycle layers, not competitors:** one task can run WATCH while executing, GATE at completion, and emit a CERTIFICATE at the end. HYBRID is exactly this composition and is the recommended enterprise default.

**Thresholds live in policy data, not code.** Example: `min_w1_coverage` — "at least 80% of MACHINE_CHECKABLE claims must have W1 evidence" — is a threshold; gate decisions are mechanical consequences of it. Changing it means changing (and signing) a policy version, which lands in the ledger.

### 6.2 The Adjudication Ladder — Five Rungs

```
R0  MACHINE RESOLVES     W1a evidence is univocal (all SUPPORTS, or any REFUTES)
                         → automatic VERIFIED/REFUTED; no doctrine needed
R1  CONSENSUS RESOLVES   W1b+W2 lean the same way; divergence UNANIMOUS/MAJORITY
                         → automatic decision at standard confidence
R2  SPLIT EVALUATION     SPLIT — mode-dependent:
                         CERTIFICATE → proceed with risk note
                         GATE+critical → escalate
R3  HUMAN RISK OWNER     Dossier delivered (§6.3); the human decides on the
                         DISAGREEMENT and RISK — not on code
R4  FAIL-SAFE            No human / window expired / "undecided": no silent pass —
                         GATE stays blocked; CERTIFICATE issues with "unresolved"
                         stamps. The system never slips through empty-handed.
```

**R3 is the project's conceptual heart — the transformation of the human role.** The founding premise: humans can no longer review the artifacts. Therefore the human at R3 is **not a code reviewer but a risk owner**. What they receive is not a diff but the disagreement itself: "Two independent intelligences split on this point; one relies on this evidence, the other on that evidence; if this side is wrong, the consequence is this." That decision requires not intelligence but **accountability and risk tolerance** — the one thing that cannot be delegated to automation. The system's philosophy: *the machine owns the verdict of intelligence; the human owns the verdict of responsibility.*

### 6.3 The Dossier — Human-Digestible Evidence

On escalation, the human receives (a *view over the ledger*, never a separate reality):

```
Dossier
  summary_page:   what was claimed / what machines proved / where the jury split
                  — plain language, jargon-free rationale translation
  risk_frame:     "if the REFUTES side is right: these consequences"
  options:        [ accept with risk note | demand independent rerun via
                    rerun_recipe | narrow/redefine the claim | reject ]
  default:        response window expiry triggers policy.fail_safe (R4)
  evidence_links: every sentence → ledger entry ID (clickable chain)
```

The dossier's language is deliberately **impact language, not code language**: "This function may flip a sign in the billing path; per the finding, invoices could total 1,000 instead of 1,000,000" — exactly what a risk owner needs to decide.

### 6.4 Worked Transition — One Disagreement, Three Behaviors

The §4.4 NaN scenario (jury SPLIT, Claude family flags NaN inconsistency, W1a tests pass, meta-claim opened):

- **CERTIFICATE mode:** certificate issues — claim VERIFIED (W1a base), risk note: "jury SPLIT, meta-claim open", scope line: "NaN scenarios not covered".
- **GATE mode:** the meta-claim is MACHINE_CHECKABLE and not policy-critical → passes; were it critical → R3 dossier, merge blocked until response.
- **WATCH mode (long-lived agent):** live flag drops; the same disagreement recurring at runtime (a pattern!) raises flag severity — pattern-recognizing watcher behavior.

One evidence chain, three policy-driven outcomes — Principle 1 demonstrated live.

### 6.5 Latency Targets (Phase 1, measurable)

- **GATE mode:** end-to-end audit of a typical PR < 30 minutes (p95), so Gate fits a CI pipeline without becoming the bottleneck.
- **WATCH mode:** stream flag latency < 5 minutes from triggering event.
- **CERTIFICATE mode:** asynchronous, no latency contract (completeness over speed).
- Latency budgets are policy data (`budget` field), measured and reported in Phase 1; missing them is a Phase 1 exit-criterion failure, not a footnote.

---

## 7. Trust and Threat Model

A system built to audit others must first pass its own audit. This is the document's honesty section.

### 7.1 Assets, Adversaries, Trust Boundaries

**Assets:** ① ledger integrity (the evidence chain), ② verdict/certificate correctness, ③ policy declaration integrity, ④ **human attention** — the scarcest resource; the dossier mechanism exists to protect it.

**Adversaries:** an Actor wanting to pass audit · a compromised or dependent jury member · a malicious watcher developer · an insider operator wanting looser audit · an outside certificate forger · **the system's own founders.**

**Zero-trust boundary lines:** the Actor writes nothing to the ledger (it only submits output) → fleet members write only their own entry types (§5.4 authority disjointness) → the dossier is a view over the ledger, never a separate truth → only signed certificates and anchors leave the system.

### 7.2 Attack Vectors → Antidotes

| # | Attack | Antidote |
|---|---|---|
| 1 | **Goodhart / "metric expert":** Actor writes code+tests that pass the audit instead of serving the goal | Claims derive from task intent; Actor never writes its own claims; meta-claims can interrogate test validity; no single score — certificates show raw tier×stance breakdown; divergence is a tripwire |
| 2 | **Meta-claim infinite regress:** "test is wrong" → "meta-claim is wrong" → ... | **Depth budget** (policy data, default max 2): a meta-claim may interrogate scope but never spawn an unbounded chain; per-claim cost ceiling; unresolved meta-claim → INCONCLUSIVE + fail-safe (R4) — no silent pass |
| 3 | **Ledger forgery / key compromise** | Hash chain + append-only (a single retroactive bit invalidates the tail; verification = replay); certificate signatures; **regular external anchoring** — tampering before the most recent anchor is always detectable, even with a stolen key, while m-of-n threshold signatures + key rotation protect the post-anchor window |
| 4 | **Jury cartel / correlated error:** members fail the same way | Blind round + family diversity + rotation (§5.2); W1a can never be overturned by doctrine; calibration ledger. **Honest note:** heterogeneity is a statistical, not cryptographic, antidote — models trained on the same internet can fail the same way (see §7.4) |
| 5 | **Watcher poisoning** | Signed manifest, `max_tier` ceiling (a watcher can never produce W1a → adds noise, cannot flip decisions), sandbox isolation, blind sessions, health tracking + revocation |
| 6 | **Claim-extraction gap:** extractor misses a claim; the audit is blind there | The extractor is itself audited (§5.5): sampled independent re-extraction, divergence between extractors raises a flag; certificates carry the honest "claim coverage is heuristic" scope line |
| 7 | **Actor produces deliberately unverifiable output** | Verifiability is system-inferred, never Actor-declared; `min_w1_coverage` threshold; unauditable tasks are not rejected but their certificates read "could not be audited" — which is itself information |
| 8 | **Cost explosion:** full fleet on every claim | Policy budgets (per-claim time/money, auditable data); tiered routing (don't call the jury where a test suffices); sampling in WATCH mode; escalation only on divergence |
| 9 | **Human-layer attacks:** rubber-stamping fatigue + dossier framing manipulation | Escalation budgets (real SPLITs reach humans; most claims resolve at R0/R1); the dossier's risk frame must present **both sides' strongest evidence**; every sentence links to an entry ID; dossier format is versioned and auditable; human decisions feed calibration (measure, not coerce — honest note) |
| 10 | **Insider loosening:** "lower the threshold just this once" | Principle 2: policy is data — versioned, signed, ledger-recorded; certificates carry which policy version decided what; loosening cannot be hidden, only done visibly |

### 7.3 The Self-Audit Paradox — "Who Audited This System?"

The thesis itself circles back: the system will largely be built by AI. The answer rests on one principle:

> **Small-Core Principle:** everything intelligent lives in the fleet (replaceable, auditable); the core (ledger, hash chain, tier rules, policy engine) is deliberately kept **boring, small, and human-readable**. The trusted computing base (TCB) is minimized — the core's complexity budget is a design invariant, not a later optimization.

Four concrete mechanisms:

1. **Mandatory dogfooding:** a Phase 1 exit criterion — the system's own v0.1 is audited by itself and receives a certificate. No claim before the system exists.
2. **Core rules are W1a-testable:** the five tier rules, chain verification, entry-authority matrix — all provable by deterministic tests; no intelligence required.
3. **Offline verifiability:** anyone can independently verify any certificate via replay — trust rests on mathematics, not on the system.
4. **Residual risk (honest):** if the core itself is flawed, everything above is theater. Hence formal verification of the core is a deliberate roadmap item (Phase 3 stretch), not decoration.

**Dogfooding micro-example:** v0.1's ledger core gets: write-path openness test (W1a: no write path exists outside task submission), chain replay verification (W1a), and 12 synthetic scenarios where the policy engine must uphold Principle 1 (W1a). Only "API idiomaticity"-class doctrinal claims reach the jury. The core is auditable without the fleet — that is the design speaking.

### 7.4 Fundamental Limits — What the System Cannot Do

1. **It cannot dissolve correlated blind spots.** Heterogeneous juries reduce shared-training-blindness but never eliminate it. W2 can never substitute W1 — hence the strict hierarchy.
2. **It cannot audit what cannot become a claim.** Intent, taste, unstated requirements... Claim extraction is heuristic; `scope_limits` exists for this. Certificates state what they do not know.
3. **It cannot eliminate human responsibility — it transforms it.** The R3 risk owner is mandatory; the machine owns the verdict of intelligence, the human owns the verdict of responsibility.
4. **It cannot prove its own core — except the part that now has proofs.** As of 2026-09-15 the adjudication ladder is machine-checked in Lean (proofs/ladder/: seven invariants over evidence lists of *arbitrary* length, plus a generated oracle re-checking the model against all 28,080 bounded receipt cases at build time — trust placement disclosed in the file headers); and as of the same date the append-only chaining of `verify_chain` is machine-checked too (proofs/ledger/Chain.lean: six theorems over chains of *arbitrary* length — writer/reader agreement, prefix-closure, payload-edit detection, honest-remint detection *modulo a stated collision hypothesis*, genesis-rooting; structural induction only, measured [propext]-maximal axiom footprint); and the structural layer of certificate⇄CT-anchor cross-verification (proofs/anchor/Anchor.lean: nine theorems — fail-closed parsing, binding-necessity, no-silent-skip, honest-mint acceptance on both verification paths, tree containment, note/proof root agreement, uuid/leaf embedding — headed by the architecture claim that a mismatched binding invalidates the sidecar *regardless of both ECDSA verdicts*; the signature checks enter as disclosed opaque booleans, so the model names the computational assumption instead of faking it; all nine measure [propext] only). What remains TCB-minimization territory: ECDSA soundness itself and the JSON/SHA-256 instantiations — computational, out of structural reach by honest design; roadmap honest. First-run value already demonstrated: the oracle caught a model/implementation divergence (R0's no-refute-anywhere guard) before anything shipped.
5. **It does not end Goodhart — it relocates it.** The attack surface moves from code to claim space; divergence detection is a tripwire, not a cure. This is an arms race, honestly named.
6. **It cannot make acceptance decisions.** A policy author who sets bad thresholds produces bad outcomes — but visibly, in the ledger. The system cannot prevent bad governance; it can make it **impossible to hide**. That may be the only thing it needs to guarantee.

### 7.5 Trust Assumptions (Explicit)

Cryptographic primitives hold (hash/signatures) · ≥1 independent jury family is reachable per audit · ≥1 human is reachable for R3 on GATE-critical paths (otherwise fail-safe blocks) · the anchor service (if used) is available. When an assumption breaks, the system does not silently continue — it enters a **visible, degraded-trust mode**.

### 7.6 Audit-Quality Measurement — the Canary Protocol

A system that claims to audit must be able to **measure its own audit quality**. Veridict ships with a continuous canary protocol:

- **Seeded-defect corpus:** a maintained corpus of artifacts with known planted defects (subtle logic bugs, missing edge-case handling, injected vulnerabilities) plus clean controls, each tagged with defect class and ground truth. Corpus items and ground truth are versioned and ledger-recorded.
- **Blind injection:** canary artifacts flow through real audits indistinguishably from production traffic (blind to fleet and jury); catch-rate per defect class is measured continuously.
- **Published metrics:** every certificate schema family carries an attached, periodically published **Quality Sheet**: per-class catch rate, false-positive rate, divergence-calibration (does SPLIT actually predict downstream-proven error?), and human-escalation accuracy. Published numbers are themselves ledger-anchored.
- **Regression tripwire:** a drop in catch-rate for any defect class is treated as a production incident — the fleet/jury composition change that caused it is identifiable from the ledger, because rotation and producer versions are recorded.

Without the canary protocol, "we audit AI" is a claim; with it, it is a measurement. This protocol is a Phase 1 exit criterion (§8, criterion ⑥).

### 7.7 Privacy Contract — Auditing Without Leaking

If jury models and watchers are third-party services, the audited material leaves the operator's boundary — the single largest enterprise objection. The contract:

- **Redaction-before-dispatch (default):** claims and artifact references are redacted/pseudonymized before reaching external producers — secrets, credentials, PII, and proprietary identifiers are stripped; verifiers receive what the *claim* requires, not the whole artifact.
- **Tiered disclosure policy (policy data, signed):** per policy declaration, artifact classes map to disclosure levels — `LOCAL_ONLY` (built-in verifiers only; nothing leaves), `REDACTED` (default; redacted views to jury/watchers), `FULL` (explicit operator opt-in, ledger-recorded). Juror/watcher manifests declare their data-handling class; the router enforces disclosure levels at dispatch.
- **Local-jury mode:** air-gapped/high-sensitivity deployments may run the W2 layer on locally hosted model families; heterogeneity requirement is unchanged, the diversity statement documents local composition.
- **Residual truth (honest):** redaction can degrade audit quality (a redacted view may hide the very defect). Certificates carry a `disclosure_level` field; a REDACTED certificate states that its verdicts are bounded by what was disclosed. Privacy and audit depth trade off **visibly**, in the ledger — consistent with §7.4 item 6.

### 7.8 Key and Identity Management

m-of-n signatures (§7.2) are only as strong as the identity system behind them:

- **Identity registry:** every producer, operator, and signer holds a registered identity (key + role + authority scope) recorded in the ledger at registration; anonymous producers are structurally impossible (consistent with §4.2, §5.3).
- **Rotation:** signing keys rotate on a policy-defined schedule; rotation events are ledger entries; old keys verify history, only the current key signs.
- **Revocation:** compromised identities are revoked via a ledger-recorded revocation entry; revocation takes effect for *future* entries, and a revoked producer's evidence written before revocation is flagged (not deleted — append-only) and surfaces in certificates through producer status.
- **Threshold governance:** the m-of-n signer set and its change procedure are themselves policy data — changing the signer set is a signed, ledger-visible event.

---

## 8. Roadmap

| Phase | Content | Exit criteria (measurable) |
|---|---|---|
| **Phase 0 — Paper** | This document + name + license decision | Document approved; git repository initialized |
| **Phase 1 — Core (B spine)** | Ledger + hash chain; claim extractor (hybrid, §5.5); built-in verifiers (test execution + reproducible run + static analysis); mini-jury (2–3 families, blind); divergence detector; policy engine (4 modes); ladder R0–R4; signed certificate + **offline verifier CLI**; **canary protocol v0** (seeded-defect corpus + blind injection + Quality Sheet, §7.6) | ① The system **audits its own v0.1 and receives a certificate** (mandatory dogfooding, §7.3) ② An independent party verifies the certificate via replay ③ ≥1 real AI-generated PR audited end-to-end ④ All five tier rules proven by tests ⑤ GATE latency target met (§6.5) ⑥ Canary Quality Sheet published with non-trivial catch-rates on the seeded corpus |
| **Phase 2 — Watcher Layer (C synthesis)** | WatcherManifest signing + session isolation; 3 example watchers (security/cost/compliance); calibration ledger; deliberation round; **dossier generator** (R3) | ① An external watcher runs a blind session ② Full turn completed: SPLIT → dossier → human decision → ledger return ③ Calibration data accumulating |
| **Phase 3 — Platform + Standard** | Watcher marketplace; hosted enterprise layer; **spec v1.0 standard publication**; community governance; formal verification of the core (ladder + ledger chaining + anchor structure: done 2026-09, proofs/ladder + proofs/ledger + proofs/anchor + proofs.yml CI; ECDSA soundness + JSON/SHA-256 instantiation: open — computational, out of structural model by design) | ① A third party implements an independent verifier from the spec ② First external production deployment ③ ≥10 active watcher manifests |

Phase 1 is deliberately narrow: it does not carry every architectural stone in this document — it carries the smallest honest core that can produce a certificate.

---

## 9. Openness and Commercial Strategy (Founder-Approved: Open-Core)

**Why fully closed fails structurally:** the design's offline-verifiability principle (§7.3) — anyone can verify any certificate by replay — is logically incompatible with a closed-source verifier. Nobody can trust a closed trust infrastructure; being forced to would repeat the exact mistake Veridict exists to fix ("they use it because they can't review it"). A closed model also cannot seed a watcher ecosystem and cannot become a standard.

**Why fully open under-monetizes:** the classic cloud-wrap move (a hyperscaler wraps the core and sells it) is left open.

**Chosen model — Open-core + protocol-first:**

| Open (Apache-2.0) | Commercial |
|---|---|
| Spec: evidence format, certificate schema, tier rules | Hosted audit platform (SaaS) |
| Ledger core (reference implementation) | Enterprise policy management + integrations (CI/CD, SIEM, compliance reporting) |
| **Offline verifier library** (design-mandated open) | **Certification authority** — the W1b watcher certification (`max_tier`, §5.3) is issued by this authority |
| Watcher interface | Marketplace commission + SLA support |

**Why this wins commercially:** with a closed model, a company that refuses to pay simply writes its own alternative — the freedom exists. With an open core, the company's alternative is to **implement your spec themselves** — possible, but you defined the protocol, so every implementation answers to your definition; companies pay for the operational layer (hosted, certification, support) where the real cost lies. The SARIF and Kubernetes pattern: **whoever defines the protocol wins; whoever sells the product earns.** Openness here is not charity — it is the moat: an audit system that is not a standard has no standing to audit anything.

**Sequencing:** Phases 1–2 open-source (adoption + reputation + dogfooding + community); the commercial layer opens at Phase 3. Long-term, if standard status settles, spec governance can move to a foundation — neutral governance universalizes the standard while the commercial layer keeps earning above it (the CNCF/Kubernetes model). The regulatory wind (EU AI Act's tamper-evident logging and human-reviewability requirements) favors open, verifiable, certifiable tooling — this model sails it.

---

## 10. Name

**Veridict** — *verify + verdict*: "the verdict that survived verification." A unique coinage (registrable as a mark), it compresses the system's output into one word and the founding thesis into one sentence: *the verdict that survived verification is the only one worth issuing.*

Runner-up names, preserved for the record: **Attestor** (rooted security term; generic, collision risk), **Probatum** (Latin "it has been proven"; seal imagery, needs explanation), **Kanıt** (Turkish for "evidence"; local-root-to-global-brand path, pronunciation risk), **Auditum** (from Latin *auditus*, "a hearing"; corporate tone, weaker story).

---

## 10.5 Prior Art and Differentiation

Veridict is early, not first — honest positioning against the nearest neighbors:

| Prior art | What it solves | Where Veridict differs |
|---|---|---|
| **SLSA / in-toto** | Supply-chain integrity: signed provenance of *build steps and artifacts*; VSA communicates verification results against a policy | Veridict audits the *semantic correctness of AI-produced output* (claims about behavior), not just the chain of custody; provenance is a necessary substrate, not the product — and interoperable rather than parallel: `veridict export --format vsa` projects any certificate onto the SLSA v1.2 Verification Summary Attestation (the VSA is a lossy view; the certificate stays authoritative) |
| **AuditWeave** (arXiv:2607.09682, Jun 2026) | Hash-chained evidence ledger for AI-agent forensic traces, with mutation-trial robustness testing | Closest neighbor and convergent validation: it independently confirms the *ledger primitive* is the right substrate for AI evidence, and its mutation trials (deliberately corrupt traces, measure detection) are exactly this protocol's canary-corpus doctrine (§9). Where it stops at *recording and reconstructing* evidence, Veridict *adjudicates* it: weighted evidence hierarchy, blind heterogeneous juries, divergence semantics, policy modes, and an offline-verifiable certificate a stranger can check without trusting us. AuditWeave is a forensic tool for one investigation; Veridict is a cross-party protocol with a revocation-enforced watcher fleet |
| **SARIF** | Interchange format for security *findings* | Veridict defines the interchange for *evidence-weighted audit verdicts* across all claim classes, with a weight hierarchy and divergence semantics — findings are inputs to W1b, not the certificate |
| **LLM-as-judge literature** (Zheng et al. arXiv:2306.05685; Wang et al. arXiv:2305.17926; Watai et al. arXiv:2410.21819) | Using models to evaluate outputs; documented position/verbosity/self-enhancement biases and multi-agent calibration | Single-judge doctrine is exactly what Veridict's structure rejects: blind heterogeneous juries, evidence tiers, strict rule that doctrine can never overturn machine evidence — and the reference jury implementation ships the mitigations this literature prescribes (sample-majority voting, evidence-first extraction, author-family exclusion), so known bias is structurally damped, not merely acknowledged |
| **CI quality gates / policy-as-code (OPA)** | Blocking builds on rule evaluation | Rules evaluate *declarations*; Veridict evaluates *claims against evidence* with an adjudication ladder and human-risk-owner escalation |
| **Formal verification** | Proving correctness against a spec | A W1a evidence class inside Veridict's fleet, applied where applicable — not a whole-system answer |
| **AI governance frameworks (NIST AI RMF, ISO 42001, EU AI Act)** | Management-level requirements (logging, human oversight, risk) | Veridict is a *technical protocol* that makes those requirements mechanically satisfiable — tamper-evident logs, evidence-weighted verdicts, digestible human escalation; a compliance target, not a competitor. Regulatory clock, refreshed 2026-09: GPAI enforcement powers active 2026-08-02; Art. 50 transparency applies since 2026-08-02 (Omnibus grace for machine-readable marking of legacy systems until 2026-12-02); the GPAI Code of Practice lists 180+ adhering signatories as of 2026-08-02 |
| **HANSARD** (arXiv:2608.22512, Aug 2026) | Tiered evidence grading for agent claims; also voices the sharpest critique of self-attested ledgers — "records produced by suspects" | Direct threat on two fronts (tiered-evidence novelty, ledger trust), and the critique is *correct* — so the architecture answers it: decisive W1a evidence is re-executed by the verifier, not accepted on the producer's say-so; the checkpoint is anchored in a third-party transparency log (Rekor) outside any participant's infrastructure; doctrine can never overturn machine evidence; juries exclude the author's model family. What HANSARD leaves as critique, Veridict ships as structure |
| **VCT** (arXiv:2606.23003, Jun 2026) | Hash-chained, tamper-evident transcripts of LLM agent interactions | Third independent confirmation of the ledger primitive in twelve months (AuditWeave, HANSARD, VCT). VCT records conversation provenance; it does not adjudicate claims over it, weight evidence, or issue certificates a stranger can verify offline — the recording/adjudicating split is the moat |
| **IET** (arXiv:2603.17445, Mar 2026) | In-band provenance for agent outputs (watermarking the model's own stream) | In-band provenance is produced by the suspect system itself — exactly the HANSARD critique; Veridict's provenance is out-of-band (transparency log) and behavioral (re-execution), never a property of the generated bytes alone. C2PA-line gap analyses (arXiv:2604.24890, 2603.02378) document the same limits for media credentials |
| **MedAgentAudit** (arXiv:2510.10185) | Empirical audit of clinical agent pipelines; measures self-consistency collapse — agents repeat their own views (98.42% in their setting) and majority voting amplifies correlated error | Corroborates two Veridict doctrines with data: divergence is information (never averaged away), and jury heterogeneity must be enforced by *family exclusion*, not by counting heads |
| **Judge-calibration cluster** (arXiv:2609.12002, 2609.12439, 2606.13221, 2607.28636; Sep–Jul 2026) | Calibrating LLM-judge scores to human ground truth (conformal prediction, bias correction) | None connects calibration outputs to an offline-verifiable artifact a third party can audit; Veridict's stance is stricter still — calibration cannot license doctrine to outrank re-executed machine evidence (the W2 tier cap is structural, not statistical) |
| **microsoft/agent-governance-toolkit** (6.3k★, active 2026) | Runtime policy enforcement for autonomous agents — guardrails, action blocking, kill switches | The highest-visibility adjacent project, and complementary in direction of flow: it constrains agents *before/during* actions; Veridict adjudicates *after* the fact into a certificate a counterparty can verify without trusting the vendor, the auditor, or the runtime. A deployment can (and arguably should) run both; side-by-side positioning published in README §Interoperability |

**The open niche (re-scanned 2026-09-15):** no prior system combines (a) a tamper-evident evidence ledger for AI output, (b) a weighted evidence hierarchy where machine evidence dominates model doctrine, (c) heterogeneous blind juries with divergence-as-information, (d) policy-selectable audit intensity, and (e) offline-verifiable certificates. Three independent 2026 papers now reach (a) alone — AuditWeave, HANSARD, VCT — which strengthens rather than weakens the claim: primitives converge, combinations don't. No published research specifically maps SLSA/VSA attestation onto AI work-product audits as of this scan (our `export --format vsa`/`spdx` projections appear to be the first shipped artifacts in that gap). Methodological note, in the spirit of the standard: an "AegisChain" entry circulating in secondary surveys of this space could not be traced to any primary source as of 2026-09-15 — surveys are not oracles; every row above was re-grounded against its primary paper or repository. Veridict's claim to precedence is the combination plus the protocol-first standardization strategy — not any single primitive.

---

## 10.6 Glossary

| Term | Definition |
|---|---|
| **Actor** | The executor AI under audit; writes nothing to the ledger except via submitted output |
| **Evidence Ledger** | Append-only, hash-chained register; the single source of proof |
| **Claim** | A falsifiable statement about what should be true of the audited output |
| **Claim Extractor** | Fleet producer converting outputs into claims; governed per §5.5 |
| **EvidenceItem** | One piece of evidence: class, tier, producer, stance, reproducibility |
| **Tier (W1a/W1b/W2/W3)** | Evidence weight classes; strict ordering per §4.3 |
| **Verdict** | Per-claim outcome: VERIFIED / REFUTED / INCONCLUSIVE + divergence |
| **Divergence** | Disagreement among verifiers; information and risk signal, not error |
| **Verifier Fleet** | Built-in verifiers + heterogeneous jury + watchers |
| **Jury** | ≥2 distinct model families giving blind, independent doctrine (W2) |
| **Watcher** | Third-party pluggable auditor bound by WatcherManifest (W1b(cert)/W3) |
| **Meta-claim** | A claim interrogating another claim's evidence (depth-budgeted) |
| **Policy Engine** | Selects audit intensity (Certificate/Gate/Watch/Hybrid) from signed policy data |
| **Adjudication Ladder** | Five rungs R0–R4 resolving claims up to the human risk owner |
| **Dossier** | Human-digestible ledger view for R3 decisions |
| **AuditCertificate** | Signed, offline-verifiable deliverable with scope limits and disclosure level |
| **Canary Protocol** | Seeded-defect blind measurement of audit quality (§7.6) |
| **Quality Sheet** | Published catch-rate/false-positive metrics from the canary protocol |
| **TCB** | Trusted computing base: the deliberately small, boring core (§7.3) |

---

## 11. Integrity Scan Addenda (Design-Review Close-Out)

Three gaps were caught in the first integrity scan and resolved in-place:

1. **Long-running tasks** → checkpoint/compaction contract added (§4.5).
2. **Claim Extractor identity** → governed as a fleet producer with deterministic+LLM hybrid implementation and re-extraction auditing (§5.5).
3. **Latency targets** → GATE < 30 min p95, WATCH < 5 min, as Phase 1 exit criteria (§6.5).

A second, perfectionist scan closed six further gaps:

4. **Schema versioning** → `schema_version` mandatory on every entry/contract; replay verifiers never guess (§4.1).
5. **Audit-quality measurement** → Canary Protocol with seeded-defect corpus, blind injection, published Quality Sheet; Phase 1 exit criterion ⑥ (§7.6).
6. **Privacy contract** → redaction-before-dispatch, tiered disclosure levels, local-jury mode; `disclosure_level` on certificates (§7.7).
7. **Key and identity management** → identity registry, rotation, revocation, threshold governance as ledger events (§7.8, `key.enrolled`/`key.revoked`).
8. **Prior-art positioning** → differentiation against SLSA/in-toto, SARIF, LLM-as-judge, OPA-style gates, formal verification, and governance frameworks (§10.5).
9. **Glossary** → normative terminology record for the standard-track spec (§10.6).

---

## 12. One-Paragraph Summary

Veridict is a protocol and system for auditing AI with AI when humans no longer can. Every act of an audited AI becomes an entry in an append-only, hash-chained evidence ledger; its outputs are broken into falsifiable claims; a fleet of built-in verifiers (deterministic machine evidence), a blind rotated jury of heterogeneous model families, and pluggable third-party watchers produce weighted evidence under a strict hierarchy (machine evidence > jury consensus > single doctrine); disagreement is treated as information and triggers escalation; a policy engine — signed, versioned data, not code — selects per-task whether the outcome is a certificate, a blocking gate, a live watch, or a hybrid; unresolved disagreement reaches a human who decides not on code but on risk, via a digestible dossier; the result is a signed certificate whose every claim can be independently verified offline by replay. The core is kept deliberately small and boring so that the system's own audit is machine-provable, the system dogfoods itself as its first customer, and the protocol — not any single model — is the root of trust.
