# The Veridict Standard — v1.0.0-draft

Date: 2026-09-10. Status: DRAFT for public review (Phase 3 deliverable, §8).
Normative language: **MUST / MUST NOT / SHOULD / MAY** per RFC 2119.
Reference implementation: this repository (`veridict/` package) at the commit
introducing this file. Where the standard and the reference implementation
diverge, the divergence MUST be recorded in §14 (registry errata) until
resolved.

Veridict answers one question with evidence that survives verification:
**what did this actor claim, what did independent producers find, and who
decided the residual risk?** Everything below exists to make that answer
append-only, falsifiable, and honestly inconclusive when it must be.

---

## 1. Conformance targets

| Level | Who | MUST satisfy |
|---|---|---|
| **Core** | ledger, schema, ladder, policy, certificate, dossier | §2–§5, §7–§13 |
| **Verifier** | built-in W1a/W1b producers | §2–§5; W1a/W1b ceilings |
| **Watcher** | third-party producers | §2, §4, §6 (+ conformance kit §6.7) |
| **Resolver** | human-facing decision surfaces (CLI/UX) | §10, §12, §13 |

A conforming Core implementation MUST be verifiable offline: replay of a
certificate MUST require only the ledger file, the certificate file, and
Core-level code (§11.4).

## 2. Canonical data model

2.1 **Canonical JSON.** `canonical_json(obj)` = JSON with sorted keys,
compact separators, ASCII escaping. All digests and signatures are computed
over canonical form. Two implementations that disagree on canonical form
cannot interoperate — this is the single most load-bearing rule.

2.2 **Digests.** `payload_digest(payload) = sha256(canonical_json(payload))`.
Identifiers are `sha256(<dotted preimage>)[:N]` with N fixed per type (§4.2,
§11.1).

2.3 **Ledger.** An append-only JSONL sequence of entries. Each entry carries
at minimum: `seq` (0-based, contiguous), `ts`, `entry_type`, `author`
(ActorRef: `kind`, `identity`, `version`), `payload`, `payload_hash`
(= payload_digest), `prev_hash`, `entry_hash`. The preimage of `entry_hash`
MUST bind all prior fields including `prev_hash`; the genesis entry's
`prev_hash` MUST be a fixed sentinel. `ts` MUST be an ISO-8601 UTC **string**
— floats MUST NOT occupy hashed positions, because canonical float
formatting is language-fragile while string formatting is not; `seq` carries
the ordering and `ts` carries provenance. An implementation MUST refuse to
load a line that is not valid JSON (a truncated tail is a crash artifact, not
a silent gap) — it MUST raise a chain error naming the line number (§7.3 m2).

2.4 **Authoritative kinds.** The entry-type registry (§14) is append-only.
v1.0.0 registers: `key.enrolled`, `task.started`, `actor.output`,
`claim.registered`, `evidence.recorded`, `divergence.flagged`,
`deliberation.rounded`, `calibration.updated`, `escalation.requested`,
`dossier.issued`, `escalation.resolved`, `policy.fail_safe`,
`policy.decision`, `watch.observed`, `policy.passed`, `checkpoint.anchored`,
`certificate.issued`, `watcher.registered`.

2.5 **Policy-is-data.** Every policy decision MUST embed the `policy_digest`
of the declaration that produced it. Decisions are reproducible from
(policy, claims, evidence) or they are not decisions.

## 3. Actors and authority

3.1 ActorRef kinds registered in v1.0.0: `verifier`, `jury`, `watcher`,
`adjudicator`, `divergence_detector`, `system`, `human`,
`watcher_registry`.

3.2 **Authority disjointness (§5.4):** a producer of one kind MUST NOT write
another kind's entries. Watchers are authoritative over NOTHING — they return
evidence items; the orchestrator records them. The human is authoritative
ONLY over `escalation.resolved` (R3). Automated systems MUST NOT write
`escalation.resolved` (§12.4).

3.3 **Abstain ≠ refute.** Absence of evidence is never evidence. A producer
that errors, times out, or returns an out-of-contract output MUST be recorded
as an abstention and MUST NOT produce a REFUTES stance.

## 4. Claims

4.1 Fields: `claim_id`, `task_id`, `subject`, `predicate`, `scope`,
`summary`, `derived_from`, `verifiability`, `falsifiable_by`, `critical_class`.

4.2 `verifiability ∈ {"MACHINE_CHECKABLE", "DOCTRINAL", "MIXED"}`.
`claim_id = sha256(task_id | summary | verifiability)[:16]` — the FULL claim
body, never a truncated natural-language slug (a truncating id silently
merges distinct claims and poisons every downstream join). An implementation
MUST reject a duplicate claim_id within one extraction pass (fail-loud, not
dedupe-silent).

4.3 A claim without a falsification channel MUST NOT be admitted as
MACHINE_CHECKABLE.

## 5. Evidence and the tier lattice

5.1 Fields: `evidence_id`, `claim_id`, `evidence_class` ∈
{TEST_EXECUTION, REPRODUCIBLE_RUN, FORMAL_PROOF, STATIC_ANALYSIS,
JURY_OPINION, WATCHER_REPORT}, `tier` ∈ {W1a, W1b, W2, W3}, `producer`,
`artifact_ref`, `reproducibility {deterministic, rerun_recipe}`, `stance` ∈
{SUPPORTS, REFUTES}, `confidence` ∈ [0,1], `rationale`, `schema_version`.

5.2 Tier semantics: W1a = executed machine truth; W1b = deterministic static
truth; W2 = heterogeneous-jury doctrine; W3 = unverified doctrine.

5.3 **The five immutable tier rules (§4.3).** A conforming implementation
MUST enforce, and MUST NOT offer configuration to disable:
  1. Strict ordering W1a > W1b > W2 > W3.
  2. Doctrine (W2/W3) can never overturn W1a.
  3. A W1b refutation of a claim supported by W1a opens a depth-budgeted
     meta-claim (coverage question), whose verdicts feed the policy engine
     and the certificate like any claim's.
  4. A SPLIT is information: it is recorded (`divergence.flagged`) and never
     averaged away.
  5. W3 alone can never yield VERIFIED; a MACHINE_CHECKABLE claim without W1
     evidence is at best INCONCLUSIVE.

5.4 **Divergence classification (normative).** Over the W2/W3 evidence on a
claim: if there is no doctrinal evidence, or no REFUTES, or no SUPPORTS, the
divergence is UNANIMOUS. Otherwise let `m` = the minority stance count; if
`m / |doctrinal| ≤ divergence_tolerance` the divergence is MAJORITY, else
SPLIT. W1a/W1b conflicts are not divergence — the ladder (§7) handles them
directly.

## 6. Watchers (third-party producers)

6.1 **WatcherManifest** (registration contract): `watcher_id`, `name`,
`version`; `producer {identity, maintainer}` (anonymous watchers MUST be
rejected); `capabilities {evidence_classes, max_tier, subscribes_to}`;
`resource_class {timeout_seconds, cost_budget, sandbox_level}`;
`integrity {code_hash, update_policy}` (the watcher's own code is pinned).

6.2 **The W1a ceiling.** `max_tier ∈ {"W1b", "W2", "W3"}` — a manifest
claiming W1a MUST be rejected at construction. W1a is executed machine truth
and is reserved to built-in verifiers. Session output tiers map 1:1 from the
ceiling; no runtime path may surface W1a from a watcher.

6.3 **Blind sessions.** The doctrine function receives exactly
`(claim_summary, artifact_reference)` — the artifact REFERENCE (path or
digest), never other producers' outputs. The deliberation round (§9) is the
only cross-visible exception, and it is jury-only.

6.4 **Authority boundary.** A watcher session returns evidence items; the
orchestrator records them as `evidence.recorded` with author kind `watcher`.
Abstention (error, timeout, None, out-of-contract stance) yields NO entry
from that run — an abstaining watcher MUST NOT block, refute, or flag.

6.5 **Resource contract.** A declared `timeout_seconds > 0` MUST be enforced
(deadline → abstain). A hung watcher must never block the audit.

6.6 **Registration.** Registration is a `watcher.registered` entry whose
payload binds `{manifest, manifest_digest, signature{key_id, algorithm,
sig_b64}}`, the signature taken over the canonical manifest body with a key
enrolled in the SAME ledger (offline parity). Latest registration wins;
verification MUST re-check entry integrity, digest-vs-body, signature, and
the manifest invariants.

6.7 **Conformance kit (certification precondition).** A watcher MUST pass the
v1.0.0 kit before marketplace listing: C1 manifest invariants; C2 W1a
ceiling; C3 blindness; C4/C5/C6 abstain on error/None/bad-stance; C7
confidence clamp; C8 evidence shape on a benign probe; C9 registry
verification; C10 deadline enforcement. The kit probes the CONTRACT, not the
watcher's opinions. The kit is a LOWER BOUND on trustworthiness, not a
proof: it exercises a watcher's function a bounded number of times, so a
stateful function can pass the kit and deviate in production — marketplace
certification therefore additionally requires review of the manifest's
`code_hash`. Similarly, deadline enforcement protects the audit, not the
host: an expired watcher's thread runs until its function completes
(host-side isolation is the control for a function that never returns).

## 7. Adjudication ladder (normative)

Walk top-down; the first matching rule decides. `w1a`/`w1b` = the W1a/W1b
evidence sets; "all-SUPPORTS" is over every evidence item on the claim.

- **R4-first.** No evidence at all ⇒ INCONCLUSIVE (absence is never a silent
  pass).
- **R0.** `verifiability == MACHINE_CHECKABLE` ∧ W1a non-empty ∧ all W1a
  SUPPORTS ∧ no REFUTES at any tier ⇒ VERIFIED (doctrine is advisory). If
  the meta-claim depth budget > 0, a coverage meta-claim is registered.
- **R1.** W1a non-empty:
  - any W1a REFUTES ⇒ REFUTED (machine truth is decisive);
  - else any W1b REFUTES ⇒ VERIFIED + coverage meta-claim (R2 signal — a
    statistical W1b refutation does not overturn W1a);
  - else any W2/W3 REFUTES ⇒ VERIFIED + meta-claim if budget (doctrine
    cannot overturn W1a).
- **R2.** Any W1b REFUTES with no W1a ⇒ INCONCLUSIVE + meta-claim (a
  statistical signal; absence of machine truth is not support).
- **R3.** `claim.critical_class ∈ policy.criticality` ∧ divergence == SPLIT
  ⇒ ESCALATED to the human risk owner; the system MUST generate a dossier
  (§12) and MUST NOT resolve itself.
- **R4 (doctrinal consensus / fail-safe).** With no W1a/W1b on the claim and
  at least one W2 item: divergence SPLIT (non-critical) ⇒ INCONCLUSIVE,
  flagged `inconclusive-unresolved:{claim_id}`; all doctrinal stances
  SUPPORTS ⇒ VERIFIED; ANY doctrinal REFUTES — even inside a MAJORITY
  favoring SUPPORTS ⇒ REFUTED (fail-closed: a lone doctrinal dissenter
  blocks, never passes). W3-only evidence (no W2) ⇒ INCONCLUSIVE (§4.3 rule
  5). Every remaining case ⇒ INCONCLUSIVE — a conforming implementation has
  NO silent pass. *Errata (§14.2):* the design's R2 makes SPLIT handling
  mode-dependent (CERTIFICATE proceeds with a risk note); v1.0.0 keeps
  non-critical SPLITs INCONCLUSIVE — that refinement is a v1.1 candidate.

Meta-claims: the R1/R2 coverage questions are registered as new DOCTRINAL
claims (predicate `coverage-of:<parent predicate>`), adjudicated by the
jury within the remaining depth budget; their verdicts feed the policy
engine and the certificate like any claim's.

A first-round split that went through deliberation keeps a visible risk note
("first-round split; post-deliberation consensus" / "… consensus not
reached") on its adjudication.

## 8. Calibration (confidence only)

8.1 When the W1a majority stance on a claim contradicts a W2/W3 producer's
stance, a `calibration.updated` entry records delta −0.1 for that producer
identity. A producer agreeing with machine truth after a prior negative
records +0.05 (rehabilitation). A tied W1a majority records nothing.

8.2 `factor = clamp(1.0 + Σ deltas, 0.5, 1.0)` (unknown identity ⇒ 1.0).
The factor MUST be applied to W2/W3 confidence at record time. Calibration
MUST NOT touch tier or stance — a discounted juror's REFUTES is worth exactly
what it was, minus the trust. Meta-claims are excluded (their evidence is the
same round).

## 9. Deliberation (the one blindness exception)

9.1 Gating: only after a first-round SPLIT, and only when policy
`deliberation_rounds ≥ 1`. Default 1; 0 disables.

9.2 Mechanics: each juror receives the OTHERS' first-round opinions
(identity-labeled: identity, family, stance, confidence; rationale NOT
forwarded) and may revise via its hook; without a hook it keeps its
first-round opinion. Revised items carry fresh evidence-id salts.

9.3 **Supersession honesty:** first-round items STAY in the ledger;
`deliberation.rounded` records `{claim_id, first_round, revised, consensus}`;
the `divergence.flagged` entry is never removed; adjudication uses the
post-deliberation set.

9.4 **Replay parity and its scope guard.** Offline verification MUST
adjudicate on the post-deliberation set: it MUST exclude exactly the
first-round item ids named by `deliberation.rounded` entries **at or below
the certificate's anchored checkpoint (seq ≤ checkpoint_seq)**. Exclusions
from entries above the anchor MUST be ignored — the signed anchor pins that
prefix's chain hash, so pre-issuance deliberation is tamper-evident while a
post-issuance fake deliberation entry must never be able to erase refuting
evidence from a replay (v1.0.0 erratum D4: the unbounded form of this rule
was exploitable and is forbidden).

## 10. Policy engine

10.1 Modes: `CERTIFICATE` (record only), `GATE` (fail-closed),
`WATCH` (observe-only — never blocks), `HYBRID` (gate semantics + full
record).

10.2 The decision is blocked iff `critical_bad ∨ any_REFUTED ∨ flags` under
GATE/HYBRID. Registered v1.0.0 flags: `coverage-below-threshold`,
`divergence-split:{claim_id}`, `inconclusive-unresolved:{claim_id}`. An
INCONCLUSIVE machine-checkable claim MUST surface a flag — a gate consumer
MUST be able to distinguish "passed clean" from "passed with an unresolved
machine claim".

10.3 WATCH mode records `watch.observed` and never blocks; the flags are
still recorded.

## 11. Certificates and offline replay

11.1 The certificate body carries: `cert_id` (sha256(task_id|artifact_digest)
[:24]), `subject {artifact_digest, task_id, actor_identity}`, `policy_ref`
(with the decision-relevant thresholds), `claims [{claim_id, verdict_value,
divergence, evidence_ids}]`, `jury_composition`, `disclosure_level`,
`divergence_summary`, `risk_level`, `score`, `scope_limits` (MUST include the
honesty clause "claim coverage is heuristic, not exhaustive" as its first
element), `ledger_anchor {checkpoint_seq, chain_hash}`, `signatures`
(ed25519 over the canonical body-without-signatures).

11.2 Issuance order is normative: claims and evidence first, then a
`checkpoint.anchored` entry (pinning the chain hash), then
`certificate.issued`.

11.3 Verification outputs `{valid, chain_valid, signature_valid,
verdicts_match, errors}` and MUST check: chain integrity from the file
(including refusal on malformed lines); signature against a key enrolled in
the ledger; anchor (checkpoint exists at `checkpoint_seq`, its `chain_hash`
matches the signed body, and a matching `certificate.issued` entry exists at
seq ≥ checkpoint); evidence references (every `evidence_ids` entry must exist
in the ledger — defense-in-depth over the anchor pin); and verdict recompute
(replay §5 ladder over ledger evidence for each cert claim, under the
cert's `policy_ref`, with the §9.4 exclusion scope). Any failure ⇒
`valid: false` with named errors.

11.4 The verifier MUST import Core-level modules only — never jury/verifier
implementations.

## 12. Dossier and resolution (R3)

12.1 On ESCALATED, the system MUST issue a `dossier.issued` entry after
`escalation.requested`. The dossier is a VIEW over the ledger — never a
separate truth. Fields: `schema_version`, `dossier_id`
(sha256(claim_id|artifact_digest)[:16]), `claim {…, verdict, rung: R3,
divergence}`, `summary_page` (plain language), `risk_frame` ("If the REFUTES
side is right: …" built from refuting evidence rationales, with an explicit
fallback), the FOUR options — `accept_with_risk`, `demand_rerun`,
`narrow_claim`, `reject` — each with an honest consequence, `default`
("response window expiry triggers policy.fail_safe (R4)"),
`evidence_links` (claim id + evidence ids), `response_window_hours`.

12.2 Every dossier sentence MUST link to ledger entry ids.

12.3 `escalation.resolved` records the human's decision (one of the four),
`decided_by`, and an optional risk note, authored by kind `human`. An
unknown decision MUST be rejected.

12.4 **Fail-safe.** Response-window expiry MUST be recorded as
`policy.fail_safe` with consequence
`gate_stays_blocked_or_certificate_stamped_unresolved`. Silence must never
converge to acceptance.

## 13. Known limitations (normative honesty)

13.1 Certificates are point-in-time statements: evidence appended after
issuance legitimately flips a replay verdict (that is tamper-evidence
working). Consumers MUST re-verify against the CURRENT ledger.

13.2 Jury heterogeneity is a policy minimum (`min_jury_families`), not proof
of independence; the diversity statement travels in `jury_composition`.

13.3 Local-jury mode (air-gapped deployments) is conformant if
heterogeneity is preserved and the composition is disclosed.

13.4 Formal verification of the Core is a Phase 3 stretch goal and is NOT a
v1.0.0 conformance requirement. Until then, the core's honesty rests on the
canonical-form discipline and the replay algorithm — a stated residual risk.

## 14. Registry governance

14.1 The entry-type registry and the flag registry are append-only. Adding a
type is minor (patch the list, bump patch version). Changing a payload
schema, a digest preimage, or a tier rule is MAJOR and requires a migration
note.

14.2 Errata. v1.0.0-draft erratum D4 (2026-09-10): replay exclusion of
superseded deliberation items was unspecified; §9.4 fixes the scope guard.
Erratum D5 (2026-09-10): the entry-hash preimage originally omitted `ts` and
`schema_version`; §2.3 now binds every stored field (chain format break —
≤0.3.0 ledgers regenerate) and mandates ISO-8601 string timestamps. Erratum
D6 (2026-09-10): §7's R4 originally read "anything else ⇒ INCONCLUSIVE",
contradicting the reference ladder; §7 now states the doctrinal-consensus
rule normatively (VERIFIED on unanimous SUPPORTS, REFUTED on any doctrinal
REFUTES even within a majority, INCONCLUSIVE on non-critical SPLIT / W3-only
/ no evidence); the design's mode-dependent SPLIT handling (§6.2 R2) remains
a v1.1 candidate. Erratum D7 (2026-09-10): §9.2 is now explicit — a revision
hook that is absent or errors degrades to keep-opinion; a juror MUST NOT be
dropped from the revised basis, which would silently erase its first-round
REFUTES.

14.3 The standard is Apache-2.0 (D8: spec + core + offline verifier are
open; hosted platform, certification authority, enterprise integrations are
commercial).
