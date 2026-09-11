# Strategy deep review — roadmap & revenue, perfectionist lens

Date: 2026-09-11. Author: maintainer + agent consensus. This is a THINKING
document, not a commitment — it exists so the next big build decision is
made against the full tradeoff map, not the loudest idea. Veridict is a
GLOBAL product; every ranking below assumes that framing, not a TR-only one.

---

## 1. Where the protocol actually stands

The honest summary, no cheerleading:

**Done and MECHANICALLY PROVEN (not merely written):**
- Append-only hash-chained ledger with cross-language-stable hashing (ISO
  ts, canonical JSON) — proven by 1500-ledger tamper soak, 100% detection.
- Falsifiable claims + W1a/W1b machine verifiers + blind ≥2-family jury +
  R0–R4 ladder with fail-closed rules — proven by contract vectors where
  TWO independent implementations (reference + spec-only) agree on all 11
  ladder cases.
- Signed certificates verifiable offline — proven by a stranger-path test
  that verifies with a STOCK ed25519 library from JSON alone.
- Watcher manifests with revocation (CRL-equivalent) — proven end-to-end.
- JSON Schema contracts for every public surface, validated against real
  artifacts in CI.
- Honest canary: 9 catches / 3 misses / 0 false positives — the misses are
  PUBLISHED, which is the point.

**What is NOT proven (and must not be claimed as proven):**
- That a real third party can actually implement the verifier from the
  standard. We KNOW it is implementable because we implemented a spec-only
  verifier — but that was us, not a stranger. Exit criterion ① is the only
  real test, and it has not happened.
- That the system survives adversarial watchers/jurors at scale. Everything
  so far is well-formed-input hardening. The failure modes that matter are
  adversarial ones, and those only appear with real adversaries.
- That anyone wants this. Zero external adopters, zero stars target hit,
  zero certificates issued outside dogfood.

**Conclusion:** the protocol's CORE is genuinely strong — the honest
inconclusiveness invariant, the structural W1a ceiling, and offline
verification are rare and defensible design choices. What is unproven is
everything downstream of "strangers see it." The next dollar of effort
should buy the STRANGER, not the feature.

---

## 2. Is the roadmap optimal? (perfectionist critique)

Three critiques, rated by how much they matter:

### Critique A — the roadmap has no "trusted-first-auditee." (HIGH)
The current P4→P5→P6→P7 shape assumes the world comes to Veridict. The
highest-leverage missing item is a **single high-visibility first auditee**
— one real repo, audited under GATE, certificate published, badge embedded,
story told. One such auditee is worth more than all remaining hardening,
because it converts "a protocol exists" into "the protocol produced a
real, checkable artifact." Recommendation: make the badge+one-reference-
audit its own milestone, ahead of further protocol work.

### Critique B — the revenue model ranks by ethics, not by closing speed. (MEDIUM)
The table lists "watcher certification" first because its incentive is
cleanest ("paid to reject"). But ethically-clean ≠ fastest to first dollar.
The fastest first revenue is **enterprise adoption support** (consulting),
which has zero product dependency and zero capital. The honest fix is not
to change the ranking but to say explicitly: *watcher certification is the
right long-term revenue, enterprise support is the likely FIRST revenue.*
The G3 gate already implies this; it should be stated, not implied.

### Critique C — G1 (≥500 stars) gates the WRONG thing. (LOW-MEDIUM)
Stars measure attention, not adoption. A repo can hit 500 stars on a good
Show HN and still have nobody running it. The gate would be stronger as
"≥500 stars **or** ≥3 external contributors **or** ≥1 external production
deployment" — the deployment criterion is the real G2 signal and currently
sits behind a star gate it doesn't need. Minor, but a perfectionist notices.

---

## 3. Revenue: what a perfectionist would actually build first

Ranked by (fit × speed × capital), with the ethics constraint as a floor
not a tiebreaker:

1. **Badge + one reference audit** (this round's badge protocol is the seed).
   $0, produces shareable proof, feeds the launch story. DO FIRST — already
   underway.
2. **Enterprise adoption support** ($0, on demand). The likely first
   dollar. Needs nothing but inbound inquiries to a free Discussions inbox.
3. **Watcher certification** ($0, review time only). The strategic revenue
   — paid to reject — but requires ≥10 manifests to have demand, so it is
   upstream of real adoption, not downstream.
4. **Hosted registry** (G2/G3-gated). The honest SaaS: only when community
   demand makes self-hosting friction the product. Never build before the
   gate — building it early is the classic open-core death (over-build the
   paid layer, under-serve the free one).
5. **Certification authority (P7)** — endgame, post-revenue, separate
   entity. Not a near-term decision at all.

The anti-corruption guardrails (paid-to-reject, never cripple the core, spin
out the CA) are the model's moat, not its cost. A perfectionist protecting
them is what keeps Veridict from becoming the thing it audits against.

---

## 4. How much further can the PROTOCOL develop? (the honest ceiling)

A perfectionist asks: what is the *terminal* state? Answer honestly — the
protocol is not near its ceiling, but the remaining distance splits into
**near**, **far**, and **speculative**:

### Near (±hours-days of work, $0, real payoff)
- Badge everywhere (this round).
- WATCH-mode streaming transport (Issue #3) — makes the "watch the agent
  as it acts" mode real instead of a policy flag.
- Streaming/event-sourced ledger (ledger as a live event log, not a file)
  — but this edges toward hosted infra; gate it.
- More canary classes (secrets-leak etc., now a good-first-issue).

### Far (±weeks-months, some capital at G2+)
- **Multi-party federation** (I already proved two KeyStores on one ledger;
  the real version is N independent auditors co-signing one certificate —
  a "quorum of verifiers" that removes the single-auditor trust point).
- **Threshold signatures / multisig certificates** — so the certificate
  survives one compromised auditor key.
- Formal verification of the ladder (P7) — machine-checked proof that the
  five tier rules admit no silent pass. This is the ultimate credibility
  move and genuinely hard.

### Speculative (only if the thesis proves out)
- Zero-knowledge proofs over the ledger (certify "all verdicts followed the
  ladder" without revealing the evidence) — powerful but heavy, and hinges
  on standards that are themselves young.
- DAO-managed certification body. The anti-corruption logic suggests a
  neutral body; a DAO is one candidate mechanism, not a goal.

### What a perfectionist would NOT build (and why)
- A self-hosted dashboard before G2. It is the classic over-build.
- "Enterprise-only" security features. Violates the open-core promise.
- A token. The moment there is a Veridict token, every audit decision
  gains a price signal and the paid-to-reject invariant decays. Reject
  repeatedly unless the thesis collapses without one.

---

## 5. The two imperatives (what actually matters now)

Perfectionism, when it is honest, distills to two sentences:

1. **The standard must be independently implementable** — everything else
   is decoration until a stranger does it (Issue #1). Protect that issue's
   priority above all else.
2. **The first real auditee is the highest-value asset we can create** —
   a checkable certificate over someone's actual repo, badge embedded,
   story told. Badge protocol is the step that makes it shareable.

Everything in §4 is ranked AFTER these two. Build order that follows
reality: launch (human) → first auditee + badge (this round's trajectory)
→ enterprise support on demand → watcher certification at demand → hosted
at the gate → formal verification (P7) when there is a credibility war to
win.