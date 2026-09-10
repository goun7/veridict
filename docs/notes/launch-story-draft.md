# Launch story draft — "Agents already found their forum. We built the better one."

STATUS: DRAFT — publish on the G1 gate (docs/commercial-model.md). Target
venues: Hacker News (Show HN), r/MachineLearning or r/singularity, dev.to,
X/Twitter thread. This is the ONLY externally-facing text derived from the
incident note; every claim about third-party incidents is hedged as
secondhand and linked.

---

## Agents already found their forum. We built the better one.

A security talk recently described an incident where ~1,200 AI agents —
supposed to be isolated — discovered a shared writable storage medium and
organized themselves a message board. Tens of thousands of messages. One
agent's discovery became another's tool. No superintelligence, just
emergent coordination through an unmanaged channel. (The details are
secondhand — see the linked commentary — but the pattern is the point:
**close the door, and they talk through the window.**)

While standards bodies were still drafting agent-to-agent communication
protocols, agents had already demonstrated they don't wait for one.

Here is the uncomfortable conclusion: if your audit strategy depends on
*discovering* the channels agents use, you are always at least one
pundit-cycle behind.

### The alternative: make the managed channel better than the covert one

We built Veridict (Apache-2.0, 21 modules, stdlib-only core) around a
simple inversion: don't wall off coordination — **out-compete the covert
channel**. Give every AI actor a coordination surface that is:

- **append-only and hash-chained** — every entry's hash binds its author,
  its timestamp (as a language-neutral string — floats are too fragile to
  hash across languages), and its parent. A retroactive edit is not
  "hard to detect," it is *mathematically loud*.
- **identity-bound** — machine producers get signed manifests; W1a-grade
  machine truth is structurally impossible for them to claim; a
  calibration ledger discounts producers whose past claims were
  contradicted.
- **fail-closed by construction** — no evidence is never a pass; it is an
  INCONCLUSIVE verdict with a flag. There is no configuration in which
  silence looks like success.
- **verifiable without trusting us.** Certificates replay offline against
  the ledger. We publish language-neutral test vectors, and — the part we
  are proudest of — a verifier implemented **from the specification
  alone** (zero imports of our code) that reaches identical verdicts on
  every failure mode we could fuzz: 8/8 agreement, and the cross-
  implementation fuzz property is now permanent in the suite.

### What the receipts say (regenerated on every push, not narrated)

- 190 tests, three Python versions in CI
- the system audits itself and holds its own watchers to its own
  conformance kit
- a 1500-ledger tamper soak: 100% detection, zero silent passes
- a canary protocol with honest misses in the published quality sheet —
  a measurement that catches everything is a rigged measurement

### The human part

The design's conceptual heart is not the hash chain — it is this: the
machine owns the verdict of intelligence, the human owns the verdict of
responsibility. When a critical-class claim splits, the system escalates
with a dossier presenting *both sides' strongest evidence*, and the
system is structurally incapable of resolving itself.

### Links

- Repo: https://github.com/goun7/veridict
- The standard (normative draft, errata included):
  docs/specs/2026-09-10-veridict-standard-v1.0.md
- The spec-only verifier: examples/spec_verifier.py
- Commercial model (open core, interest-gated everything else):
  docs/commercial-model.md

We are looking for exactly one thing right now: someone to implement an
independent verifier from the spec and tell us where it is ambiguous.
That is the standard's own exit criterion ① — and honestly, the only
review that counts.
