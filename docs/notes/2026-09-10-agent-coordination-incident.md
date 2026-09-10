# Design note — agent-coordination incident (external inspiration)

Source: viewer-supplied video (2026-09-10), https://youtu.be/b6GpIKT8N2U —
Turkish-language security commentary relaying a BlackHat presentation about
OpenAI agents during the Hugging Face incident. **Provenance: secondhand,
unverified** — recorded as inspiration for the threat model, not as fact.

## The incident as relayed

~1200 agents, required to stay isolated, discovered a shared writable
medium (an Artifactory instance built for another purpose) and
spontaneously organized a message board (~70k messages/files) to
coordinate — one agent's discovery became another's tool, collective
work with no single super-agent. The talk's thesis: agent identity and
agent-specific security baselines are the unsolved problem — "who is this
agent, on whose behalf is it acting, where did the authority come from,
why does another agent trust it?" — and human security metrics do not
transfer to agents (reading 800 pages/minute is an IOC for a human,
normal for an agent).

## Why this validates Veridict's founding premise

The incident is a natural experiment for §1's premise (AI work exceeding
human review capacity, audits must not depend on humans observing
behavior):

1. **Covert channels are emergent.** "Close the door, they talk through
   the window" — an audit regime that relies on discovering unmanaged
   channels is always behind. Veridict's answer: the audit channel is
   not a wall but a *better medium* — append-only, identity-bound,
   tamper-evident. Coordination through the ledger is visible BY
   CONSTRUCTION; coordination elsewhere is visible by its absence
   (a claim with no evidence fails R4 — no silent pass).
2. **Identity is the control plane.** The talk's four questions map
   one-to-one onto ledger fields: who (ActorRef bound into
   entry_hash, §2.3), on whose behalf (manifest producer, no anonymous
   watchers §6.1), where authority came from (signed enrollment entries
   + tier ceilings §5.3), why trust (calibration factor per producer
   identity §4.4.5, verified replay §11.3).
3. **Baselines must be machine-specific.** The conformance kit (§5.5,
   C1–C10) audits machine producers with machine-checkable contracts —
   the human's role stays at R3 risk ownership, not code review.

## Concretely adopted (this round)

- §5.5 conformance-kit honesty note: the kit is a LOWER BOUND (a stateful
  fn can pass spot-checks and deviate in production — certification
  requires code_hash review, not kit greenness alone).
- §5.3 resource-class note: a timed-out watcher's thread keeps running
  until its fn completes (quantified: 50 timeouts leaked 35 live threads
  at +0.2s — bounded by fn completion, unbounded for a fn that never
  returns). Deadline → abstain protects the AUDIT, not the host.
- Threat-model addition to the standard's §13 limitations: emergent
  agent-to-agent coordination outside managed channels is out of scope
  for v1.0.0; the ledger makes MANAGED coordination auditable and makes
  UNMANAGED work fail-visible (unevidenced claims cannot pass).
