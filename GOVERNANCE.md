# Veridict Governance

## Principle

Veridict audits other systems; its own legitimacy depends on being auditable
and neutrally governed. The governance goal is the SARIF/Kubernetes pattern:
the standard is open and universal, the operational layer earns its keep
above it. Long-term, if standard status settles, spec governance moves to a
foundation (the CNCF model).

## Maintainer model

- **Current stage:** BDFL — the project founder holds final call on the
  spec, the entry-type registry, and the tier rules.
- **Growth stage:** a maintainer council per component (core, watcher
  platform, standard). Decisions by lazy consensus; a formal objection
  escalates to the council.
- **Maturity stage:** foundation transfer of the SPEC and CORE; the
  commercial layer (hosted platform, certification authority, enterprise
  integrations) remains separate (open-core Model C, D8).

## Watcher onboarding (§5.5)

1. **Conformance is the bar.** A watcher MUST pass the v1.0.0 conformance
   kit (C1–C10) before listing. The kit probes the platform contract —
   blindness, ceilings, abstain semantics, resource deadlines — not the
   watcher's opinions.
2. **W1a is closed.** Executed machine truth (W1a) is reserved to built-in
   verifiers. No watcher manifest may claim it, ever.
3. **No anonymous producers.** A watcher names an identity and a maintainer
   who answers for its doctrine.
4. **Integrity pinning.** A watcher's manifest carries its own `code_hash`;
   marketplace listings must match it.
5. **Abstain ≠ refute.** A watcher that errors, times out, or speaks out of
   contract is silent, never refuting. Kits and reviewers test this.
6. **Health tracking.** Persistently silent or crashing producers lose
   listing priority (calibration already discounts contradicted doctrine —
   §4.4.5).

## Standard-change process

- The **entry-type registry** and the **flag registry** are append-only.
- The standard follows semver: new optional fields = patch/minor; any change
  to a digest preimage, a payload schema, or a tier rule = MAJOR with a
  migration note.
- Errata are recorded in the standard (§14.2) with the defect id and date —
  e.g. v1.0.0 erratum D4 (replay-exclusion scope guard).

## The human risk owner (§6.1 R3)

Escalations to a human (`R3`) MUST be resolved by a human. No automated
system — including CI, agents, or the project's own dogfood — may write an
`escalation.resolved` entry on another party's behalf. Simulated decisions
in demos MUST be labelled as simulated in the entry's `risk_note`.
