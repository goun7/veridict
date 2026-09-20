# The Veridict Standard — v1.1-draft (delta from v1.0.0-draft)

Date: 2026-09-12. Status: DRAFT for public review.

This document is a **delta specification**: it is normatively read ON TOP of
[`2026-09-10-veridict-standard-v1.0.md`](2026-09-10-veridict-standard-v1.0.md)
(referred to as "v1.0"). Everything v1.0 says continues to hold except where
this document explicitly amends. The scope of v1.1 is deliberately minimal —
one ratified sentence (D10) — per the project's standards discipline: no new
normative surface opens before an independent verifier exercises the
existing one (v1.0 + errata remain the verification target of record until
v1.1 is ratified).

## Amendments

### A1 — Realtime WATCH transport latency (ratifies v1.0 §10.3 erratum D10)

v1.0 §10.3 records (via erratum D10, §14.2) that v1.0.0 defines WATCH as a
policy mode over the evidence ledger, does NOT specify a streaming/realtime
transport, and defers a normative latency sentence to v1.1. v1.1 ratifies
that sentence in the form proposed by D10:

> A conforming WATCH transport MUST surface the flag set recomputed over
> an appended entry within a bounded detection interval declared by the
> deployment, and MUST NOT block, alter, or append to the audited ledger.

**Normative consequences:**

1. **Declared, not fixed, interval.** The bounded detection interval is a
   *deployment declaration*, not a constant of the standard — a watcher
   stream that declares 5 s and delivers within 5 s conforms; a batch
   engine that recomputes flags only on audit completion is simply not a
   WATCH *transport* (it is a WATCH *policy mode*, still conforming as
   v1.0 defines it).
2. **Transport, not authority.** The MUST NOT clauses make the transport
   read-only by construction: the audited ledger remains the only
   appendable record, by the single writer holding the key (§2, §3.2). A
   transport that writes, patches, or reorders entries is non-conforming
   regardless of its timing.
3. **Same ladder, same flags.** The flag set surfaced is the one v1.0
   §10.3 already defines: recomputed per appended entry through the SAME
   §7 adjudication ladder as the batch engine. The transport surface
   adds no verdicts, no tiers, and no evidence classes.

**Reference implementation candidate (non-normative note):**
`veridict/watcher_stream.py` implements append detection + per-increment
flag recomputation under these rules; its tests pin the read-only property
and the per-increment recompute. Conformance of a GIVEN transport to this
sentence still cannot be certified by code inspection alone — the
detection interval is measured against the deployment's own declaration,
which is why the sentence binds the deployment, not the software.

### A2 — Jury composition is normative (ratifies v1.0 §14.2 erratum D12)

v1.0's §5 defined only tier semantics and never stated jury composition as
normative text, so an implementer reading v1.0 alone could lawfully build a
single-provider jury that self-reviews its own output — the self-preference
the requirement exists to forbid. v1.0 §14.2 (erratum D12) closed that gap
in-place; v1.1 ratifies it here so the rule reads from §5 rather than from
an erratum:

1. **Two providers, two families.** A conforming implementation MUST NOT
   issue a certificate on a jury of fewer than two providers or fewer than
   two distinct `family` values.
2. **Self-family exclusion.** A juror drawn from the audited author's own
   model family MUST be excluded BEFORE the count, not counted as the
   second family.
3. **Fail closed, never shrink.** A panel that cannot meet the count after
   exclusion MUST fail closed rather than issue on a conflicted panel.

**Reference implementation note (non-normative):** the reference
implementation enforces all three at `Jury.__init__` — before any
certificate is issued, before the orchestrator is reached — raising rather
than emitting a certificate with a non-conforming panel. Measured by direct
probe: a one-family `Jury` cannot be constructed.

**Scope limit, kept honest:** these rules constrain COMPOSITION, not
HONESTY. Two families do not prove either juror reported truthfully, which
remains §11.3's business. A conspiracy of two families passes this rule;
the rule's purpose is to remove the *accidental* case, not the adversarial
one.

**Ratification status:** DRAFT until an independent implementation
exercises it (v1.0 issue #1's exit criterion). Until ratified, a verifier
checking jury composition reads the rule from v1.0 §14.2, where it is
already normative — this delta moves its LOCATION, not its force.

### Conformance targets affected

| Target | v1.0 requirement | v1.1 addition |
|---|---|---|
| Core | unchanged (§2–§5, §7–§13) | — |
| Verifier | unchanged | — |
| Watcher | unchanged (§6, conformance kit §6.7) | — |
| Resolver | unchanged (§10, §12) | WATCH *transports* that claim conformance must honor A1 |

A deployment running only the batch engine needs NO change for v1.1
conformance. Only a component that *calls itself* a WATCH transport is
newly normatively bound.

## Deliberately deferred (unchanged, recorded for sequencing honesty)

The following remain v1.2+ candidates exactly as v1.0 §14.2 deferred them;
v1.1 takes only D10 so the delta stays independently verifiable:

- Design §6.2 R2 — mode-dependent SPLIT handling (v1.0 §7 erratum D6 note).
- N-signer federation and threshold/multisig certificate classes.
- Any change to §14.1 registries (none needed by A1).

## Ratification

This delta is DRAFT until: (a) at least one implementation OTHER than the
reference exercises A1 against a declared interval and publishes the
receipt, and (b) errata review confirms no v1.0 sentence contradicts A1.
Ratification then re-issues the standard as v1.1.0 with this delta folded
into §10.3 and the D10 erratum entry closed.
