# Veridict

*The verdict that survived verification.*

A protocol and system for **auditing AI with AI** when humans no longer can:
an append-only evidence ledger, falsifiable claims, a heterogeneous blind jury,
pluggable watchers, policy-selectable audit intensity (certificate / gate /
watch / hybrid), and a signed certificate that anyone can verify offline.

## Documents

- **Design document (founding paper):** [`docs/specs/2026-09-09-veridict-design.md`](docs/specs/2026-09-09-veridict-design.md)

## Status

Phase 1 core implemented: ledger, claim extraction, W1a/W1b verifiers, blind jury,
divergence detector, R0–R4 ladder, 4-mode policy engine, signed certificates with
offline replay verification, canary protocol v0.

Phase 2 watcher layer implemented: signed watcher manifests in a ledger registry
(W1a forbidden by design), blind watcher sessions with tier ceilings and
abstain≠refute, orchestrator routing, a calibration ledger that discounts
W1a-contradicted producers, a deliberation round after a split, escalation
dossiers with human decision return and the R4 fail-safe. Dogfood v0.2 exercises
all three Phase 2 exit criteria end-to-end: external watchers running blind
sessions, a full turn from critical split to dossier to human resolution, and
calibration accumulating across audit passes on the same ledger. The watcher
conformance kit (`veridict/conformance.py`, 10 checks C1–C10) is the
certification precondition: dogfood holds its own example watchers to it.
Self-audit: `python scripts/dogfood.py`.

Phase 3 substrate in place: spec v1.0.0-draft (`docs/specs/`), governance
docs, conformance test vectors (`docs/standard-test-vectors/` — regenerate
with `python scripts/build_test_vectors.py`), and a **verifier written from
the standard alone** (`examples/spec_verifier.py` — zero veridict imports)
that reproduces the reference verdict from the vectors. The chain format
binds every stored field including timestamps; deterministic fuzz properties
pin serialization and tamper detection. Phase 3 exit criteria that remain
open are external by nature: an independent verifier implemented from the
spec, a first external production deployment, and ≥10 active watcher
manifests.

## Model

Open-core: spec + ledger core + offline verifier are Apache-2.0 (planned);
hosted platform, certification authority, and enterprise integrations are commercial.
