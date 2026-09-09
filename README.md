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
offline replay verification, canary protocol v0. Self-audit: `python scripts/dogfood.py`.

## Model

Open-core: spec + ledger core + offline verifier are Apache-2.0 (planned);
hosted platform, certification authority, and enterprise integrations are commercial.
