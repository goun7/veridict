# Veridict

[![CI](https://github.com/goun7/veridict/actions/workflows/ci.yml/badge.svg)](https://github.com/goun7/veridict/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![Standard](https://img.shields.io/badge/standard-v1.0.0--draft-8A2BE2.svg)](docs/specs/2026-09-10-veridict-standard-v1.0.md)

*The verdict that survived verification.*

Veridict is a protocol and reference implementation for **auditing AI with AI
when humans no longer can**. An append-only, hash-chained evidence ledger
records every step of an audit: falsifiable claims, machine verifiers, a
blind heterogeneous jury, third-party watchers, and a signed certificate that
**anyone can verify offline** — no trust in the auditor required.

The founding premise: as AI output outgrows human review capacity, the human
role is not *code reviewer* but **risk owner**. Veridict is built around that
transformation — the machine owns the verdict of intelligence, the human owns
the verdict of responsibility.

## Why an audit ledger

- **No silent passes.** No evidence → INCONCLUSIVE, flagged — never a clean bill.
- **Tiers, not vibes.** W1a (machine truth) > W1b (statistical reproduction) > W2/W3 (jury doctrine) — the ladder never lets doctrine overturn machine evidence, and W3 alone never verifies.
- **Identity is binding.** Every entry's hash binds its author; watcher manifests are signed, W1a is structurally impossible for them; a calibration ledger discounts producers whose claims were contradicted.
- **Verify, don't trust.** Certificates replay offline against the ledger. `examples/spec_verifier.py` is a verifier written **from the standard alone** (zero imports of this codebase) that reaches the same verdicts from the published test vectors.

## Quickstart

```bash
pip install -e . && pip install pytest

# audit a task end-to-end (GATE mode) — see examples/ for runnable scenarios
veridict --help

# the system audits itself: ledger → claims → jury → certificate → offline verify
python scripts/dogfood.py

# verify a certificate offline (the property third parties care about)
veridict verify --ledger dogfood_ledger.jsonl --cert dogfood_cert.json

# regenerate the standard's conformance test vectors (deterministic)
python scripts/build_test_vectors.py

# measure GATE latency against the design budget (§6.5: p95 < 30 min)
python scripts/measure_latency.py
```

## Receipts (evidence over claims)

| Check | Result |
|---|---|
| Test suite | 186 passed (both invocation styles, Python 3.12–3.14 in CI) |
| Self-audit | valid certificate, risk `low`, GATE not blocked |
| Offline replay | `veridict verify` rc 0 on the dogfood certificate |
| Canary protocol | 2 seeded defects caught / 0 false positives |
| Tamper soak | 1500 mutated ledgers, 5 seeds → 100% detected, 0 silent passes |
| Spec parity | reference verifier ≡ spec-only verifier on 8 failure modes |

CI runs all of the above on every push — the receipts are regenerated, not
narrated.

## Documents

- **Standard (normative draft):** [`docs/specs/2026-09-10-veridict-standard-v1.0.md`](docs/specs/2026-09-10-veridict-standard-v1.0.md) — §14.2 carries errata; errata proposals are a first-class issue template
- **Design document (founding paper):** [`docs/specs/2026-09-09-veridict-design.md`](docs/specs/2026-09-09-veridict-design.md)
- **Architecture:** [`ARCHITECTURE.md`](ARCHITECTURE.md) — module map to standard sections
- **Contributing / Governance / Security:** [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`GOVERNANCE.md`](GOVERNANCE.md) · [`SECURITY.md`](SECURITY.md)

## Status & roadmap

Phase 1 (core) and Phase 2 (watcher layer) are implemented with end-to-end
receipts in the dogfood run. Phase 3 (platform + standard) substrate is in
place: spec draft, conformance kit (C1–C10), marketplace index, test vectors,
spec-only verifier. The remaining exit criteria are external by nature:

1. an **independent verifier** implemented from the spec by someone else,
2. a first **external production deployment**,
3. **≥10 active watcher manifests** on the marketplace.

Current work tracks the [`docs/plans/`](docs/plans/) series; the commercial
model is documented in [`docs/commercial-model.md`](docs/commercial-model.md).

## Model

Open-core: the standard, the ledger core, and the offline verifier are
Apache-2.0 — forever. Commercial offerings (hosted platform, watcher
certification, enterprise integrations) build on top and never gate the
open core. See [`docs/commercial-model.md`](docs/commercial-model.md).
