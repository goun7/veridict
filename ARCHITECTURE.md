# Architecture — module map to the standard

Veridict core is 21 modules, ~2.3k lines, stdlib-only (the single
third-party dependency is `cryptography` for ed25519 signing). The normative
reference is `docs/specs/2026-09-10-veridict-standard-v1.0.md` (the
"standard"); the founding design is
`docs/specs/2026-09-09-veridict-design.md` ("design").

## The spine (evidence in, verdict out)

| Module | Role | Reference |
|---|---|---|
| `ledger.py` | append-only hash chain; entry preimage binds every field incl. ISO-8601 `ts`; `ChainError` on malformed lines | standard §2.3, §7.3 |
| `schemas.py` | ActorRef, Claim, EvidenceItem, TaskManifest dataclasses; tier rules as constructors | standard §2, §4 |
| `utils.py` | canonical JSON (sorted/compact), payload digest, sha256 | standard §2.1–2.2 |
| `keys.py` | ed25519 enrollment + signing; keys enroll into the SAME ledger they later verify against | standard §7.8, §11.2 |
| `claim_extractor.py` | hybrid claim extraction: explicit DOCTRINE lines + auto-claims (tests, reproducibility); `claim_id = sha256(task_id\|summary\|verifiability)[:16]` | standard §3 |
| `verifiers.py` | built-in W1a/W1b producers: test execution, reproducible run | standard §4 (tiers) |
| `jury.py` | blind heterogeneous jury (W2/W3); `Opinion` stream; deliberate() revision round — absent/erroring hooks degrade to keep-opinion (§9.2) | standard §4.4.3, §9.2 |
| `divergence.py` | UNANIMOUS/MAJORITY/SPLIT classification over W2/W3 stances | standard §5.4 |
| `ladder.py` | adjudication R0→R4 (top-down; R4-first no-evidence fail-safe; doctrinal-consensus R4) | standard §7 |
| `policy.py` | 4-mode policy declaration (CERTIFICATE/GATE/WATCH/HYBRID) as signed ledger data; tolerant loading of new knobs | standard §8 |
| `audit.py` | the orchestrator: verify → jury → divergence → ladder → certificate; records every step; applies calibration factors; opens deliberation rounds and meta-claims; issues dossiers | standard §4.4, §6, §9 |
| `certificate.py` | cert assembly + `verify_certificate` (offline replay: chain, signature, anchor, issuance entry, evidence subset, verdict recompute) | standard §11 |
| `canary.py` | blind injection corpus + quality sheet + `build_orchestrator` | design §7.6 |

## The watcher layer (third-party producers)

| Module | Role | Reference |
|---|---|---|
| `watchers.py` | signed manifests (W1a structurally banned), blind sessions, tier-ceiling clamping, deadline→abstain; ManifestRegistry verify/revoke | standard §6 |
| `conformance.py` | C1–C10 certification kit — an honest LOWER BOUND (stateful fns can defeat spot-checks; code_hash review remains a certification step) | standard §6.7 |
| `calibration.py` | per-producer confidence factor ledger: W1a-contradiction discount −0.1, rehab +0.05, clamp [0.5, 1.0]; confidence only, never tier/stance | standard §4.4.5 |
| `dossier.py` | R3 human-risk-owner view (risk frames from REFUTES rationale, evidence links) + decision return + R4 fail-safe; refuses fabricated dossier ids | standard §12 |
| `registry_index.py` | marketplace index: build/validate/export/load over `watcher.registered` (latest-wins, signature + digest verified) | standard §6.6 |

## Verification surfaces

| Surface | Entry | Notes |
|---|---|---|
| CLI | `veridict audit/verify/quality-sheet/dossier/resolve/index` | rc 0 pass, rc 1 fail/error (R2/R3) |
| Reference verifier | `veridict.certificate.verify_certificate` | §11.3 |
| **Spec-only verifier** | `examples/spec_verifier.py` | written from the standard ALONE (no veridict imports) — the exit-criterion-① rehearsal |
| Test vectors | `docs/standard-test-vectors/` | deterministic (fixed ts, fixed ed25519 seed); byte-pinned by regeneration test |
| Dogfood | `scripts/dogfood.py` | the system audits itself; phase-2 receipt block; reentrancy-guarded |
| Vectors builder | `scripts/build_test_vectors.py` | deterministic regeneration |
| Fuzz | `tests/test_fuzz_ledger.py` | seeded properties: roundtrip byte-exactness, tamper always caught |

## Governance docs

`LICENSE` (Apache-2.0), `CONTRIBUTING.md`, `GOVERNANCE.md`,
`CHANGELOG.md`, and `docs/notes/` (external-incident design notes).
