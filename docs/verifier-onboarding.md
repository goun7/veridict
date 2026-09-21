# Independent Verifier Onboarding (issue #1 closure kit)

The standard's credibility rests on someone else being able to say "valid"
without running our code. This document is the contract for doing exactly
that — it is the checklist a third-party verifier follows, and the checklist
we run against every candidate before closing [#1](https://github.com/goun7/veridict/issues/1).

What counts as done: an implementation, written **from the spec alone**, that
produces the pinned expected outputs below. Python is not required; importing
the `veridict` package is forbidden (that is the point). If you want a
second reference to compare against, `examples/spec_verifier.py` is our own
from-the-spec reimplementation (stdlib + one ed25519 dependency) — write
yours before peeking if you can.

## Tier 0 — what you may trust (and nothing else)

| Artifact | Role |
|---|---|
| [`docs/specs/2026-09-10-veridict-standard-v1.0.md`](specs/2026-09-10-veridict-standard-v1.0.md) | the normative text; section refs below point here |
| [`docs/schemas/`](schemas/) | JSON Schemas for ledger entries, certificates, watcher manifests |
| [`docs/standard-test-vectors/`](standard-test-vectors/) | conformance corpus: `ledger.jsonl`, `certificate.json`, `expected_verify.json`, `ladder_vectors.json`, `watcher_vectors.json` |
| [`docs/standard-test-vectors/settlement/`](standard-test-vectors/settlement/) | the claims surface a payment layer consumes: `claim.json`, `expected_reconcile.json`, four tamper cases pinned to distinct rejection classes |
| [`dogfood_ledger.jsonl`](../dogfood_ledger.jsonl) + [`dogfood_cert.json`](../dogfood_cert.json) + [`docs/receipts-anchor-v050-dogfood.json`](receipts-anchor-v050-dogfood.json) | a real, anchored end-to-end run (Rekor sidecar included) |
| [`docs/receipts-ladder-verification.json`](receipts-ladder-verification.json) | the 28,080-case ladder receipt (sha256 of the table is inside) |

## Tier 1 — byte-level obligations, with the traps we actually fell into

1. **Canonical JSON (§2.1).** Sorted keys, compact separators, non-ASCII
   escaped. Everything digestible is digested *through* this one function;
   one separator difference and every hash disagrees.
2. **Entry hash preimage (§2.3).** `sha256_hex` over `"|".join([prev_hash,
   payload_digest, entry_type, str(seq), canonical_json(author),
   canonical_json(ts), schema_version])`. Note `str(seq)` is *not*
   JSON-encoded, while `author` and `ts` **are** — a bare ISO string becomes
   a quoted JSON string inside the preimage. (Trap: our first fuzz round
   caught `ts` missing from the preimage entirely; a ledger whose
   timestamps can be edited is not an audit ledger.)
3. **`ts` is an ISO-8601 UTC string**, never a float — float formatting is
   language-fragile; ordering lives in `seq`.
4. **`payload_hash` is its own field** — a retroactive payload edit makes
   *both* stored hashes stale; check order affects the diagnostic message,
   never the boolean verdict.
5. **Certificate signature.** Ed25519 over the canonical-JSON *body* (all
   fields except `signature`), public key from the enrolled `key.enrolled`
   ledger entry — the certificate is validated against the ledger, not in
   isolation.
6. **Verdict recomputation.** Claims carry `{claim_id, divergence,
   evidence_ids, verdict_value}` — **there is no rung field on claims**;
   evidence tier/stance/producer come from the `evidence.recorded` payload
   entries joined by `evidence_id`. Recompute with the §7 ladder and compare.
7. **The R0 guard (§7).** Doctrine can overturn a machine verdict only when
   **no evidence at ANY tier refutes** the claim — refutation at W1b or W2p
   counts just as much as W1a. (Trap: this exact subtlety is where our own
   Lean model diverged from the implementation; the 28,080-row oracle caught
   it before anything shipped. If your ladder and ours differ on one case,
   suspect this rule first.)
8. **Anchors.** The sidecar shape is `{anchor_version, bound, digest,
   rekor{server, uuid, entry{body, integratedTime, logID, logIndex,
   verification}}}`; `bound` ties `entry_hash`+`artifact_digest`+certificate
   digest — a verification tool that ignores the binding verifies a
   signature over nothing relevant.
9. **Divergence tolerance (§7.3 D3-errata included).** Majority-SUPPORTS
   with a lone REFUTES ⇒ REFUTED — fail-closed consensus, pinned case by
   case in `ladder_vectors.json`.

## Tier 2 — the cross-check recipe (one command)

```bash
python3 scripts/crosscheck_verifier.py --extra path/to/your_verifier_module.py
```

It runs the reference CLI and the spec-only verifier over
`{vectors, dogfood}` and asserts byte-equal reports; `--extra` adds your
module (exposing `verify_certificate(ledger_path, cert_path) -> report`) to
the same comparison. Exit 0 with the external flag is the machine-checkable
definition of "conforms".

Expected vector report (must be EXACT, key order irrelevant):

```json
{"valid": true, "chain_valid": true, "signature_valid": true,
 "verdicts_match": true, "errors": []}
```

## Tier 3 — the proofs are your behavioral spec

Where prose is ambiguous, the machine-checked statements are not:

- `proofs/ladder/Ladder.lean` — seven invariants your ladder must obey for
  every evidence list, arbitrary length (e.g. doctrine-can-never-topple at
  R0 given any refuting evidence; W1a-decisiveness).
- `proofs/ledger/Chain.lean` — six chaining theorems: what tampering can and
  cannot survive (everything else your verifier must detect).
- `proofs/anchor/Anchor.lean` — nine anchor theorems over the sidecar
  cross-check: fail-closed parsing, binding-necessity, no-silent-skip, and
  the architecture claim (A4) that a mismatched binding invalidates the
  anchor regardless of both ECDSA verdicts — your verifier must reject
  there even when the signatures are perfect.
- `docs/receipts-ladder-verification.json` + `proofs/ladder/TruthTable.lean`
  — the full bounded behavior table; `lake build` in `proofs/ladder` replays
  all 28,080 cases against the Lean model in CI. If your implementation
  disagrees with the table anywhere, the table is right until you prove
  otherwise against the spec text — cite the section.

## Submitting

Open a PR adding `verifiers/<yourname>/` (or keep it in your repo and comment
on #1). Include: language, commit hash of the spec you implemented against,
output of the Tier 2 command (or an equivalent transcript), and anything the
spec left genuinely ambiguous — ambiguity reports are contributions, not
complaints. We run your verifier in our CI against the pinned corpus before
#1 closes; the first external "valid" that never touched our code is the
whole point of the standard.
