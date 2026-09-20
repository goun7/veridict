# Settlement-claims conformance vectors

The next surface outwards from the certificate vectors: the **claim** a
payment layer consumes. Built by `scripts/build_settlement_vectors.py` —
deterministic (no keys, no clock, no network): the claim is a pure function
of the certificate fields and the shipped default policy.

## Contract for an independent settlement layer

Inputs: `../certificate.json` (the pinned certificate vector) + the default
`SettlementPolicy`. The payer MUST have verified the certificate FIRST
(`veridict verify`, or `examples/spec_verifier.py` from the standard alone —
see the certificate vectors). This vector does not speak to certificate
validity; conflating the two is how silent passes happen.

From those inputs, an implementation MUST:

1. derive `claim.json` — every field recomputed from the certificate
   (accepted/total claim counts, jury families, risk level, policy digest);
2. compute `claim_digest` over every claim field EXCEPT `claim_digest`
   itself (self-reference would make the binding cosmetic);
3. reconcile a presented claim by recomputing the expected claim and
   comparing digests, reaching exactly `expected_reconcile.json`
   (`{valid: true, ...}`);
4. REJECT every case in `tamper/`, whose expected outcome is pinned in
   `expected_tamper.json`. Each case is one forgery class a paying agent
   can attempt:

   | case | attack | why it is refused |
   |---|---|---|
   | `edited_after_issuance` | `valid` flipped, stale digest kept | digest does not recompute from the claim's own fields |
   | `verdict_flipped` | `valid` flipped, digest re-forged | the asserted verdict does not follow from this certificate |
   | `wrong_certificate` | `cert_id` changed, digest re-forged | claim does not match what THIS cert yields |
   | `coverage_inflated` | counts inflated, digest re-forged | recomputed claim disagrees with the presented one |

   `expected_tamper.json` pins `valid: false` plus the rejection class. The
   `reasons` strings are informational — an independent implementation will
   word them differently; `valid: false` is what a payer must act on.

## Honest limits

- A claim reconciling against a FORGED certificate reconciles just fine, and
  that is by design — verify the certificate first (composable, not
  conflated).
- The pinned certificate carries stub jurors (two real families, so the
  diversity rule passes, but neither is an LLM). A claim resting on it is a
  contract demonstration, not evidence about real work.
- Amounts are deliberately absent: mapping acceptance to a price is the
  payment layer's bookkeeping, not this protocol's.

`tests/test_settlement_vectors.py` pins these files and the byte-determinism
of regeneration.
