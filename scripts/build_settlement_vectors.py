#!/usr/bin/env python3
"""Build the settlement-claims conformance vectors.

The certificate vectors (docs/standard-test-vectors/{ledger,certificate}.json)
pin the standard's OFFLINE VERIFICATION surface. These vectors pin the next
surface outwards: the CLAIM a payment layer consumes (issue #10 Lane 3,
`veridict settle`). An agent that did the work has every reason to forge the
claim it presents for payment, so the contract here is not "trust the claim"
but "the claim must follow, field by field, from a certificate the payer
ALREADY verified" (see veridict/settlement.py docstring).

Determinism: no key generation, no clock, no network. The claim is a pure
function of (certificate fields, policy), and the policy is the shipped
default. Rebuilding from the pinned certificate reproduces every file
byte-for-byte — pinned by tests/test_settlement_vectors.py.

Consumers (Sester/x402-family bridges, or any settlement layer) MUST, from
certificate.json + policy alone:
  1. recompute the claim's every derived field (accepted/total coverage,
     jury families, risk, policy_digest),
  2. recompute claim_digest over those fields (every field except itself),
  3. reconcile a presented claim by recomputing it and comparing digests,
  4. reach exactly expected_reconcile.json for the honest claim, and reject
     every tamper/*.json case.

Honest scope (stated in the README too): this vector says nothing about
whether the certificate itself is valid — that is the certificate vector's
job, and the settlement module deliberately does not conflate the two.
"""
from __future__ import annotations

import copy
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.settlement import (
    SettlementPolicy,
    _claim_digest,
    build_settlement_claim,
    verify_settlement_claim,
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERT = os.path.join(REPO, "docs", "standard-test-vectors", "certificate.json")
OUT = os.environ.get(
    "SETTLEMENT_VECTOR_OUT",
    os.path.join(REPO, "docs", "standard-test-vectors", "settlement"))

# The policy the vectors are built under. Pinned explicitly (not "default()")
# so a future default change cannot silently re-define the contract: a change
# here must be a deliberate edit to this file, and the pinning test fails.
VECTOR_POLICY = SettlementPolicy()


def _write(path: str, obj) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write("\n")


def _tamper(claim: dict, reforge: bool = True, **changes) -> dict:
    """Apply changes, optionally re-computing the digest. reforge=True models
    an attacker who re-forges consistently (the harder case); reforge=False
    models the naive attacker who leaves the old digest stale — caught twice
    over, since the digest no longer recomputes from the claim's own fields.
    """
    forged = copy.deepcopy(claim)
    forged.update(changes)
    if reforge:
        forged["claim_digest"] = _claim_digest(forged)
    return forged


def build() -> None:
    os.makedirs(OUT, exist_ok=True)
    with open(CERT, encoding="utf-8") as f:
        cert = json.load(f)

    # --- the honest claim + its reconciliation --------------------------
    claim = build_settlement_claim(cert, VECTOR_POLICY)
    claim_dict = json.loads(claim.to_json())
    _write(os.path.join(OUT, "claim.json"), claim_dict)
    reconcile = verify_settlement_claim(claim_dict, cert, VECTOR_POLICY)
    assert reconcile["valid"] is True, reconcile
    _write(os.path.join(OUT, "expected_reconcile.json"), reconcile)

    # --- tamper cases: each must be rejected, each for a distinct reason -
    tampers = {
        # valid is INSIDE the digest preimage, but the digest is NOT
        # recomputed -> self-inconsistent ("edited after issuance"). This is
        # the naive attacker; the reforged variants below are the careful one.
        "edited_after_issuance": _tamper(claim_dict, reforge=False, valid=False),
        # Reforged consistently, but the verdict it asserts does not follow
        # from this certificate.
        "verdict_flipped": _tamper(claim_dict, valid=False),
        # Claims to be about a different certificate entirely.
        "wrong_certificate": _tamper(claim_dict, cert_id="0" * 24),
        # Inflates coverage while keeping the digest consistent.
        "coverage_inflated": _tamper(claim_dict, accepted_claims=99,
                                     total_claims=99),
    }
    expected_tamper = {}
    tdir = os.path.join(OUT, "tamper")
    os.makedirs(tdir, exist_ok=True)
    for name, forged in tampers.items():
        _write(os.path.join(tdir, f"{name}.json"), forged)
        report = verify_settlement_claim(forged, cert, VECTOR_POLICY)
        assert report["valid"] is False, f"tamper {name} was ACCEPTED"
        # The REJECTION CLASS is the conformance contract; the reason text
        # is informational (an independent implementation will word it
        # differently). valid=False is what a payer must act on.
        expected_tamper[name] = {
            "valid": report["valid"],
            "expected_cert_id": report["expected_cert_id"],
            "presented_cert_id": report["presented_cert_id"],
            "self_consistent_digest": _claim_digest(forged)
            == forged.get("claim_digest"),
            "matches_certificate": report["expected_digest"]
            == forged.get("claim_digest"),
        }
    _write(os.path.join(OUT, "expected_tamper.json"), expected_tamper)

    readme = os.path.join(OUT, "README.md")
    with open(readme, "w", encoding="utf-8") as f:
        f.write(README)
    print("settlement vectors written:", OUT)


README = """# Settlement-claims conformance vectors

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
"""


if __name__ == "__main__":
    build()
