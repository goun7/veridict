#!/usr/bin/env python3
"""verify_settlement_vector — zero-dependency selftest for the claims bridge.

The mirror image of scripts/pugio_watch_receiver.py for the settlement
surface: a consumer in ANOTHER repo (a payment layer, an x402-family
bridge) runs this against our pinned vector directory and gets a loud
PASS/RED, so bridge continuity does not depend on our pipeline staying
alive (Sester Q2). Pure stdlib — no veridict import, no install step: a
consumer copies this file plus docs/standard-test-vectors/settlement/.

Contract (see that directory's README):
  - claim.json must be derivable from certificate.json under the default
    policy, and claim_digest must recompute from the claim's own fields;
  - every tamper/*.json must be REFUSED.

Fail-loud (the shared doctrine): a single RED line exits 1. There is no
silent pass and no partial success.

Usage:
  python3 verify_settlement_vector.py                     # selftest (exit 0/1)
  python3 verify_settlement_vector.py /path/to/vector     # explicit dir
  python3 verify_settlement_vector.py --claim x.json --cert c.json   # one claim

Honest limit: this checks the CLAIM follows from the CERTIFICATE. It does
not verify the certificate itself — that is examples/spec_verifier.py's
job, and conflating the two is how silent passes happen.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

# The shipped default policy, restated here so this file is self-contained.
# A consumer implementing the standard re-derives these from the spec text.
DEFAULT_POLICY = {
    "accept_verdicts": ["VERIFIED"],
    "max_risk": "low",
    "min_jury_families": 2,
    "min_claim_coverage": 1.0,
}
RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# The digest preimage: every claim field except claim_digest itself.
# Self-reference would make the binding cosmetic (mutate + recompute passes).
DIGEST_FIELDS = ("cert_id", "task_id", "artifact_digest", "valid", "reasons",
                 "accepted_claims", "total_claims", "jury_families",
                 "risk_level", "policy_digest")


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def policy_digest(policy: dict) -> str:
    return hashlib.sha256(_canon(policy)).hexdigest()


def claim_digest(claim: dict) -> str:
    body = {k: claim.get(k) for k in DIGEST_FIELDS}
    return hashlib.sha256(_canon(body)).hexdigest()


def build_claim(cert: dict, policy: dict) -> dict:
    """The independent consumer's re-derivation of the claim from the
    certificate. Mirrors veridict/settlement.py semantics as documented in
    the vector README; disagreements here ARE the findings we want."""
    reasons: list[str] = []
    claims = cert.get("claims", [])
    verdicts = [c.get("verdict_value") for c in claims]
    accepted = sum(1 for v in verdicts if v in policy["accept_verdicts"])
    coverage = accepted / len(claims) if claims else 0.0
    families = cert.get("jury_composition", {}).get("families", [])
    risk = cert.get("risk_level", "high")          # unknown risk fails closed

    if not claims:
        reasons.append("certificate has no claims — nothing was adjudicated")
    if coverage < policy["min_claim_coverage"]:
        reasons.append(f"claim coverage {coverage:.2f} < "
                       f"{policy['min_claim_coverage']:.2f}")
    if len(set(families)) < policy["min_jury_families"]:
        reasons.append(f"jury families {len(set(families))} < "
                       f"{policy['min_jury_families']} (single-family "
                       "verdict is self-preference)")
    if RISK_ORDER.get(risk, 3) > RISK_ORDER.get(policy["max_risk"], 0):
        reasons.append(f"risk {risk} exceeds policy maximum "
                       f"{policy['max_risk']}")

    claim = {
        "cert_id": cert.get("cert_id", ""),
        "task_id": cert.get("subject", {}).get("task_id", ""),
        "artifact_digest": cert.get("subject", {}).get("artifact_digest", ""),
        "valid": not reasons,
        "reasons": reasons,
        "accepted_claims": accepted,
        "total_claims": len(claims),
        "jury_families": sorted(set(families)),
        "risk_level": risk,
        "policy_digest": policy_digest(policy),
    }
    claim["claim_digest"] = claim_digest(claim)
    return claim


def reconcile(presented: dict, cert: dict, policy: dict) -> tuple[bool, list[str]]:
    """Does the presented claim follow from this certificate under this
    policy? Nothing about the presented claim is trusted except which cert
    it claims to be about."""
    reasons: list[str] = []
    expected = build_claim(cert, policy)
    cid = presented.get("claim_digest", "")

    self_consistent = claim_digest(presented) == cid
    matches = cid == expected["claim_digest"]
    if not self_consistent:
        reasons.append("claim_digest does not recompute from the claim's own "
                       "fields — the claim was edited after issuance")
    if not matches:
        reasons.append("claim does not follow from this certificate under "
                       "this policy")
    if presented.get("valid") is not expected["valid"]:
        reasons.append(f"presented valid={presented.get('valid')} but the "
                       f"certificate yields valid={expected['valid']}")
    if not expected["valid"]:
        reasons.extend(expected["reasons"])
    ok = (self_consistent and matches
          and presented.get("valid") is True and expected["valid"] is True)
    return ok, reasons


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def selftest(vector_dir: str) -> int:
    """Clean vector → PASS; any tamper → RED. One RED line exits 1."""
    cert_path = os.path.join(vector_dir, "..", "certificate.json")
    if not os.path.exists(cert_path):
        print(f"RED certificate not found at {cert_path} — the settlement "
              "vector derives from the certificate vector one directory up; "
              "copy the whole standard-test-vectors/ tree")
        return 1
    cert = _load(cert_path)
    expected_claim = _load(os.path.join(vector_dir, "claim.json"))
    expected_recon = _load(os.path.join(vector_dir, "expected_reconcile.json"))
    tdir = os.path.join(vector_dir, "tamper")
    fails: list[str] = []

    # 1) the honest claim is exactly what the certificate yields
    rebuilt = build_claim(cert, DEFAULT_POLICY)
    if rebuilt != expected_claim:
        fails.append("clean: claim does not recompute from the certificate: "
                     + ", ".join(f"{k}={rebuilt[k]!r} vs "
                                 f"{expected_claim.get(k)!r}"
                                 for k in set(rebuilt) | set(expected_claim)
                                 if rebuilt.get(k) != expected_claim.get(k)))
    # 2) its digest is honest about its own fields
    if claim_digest(expected_claim) != expected_claim["claim_digest"]:
        fails.append("clean: claim_digest does not recompute from the claim")
    # 3) it reconciles to the pinned report
    ok, reasons = reconcile(expected_claim, cert, DEFAULT_POLICY)
    if not ok:
        fails.append(f"clean: honest claim refused: {reasons}")
    if ok != expected_recon["valid"] or reasons != expected_recon["reasons"]:
        fails.append("clean: reconciliation disagrees with the pinned report")

    # 4) every tamper case is refused
    pinned_tamper = _load(os.path.join(vector_dir, "expected_tamper.json"))
    for name in sorted(pinned_tamper):
        forged = _load(os.path.join(tdir, f"{name}.json"))
        ok, reasons = reconcile(forged, cert, DEFAULT_POLICY)
        if ok:
            fails.append(f"tamper {name}: ACCEPTED (must be refused)")
        exp = pinned_tamper[name]
        if exp["valid"] is not False:
            fails.append(f"tamper {name}: pinned expected valid is not False")
        # the pinned rejection class must hold
        actual_matches = expected_claim["claim_digest"] == forged["claim_digest"]
        if actual_matches != exp["matches_certificate"]:
            fails.append(f"tamper {name}: matches_certificate class changed")

    if fails:
        for f_ in fails:
            print(f"RED {f_}")
        print(f"FAIL: {len(fails)} check(s) red")
        return 1
    n = len(pinned_tamper)
    print(f"PASS: claim recomputes from the certificate; "
          f"{n}/{n} tamper cases refused; 0 false accepts")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("vector", nargs="?",
                    default=os.path.join(os.path.dirname(os.path.dirname(
                        os.path.abspath(__file__))), "docs",
                        "standard-test-vectors", "settlement"),
                    help="the settlement vector directory (default: shipped)")
    ap.add_argument("--claim", help="reconcile a single claim file instead")
    ap.add_argument("--cert", help="certificate for --claim (default: the "
                    "vector's parent certificate)")
    args = ap.parse_args(argv)

    if args.claim:
        cert_path = args.cert or os.path.join(args.vector, "..",
                                              "certificate.json")
        ok, reasons = reconcile(_load(args.claim), _load(cert_path),
                                DEFAULT_POLICY)
        print(json.dumps({"valid": ok, "reasons": reasons}, sort_keys=True))
        return 0 if ok else 1

    return selftest(args.vector)


if __name__ == "__main__":
    sys.exit(main())
