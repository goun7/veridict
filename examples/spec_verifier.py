#!/usr/bin/env python
"""A Veridict verifier implemented FROM THE STANDARD ALONE.

This file imports NOTHING from the veridict package — only the standard
library plus an ed25519 implementation (the standard mandates the signature
ALGORITHM, §11.1; any implementer must bring some library for it). It is the
Phase 3 exit-criterion-① rehearsal: if the standard (docs/specs/
2026-09-10-veridict-standard-v1.0.md) were ambiguous or wrong, this file
could not have been written against it alone.

Implements: §2.1 canonical JSON, §2.2 digests, §2.3 chain + ts rule,
§5.4 divergence classification, §7 adjudication ladder, §9.4 replay-exclusion
scope, §11.3 offline verification.

Usage:
    python examples/spec_verifier.py --ledger L.jsonl --cert C.json \
        [--expected expected_verify.json]
Exit 0 when the computed report matches --expected (or is valid=true when no
expectation is given), 1 otherwise.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys

GENESIS = "0" * 64

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover
    sys.exit("spec_verifier needs an ed25519 implementation: pip install cryptography")


class SpecError(Exception):
    pass


# §2.1 canonical JSON: sorted keys, compact separators, ASCII escaping.
def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(s) -> str:
    return hashlib.sha256(s.encode("utf-8") if isinstance(s, str) else s).hexdigest()


def payload_digest(payload: dict) -> str:
    return sha256_hex(canonical_json(payload))


def entry_hash(entry: dict) -> str:
    """§2.3: the preimage binds EVERY prior field (incl. ts, prev_hash)."""
    return sha256_hex("|".join([
        entry["prev_hash"], entry["payload_hash"], entry["entry_type"],
        str(entry["seq"]), canonical_json(entry["author"]),
        canonical_json(entry["ts"]), entry["schema_version"]]))


def load_ledger(path: str) -> list[dict]:
    entries = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                raise SpecError(f"malformed ledger line {lineno}: "
                                "line is not valid JSON")
    return entries


def verify_chain(entries: list[dict]) -> tuple[bool, str]:
    prev = GENESIS
    for e in entries:
        if e["payload_hash"] != payload_digest(e["payload"]):
            return False, f"payload hash mismatch at seq {e['seq']}"
        if e["entry_hash"] != entry_hash(e):
            return False, f"entry hash mismatch at seq {e['seq']}"
        if e["prev_hash"] != prev:
            return False, f"prev_hash mismatch at seq {e['seq']}"
        prev = e["entry_hash"]
    return True, "ok"


def ed25519_verify(pub_pem: str, message: bytes, sig_b64: str) -> bool:
    try:
        pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        pub.verify(base64.b64decode(sig_b64, validate=True), message)
        return True
    except (InvalidSignature, binascii.Error, ValueError, TypeError):
        return False


def classify_divergence(evidence: list[dict], tolerance: float) -> str:
    """§5.4."""
    doctrinal = [e for e in evidence if e["tier"] in ("W2", "W3")]
    if not doctrinal:
        return "UNANIMOUS"
    n_sup = sum(1 for e in doctrinal if e["stance"] == "SUPPORTS")
    n_ref = len(doctrinal) - n_sup
    if n_sup == 0 or n_ref == 0:
        return "UNANIMOUS"
    minority = min(n_sup, n_ref)
    return "MAJORITY" if minority / len(doctrinal) <= tolerance else "SPLIT"


def adjudicate_spec(claim: dict, evidence: list[dict],
                    criticality: list, tolerance: float) -> str:
    """§7, top-down (includes the D3-errata doctrinal-consensus R4)."""
    if not evidence:
        return "INCONCLUSIVE"                                   # R4-first
    w1a = [e for e in evidence if e["tier"] == "W1a"]
    w1b = [e for e in evidence if e["tier"] == "W1b"]
    w2plus = [e for e in evidence if e["tier"] in ("W2", "W3")]
    divergence = classify_divergence(evidence, tolerance)
    if (claim["verifiability"] == "MACHINE_CHECKABLE" and w1a
            and all(e["stance"] == "SUPPORTS" for e in w1a)
            and not any(e["stance"] == "REFUTES" for e in evidence)):
        return "VERIFIED"                                       # R0
    if w1a:
        if any(e["stance"] == "REFUTES" for e in w1a):
            return "REFUTED"                                    # R1
        if any(e["stance"] == "REFUTES" for e in w1b):
            return "VERIFIED"                                   # R1 (R2 signal)
        return "VERIFIED"                                       # R1
    if any(e["stance"] == "REFUTES" for e in w1b):
        return "INCONCLUSIVE"                                   # R2
    if claim.get("critical_class") in criticality and divergence == "SPLIT":
        return "ESCALATED"                                      # R3
    if w2plus and any(e["tier"] == "W2" for e in w2plus):       # R4
        if divergence == "SPLIT":
            return "INCONCLUSIVE"                               # non-critical split
        if all(e["stance"] == "SUPPORTS" for e in w2plus):
            return "VERIFIED"                                   # doctrinal consensus
        return "REFUTED"            # any doctrinal REFUTES — fail-closed
    return "INCONCLUSIVE"           # W3-only / remaining cases — no silent pass


def verify_certificate(ledger_path: str, cert_path: str) -> dict:
    """§11.3 — the normative offline verification."""
    report = {"valid": False, "chain_valid": False, "signature_valid": False,
              "verdicts_match": False, "errors": []}
    errors = report["errors"]
    try:
        entries = load_ledger(ledger_path)
    except SpecError as exc:
        errors.append(f"chain: {exc}")
        return report
    chain_ok, msg = verify_chain(entries)
    if not chain_ok:
        errors.append(f"chain: {msg}")
        return report
    report["chain_valid"] = True

    with open(cert_path, encoding="utf-8") as f:
        cert = json.load(f)
    body = {k: v for k, v in cert.items() if k != "signatures"}
    if not cert.get("signatures"):
        errors.append("signature: certificate carries no signatures")
        return report
    sig0 = cert["signatures"][0]
    pub = next((e["payload"]["public_pem"] for e in entries
                if e["entry_type"] == "key.enrolled"
                and e["payload"]["key_id"] == sig0["key_id"]), None)
    sig_ok = bool(pub) and ed25519_verify(pub, canonical_json(body).encode("utf-8"),
                                          sig0["sig_b64"])
    report["signature_valid"] = sig_ok
    if not sig_ok:
        errors.append("signature: no enrolled key verifies the certificate body")

    anchor = cert.get("ledger_anchor", {})
    cp_seq = anchor.get("checkpoint_seq")
    anchor_ok = (isinstance(cp_seq, int) and 0 <= cp_seq < len(entries)
                 and entries[cp_seq]["entry_type"] == "checkpoint.anchored"
                 and entries[cp_seq]["payload"]["chain_hash"] == anchor.get("chain_hash"))
    if not anchor_ok:
        errors.append("anchor: checkpoint does not match ledger")
    issued = (isinstance(cp_seq, int)
              and any(e["entry_type"] == "certificate.issued"
                      and e["payload"].get("cert_id") == cert.get("cert_id")
                      and e["seq"] >= cp_seq for e in entries))
    if not issued:
        errors.append("certificate: no matching certificate.issued entry in ledger")
    if not (sig_ok and anchor_ok and issued):
        return report

    # §9.4: superseded first-round items, anchored prefix ONLY.
    superseded: set[str] = set()
    for e in entries:
        if e["entry_type"] == "deliberation.rounded" and e["seq"] <= cp_seq:
            superseded.update(x["evidence_id"]
                              for x in e["payload"].get("first_round", []))
    known: set[str] = set()
    ev_by_claim: dict[str, list[dict]] = {}
    for e in entries:
        if e["entry_type"] == "evidence.recorded":
            known.add(e["payload"]["evidence_id"])
            if e["payload"]["evidence_id"] in superseded:
                continue
            ev_by_claim.setdefault(e["payload"]["claim_id"], []).append(e["payload"])
    registered = {e["payload"]["claim_id"]: e["payload"]
                  for e in entries if e["entry_type"] == "claim.registered"}
    pr = cert.get("policy_ref", {})
    tolerance = pr.get("thresholds", {}).get("divergence_tolerance", 1 / 3)
    criticality = pr.get("criticality", [])
    verdicts_match = True
    for c in cert["claims"]:
        if c["claim_id"] not in registered:
            errors.append(f"claims: {c['claim_id']} not registered in ledger")
            verdicts_match = False
            continue
        for eid in c.get("evidence_ids", []):
            if eid not in known:
                errors.append(f"evidence: cert references unknown evidence {eid}")
                verdicts_match = False
        recomputed = adjudicate_spec(registered[c["claim_id"]],
                                     ev_by_claim.get(c["claim_id"], []),
                                     criticality, tolerance)
        if recomputed != c["verdict_value"]:
            errors.append(f"verdict mismatch for {c['claim_id']}: "
                          f"cert={c['verdict_value']} recomputed={recomputed}")
            verdicts_match = False
    report["verdicts_match"] = verdicts_match
    report["valid"] = not errors
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="spec_verifier")
    p.add_argument("--ledger", required=True)
    p.add_argument("--cert", required=True)
    p.add_argument("--expected")
    args = p.parse_args(argv)
    report = verify_certificate(args.ledger, args.cert)
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.expected:
        with open(args.expected, encoding="utf-8") as f:
            expected = json.load(f)
        return 0 if report == expected else 1
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
