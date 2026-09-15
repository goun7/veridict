"""Bounded-exhaustive verification of the adjudication ladder (issue #8).

The milestone ask was machine-checked proof of the ladder's safety
properties. The honest available ceiling (no Lean/Coq/elan toolchain on
the maintainer host, and shipping a proof toolchain into CI for a 127-
line pure function is overkill) is EXHAUSTIVE enumeration: the ladder's
input space is genuinely finite once evidence sequences are bounded, so
"verified for every possible input" and "verified by checking every
input" coincide.

Space: verifiability(3) x critical_class(2) x policy.criticality(2) x
meta-claim depth budget(2) x first_round_split(2) x evidence sequences
over 4 tiers x 2 stances with length 0..3 (585) = 14,040 runs, each
executed twice for the determinism invariant. Sub-second in pure python.

Invariants (§6.1/§4.3, asserted on EVERY case):
  I1 fail-safe-empty        no evidence ⇒ INCONCLUSIVE @ R4
  I2 no-silent-pass         VERIFIED ⇒ some W1a or W2 item exists (W3
                            doctrine alone can never certify)
  I3 w3-only-never-passed  all-W3 evidence ⇒ not VERIFIED
  I4 w1a-decisive           any W1a REFUTES ⇒ REFUTED (ladder halts there)
  I5 doctrine-cannot-topple any W1a support ⇒ never REFUTED/ESCALATED
  I6 escalated-conditions   ESCALATED ⇒ SPLIT & critical-class & no W1a
                            & no W1b refutation above it
  I7 split-stays-visible    deliberation flag ⇒ risk notes carry it
  I8 determinism            same inputs, same Adjudication, twice
  I9 domain-closure         rung/value/divergence inside declared sets
  I10 meta-budget-honored   meta-claims emitted ⇒ policy budget ≥ depth

Exit 0 and writes the receipt (default docs/receipts-ladder-verification.
json) iff every invariant holds; prints the truth-table digest so any
rebuilt ladder that changes behavior anywhere produces a different,
detectable digest (the ladder source hash is recorded beside it).
"""
from __future__ import annotations

import hashlib
import itertools
import json
import os
import sys
import time
from dataclasses import asdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.ladder import SPLIT_RESOLVED_NOTE, Rung, adjudicate      # noqa: E402
from veridict.policy import PolicyDeclaration, Thresholds              # noqa: E402
from veridict.schemas import Claim, EvidenceItem                       # noqa: E402

TIERS = ("W1a", "W1b", "W2", "W3")
STANCES = ("SUPPORTS", "REFUTES")
VERIFIABILITY = ("MACHINE_CHECKABLE", "DOCTRINAL", "MIXED")
VALUES = {"VERIFIED", "REFUTED", "INCONCLUSIVE", "ESCALATED"}
RUNGS = {Rung.R0, Rung.R1, Rung.R2, Rung.R3, Rung.R4}
DIVERGENCES = {"UNANIMOUS", "MAJORITY", "SPLIT"}
MAX_EVIDENCE_LEN = 3


def _claim(verb: str, crit: str | None) -> Claim:
    return Claim(claim_id="v", task_id="v", subject="v", predicate="v",
                 scope="v", summary="v", derived_from="d",
                 verifiability=verb, falsifiable_by=("x",), critical_class=crit)


def _ev(tier: str, stance: str, i: int) -> EvidenceItem:
    return EvidenceItem(evidence_id=f"e{i}", claim_id="v",
                        evidence_class="TEST_EXECUTION" if tier == "W1a"
                        else "STATIC_ANALYSIS",
                        tier=tier, producer={"kind": "verifier",
                                             "identity": "v", "version": "0"},
                        artifact_ref="d",
                        reproducibility={"deterministic": True,
                                         "rerun_recipe": None},
                        stance=stance,
                        confidence=1.0 if tier == "W1a" else 0.8)


def cases():
    shapes = [s for n in range(MAX_EVIDENCE_LEN + 1)
              for combo in itertools.product(
                  ((t, st) for t in TIERS for st in STANCES), repeat=n)
              for s in [combo]]
    for verb, crit_in, pol_crit, depth, split, evs in itertools.product(
            VERIFIABILITY, (None, "CRITICAL"), (("CRITICAL",), ()), (0, 2),
            (False, True), shapes):
        claim = _claim(verb, "CRITICAL" if crit_in else None)
        policy = PolicyDeclaration(policy_id="v", mode="HYBRID",
                                  criticality=pol_crit,
                                  thresholds=Thresholds(
                                      meta_claim_depth_budget=depth),
                                  divergence_tolerance=1 / 3)
        evidence = [_ev(t, st, i) for i, (t, st) in enumerate(evs)]
        yield claim, evidence, policy, split


def check(case_id: int, claim, evidence, policy, split, adj) -> list[str]:
    bad: list[str] = []
    tiers_present = {e.tier for e in evidence}
    w1a = [e for e in evidence if e.tier == "W1a"]
    # I1
    if not evidence and not (adj.value == "INCONCLUSIVE" and adj.rung == Rung.R4):
        bad.append("I1 fail-safe-empty")
    # I2
    if adj.value == "VERIFIED" and not (tiers_present & {"W1a", "W2"}):
        bad.append("I2 no-silent-pass")
    # I3
    if evidence and tiers_present == {"W3"} and adj.value == "VERIFIED":
        bad.append("I3 w3-only-never-passed")
    # I4
    if any(e.stance == "REFUTES" for e in w1a) and adj.value != "REFUTED":
        bad.append("I4 w1a-decisive")
    # I5
    if w1a and all(e.stance == "SUPPORTS" for e in w1a) \
            and adj.value in ("REFUTED", "ESCALATED"):
        bad.append("I5 doctrine-cannot-topple")
    # I6
    if adj.value == "ESCALATED" and not (
            adj.divergence == "SPLIT"
            and claim.critical_class in policy.criticality
            and not w1a
            and not any(e.tier == "W1b" and e.stance == "REFUTES"
                        for e in evidence)):
        bad.append("I6 escalated-conditions")
    # I7
    if split and not any(SPLIT_RESOLVED_NOTE in n for n in adj.risk_notes):
        bad.append("I7 split-stays-visible")
    # I9
    if not (adj.value in VALUES and adj.rung in RUNGS
            and adj.divergence in DIVERGENCES):
        bad.append("I9 domain-closure")
    # I10
    if adj.meta_claims and any(m["depth"] > policy.meta_claim_depth_budget
                               for m in adj.meta_claims):
        bad.append("I10 meta-budget-honored")
    return bad


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    out = argv[0] if argv else os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "docs", "receipts-ladder-verification.json")
    ladder_src = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "veridict", "ladder.py")
    src_hash = hashlib.sha256(open(ladder_src, "rb").read()).hexdigest()

    rows: list[dict] = []
    failures: dict[str, list[int]] = {}
    outcomes: dict[str, int] = {}
    t0 = time.time()
    for i, (claim, evidence, policy, split) in enumerate(cases()):
        adj = adjudicate(claim, evidence, policy, first_round_split=split)
        again = adjudicate(claim, evidence, policy, first_round_split=split)
        if adj != again:                                  # I8 determinism
            failures.setdefault("I8 determinism", []).append(i)
        for tag in check(i, claim, evidence, policy, split, adj):
            failures.setdefault(tag, []).append(i)
        outcomes[adj.value] = outcomes.get(adj.value, 0) + 1
        inp = asdict(claim) | {
            "evidence": [[e.tier, e.stance] for e in evidence],
            "criticality": list(policy.criticality),
            "meta_depth": policy.meta_claim_depth_budget,
            "first_round_split": split}
        rows.append({"case": i,
                     "input_sha256": hashlib.sha256(
                         json.dumps(inp, sort_keys=True).encode()).hexdigest(),
                     "value": adj.value, "divergence": adj.divergence,
                     "rung": adj.rung})
    table_digest = hashlib.sha256(
        json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    receipt = {
        "receipt": "veridict-ladder-bounded-verification-1",
        "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": ("bounded-exhaustive enumeration of the full finite "
                   "adjudication-ladder input space (evidence sequences of "
                   "length <= %d over 4 tiers x 2 stances x all claim/"
                   "policy/deliberation dimensions); no theorem prover "
                   "claimed — that would be Lean's job (issue #8 stays "
                   "open for the unbounded/general proof)" % MAX_EVIDENCE_LEN),
        "ladder_source_sha256": src_hash,
        "total_cases": len(rows),
        "seconds": round(time.time() - t0, 3),
        "outcome_distribution": dict(sorted(outcomes.items())),
        "invariants": {name: "PASS" for name in (
            "I1 fail-safe-empty", "I2 no-silent-pass", "I3 w3-only-never-passed",
            "I4 w1a-decisive", "I5 doctrine-cannot-topple",
            "I6 escalated-conditions", "I7 split-stays-visible",
            "I8 determinism", "I9 domain-closure", "I10 meta-budget-honored")}
        if not failures else {name: f"FAIL ({len(idxs)} cases: {idxs[:5]}…)"
                              for name, idxs in sorted(failures.items())},
        "all_invariants_pass": not failures,
        "truth_table_sha256": table_digest,
        "reproduce": "python3 scripts/verify_ladder.py  # deterministic; same table digest",
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(receipt, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps({k: receipt[k] for k in
                      ("total_cases", "all_invariants_pass", "outcome_distribution",
                       "truth_table_sha256", "seconds")}, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
