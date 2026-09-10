"""Adjudication ladder (§6.1): R0 machine -> R4 fail-safe. No silent pass."""
from __future__ import annotations

from dataclasses import dataclass

from .divergence import compute_divergence
from .schemas import Claim, EvidenceItem


class Rung:
    """Rung labels (§6.1) as plain str constants — safe for ledger/certificate JSON."""
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


SPLIT_RESOLVED_NOTE = "first-round split; post-deliberation consensus"


@dataclass(frozen=True)
class Adjudication:
    claim_id: str
    value: str            # VERIFIED | REFUTED | INCONCLUSIVE | ESCALATED
    divergence: str       # UNANIMOUS | MAJORITY | SPLIT
    rung: str             # one of Rung.*
    risk_notes: tuple[str, ...] = ()
    meta_claims: tuple[dict, ...] = ()


def adjudicate(claim: Claim, evidence: list[EvidenceItem], policy,
               first_round_split: bool = False) -> Adjudication:
    """Walk R0->R4 top-down; first matching rung decides.

    Doubt only comes from refutation: W1a support plus silent doctrine is a
    clean R0. Tier rules of §4.3: strict ordering puts W1a above everything
    (R1); doctrine cannot overturn W1a (R1); a W1b refutation is a statistical
    signal that opens a meta-claim, not a refutation (R2); a critical-class
    doctrinal SPLIT escalates to the human risk owner (R3); and absence of
    evidence is never a silent pass (R4).

    `first_round_split` marks a claim whose first-round jury round SPLIT and
    went through a deliberation round (§4.4.3): the risk note keeps the split
    visible even when the revised items reached consensus.
    """
    w1a = [e for e in evidence if e.tier == "W1a"]
    w1b = [e for e in evidence if e.tier == "W1b"]
    w2plus = [e for e in evidence if e.tier in ("W2", "W3")]
    divergence = compute_divergence(evidence, getattr(policy, "divergence_tolerance", 1 / 3))
    risk: list[str] = []
    if first_round_split:
        risk.append(SPLIT_RESOLVED_NOTE if divergence != "SPLIT"
                    else SPLIT_RESOLVED_NOTE + " not reached")
    metas: list[dict] = []

    def _meta(depth: int = 1) -> None:
        if policy.meta_claim_depth_budget >= depth:
            metas.append({"subject": f"coverage-of:{claim.predicate}", "depth": depth})

    # R4 fail-safe: no evidence is never a silent pass (§4.3 rule 5).
    if not evidence:
        risk.append("no evidence collected — fail-safe (R4)")
        return Adjudication(claim.claim_id, "INCONCLUSIVE", divergence, Rung.R4,
                            tuple(risk), tuple(metas))

    # R0: machine-checkable claim fully supported by W1a with no refuting
    # signal at any tier — machine evidence is univocal, doctrine is advisory.
    if (claim.verifiability == "MACHINE_CHECKABLE" and w1a
            and all(e.stance == "SUPPORTS" for e in w1a)
            and not any(e.stance == "REFUTES" for e in evidence)):
        if policy.meta_claim_depth_budget > 0:
            _meta(1)
        risk.append("R0: verified on machine evidence alone; jury doctrine is advisory")
        return Adjudication(claim.claim_id, "VERIFIED", divergence, Rung.R0,
                            tuple(risk), tuple(metas))

    # R1: W1a is decisive — its refutation refutes the claim outright (§4.3 R1
    # strict ordering), and its support cannot be overturned by doctrine (R2).
    if w1a:
        if any(e.stance == "REFUTES" for e in w1a):
            return Adjudication(claim.claim_id, "REFUTED", divergence, Rung.R1,
                                tuple(risk), tuple(metas))
        if any(e.stance == "REFUTES" for e in w1b):
            # R2: W1b refutes alongside W1a support — a statistical signal that
            # opens a coverage meta-claim, not a refutation.
            risk.append("R2: W1b refute is a signal; W1a support stands — "
                        "coverage meta-claim opened")
            _meta(1)
            return Adjudication(claim.claim_id, "VERIFIED", divergence, Rung.R2,
                                tuple(risk), tuple(metas))
        if any(e.stance == "REFUTES" for e in w2plus):
            risk.append("R1: doctrinal dissent cannot overturn W1a machine evidence")
            if policy.meta_claim_depth_budget > 0:
                _meta(1)
            if metas:
                risk.append("meta-claim opened: does the W1a evidence actually cover the claim?")
        return Adjudication(claim.claim_id, "VERIFIED", divergence, Rung.R1,
                            tuple(risk), tuple(metas))

    # R2: W1b refutation without W1a — statistical signal, opens meta-claim.
    if any(e.stance == "REFUTES" for e in w1b):
        risk.append("R2: W1b refute is a signal; W1a was absent — depth budget opens meta-claim")
        _meta(1)
        return Adjudication(claim.claim_id, "INCONCLUSIVE", divergence, Rung.R2,
                            tuple(risk), tuple(metas))

    # R3: critical-class doctrinal SPLIT escalates to the human risk owner.
    if claim.critical_class in policy.criticality and divergence == "SPLIT":
        risk.append("R3: critical-class split — human risk owner must decide")
        return Adjudication(claim.claim_id, "ESCALATED", divergence, Rung.R3,
                            tuple(risk), tuple(metas))

    # R4 residual: doctrinal-only evidence — never VERIFIED on W3 alone (§4.3 rule 5).
    if w2plus and any(e.tier == "W2" for e in w2plus):
        if divergence == "SPLIT":
            risk.append("R4: doctrinal split on a non-critical claim — not escalated")
            return Adjudication(claim.claim_id, "INCONCLUSIVE", divergence, Rung.R4,
                                tuple(risk), tuple(metas))
        value = "VERIFIED" if all(e.stance == "SUPPORTS" for e in w2plus) else "REFUTED"
        risk.append("R4: doctrinal-only verdict; no machine evidence backs this claim")
        return Adjudication(claim.claim_id, value, divergence, Rung.R4,
                            tuple(risk), tuple(metas))

    risk.append("R4: no conclusive evidence — fail-safe")
    return Adjudication(claim.claim_id, "INCONCLUSIVE", divergence, Rung.R4,
                        tuple(risk), tuple(metas))
