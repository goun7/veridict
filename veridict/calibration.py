"""Calibration ledger (§4.4.5): W1a-contradicted producers lose confidence.

When machine evidence (W1a) contradicts a W2/W3 producer's stance, that
producer's FUTURE confidence is discounted. Calibration touches ONLY
confidence — never tier, never stance. Entries are `calibration.updated`,
authored by the adjudicator.
"""
from __future__ import annotations

from dataclasses import replace

from .ledger import Ledger
from .schemas import ActorRef, Claim, EvidenceItem

NEGATIVE_DELTA = -0.1
REHAB_DELTA = 0.05
FACTOR_FLOOR = 0.5
FACTOR_CEILING = 1.0


def _has_negative_delta(ledger: Ledger, identity: str) -> bool:
    return any(e["payload"]["producer_identity"] == identity
               and e["payload"]["delta"] < 0
               for e in ledger.query("calibration.updated"))


def update_calibration(ledger: Ledger, actor: ActorRef, claims: list[Claim],
                       evidence_by_claim: dict) -> list[dict]:
    """Append `calibration.updated` entries; returns the appended entries.

    Per claim: the W1a majority stance is the machine truth (a W1a tie means no
    update). Each W2/W3 producer contradicting it takes delta -0.1; a producer
    agreeing with the truth despite at least one prior negative delta takes
    +0.05 (rehabilitation).
    """
    entries: list[dict] = []
    for claim in claims:
        evs = evidence_by_claim.get(claim.claim_id, [])
        w1a = [e for e in evs if e.tier == "W1a"]
        if not w1a:
            continue
        n_sup = sum(1 for e in w1a if e.stance == "SUPPORTS")
        n_ref = len(w1a) - n_sup
        if n_sup == n_ref:                       # tied machine truth: no update
            continue
        truth = "SUPPORTS" if n_sup > n_ref else "REFUTES"
        for ev in evs:
            if ev.tier not in ("W2", "W3"):
                continue
            identity = ev.producer.get("identity")
            if ev.stance != truth:
                delta, reason = NEGATIVE_DELTA, "W1a contradicted doctrine"
            elif _has_negative_delta(ledger, identity):
                delta, reason = REHAB_DELTA, "W1a agreed after correction"
            else:
                continue                          # agreement without a history: neutral
            entries.append(ledger.append("calibration.updated", actor, {
                "producer_identity": identity, "delta": delta,
                "reason": reason, "claim_id": claim.claim_id}))
    return entries


def calibration_factor(ledger: Ledger, identity: str) -> float:
    """clamp(1.0 + sum of deltas, 0.5, 1.0); unknown identity -> 1.0."""
    total = sum(e["payload"]["delta"] for e in ledger.query("calibration.updated")
                if e["payload"]["producer_identity"] == identity)
    # round(…, 10): float deltas accumulate 1e-16 dust (0.9 + 0.05); the factor
    # is a policy surface, keep it exact at policy precision.
    return round(max(FACTOR_FLOOR, min(FACTOR_CEILING, 1.0 + total)), 10)


def apply_factor(item: EvidenceItem, ledger: Ledger) -> EvidenceItem:
    """Record-time discount (§4.4.5): W2/W3 confidence × producer factor.

    Tier and stance are NEVER touched. W1a/W1b items pass through unchanged.
    """
    if item.tier not in ("W2", "W3"):
        return item
    factor = calibration_factor(ledger, item.producer.get("identity", ""))
    if factor >= FACTOR_CEILING:
        return item
    return replace(item, confidence=min(item.confidence * factor, FACTOR_CEILING))
