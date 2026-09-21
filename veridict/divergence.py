"""Divergence detection (§4.1 divergence.flagged, §5.4): disagreement is information."""
from __future__ import annotations

from .schemas import EvidenceItem


def compute_divergence(evidence: list[EvidenceItem], tolerance: float = 1 / 3) -> str:
    """Classify doctrinal disagreement (W2/W3 stances only).

    Minority fraction <= tolerance -> MAJORITY, else SPLIT; W1-only -> UNANIMOUS
    (vacuous — the ladder handles W1 conflicts directly).
    """
    doctrinal = [e for e in evidence if e.tier in ("W2", "W3")]
    if not doctrinal:
        return "UNANIMOUS"
    n_sup = sum(1 for e in doctrinal if e.stance == "SUPPORTS")
    n_ref = len(doctrinal) - n_sup
    if n_sup == 0 or n_ref == 0:
        return "UNANIMOUS"
    minority = min(n_sup, n_ref)
    # Audit F6: compare in exact rational arithmetic. The ratio minority/n
    # against tolerance is a float comparison at a rounding-sensitive
    # boundary — tolerance 1/3 with n=3, minority=1 is 0.333... <= 0.333...,
    # which is True today, but the same comparison for a tolerance like 0.4
    # (n=5, minority=2) sits exactly on a representable boundary where two
    # arithmetic paths can land on opposite sides of the line. Any fixed
    # decimal scale is wrong too: 1/3 is 333/1000, which is strictly less
    # than 1/3 and flips n=3/minority=1 from MAJORITY to SPLIT.
    #
    # Cross-multiply the exact rational instead: minority/n <= p/q becomes
    # minority * q <= p * n. Fraction.limit_denominator(1000) recovers p/q
    # for every tolerance the standard contemplates (1/3, 1/2, 1/4, 2/3) and
    # for a float like 0.3333333333 yields exactly 1/3, so the computed bound
    # is the one the operator wrote, not the nearest representable decimal.
    from fractions import Fraction
    n = len(doctrinal)
    tol = Fraction(tolerance).limit_denominator(1000)
    return "MAJORITY" if minority * tol.denominator <= tol.numerator * n else "SPLIT"
