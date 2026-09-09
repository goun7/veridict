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
    return "MAJORITY" if minority / len(doctrinal) <= tolerance else "SPLIT"
