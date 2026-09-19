"""Settlement bridge tests — the fail-closed contract.

The bridge's whole value is that a *dropped or malformed* certificate can
never become a payment. Every test below is one way that could happen;
each must produce valid=False with a stated reason, never an exception
and never a silent pass.
"""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.settlement import (SettlementPolicy, build_settlement_claim)

CERT = {
    "cert_id": "test-cert-1",
    "subject": {"task_id": "task-1", "artifact_digest": "abc123"},
    "claims": [
        {"claim_id": "c1", "verdict_value": "VERIFIED", "divergence": "UNANIMOUS"},
        {"claim_id": "c2", "verdict_value": "VERIFIED", "divergence": "UNANIMOUS"},
    ],
    "jury_composition": {"families": ["model-a", "model-b"]},
    "risk_level": "low",
}


def test_clean_certificate_authorizes_release():
    sc = build_settlement_claim(CERT)
    assert sc.valid is True
    assert sc.accepted_claims == 2 and sc.total_claims == 2
    assert sc.jury_families == ["model-a", "model-b"]


def test_refuted_claim_blocks_release():
    """One REFUTED claim ⇒ coverage below 1.0 ⇒ no release."""
    import copy
    c = copy.deepcopy(CERT)
    c["claims"][1]["verdict_value"] = "REFUTED"
    sc = build_settlement_claim(c)
    assert sc.valid is False
    assert any("coverage" in r for r in sc.reasons)


def test_single_family_jury_blocks_release():
    """§5.2: one family is a model reviewing its own output."""
    import copy
    c = copy.deepcopy(CERT)
    c["jury_composition"] = {"families": ["only-one"]}
    sc = build_settlement_claim(c)
    assert sc.valid is False
    assert any("self-preference" in r for r in sc.reasons)


def test_elevated_risk_blocks_release():
    import copy
    c = copy.deepcopy(CERT)
    c["risk_level"] = "medium"
    sc = build_settlement_claim(c)
    assert sc.valid is False
    assert any("risk" in r for r in sc.reasons)


def test_empty_certificate_fails_closed():
    """No claims at all — the refusal must be explicit, never an exception."""
    sc = build_settlement_claim({})
    assert sc.valid is False
    assert sc.reasons


def test_missing_risk_assumed_worst():
    """Unknown risk field defaults to the most permissive-rejecting value,
    not to a silent accept."""
    import copy
    c = copy.deepcopy(CERT)
    del c["risk_level"]
    sc = build_settlement_claim(c)
    assert sc.valid is False
    assert any("risk" in r for r in sc.reasons)


def test_policy_digest_is_bound_into_claim():
    """The policy that authorized release is part of the claim digest, so
    it cannot be swapped for a looser one after the fact."""
    sc = build_settlement_claim(CERT, SettlementPolicy())
    assert sc.policy_digest
    assert sc.claim_digest
    # changing the policy changes the digest — the binding is real
    other = build_settlement_claim(CERT, SettlementPolicy(max_risk="high"))
    assert other.policy_digest != sc.policy_digest
    assert other.claim_digest != sc.claim_digest


def test_claim_is_json_serializable_and_stable():
    sc = build_settlement_claim(CERT)
    first = sc.to_json()
    assert sc.to_json() == first, "serialization must be stable"


def test_stricter_policy_can_reject_what_default_accepts():
    """A high-coverage certificate still fails a policy demanding 2 families
    when only one is present — the policy is the caller's, not ours."""
    import copy
    c = copy.deepcopy(CERT)
    c["jury_composition"] = {"families": ["only-one"]}
    sc = build_settlement_claim(c, SettlementPolicy(min_jury_families=2))
    assert sc.valid is False
