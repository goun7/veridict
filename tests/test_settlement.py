"""Settlement bridge tests — the fail-closed contract.

The bridge's whole value is that a *dropped or malformed* certificate can
never become a payment. Every test below is one way that could happen;
each must produce valid=False with a stated reason, never an exception
and never a silent pass.
"""
from __future__ import annotations

import copy
import json
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


from veridict.settlement import verify_settlement_claim


def test_claim_reconciles_against_its_own_certificate():
    """The honest round trip: build a claim, verify it against the cert."""
    sc = build_settlement_claim(CERT)
    out = verify_settlement_claim(json.loads(sc.to_json()), CERT)
    assert out["valid"] is True
    assert out["reasons"] == []
    assert out["expected_cert_id"] == "test-cert-1"


def test_forged_valid_flag_is_caught():
    """A claim edited to say valid:true over a failing cert must not pass.

    This is the attack that matters: the agent fails the work, then
    rewrites the claim. The digest is bound to the *recomputed* truth, so
    the edit is detected even before the verdict is checked.
    """
    import copy
    failing = copy.deepcopy(CERT)
    failing["claims"][0]["verdict_value"] = "REFUTED"
    sc = build_settlement_claim(failing)          # honestly says invalid
    forged = json.loads(sc.to_json())
    forged["valid"] = True                        # the lie
    out = verify_settlement_claim(forged, failing)
    assert out["valid"] is False
    assert any("does not recompute" in r for r in out["reasons"])


def test_policy_swap_after_issuance_is_caught():
    """A claim issued under a strict policy, re-presented under a loose one.

    The caller cannot relax the rules retroactively: the digest binds the
    policy that actually authorized the claim.
    """
    sc = build_settlement_claim(CERT, SettlementPolicy())
    loose = SettlementPolicy(max_risk="critical", min_jury_families=1,
                             min_claim_coverage=0.0)
    out = verify_settlement_claim(json.loads(sc.to_json()), CERT, loose)
    assert out["valid"] is False
    assert any("does not follow from" in r for r in out["reasons"])


def test_claim_from_wrong_certificate_is_caught():
    """A valid claim presented against a different cert must fail."""
    sc = build_settlement_claim(CERT)
    import copy
    other = copy.deepcopy(CERT)
    other["cert_id"] = "a-different-cert"
    out = verify_settlement_claim(json.loads(sc.to_json()), other)
    assert out["valid"] is False
    assert out["expected_cert_id"] != "a-different-cert" or out["reasons"]


def test_empty_claim_fails_closed():
    """No fields at all — a dropped or malformed claim is a refusal."""
    out = verify_settlement_claim({}, CERT)
    assert out["valid"] is False
    assert out["reasons"]
