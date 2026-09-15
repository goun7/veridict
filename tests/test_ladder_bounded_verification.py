"""The bounded-exhaustive ladder verification is a CI-gated receipt.

Re-runs the FULL enumeration (28,080 cases, ~1.5s) and locks the truth-
table digest: any behavioral change to veridict/ladder.py anywhere in the
space fails here until the receipt is consciously regenerated — the
regeneration itself is then a reviewed, dated, source-hashed event.
"""
import importlib.util
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

_spec = importlib.util.spec_from_file_location(
    "verify_ladder", os.path.join(REPO, "scripts", "verify_ladder.py"))
vl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vl)


def test_full_enumeration_passes_and_matches_committed_receipt(tmp_path):
    out = str(tmp_path / "receipt.json")
    rc = vl.main([out])
    fresh = json.load(open(out))
    committed = json.load(open(os.path.join(
        REPO, "docs", "receipts-ladder-verification.json")))
    assert rc == 0 and fresh["all_invariants_pass"]
    assert fresh["truth_table_sha256"] == committed["truth_table_sha256"], \
        "ladder behavior changed — regenerate the receipt deliberately"
    assert fresh["ladder_source_sha256"] == committed["ladder_source_sha256"], \
        "ladder source drifted without receipt regeneration"


def test_tampering_ladder_input_space_is_detected(monkeypatch):
    """Meta-check: the enumeration is actually sensitive — widen what R0
    accepts and the invariants must scream (no vacuous green suite)."""
    import veridict.ladder as L
    real = L.adjudicate

    def broken(claim, evidence, policy, first_round_split=False):
        adj = real(claim, evidence, policy, first_round_split)
        if adj.value == "INCONCLUSIVE" and not evidence:
            return L.Adjudication(adj.claim_id, "VERIFIED", adj.divergence,
                                  adj.rung, adj.risk_notes, adj.meta_claims)
        return adj

    monkeypatch.setattr(vl, "adjudicate", broken)
    failures = 0
    for i, (claim, evidence, policy, split) in enumerate(vl.cases()):
        if i % 37:                      # sample the space, keep it snappy
            continue
        adj = broken(claim, evidence, policy, split)
        bad = vl.check(i, claim, evidence, policy, split, adj)
        if "I1 fail-safe-empty" in bad or "I2 no-silent-pass" in bad:
            failures += 1
    assert failures, "the invariant checks cannot see a silent-pass bug"
