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


def test_shipped_truth_table_matches_live_enumeration():
    """D21 regression: the committed TruthTable.lean must describe the ladder
    that ships with it.

    The receipt guards `truth_table_sha256` and `ladder_source_sha256`, but
    both describe what verify_ladder.py computes NOW — they do not check that
    the ROWDATA actually committed to the repo encodes it. e345259 changed
    the ladder (D14) without regenerating the table, and the suite stayed
    green: the receipt was regenerated, the Lean file was not, and nobody
    noticed until the Lean build was inspected and found sorryAx in the
    axiom list. This test decodes the shipped ROWDATA directly and compares
    each row against a fresh enumeration, so a stale table fails HERE
    instead of in a Lean build nobody ran.
    """
    import re
    from veridict.ladder import adjudicate
    tt = open(os.path.join(REPO, "proofs", "ladder", "TruthTable.lean")).read()
    m = re.search(r'def ROWDATA : String :=\n\s*"([^"]+)"', tt)
    assert m, "ROWDATA not found in TruthTable.lean"
    data = m.group(1)
    assert len(data) % 12 == 0, f"row width is 12, got {len(data) % 12}"
    # decodeRows: m c p b f evpack[4] v d r
    VALUE = {0: "VERIFIED", 1: "REFUTED", 2: "INCONCLUSIVE", 3: "ESCALATED"}
    DIV = {0: "UNANIMOUS", 1: "MAJORITY", 2: "SPLIT"}
    RUNG = {0: "R0", 1: "R1", 2: "R2", 3: "R3", 4: "R4"}
    n_rows = len(data) // 12
    cases = list(vl.cases())
    assert n_rows == len(cases), f"table has {n_rows} rows, cases are {len(cases)}"
    mismatches = 0
    for i, (claim, evidence, policy, split) in enumerate(cases):
        # pack order (export script line 76): m c p b f v d r evpack[4]
        row = data[i * 12:(i + 1) * 12]
        want = adjudicate(claim, evidence, policy, first_round_split=split)
        got_v = VALUE[int(row[5])]
        got_d = DIV[int(row[6])]
        got_r = RUNG[int(row[7])]
        if (want.value, want.divergence, want.rung) != (got_v, got_d, got_r):
            mismatches += 1
            if mismatches <= 3:
                print(f"row {i}: table=({got_v},{got_d},{got_r}) "
                      f"ladder=({want.value},{want.divergence},{want.rung})")
    assert mismatches == 0, (
        f"{mismatches} of {n_rows} rows in the committed TruthTable.lean do "
        "not match the shipped ladder — regenerate "
        "proofs/ladder/TruthTable.lean with scripts/export_lean_truth_table.py")
