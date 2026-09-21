"""Dogfood self-audit tests (§7.3 m1): main cert contract + Phase 2 receipts.

dogfood() refuses re-entry (VERIDICT_DOGFOOD_ACTIVE guard), so the module
shares ONE dogfood() run via a module-scoped fixture; every assertion in this
file rides that single audit.
"""
import os
import time

import pytest

from scripts.dogfood import dogfood
from veridict.certificate import verify_certificate
from veridict.ledger import Ledger
from veridict.registry_index import load_index, validate_index


@pytest.fixture(scope="module")
def dogfood_out():
    started = time.time()
    out = dogfood()
    return out, time.time() - started


def test_dogfood_audits_itself_and_verifies(dogfood_out):
    out, elapsed = dogfood_out
    assert out["cert"]["policy_mode"] == "HYBRID"
    assert out["outcome"].blocked is False
    assert out["verification"]["valid"] is True, out["verification"]["errors"]
    # §6.5 resource contract: the audit declares and enforces its own
    # timeout_seconds, so this is a regression alarm, not a conformance check.
    # The audit runs the FULL suite (minus this file) on cold caches, and its
    # wall time moves with machine load and with how many tests exist — a
    # fixed 600s bound broke every time the suite grew past it (610.7s after
    # the watcher tests landed). Assert the contract the standard states:
    # finished well inside the 30-min budget, and did not hit the fail-safe
    # timeout path (which returns blocked=True instead).
    assert elapsed < 30 * 60, \
        f"dogfood hit {elapsed:.0f}s — over the 30-min §6.5 budget"


def test_dogfood_phase2_receipt_block(dogfood_out):
    out, _ = dogfood_out
    p2 = out["phase2"]
    assert set(p2["watchers_registered"]) == {
        "example-security", "example-cost", "example-compliance",
        "example-secret-scan", "example-license-scan",
        "example-docker-best-practices", "example-doc-sync",
        "example-sbom-spdx", "example-a11y", "example-import-weight"}
    assert p2["watcher_evidence"] >= 1        # receipt ①: blind watcher sessions
    assert p2["calibration_entries"] >= 1     # receipt ③: calibration accumulates
    assert p2["deliberation_entries"] >= 1    # the forced SPLIT ran its round
    assert p2["dossier_issued"] is True       # receipt ②: full turn
    assert p2["escalation_resolved"] is True  # receipt ②: human decision returned
    assert p2["fail_safe_used"] is False
    # T26: every shipped example passes the conformance kit (§5.5 bar)
    assert p2["conformance"] == {
        "example-security": True, "example-cost": True,
        "example-compliance": True, "example-secret-scan": True,
        "example-license-scan": True, "example-docker-best-practices": True,
        "example-doc-sync": True, "example-sbom-spdx": True,
        "example-a11y": True, "example-import-weight": True}
    assert p2["revocation_enforced"] is True  # §6.6 receipt: self-revocation enforced
    # T28: marketplace index exported from the dogfood ledger and it validates
    assert p2["marketplace_index"] is True
    assert os.path.exists(out["index_path"])
    idx_report = validate_index(load_index(out["index_path"]),
                                Ledger.load(out["ledger_path"]))
    assert idx_report["valid"] is True, idx_report["errors"]
    # the segment must leave the MAIN contract exactly as before
    assert out["cert"]["risk_level"] == "low"
    assert out["outcome"].blocked is False
    assert out["verification"]["valid"] is True


def test_dogfood_ledger_registers_watchers_and_verifies(dogfood_out):
    out, _ = dogfood_out
    led = Ledger.load(out["ledger_path"])
    registered = {e["payload"]["manifest"]["watcher_id"]
                  for e in led.query("watcher.registered")}
    assert registered == {
        "example-security", "example-cost", "example-compliance",
        "example-secret-scan", "example-license-scan",
        "example-docker-best-practices", "example-doc-sync",
        "example-sbom-spdx", "example-a11y", "example-import-weight"}
    # receipt ② full turn in the saved ledger, honestly labelled as simulated
    resolved = led.query("escalation.resolved")
    assert len(resolved) == 1
    payload = resolved[0]["payload"]
    assert payload["decision"] == "demand_rerun"
    assert payload["decided_by"] == "gokun"
    assert "simulated human decision" in payload["risk_note"]
    verification = verify_certificate(out["ledger_path"], out["cert_path"])
    assert verification["valid"] is True, verification["errors"]


def test_dogfood_second_pass_calibration_discount(dogfood_out):
    out, _ = dogfood_out
    led = Ledger.load(out["ledger_path"])
    disputed = {e["payload"]["producer_identity"]
                for e in led.query("calibration.updated")
                if e["payload"]["delta"] < 0}
    assert disputed, "calibration segment must contradict a W2/W3 producer"
    rows = [e for e in led.query("evidence.recorded")
            if e["payload"]["producer"].get("kind") == "jury"
            and e["payload"]["producer"]["identity"] in disputed
            and e["payload"]["stance"] == "REFUTES"
            and e["payload"]["tier"] == "W2"
            and abs(e["payload"]["confidence"] - 0.72) < 1e-9]
    assert rows, ("second pass must record the disputed W2 producer at "
                  "0.8 × 0.9 = 0.72 (tier/stance untouched)")
