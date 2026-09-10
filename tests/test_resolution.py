"""Task 23 (§6.1): human decision return + R4 fail-safe — no silent pass."""
import pytest

from test_dossier import escalated_run     # shared escalation fixture

from veridict.cli import main
from veridict.dossier import apply_fail_safe, dossier_for, resolve_dossier
from veridict.ledger import Ledger
from veridict.policy import PolicyDeclaration, PolicyEngine, Thresholds
from veridict.schemas import ActorRef, Claim, EvidenceItem


def test_full_turn_split_to_dossier_to_decision(tmp_path):
    # §8 exit criterion ②: critical SPLIT → ESCALATED → dossier.issued →
    # human decision → escalation.resolved back in the ledger.
    result, led, cid = escalated_run(tmp_path)
    d = dossier_for(led, cid)
    entry = resolve_dossier(led, d["dossier_id"], "accept_with_risk",
                            decided_by="risk-owner-1",
                            risk_note="owned; ship with monitoring")
    assert entry["entry_type"] == "escalation.resolved"
    assert entry["author"] == {"kind": "human", "identity": "risk-owner-1",
                               "version": "user"}
    p = entry["payload"]
    assert p["dossier_id"] == d["dossier_id"]
    assert p["decision"] == "accept_with_risk"
    assert p["decided_by"] == "risk-owner-1"
    assert p["risk_note"] == "owned; ship with monitoring"
    assert isinstance(p["ts"], float)
    assert led.query("escalation.resolved") == [entry]


def test_invalid_decision_raises():
    led = Ledger()
    with pytest.raises(ValueError):
        resolve_dossier(led, "d-1", "maybe", decided_by="h")
    assert led.query("escalation.resolved") == []   # nothing written on reject


def test_fail_safe_entry_written():
    led = Ledger()
    entry = apply_fail_safe(led, "d-1", ActorRef(kind="system",
                                                 identity="veridict-policy",
                                                 version="0.1.0"))
    assert entry["entry_type"] == "policy.fail_safe"
    assert entry["author"]["kind"] == "system"
    assert entry["payload"]["dossier_id"] == "d-1"
    assert entry["payload"]["consequence"] == \
        "gate_stays_blocked_or_certificate_stamped_unresolved"
    assert isinstance(entry["payload"]["ts"], float)


def test_gate_stays_blocked_after_fail_safe(tmp_path):
    # R4: no silent pass. The fail-safe records the consequence; a FRESH engine
    # pass over the same ledger must still block the GATE on the unresolved
    # escalation (ESCALATED critical claim).
    result, led, cid = escalated_run(tmp_path)
    d = dossier_for(led, cid)
    apply_fail_safe(led, d["dossier_id"],
                    ActorRef(kind="system", identity="veridict-policy",
                             version="0.1.0"))
    claims = [Claim.from_dict(e["payload"]) for e in led.query("claim.registered")]
    ev_by: dict[str, list] = {}
    for e in led.query("evidence.recorded"):
        ev_by.setdefault(e["payload"]["claim_id"], []).append(
            EvidenceItem.from_dict(e["payload"]))
    pol = PolicyDeclaration(policy_id="gate-fs", mode="GATE",
                            criticality=("payments",), thresholds=Thresholds(),
                            divergence_tolerance=1 / 3)
    outcome = PolicyEngine(led).apply(claims, ev_by, pol,
                                      ActorRef(kind="policy_engine",
                                               identity="t", version="0"))
    assert outcome.blocked is True
    assert outcome.per_claim[cid]["value"] == "ESCALATED"
    assert led.query("policy.fail_safe")[-1]["payload"]["consequence"] == \
        "gate_stays_blocked_or_certificate_stamped_unresolved"


def test_cli_dossier_renders(tmp_path, capsys):
    result, led, cid = escalated_run(tmp_path)
    lp = str(tmp_path / "led.jsonl")
    led.save(lp)
    rc = main(["dossier", "--ledger", str(lp), "--claim-id", cid])
    out = capsys.readouterr()
    assert rc == 0
    assert "payment-totals-are-computed-with-rounding" in out.out
    assert "Summary" in out.out
    # --out writes the markdown to a file instead of stdout
    md_path = tmp_path / "dossier.md"
    rc2 = main(["dossier", "--ledger", str(lp), "--claim-id", cid,
                "--out", str(md_path)])
    out2 = capsys.readouterr()
    assert rc2 == 0
    assert out2.out == ""
    assert "Summary" in md_path.read_text()


def test_cli_dossier_missing_exits_1(tmp_path, capsys):
    result, led, cid = escalated_run(tmp_path)
    lp = str(tmp_path / "led.jsonl")
    led.save(lp)
    rc = main(["dossier", "--ledger", str(lp), "--claim-id", "no-such-claim"])
    out = capsys.readouterr()
    assert rc == 1
    assert "error" in out.err


def test_cli_resolve_ok_and_invalid(tmp_path, capsys):
    result, led, cid = escalated_run(tmp_path)
    lp = str(tmp_path / "led.jsonl")
    led.save(lp)
    d = dossier_for(led, cid)
    rc = main(["resolve", "--ledger", str(lp), "--dossier-id", d["dossier_id"],
               "--decision", "reject", "--decided-by", "owner", "--note", "no"])
    out = capsys.readouterr()
    assert rc == 0
    assert "reject" in out.out
    reloaded = Ledger.load(lp)
    assert [e["payload"]["decision"]
            for e in reloaded.query("escalation.resolved")] == ["reject"]
    # invalid decision → rc 1 + stderr message (main's ValueError wrapper)
    rc2 = main(["resolve", "--ledger", str(lp), "--dossier-id", d["dossier_id"],
                "--decision", "maybe", "--decided-by", "owner"])
    err = capsys.readouterr()
    assert rc2 == 1
    assert "error" in err.err
