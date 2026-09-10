import json

from veridict.audit import AuditOrchestrator
from veridict.jury import Jury, Opinion, ScriptedProvider
from veridict.ledger import Ledger
from veridict.keys import KeyStore
from veridict.policy import PolicyDeclaration, Thresholds, load_policy
from veridict.schemas import TaskManifest


def _task(tmp_path, intent=("DOCTRINE: add computes the sum of two numbers",)):
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "test_calc.py").write_text(
        "from calc import add\n\ndef test_add():\n    assert add(1, 1) == 2\n")
    return TaskManifest(task_id="td1", artifact_path=str(tmp_path),
                        actor_identity="ai-dev", intent_lines=tuple(intent),
                        criticality=(), has_existing_tests=True, pytest_args=())


def _orch(ledger, providers=None, **policy_kwargs):
    ks = KeyStore(ledger)            # enroll into the AUDIT ledger: offline
    kid = ks.generate_and_enroll("core")   # verify needs key.enrolled entries
    if providers is None:
        providers = [ScriptedProvider(family="a", identity="a-1",
                                      default=Opinion("SUPPORTS", 0.8, "ok")),
                     ScriptedProvider(family="b", identity="b-1",
                                      default=Opinion("SUPPORTS", 0.8, "ok"))]
    kw = {"criticality": (), **policy_kwargs}
    pol = PolicyDeclaration(policy_id="pd", mode="CERTIFICATE",
                            thresholds=Thresholds(), divergence_tolerance=1 / 3,
                            **kw)
    return AuditOrchestrator(ledger, pol, Jury(providers), ks, kid)


def test_verify_certificate_replay_matches_post_deliberation_verdict(tmp_path):
    # §7.3 m3 parity: replay recomputes verdicts from LEDGER evidence; with the
    # first round recorded, replay must land on the post-deliberation verdict.
    def b_revise(opinions):
        return Opinion("SUPPORTS", 0.8, "convinced by co-reviewer")

    led = Ledger()
    result = _orch(led, providers=_split_providers(b_revise)).run(_task(tmp_path))
    cid = _intent_cid(led)
    assert result["outcome"].per_claim[cid]["divergence"] == "UNANIMOUS"
    cert_claims = {c["claim_id"]: c["verdict_value"] for c in result["cert"]["claims"]}
    from veridict.certificate import verify_certificate
    import tempfile, os
    with tempfile.TemporaryDirectory() as td:
        lp, cp = os.path.join(td, "led.jsonl"), os.path.join(td, "cert.json")
        led.save(lp)
        with open(cp, "w") as f:
            json.dump(result["cert"], f)
        v = verify_certificate(lp, cp)
    assert v["valid"] is True, v["errors"]


def _split_providers(b_revise=None):
    return [ScriptedProvider(family="a", identity="a-1",
                             default=Opinion("SUPPORTS", 0.8, "ok"),
                             fn=lambda s: Opinion("SUPPORTS", 0.8, "ok")),
            ScriptedProvider(family="b", identity="b-1",
                             default=Opinion("REFUTES", 0.9, "doubt"),
                             fn=lambda s: Opinion("REFUTES", 0.9, "doubt"),
                             revise=b_revise)]


def _intent_cid(led):
    return next(e["payload"]["claim_id"] for e in led.entries
                if e["entry_type"] == "claim.registered"
                and e["payload"]["predicate"] == "add-computes-the-sum-of-two-numbers")


def test_split_triggers_deliberation_and_records_round(tmp_path):
    seen = {}

    def b_revise(opinions):
        seen["opinions"] = opinions
        return Opinion("SUPPORTS", 0.8, "convinced by co-reviewer")

    led = Ledger()
    result = _orch(led, providers=_split_providers(b_revise)).run(_task(tmp_path))
    cid = _intent_cid(led)
    rounds = [e for e in led.entries if e["entry_type"] == "deliberation.rounded"
              and e["payload"]["claim_id"] == cid]
    assert rounds, "split must open a deliberation round"
    r = rounds[0]
    assert r["author"]["kind"] == "adjudicator"
    assert [x["stance"] for x in r["payload"]["first_round"]] == ["SUPPORTS", "REFUTES"]
    assert [x["stance"] for x in r["payload"]["revised"]] == ["SUPPORTS", "SUPPORTS"]
    assert r["payload"]["consensus"] == "UNANIMOUS"
    # cross-visible packet: b saw only a's first-round opinion (self excluded)
    assert [o["identity"] for o in seen["opinions"]] == ["a-1"]
    # first-round items stay in the ledger; b's SECOND item is the revised SUPPORTS one
    b_rows = [e["payload"] for e in led.entries if e["entry_type"] == "evidence.recorded"
              and e["payload"]["producer"].get("identity") == "b-1"
              and e["payload"]["claim_id"] == cid]
    assert [p["stance"] for p in b_rows] == ["REFUTES", "SUPPORTS"]
    # adjudication uses POST-deliberation items: consensus is UNANIMOUS
    final = result["outcome"].per_claim[cid]
    assert final["divergence"] == "UNANIMOUS"
    assert final["value"] == "VERIFIED"
    # the first-round split is never hidden
    assert any(e["entry_type"] == "divergence.flagged" for e in led.entries)


def test_no_split_no_deliberation(tmp_path):
    led = Ledger()
    _orch(led).run(_task(tmp_path))
    assert not any(e["entry_type"] == "deliberation.rounded" for e in led.entries)


def test_persistent_split_after_deliberation_keeps_risk_note(tmp_path):
    # providers keep their first-round stances (no revise hook) — the split persists
    intent = ("DOCTRINE(payments): payment totals are computed with rounding",)
    led = Ledger()
    result = _orch(led, providers=_split_providers(),
                   criticality=("payments",)).run(_task(tmp_path, intent))
    cid = next(e["payload"]["claim_id"] for e in led.entries
               if e["entry_type"] == "claim.registered"
               and e["payload"]["predicate"] == "payment-totals-are-computed-with-rounding")
    rounds = [e for e in led.entries if e["entry_type"] == "deliberation.rounded"
              and e["payload"]["claim_id"] == cid]
    assert rounds and rounds[0]["payload"]["consensus"] == "SPLIT"
    final = result["outcome"].per_claim[cid]
    assert final["value"] == "ESCALATED" and final["divergence"] == "SPLIT"
    esc = [e for e in led.entries if e["entry_type"] == "escalation.requested"]
    assert esc and any(
        note.startswith("first-round split; post-deliberation consensus")
        for note in esc[0]["payload"]["risk_notes"])


def test_zero_deliberation_rounds_disables(tmp_path):
    led = Ledger()
    result = _orch(led, providers=_split_providers(), deliberation_rounds=0).run(
        _task(tmp_path))
    assert not any(e["entry_type"] == "deliberation.rounded" for e in led.entries)
    cid = _intent_cid(led)
    final = result["outcome"].per_claim[cid]
    assert final["divergence"] == "SPLIT" and final["value"] == "INCONCLUSIVE"


def test_old_policy_without_key_still_loads(tmp_path):
    raw = {"policy_id": "old", "mode": "HYBRID", "criticality": ["payments"],
           "thresholds": {"min_jury_families": 2, "min_w1_coverage": 0.8},
           "divergence_tolerance": 0.34}
    p = tmp_path / "old.json"
    p.write_text(json.dumps(raw))
    pol = load_policy(str(p))
    assert pol.deliberation_rounds == 1


def test_policy_roundtrip_carries_deliberation_rounds():
    pol = PolicyDeclaration(policy_id="p-new", mode="GATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3,
                            deliberation_rounds=2)
    assert load_policy(pol.to_dict()) == pol


def test_verify_ignores_post_checkpoint_deliberation_entries(tmp_path):
    """D4 (audit round 4): replay-exclusion of superseded first-round items must
    be bound to the checkpoint the cert anchors to. A post-issuance fake
    deliberation.rounded entry that 'supersedes' freshly appended REFUTES
    evidence must NOT make the tampered ledger verify clean."""
    import os

    from veridict.certificate import verify_certificate
    from veridict.schemas import ActorRef
    from veridict.utils import sha256_hex

    led = Ledger()
    result = _orch(led).run(_task(tmp_path))
    cid = _intent_cid(led)
    fake_ev = {"evidence_id": sha256_hex("atk|fake")[:24], "claim_id": cid,
               "evidence_class": "JURY_OPINION", "tier": "W2",
               "producer": {"kind": "jury", "identity": "evil-1", "version": "0",
                            "family": "evil"},
               "artifact_ref": "digest",
               "reproducibility": {"deterministic": False, "rerun_recipe": None},
               "stance": "REFUTES", "confidence": 0.99}
    led.append("evidence.recorded",
               ActorRef(kind="jury", identity="evil-1", version="0"), fake_ev)
    led.append("deliberation.rounded",
               ActorRef(kind="adjudicator", identity="veridict-ladder",
                        version="0.2.0"),
               {"claim_id": cid,
                "first_round": [{"evidence_id": fake_ev["evidence_id"],
                                 "stance": "REFUTES"}],
                "revised": [], "consensus": "UNANIMOUS"})
    lp, cp = os.path.join(tmp_path, "led.jsonl"), os.path.join(tmp_path, "cert.json")
    led.save(lp)
    with open(cp, "w") as f:
        json.dump(result["cert"], f)
    report = verify_certificate(lp, cp)
    assert report["valid"] is False, report
    assert report["verdicts_match"] is False
