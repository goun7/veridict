"""Task 22 (§6.3): the dossier is a VIEW over the ledger, never separate truth."""
import json

from veridict.audit import AuditOrchestrator
from veridict.dossier import (dossier_for, generate_dossier, render_markdown,
                              resolve_dossier, apply_fail_safe)
from veridict.jury import Jury, Opinion, ScriptedProvider
from veridict.keys import KeyStore
from veridict.ledger import Ledger
from veridict.ladder import Adjudication
from veridict.policy import PolicyDeclaration, Thresholds, load_policy
from veridict.schemas import Claim, EvidenceItem, TaskManifest


def _task(tmp_path,
          intent=("DOCTRINE(payments): payment totals are computed with rounding",)):
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "test_calc.py").write_text(
        "from calc import add\n\ndef test_add():\n    assert add(1, 1) == 2\n")
    return TaskManifest(task_id="dos1", artifact_path=str(tmp_path),
                        actor_identity="ai-dev", intent_lines=tuple(intent),
                        criticality=(), has_existing_tests=True, pytest_args=())


def _split_providers():
    return [ScriptedProvider(family="a", identity="a-1",
                             default=Opinion("SUPPORTS", 0.8,
                                             "totals round per doctrine"),
                             fn=lambda s: Opinion("SUPPORTS", 0.8,
                                                  "totals round per doctrine")),
            ScriptedProvider(family="b", identity="b-1",
                             default=Opinion("REFUTES", 0.9,
                                             "rounding drops cents on totals"),
                             fn=lambda s: Opinion("REFUTES", 0.9,
                                                  "rounding drops cents on totals"))]


def escalated_run(tmp_path, ledger=None, providers=None):
    """Shared escalation fixture: a critical-class doctrinal SPLIT escalates.

    Returns (orchestrator result, ledger, escalated claim_id). Imported by
    tests/test_resolution.py for the §6.1 full-turn criterion.
    """
    led = ledger if ledger is not None else Ledger()
    ks = KeyStore(led)                     # enroll into the audit ledger itself
    kid = ks.generate_and_enroll("core")
    pol = PolicyDeclaration(policy_id="pd-esc", mode="CERTIFICATE",
                            criticality=("payments",), thresholds=Thresholds(),
                            divergence_tolerance=1 / 3)
    orch = AuditOrchestrator(led, pol, Jury(providers or _split_providers()), ks, kid)
    result = orch.run(_task(tmp_path))
    cid = next(e["payload"]["claim_id"] for e in led.entries
               if e["entry_type"] == "claim.registered"
               and e["payload"]["predicate"]
               == "payment-totals-are-computed-with-rounding")
    return result, led, cid


def test_escalation_issues_dossier(tmp_path):
    result, led, cid = escalated_run(tmp_path)
    entries = [e for e in led.entries if e["entry_type"] == "dossier.issued"]
    assert len(entries) == 1
    assert entries[0]["author"]["kind"] == "adjudicator"
    d = entries[0]["payload"]
    assert d["schema_version"] == "1.0"
    assert d["claim"]["claim_id"] == cid
    assert d["claim"]["predicate"] == "payment-totals-are-computed-with-rounding"
    assert d["claim"]["verdict"] == "ESCALATED"
    assert d["claim"]["rung"] == "R3"
    assert d["claim"]["divergence"] == "SPLIT"
    # options are exactly the 4 §6.3 options, in order
    assert [o["id"] for o in d["options"]] == [
        "accept_with_risk", "demand_rerun", "narrow_claim", "reject"]
    assert all(set(o) == {"id", "label", "consequence"} for o in d["options"])
    # default names the window and the R4 fail-safe
    assert "24h" in d["default"] and "policy.fail_safe" in d["default"] \
        and "R4" in d["default"]
    assert d["response_window_hours"] == 24
    # escalation.requested is appended BEFORE the dossier
    types = [e["entry_type"] for e in led.entries]
    assert types.index("escalation.requested") < types.index("dossier.issued")


def test_dossier_summary_and_risk_frame_use_ledger_rationales(tmp_path):
    result, led, cid = escalated_run(tmp_path)
    d = dossier_for(led, cid)
    # plain-language escalation context, jargon-free
    assert "could not be settled by machine evidence alone" in d["summary_page"]
    assert "payment totals are computed with rounding" in d["summary_page"]
    # impact language from the REFUTES side's persisted rationale
    assert d["risk_frame"].startswith("If the REFUTES side is right: ")
    assert "rounding drops cents on totals" in d["risk_frame"]


def test_dossier_evidence_links_resolve(tmp_path):
    result, led, cid = escalated_run(tmp_path)
    d = dossier_for(led, cid)
    claim_ids = {e["payload"]["claim_id"] for e in led.query("claim.registered")}
    ev_ids = {e["payload"]["evidence_id"] for e in led.query("evidence.recorded")}
    assert d["evidence_links"][0] == cid
    assert len(d["evidence_links"]) == len(set(d["evidence_links"]))  # deduped
    for link in d["evidence_links"]:
        assert link in claim_ids or link in ev_ids, f"unresolvable link {link}"


def test_no_escalation_no_dossier(tmp_path):
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("core")
    providers = [ScriptedProvider(family="a", identity="a-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok")),
                 ScriptedProvider(family="b", identity="b-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok"))]
    pol = PolicyDeclaration(policy_id="pd", mode="CERTIFICATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    AuditOrchestrator(led, pol, Jury(providers), ks, kid).run(
        _task(tmp_path, intent=("DOCTRINE: add computes the sum of two numbers",)))
    assert not any(e["entry_type"] == "dossier.issued" for e in led.entries)


def test_dossier_for_latest_wins(tmp_path):
    result, led, cid = escalated_run(tmp_path)
    first = dossier_for(led, cid)
    assert first is not None
    from veridict.schemas import ActorRef
    from veridict.utils import sha256_hex
    newer = dict(first)
    newer["dossier_id"] = sha256_hex("second|" + cid)[:16]
    led.append("dossier.issued", ActorRef(kind="adjudicator",
                                          identity="veridict-ladder",
                                          version="0.2.0"), newer)
    assert dossier_for(led, cid)["dossier_id"] == newer["dossier_id"]
    assert dossier_for(led, "no-such-claim") is None


def test_render_markdown_sections(tmp_path):
    result, led, cid = escalated_run(tmp_path)
    d = dossier_for(led, cid)
    md = render_markdown(d)
    for heading in ("Summary", "Risk frame", "Options", "Default"):
        assert heading in md
    for label in ("Accept with risk note", "Demand independent rerun",
                  "Narrow or redefine the claim", "Reject the output"):
        assert label in md
    assert d["dossier_id"] in md                       # title carries the id
    assert "payment-totals-are-computed-with-rounding" in md
    for link in d["evidence_links"]:                   # bullet list of ids
        assert link in md


def test_old_policy_without_window_key_loads(tmp_path):
    raw = {"policy_id": "old", "mode": "HYBRID", "criticality": ["payments"],
           "thresholds": {"min_jury_families": 2, "min_w1_coverage": 0.8},
           "divergence_tolerance": 0.34}
    p = tmp_path / "old.json"
    p.write_text(json.dumps(raw))
    pol = load_policy(str(p))
    assert pol.response_window_hours == 24


def test_policy_roundtrip_carries_window_hours():
    pol = PolicyDeclaration(policy_id="p-w", mode="GATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3,
                            response_window_hours=72)
    assert load_policy(pol.to_dict()) == pol


# ---- generate_dossier unit contracts (branches unreachable via the fixture) ----

def _claim():
    return Claim(claim_id="c-x", task_id="t1", subject="payments",
                 predicate="payment-totals-are-computed-with-rounding",
                 scope="repo", summary="payment totals are computed with rounding",
                 derived_from="digest-1", verifiability="DOCTRINAL",
                 falsifiable_by=("jury",), critical_class="payments")


def _ev(eid, stance, rationale):
    return EvidenceItem(
        evidence_id=eid, claim_id="c-x", evidence_class="JURY_OPINION", tier="W2",
        producer={"kind": "jury", "identity": eid, "version": "0", "family": "f"},
        artifact_ref="digest-1",
        reproducibility={"deterministic": False, "rerun_recipe": None},
        stance=stance, confidence=0.9, rationale=rationale)


_ADJ = Adjudication("c-x", "ESCALATED", "SPLIT", "R3")


def _policy(**kw):
    return PolicyDeclaration(policy_id="p", mode="CERTIFICATE", criticality=("payments",),
                             thresholds=Thresholds(), divergence_tolerance=1 / 3, **kw)


def test_generate_dossier_risk_frame_dedups_rationales():
    ev = [_ev("e1", "REFUTES", "rounding drops cents"),
          _ev("e2", "REFUTES", "rounding drops cents"),
          _ev("e3", "SUPPORTS", "fine")]
    d = generate_dossier(_claim(), _ADJ, ev, Ledger(), _policy(), "digest-1")
    assert d["risk_frame"] == ("If the REFUTES side is right: "
                               "rounding drops cents")


def test_generate_dossier_risk_frame_fallback_without_refutes():
    d = generate_dossier(_claim(), _ADJ, [_ev("e4", "SUPPORTS", "fine")],
                         Ledger(), _policy(), "digest-1")
    assert d["risk_frame"] == ("If the REFUTES side is right: "
                               "the claim's failure mode is unmitigated")


def test_generate_dossier_id_is_stable_short_hash():
    d1 = generate_dossier(_claim(), _ADJ, [_ev("e1", "REFUTES", "r")],
                          Ledger(), _policy(), "digest-1")
    d2 = generate_dossier(_claim(), _ADJ, [_ev("e1", "REFUTES", "r")],
                          Ledger(), _policy(), "digest-1")
    d3 = generate_dossier(_claim(), _ADJ, [_ev("e1", "REFUTES", "r")],
                          Ledger(), _policy(), "other-digest")
    assert d1["dossier_id"] == d2["dossier_id"]
    assert len(d1["dossier_id"]) == 16 and d1["dossier_id"] != d3["dossier_id"]


def test_resolve_rejects_fabricated_dossier_id(tmp_path):
    """Audit D4: a resolution for a dossier that was never issued would
    fabricate human authority — must be rejected before any write."""
    led = Ledger()
    try:
        resolve_dossier(led, "deadbeefdeadbeef", "accept_with_risk", "gokun")
        raised = False
    except ValueError:
        raised = True
    assert raised and not led.query("escalation.resolved")


def test_fail_safe_rejects_fabricated_dossier_id():
    from veridict.schemas import ActorRef
    led = Ledger()
    try:
        apply_fail_safe(led, "deadbeefdeadbeef",
                        ActorRef(kind="system", identity="core", version="1"))
        raised = False
    except ValueError:
        raised = True
    assert raised and not led.query("policy.fail_safe")
