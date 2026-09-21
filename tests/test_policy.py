import json
from veridict.policy import (PolicyEngine, PolicyDeclaration, Thresholds, load_policy)
from veridict.ledger import Ledger
from veridict.schemas import ActorRef, Claim, EvidenceItem

def _claim(cid="c1", ver="MACHINE_CHECKABLE"):
    return Claim(claim_id=cid, task_id="t", subject="s", predicate="p", scope="r",
                 summary="x", derived_from="d", verifiability=ver,
                 falsifiable_by=("test_execution",), critical_class="payments")

def _ev(cid="c1", tier="W1a", stance="SUPPORTS"):
    return EvidenceItem(evidence_id=f"e-{cid}-{tier}-{stance}", claim_id=cid,
                        evidence_class="TEST_EXECUTION" if tier.startswith("W1") else "JURY_OPINION",
                        tier=tier, producer={"kind": "verifier", "identity": "v",
                                             "version": "0.1.0"},
                        artifact_ref="d", reproducibility={"deterministic": True,
                        "rerun_recipe": {"cmd": ["pytest"]}}, stance=stance, confidence=1.0)

DECL = PolicyDeclaration(policy_id="p1", mode="GATE", criticality=("payments",),
                         thresholds=Thresholds(), divergence_tolerance=1/3)

def test_gate_blocks_on_critical_refuted():
    led = Ledger()
    out = PolicyEngine(led).apply([_claim()], {"c1": [_ev(stance="REFUTES")]}, DECL,
                                  ActorRef(kind="system", identity="core", version="0"))
    assert out.blocked is True and out.mode == "GATE"
    kinds = [e["payload"]["decision_kind"] for e in led.query("policy.decision")]
    assert kinds == ["gate.blocked"]

def test_gate_blocks_on_low_coverage():
    led = Ledger()
    out = PolicyEngine(led).apply([_claim()], {"c1": []}, DECL,
                                  ActorRef(kind="system", identity="core", version="0"))
    assert out.blocked and out.coverage == 0.0

def test_watch_never_blocks_but_records():
    led = Ledger()
    decl = PolicyDeclaration(policy_id="p2", mode="WATCH", criticality=("payments",),
                             thresholds=Thresholds(), divergence_tolerance=1/3)
    out = PolicyEngine(led).apply([_claim()], {"c1": [_ev(stance="REFUTES")]}, decl,
                                  ActorRef(kind="system", identity="core", version="0"))
    assert out.blocked is False and out.mode == "WATCH"
    kinds = [e["payload"]["decision_kind"] for e in led.query("policy.decision")]
    assert kinds == ["watch.observed"]

def test_policy_is_data_decision_recorded_with_digest():
    led = Ledger()
    PolicyEngine(led).apply([_claim()], {"c1": [_ev()]}, DECL,
                            ActorRef(kind="system", identity="core", version="0"))
    e = led.query("policy.decision")[0]
    assert e["payload"]["policy_digest"] and e["payload"]["policy_id"] == "p1"

def test_load_policy_from_json_roundtrip(tmp_path):
    d = DECL.to_dict()
    p = tmp_path / "pol.json"
    p.write_text(json.dumps(d))
    decl = load_policy(str(p))
    assert decl == DECL

def test_hybrid_blocks_like_gate():
    led = Ledger()
    decl = PolicyDeclaration(policy_id="p3", mode="HYBRID", criticality=("payments",),
                             thresholds=Thresholds(), divergence_tolerance=1/3)
    out = PolicyEngine(led).apply([_claim()], {"c1": [_ev(stance="REFUTES")]}, decl,
                                  ActorRef(kind="system", identity="core", version="0"))
    assert out.blocked is True

def test_inconclusive_machine_claim_flags_gate():
    led = Ledger()
    out = PolicyEngine(led).apply([_claim()], {"c1": [_ev(tier="W1b", stance="REFUTES")]},
                                  DECL, ActorRef(kind="system", identity="core", version="0"))
    assert out.blocked is True
    assert any(f.startswith("inconclusive-unresolved:") for f in out.flags)


def _mc_claim(cid, predicate, ver):
    """Claim is frozen — build with the right predicate directly."""
    return Claim(claim_id=cid, task_id="t", subject="intent", predicate=predicate,
                 scope="module", summary="x", derived_from=None, verifiability=ver,
                 falsifiable_by=("test_execution",), critical_class=None)


def test_meta_coverage_flag_does_not_block_gate(tmp_path):
    """D15's second half: a meta-coverage flag is advisory, not a verdict.

    The flag exists so a juror's refusal of its own coverage question stays
    visible. But a flag that blocks IS a verdict — and this one would hand
    the deciding vote to the dissenter §5.3 rule 2 refuses to honor. D15
    excluded meta-claims from `any_refuted` but left them in `flags`, and
    GATE/HYBRID block on any flag, so the exclusion only held in CERTIFICATE
    mode. Measured before the fix: 3/3 clean cases blocked under HYBRID with
    a jury that refutes everything.

    The ladder opens its own coverage meta-claim (R1/R2) when a juror has
    already dissented; its subject is "coverage-of:{predicate}" of the claim
    it covers. Meta-ness is now identified structurally — a claim is meta
    only when "coverage-of:{its predicate}" is a subject the ladder actually
    recorded — never by testing the operator claim's own predicate text.
    See the companion test below for why that distinction matters.
    """
    led = Ledger()
    engine = PolicyEngine(led)
    dec = PolicyDeclaration(policy_id="p1", mode="HYBRID", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1/3)
    top = _mc_claim("top", "payments-are-sound", "MIXED")
    meta = _mc_claim("meta", "payments-are-sound", "DOCTRINAL")
    # top-level has W1a SUPPORTS but a dissenting W2 juror (that dissent is
    # what opens the coverage meta-claim in a real run); the meta-claim gets
    # a W2 REFUTES — a jury refusing to answer its own coverage question.
    r = engine.apply([top, meta],
                     {"top": [_ev("top", "W1a", "SUPPORTS"),
                              _ev("top", "W2", "REFUTES")],
                      "meta": [_ev("meta", "W2", "REFUTES")]},
                     dec, ActorRef(kind="system", identity="a", version="1"))
    assert r.per_claim["top"]["value"] == "VERIFIED", \
        "W1a support with only doctrinal dissent still verifies (D14)"
    assert r.per_claim["top"]["meta_claims"], \
        "the dissent must open the coverage meta-claim for the covered claim"
    assert r.per_claim["meta"]["value"] == "REFUTED", \
        "the jury's refusal refutes the meta-claim"
    assert not r.blocked, "a meta-coverage refusal must not block the gate"
    assert any(f.startswith("meta-coverage-unconfirmed:") for f in r.flags), \
        "the refusal must stay visible even though it does not decide"


def test_operator_claim_named_like_a_meta_claim_still_blocks():
    """Audit F3: meta-ness must not be inferred from attacker-influenced text.

    The old rule detected meta-claims by testing whether an OPERATOR claim's
    own predicate starts with "coverage-of-". Predicates come from
    ClaimExtractor._slug(intent_line) — the audited AI's own wording — so
    'DOCTRINE: coverage of payments is sound' produced predicate
    'coverage-of-payments-is-sound', and a refuted top-level claim then had
    blocked=False: only the advisory flag, a clean end-to-end false pass.
    An operator claim is a claim ABOUT the artifact; it is not a meta-claim
    of anything, and a refuted one must block. Nothing the ladder recorded
    covers it, so no exclusion and no advisory flag is owed.
    """
    led = Ledger()
    engine = PolicyEngine(led)
    dec = PolicyDeclaration(policy_id="p1", mode="HYBRID", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1/3)
    smuggled = _mc_claim("smug", "coverage-of-payments-is-sound", "DOCTRINAL")
    r = engine.apply([smuggled],
                     {"smug": [_ev("smug", "W2", "REFUTES")]},
                     dec, ActorRef(kind="system", identity="a", version="1"))
    assert r.per_claim["smug"]["value"] == "REFUTED"
    assert r.blocked, ("a refuted operator claim whose predicate merely looks "
                       "like a meta-claim must still block the gate")
    assert not any(f.startswith("meta-coverage-unconfirmed:") for f in r.flags), \
        "no ladder meta-claim was opened, so no advisory flag is owed"


def test_fail_closed_survives_the_d15_second_half(tmp_path):
    """The fix above must not widen the fail-closed hole: a refuted
    top-level machine claim still blocks, with no meta-claim involved."""
    led = Ledger()
    engine = PolicyEngine(led)
    dec = PolicyDeclaration(policy_id="p1", mode="HYBRID", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1/3)
    top = _mc_claim("top", "existing-test-suite-passes", "MACHINE_CHECKABLE")
    r = engine.apply([top], {"top": [_ev("top", "W1a", "REFUTES")]},
                     dec, ActorRef(kind="system", identity="a", version="1"))
    assert r.per_claim["top"]["value"] == "REFUTED"
    assert r.blocked, "a refuted top-level claim must still block the gate"


def test_evidence_from_a_foreign_artifact_cannot_verify_a_claim():
    """Audit F7: the ladder never inspected artifact_ref, so evidence produced
    against artifact Y could verify a claim derived from artifact X. Both live
    in the same evidence pool whenever the pool is assembled from a shared
    source or a federated ledger — watcher_stream materializes remote evidence
    with no artifact check — so this is reachable, not hypothetical.

    Verdicts must be computed on bound evidence only. Exclusion is fail-closed:
    the claim loses the borrowed proof and lands in the R4 fail-safe rather
    than passing on it, and the exclusion is surfaced as a flag because a
    silent one would hide a misbound pool behind a verdict computed on less
    evidence than the caller believes it had.
    """
    dec = PolicyDeclaration(policy_id="p1", mode="HYBRID", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1/3)
    claim = Claim(claim_id="c1", task_id="t", subject="s", predicate="p",
                  scope="r", summary="x", derived_from="sha256-of-artifact-X",
                  verifiability="MIXED", falsifiable_by=("test_execution",),
                  critical_class="payments")
    foreign = EvidenceItem(evidence_id="e-foreign", claim_id="c1",
                           evidence_class="TEST_EXECUTION", tier="W1a",
                           producer={"kind": "verifier", "identity": "v",
                                     "version": "0.1.0"},
                           artifact_ref="sha256-of-artifact-Y",
                           reproducibility={"deterministic": True,
                           "rerun_recipe": {"cmd": ["pytest"]}},
                           stance="SUPPORTS", confidence=1.0)
    oc = PolicyEngine(Ledger()).apply([claim], {"c1": [foreign]}, dec,
                   ActorRef(kind="system", identity="a", version="1"))
    assert oc.per_claim["c1"]["value"] == "INCONCLUSIVE", \
        "a claim cannot be VERIFIED on evidence from a different artifact"
    assert oc.blocked, "an INCONCLUSIVE claim must not silently pass"
    assert any("evidence-artifact-mismatch" in f for f in oc.flags), \
        "the excluded evidence must stay visible in the decision record"


def test_evidence_from_the_same_artifact_is_unaffected():
    """F7 negative control: the binding must not reject honest evidence."""
    dec = PolicyDeclaration(policy_id="p1", mode="HYBRID", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1/3)
    claim = Claim(claim_id="c1", task_id="t", subject="s", predicate="p",
                  scope="r", summary="x", derived_from="sha256-of-artifact-X",
                  verifiability="MIXED", falsifiable_by=("test_execution",),
                  critical_class="payments")
    ev = EvidenceItem(evidence_id="e-bound", claim_id="c1",
                      evidence_class="TEST_EXECUTION", tier="W1a",
                      producer={"kind": "verifier", "identity": "v",
                                "version": "0.1.0"},
                      artifact_ref="sha256-of-artifact-X",
                      reproducibility={"deterministic": True,
                      "rerun_recipe": {"cmd": ["pytest"]}},
                      stance="SUPPORTS", confidence=1.0)
    oc = PolicyEngine(Ledger()).apply([claim], {"c1": [ev]}, dec,
                   ActorRef(kind="system", identity="a", version="1"))
    assert oc.per_claim["c1"]["value"] == "VERIFIED"
    assert not any("evidence-artifact-mismatch" in f for f in oc.flags)
