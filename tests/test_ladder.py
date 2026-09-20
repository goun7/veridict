from veridict.divergence import compute_divergence
from veridict.ladder import adjudicate
from veridict.schemas import Claim, EvidenceItem

class StubPolicy:
    mode = "CERTIFICATE"
    criticality = ("payments",)
    meta_claim_depth_budget = 2
    divergence_tolerance = 1 / 3

def _claim(ver="MACHINE_CHECKABLE", crit="payments", pred="x-equals-y"):
    return Claim(claim_id="c1", task_id="t1", subject="s", predicate=pred, scope="r",
                 summary="x equals y", derived_from="digest", verifiability=ver,
                 falsifiable_by=("test_execution",), critical_class=crit)

def _ev(tier, stance, n=1):
    return [EvidenceItem(evidence_id=f"e{i}-{tier}-{stance}", claim_id="c1",
                         evidence_class="TEST_EXECUTION" if tier.startswith("W1") else "JURY_OPINION",
                         tier=tier, producer={"kind": "verifier", "identity": f"v{i}",
                                              "version": "0.1.0"},
                         artifact_ref="digest", reproducibility={"deterministic": True,
                         "rerun_recipe": {"cmd": ["pytest"]}}, stance=stance, confidence=1.0)
            for i in range(n)]

def test_r0_machine_supported_by_w1a():
    a = adjudicate(_claim(), _ev("W1a", "SUPPORTS", 2), StubPolicy())
    assert a.value == "VERIFIED" and a.rung == "R0" and a.meta_claims

def test_r1_doctrine_cannot_overturn_w1a():
    ev = _ev("W1a", "SUPPORTS", 1) + _ev("W2", "REFUTES", 1) + _ev("W2", "REFUTES", 1)
    a = adjudicate(_claim(), ev, StubPolicy())
    assert a.value == "VERIFIED" and a.rung == "R1"
    assert any("cannot overturn" in n for n in a.risk_notes)

def test_r2_w1b_refute_opens_meta_claim_not_refutation():
    ev = _ev("W1a", "SUPPORTS", 2) + _ev("W1b", "REFUTES", 1)
    a = adjudicate(_claim(crit="payments"), ev, StubPolicy())
    assert a.value == "VERIFIED" and a.rung == "R2"
    assert a.meta_claims and a.meta_claims[0]["subject"].startswith("coverage-of:")

def test_r3_critical_split_escalates():
    ev = _ev("W2", "SUPPORTS", 2) + _ev("W2", "REFUTES", 2)
    a = adjudicate(_claim(crit="payments"), ev, StubPolicy())
    assert a.value == "ESCALATED" and a.rung == "R3"

def test_r4_no_evidence_is_never_silent_pass():
    a = adjudicate(_claim(), [], StubPolicy())
    assert a.value == "INCONCLUSIVE" and a.rung == "R4"
    assert any("no evidence" in n for n in a.risk_notes)


def test_w1b_support_survives_doctrinal_dissent():
    """§5.3 rule 1: W1b outranks W2. A deterministic static SUPPORT cannot be
    turned into a REFUTED verdict by a juror's disagreement.

    This is the false-positive mechanism the real-LLM canary exposed: a 3B
    juror REFUTED 'forbidden-constructs-absent' on clean code with the
    rationale that the digest carried no information about the function —
    a refusal of the question, not a finding about the code. The static
    analyzer had SUPPORTED the same claim deterministically. Letting the
    dissent decide produced a false positive; the verdict now stands."""
    from veridict.ladder import adjudicate
    from veridict.policy import PolicyDeclaration, Thresholds
    from veridict.schemas import Claim, EvidenceItem
    w1b = EvidenceItem(evidence_id="e1", claim_id="c", evidence_class="STATIC_ANALYSIS",
                       tier="W1b", producer={}, artifact_ref="a",
                       reproducibility={}, stance="SUPPORTS", confidence=1.0,
                       rationale="no bare-except findings")
    w2 = EvidenceItem(evidence_id="e2", claim_id="c", evidence_class="JURY_OPINION",
                      tier="W2", producer={}, artifact_ref="a",
                      reproducibility={}, stance="REFUTES", confidence=0.9,
                      rationale="digest provides no information")
    claim = Claim(claim_id="c", task_id="t", subject="repo", scope="module",
                  predicate="forbidden-constructs-absent",
                  summary="no bare except introduced",
                  derived_from="policy", verifiability="MACHINE_CHECKABLE",
                  falsifiable_by=("static_analysis",), critical_class=None)
    pol = PolicyDeclaration(policy_id="p", mode="HYBRID", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    adj = adjudicate(claim, [w1b, w2], pol)
    assert adj.value == "VERIFIED", \
        "W1b SUPPORT must not be overturned by W2 doctrinal dissent"
    assert any("outranks" in r for r in adj.risk_notes), adj.risk_notes
    # W1b absent — the old behavior must still hold (W2 dissent decides)
    adj2 = adjudicate(claim, [w2], pol)
    assert adj2.value == "REFUTED", adj2.value


def test_w1b_support_survives_in_full_audit():
    """The same rule through the whole AuditOrchestrator, not just the
    ladder function in isolation."""
    from veridict.audit import AuditOrchestrator
    from veridict.jury import Jury, ScriptedProvider, Opinion
    from veridict.keys import KeyStore
    from veridict.ledger import Ledger
    from veridict.policy import PolicyDeclaration, Thresholds
    from veridict.schemas import TaskManifest
    import tempfile, os
    tmp = tempfile.mkdtemp()
    pkg = os.path.join(tmp, "pkg"); os.makedirs(pkg)
    open(os.path.join(pkg, "calc.py"), "w").write("def add(a, b):\n    return a + b\n")
    open(os.path.join(pkg, "test_calc.py"), "w").write(
        "def test_add():\n    from calc import add\n    assert add(1, 2) == 3\n")
    led = Ledger(); ks = KeyStore(led); kid = ks.generate_and_enroll("t")
    # Both jurors REFUTE every claim — the small-model behavior
    jury = Jury([
        ScriptedProvider(family="a", identity="a-1",
                         default=Opinion("REFUTES", 0.9, "digest says nothing")),
        ScriptedProvider(family="b", identity="b-1",
                         default=Opinion("REFUTES", 0.9, "digest says nothing")),
    ])
    pol = PolicyDeclaration(policy_id="t", mode="CERTIFICATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    task = TaskManifest(task_id="t1", artifact_path=pkg, actor_identity="a",
                        intent_lines=["MACHINE: add computes the sum of two numbers"],
                        criticality=(), has_existing_tests=True, pytest_args=["-q"])
    r = AuditOrchestrator(led, pol, jury, ks, kid).run(task, "REDACTED")
    # Top-level claims are all machine-backed: intent via W1a, forbidden-
    # constructs via W1b. No juror dissent may leave a TOP-LEVEL claim
    # REFUTED on provably clean code (§5.3 rule 1).
    #
    # Meta-claims are a different matter and are DELIBERATELY allowed to
    # stay REFUTED: they are DOCTRINAL coverage questions with no W1
    # evidence, opened by the ladder precisely because a juror dissented.
    # Their verdict is recorded and flagged as meta-coverage-unconfirmed,
    # not promoted into a gate block — the flag is the honest signal.
    oc = r["outcome"]
    assert not oc.blocked, "clean code must not be gated"
    # Meta-claim refusals must stay visible rather than silently deciding
    assert any("meta-coverage-unconfirmed" in f for f in oc.flags), \
        f"meta-claim refusals must stay visible in flags: {oc.flags}"
    # Every TOP-LEVEL claim (the three real ones, not coverage-of-*)
    # must be VERIFIED: each has W1 machine support and the jurors'
    # refusal to answer a coverage question cannot overturn that.
    top = [cid for cid, per in oc.per_claim.items()]
    ledgered = [e.get("payload", {}) for e in led.entries
                if e.get("entry_type") == "claim.registered"]
    top_ids = {p["claim_id"] for p in ledgered
               if not p["predicate"].startswith("coverage-of-")}
    refuted_top = [cid for cid in top_ids
                   if oc.per_claim[cid]["value"] != "VERIFIED"]
    assert not refuted_top, \
        f"top-level claims not all VERIFIED on clean code: {refuted_top}"
    print(f"verdicts: " +
          ", ".join(f"{cid[:8]}={per['value']}"
                    for cid, per in oc.per_claim.items()))
