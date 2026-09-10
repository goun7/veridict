"""Contract vectors pinning (§6.3/§6.4 watcher session + §7 ladder).

The certificate vectors pin §11.3; these pin the producer-side and decision-
side semantics. Each case is executed against the REFERENCE implementation
and must reproduce the stored expected output byte-for-byte (deterministic
fields only). The ladder vectors were additionally asserted, at build time,
against the SPEC-ONLY ladder — reference and spec-only implementations agree
on the entire decision table.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.ladder import adjudicate
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import Claim, EvidenceItem
from veridict.watchers import WatcherManifest, WatcherSession, run_session

VEC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "docs", "standard-test-vectors")


def _manifest(m):
    return WatcherManifest(
        watcher_id=m["watcher_id"], name="W", version="1.0.0",
        producer={"identity": "w-" + m["watcher_id"], "maintainer": "m"},
        capabilities={"evidence_classes": tuple(m["evidence_classes"]),
                      "max_tier": m["max_tier"], "subscribes_to": ("*",)},
        resource_class={"timeout_seconds": m["timeout_seconds"],
                        "cost_budget": None, "sandbox_level": "none"},
        integrity={"code_hash": "0" * 64, "update_policy": "pinned"})


def _claim(c):
    return Claim(claim_id=c["claim_id"], task_id="t", subject="s",
                 predicate="p", scope="s", summary=c["summary"],
                 derived_from="d", verifiability=c["verifiability"],
                 falsifiable_by=("x",), critical_class=c["critical_class"])


def test_watcher_vectors():
    doc = json.load(open(os.path.join(VEC, "watcher_vectors.json")))
    claim = _claim(doc["claim"])
    scripts = {
        "normal-support": lambda s, r: ("SUPPORTS", 0.9, "ok"),
        "confidence-clamps-high": lambda s, r: ("REFUTES", 7.5, "x"),
        "confidence-clamps-low": lambda s, r: ("SUPPORTS", -3.0, "x"),
        "bad-stance-abstains": lambda s, r: ("MAYBE", 0.5, "x"),
        "none-abstains": lambda s, r: None,
        "exception-abstains": lambda s, r: 1 / 0,
        "malformed-shape-abstains": lambda s, r: ("SUPPORTS",),
        "list-output-accepted": lambda s, r: ["REFUTES", 0.8, "x"],
        "ceiling-never-w1a": lambda s, r: ("SUPPORTS", 1.0, "x"),
        "sleep-past-deadline": lambda s, r: (_ for _ in ()).throw(TimeoutError()),
    }
    for case in doc["cases"]:
        session = WatcherSession(_manifest(case["manifest"]), scripts[case["fn_script"]])
        ev = run_session(session, claim, doc["artifact_digest"],
                         timeout_seconds=case["manifest"]["timeout_seconds"])
        got = None if ev is None else {
            "stance": ev.stance, "confidence": ev.confidence, "tier": ev.tier,
            "evidence_class": ev.evidence_class,
            "producer_kind": ev.producer["kind"]}
        assert got == case["expected"], (case["id"], got, case["expected"])


def test_ladder_vectors():
    doc = json.load(open(os.path.join(VEC, "ladder_vectors.json")))
    for case in doc["cases"]:
        claim = Claim(claim_id=case["claim"]["claim_id"], task_id="t",
                      subject="s", predicate="p", scope="s", summary="s",
                      derived_from="d",
                      verifiability=case["claim"]["verifiability"],
                      falsifiable_by=("x",),
                      critical_class=case["claim"]["critical_class"])
        items = [EvidenceItem(
            evidence_id=f"vec-{case['id']}-{j}", claim_id=claim.claim_id,
            evidence_class="TEST_EXECUTION" if e["tier"] == "W1a" else "JURY_OPINION",
            tier=e["tier"],
            producer={"kind": "jury", "identity": f"p{j}", "version": "1.0.0",
                      "family": f"f{j}"}, artifact_ref="art",
            reproducibility={"deterministic": e["tier"] == "W1a",
                             "rerun_recipe": None},
            stance=e["stance"], confidence=0.8, rationale="vec")
            for j, e in enumerate(case["evidence"])]
        pol = PolicyDeclaration(policy_id="vec", mode="GATE",
                                criticality=tuple(case["criticality"]),
                                thresholds=Thresholds(),
                                divergence_tolerance=case["divergence_tolerance"])
        adj = adjudicate(claim, items, pol)
        assert adj.value == case["expected"]["value"], case["id"]
        assert str(adj.rung) == case["expected"]["rung"], case["id"]
        assert adj.divergence == case["expected"]["divergence"], case["id"]
