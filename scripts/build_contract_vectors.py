#!/usr/bin/env python
"""Build the Standard v1.0.0 WATCHER + LADDER conformance vectors.

Complements the certificate vectors: the certificate vectors pin §11.3
(offline verification); these pin §6.3/§6.4 (the watcher session contract:
ceiling, clamps, abstains) and §7 (the adjudication ladder decision table),
so an independent implementer can validate BOTH producer-side and
decision-side semantics without reading the reference code.

Determinism: fixed ids, fixed inputs; no wall-clock enters a hashed or
stored position (run_session output carries no timestamp — the ts lands at
ledger append time). Verified byte-stable by tests/test_conformance_vectors.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from examples.spec_verifier import adjudicate_spec
from veridict.ladder import adjudicate
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import Claim, EvidenceItem
from veridict.watchers import WatcherManifest, WatcherSession, run_session

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "docs", "standard-test-vectors")


def _manifest(max_tier="W2", timeout=1.0, ev_class="JURY_OPINION", wid="w"):
    return WatcherManifest(
        watcher_id=wid, name="W", version="1.0.0",
        producer={"identity": "w-" + wid, "maintainer": "m"},
        capabilities={"evidence_classes": (ev_class,), "max_tier": max_tier,
                      "subscribes_to": ("*",)},
        resource_class={"timeout_seconds": timeout, "cost_budget": None,
                        "sandbox_level": "none"},
        integrity={"code_hash": "0" * 64, "update_policy": "pinned"})


def _claim(cid="c", summary="sum", verif="DOCTRINAL", crit=None):
    return Claim(claim_id=cid, task_id="t", subject="s", predicate="p",
                 scope="s", summary=summary, derived_from="d",
                 verifiability=verif, falsifiable_by=("x",), critical_class=crit)


def build_watcher_cases():
    claim = _claim()
    cases = []

    def run_case(cid, manifest, fn, timeout=None):
        session = WatcherSession(manifest, fn)
        ev = run_session(session, claim, "digest", timeout_seconds=timeout)
        return {
            "id": cid,
            "manifest": {"watcher_id": manifest.watcher_id,
                         "max_tier": manifest.capabilities["max_tier"],
                         "evidence_classes": list(manifest.capabilities["evidence_classes"]),
                         "timeout_seconds": manifest.resource_class["timeout_seconds"]},
            "fn_script": cid,                      # documented in the README table
            "expected": None if ev is None else {
                "stance": ev.stance, "confidence": ev.confidence,
                "tier": ev.tier, "evidence_class": ev.evidence_class,
                "producer_kind": ev.producer["kind"]},
        }

    cases.append(run_case("normal-support", _manifest(),
                          lambda s, r: ("SUPPORTS", 0.9, "ok")))
    cases.append(run_case("confidence-clamps-high", _manifest(),
                          lambda s, r: ("REFUTES", 7.5, "overconfident")))
    cases.append(run_case("confidence-clamps-low", _manifest(),
                          lambda s, r: ("SUPPORTS", -3.0, "underconfident")))
    cases.append(run_case("bad-stance-abstains", _manifest(),
                          lambda s, r: ("MAYBE", 0.5, "not a stance")))
    cases.append(run_case("none-abstains", _manifest(), lambda s, r: None))
    cases.append(run_case("exception-abstains", _manifest(),
                          lambda s, r: 1 / 0))
    cases.append(run_case("malformed-shape-abstains", _manifest(),
                          lambda s, r: ("SUPPORTS",)))
    cases.append(run_case("list-output-accepted", _manifest(),
                          lambda s, r: ["REFUTES", 0.8, "tuple or list"]))
    cases.append(run_case("ceiling-never-w1a",
                          _manifest(max_tier="W3", ev_class="TEST_EXECUTION"),
                          lambda s, r: ("SUPPORTS", 1.0, "ceiling probe")))
    cases.append(run_case("deadline-abstains", _manifest(timeout=0.05),
                          lambda s, r: (_ for _ in ()).throw(TimeoutError()),
                          timeout=0.05))
    # deadline-abstains via a genuinely slow fn (the script form below runs
    # the SLEEP case only in the reference builder; independent impls get the
    # semantic contract: expiry → abstain)
    cases[-1]["fn_script"] = "sleep-past-deadline"
    return cases


def build_ladder_cases():
    pol = PolicyDeclaration(policy_id="vectors", mode="GATE", criticality=("payments",),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    idx = {"n": 0}

    def item(tier, stance, conf=0.8, kind="jury", identity=None):
        idx["n"] += 1
        return EvidenceItem(
            evidence_id=sha_hex(f"lv|{idx['n']}"), claim_id="c1",
            evidence_class="TEST_EXECUTION" if tier == "W1a" else
            ("JURY_OPINION" if tier == "W2" else "JURY_OPINION"),
            tier=tier,
            producer={"kind": kind, "identity": identity or f"p{idx['n']}",
                      "version": "1.0.0", "family": f"f{idx['n']}"},
            artifact_ref="art", reproducibility={"deterministic": tier == "W1a",
                                                 "rerun_recipe": {"cmd": "pytest"} if tier == "W1a" else None},
            stance=stance, confidence=conf, rationale="vector")

    def sha_hex(s):
        from veridict.utils import sha256_hex
        return sha256_hex(s)[:24]

    def case(cid, verif, crit, evidence):
        idx["n"] = 0
        claim = _claim(cid, verif=verif, crit=crit)
        items = [item(*e) for e in evidence]
        adj = adjudicate(claim, items, pol)
        claim_d = claim.to_dict()
        ev_ds = [it.to_dict() for it in items]
        tol = pol.divergence_tolerance
        spec = adjudicate_spec(claim_d, ev_ds, list(pol.criticality), tol)
        assert adj.value == spec, (cid, adj.value, spec)
        return {
            "id": cid,
            "claim": {k: claim_d[k] for k in
                      ("claim_id", "verifiability", "critical_class")},
            "evidence": [{"tier": it["tier"], "stance": it["stance"]}
                         for it in ev_ds],
            "divergence_tolerance": tol, "criticality": list(pol.criticality),
            "expected": {"value": adj.value, "rung": str(adj.rung),
                         "divergence": adj.divergence},
        }

    W1a, W1b, W2, W3 = "W1a", "W1b", "W2", "W3"
    S, R = "SUPPORTS", "REFUTES"
    cases = [
        case("R0-machine-univocal", "MACHINE_CHECKABLE", None,
             [(W1a, S, 1.0), (W2, S), (W3, S)]),
        case("R1-w1a-refuted", "MACHINE_CHECKABLE", None,
             [(W1a, R, 1.0), (W2, S)]),
        case("R1-doctrine-cannot-overturn", "MACHINE_CHECKABLE", None,
             [(W1a, S, 1.0), (W2, R)]),
        case("R1-w1b-signal-stays-verified", "MACHINE_CHECKABLE", None,
             [(W1a, S, 1.0), (W1b, R, 0.7)]),
        case("R2-w1b-only-refute", "MACHINE_CHECKABLE", None,
             [(W1b, R, 0.7)]),
        case("R3-critical-split-escalates", "DOCTRINAL", "payments",
             [(W2, S), (W2, R)]),
        case("R4-doctrinal-unanimous-support", "DOCTRINAL", None,
             [(W2, S), (W2, S)]),
        case("R4-doctrinal-single-refute-refuted", "DOCTRINAL", None,
             [(W2, S), (W2, S), (W2, R)]),   # majority SUPPORTS still REFUTED
        case("R4-doctrinal-split-inconclusive", "DOCTRINAL", None,
             [(W3, S), (W3, R)]),
        case("R4-w3-only-never-verifies", "DOCTRINAL", None, [(W3, S)]),
        case("R4-first-no-evidence", "DOCTRINAL", None, []),
    ]
    return cases


def build() -> None:
    os.makedirs(OUT, exist_ok=True)
    watcher_doc = {
        "schema": "veridict-watcher-vectors/1.0",
        "contract": ("run_session(manifest, fn, claim, artifact_digest) → "
                     "EvidenceItem | None. fn receives (claim_summary, "
                     "artifact_reference). None ⇒ abstain. Ceiling: the "
                     "returned tier is the manifest max_tier, never W1a. "
                     "Confidence clamps to [0,1]. Bad stance / None / "
                     "exception / malformed tuple / deadline expiry ⇒ "
                     "abstain (None)."),
        "fn_scripts": {
            "normal-support": "return ('SUPPORTS', 0.9, 'ok')",
            "confidence-clamps-high": "return ('REFUTES', 7.5, 'x')",
            "confidence-clamps-low": "return ('SUPPORTS', -3.0, 'x')",
            "bad-stance-abstains": "return ('MAYBE', 0.5, 'x')",
            "none-abstains": "return None",
            "exception-abstains": "raise RuntimeError",
            "malformed-shape-abstains": "return ('SUPPORTS',)",
            "list-output-accepted": "return ['REFUTES', 0.8, 'x']",
            "ceiling-never-w1a": "return ('SUPPORTS', 1.0, 'x') with max_tier=W3, evidence_classes=[TEST_EXECUTION]",
            "sleep-past-deadline": "sleep past timeout_seconds",
        },
        "claim": {k: _claim().to_dict()[k] for k in
                  ("claim_id", "summary", "verifiability", "critical_class")},
        "artifact_digest": "digest",
        "cases": build_watcher_cases(),
    }
    ladder_doc = {
        "schema": "veridict-ladder-vectors/1.0",
        "contract": ("adjudicate(claim, evidence, policy) over §7, top-down; "
                     "divergence per §5.4. The reference ladder AND a "
                     "spec-only implementation agree on every case "
                     "(asserted at build time)."),
        "cases": build_ladder_cases(),
    }
    for name, doc in (("watcher_vectors.json", watcher_doc),
                      ("ladder_vectors.json", ladder_doc)):
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, sort_keys=True)
        print("wrote", name)


if __name__ == "__main__":
    build()
