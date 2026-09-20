"""Schema + end-to-end fuzz (P4-T7). Seeded, zero-dependency properties:

1. EvidenceItem roundtrip is a fixed point for every legal field combination.
2. A RANDOM audit (random fixture, random claims) saved and reloaded must
   verify offline — and the SPEC-ONLY verifier (written from the standard
   alone) must agree with the reference on the verdict, per random input.
   This is cross-implementation parity as a fuzz property, not a fixed case.
"""
import json
import os
import random
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "examples"))

from examples.spec_verifier import verify_certificate as spec_verify
from veridict.certificate import verify_certificate as ref_verify
from veridict.claim_extractor import ClaimExtractor
from veridict.jury import Opinion, ScriptedProvider
from veridict.keys import KeyStore
from veridict.ladder import adjudicate
from veridict.ledger import Ledger
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import ActorRef, EVIDENCE_CLASSES, EvidenceItem, TaskManifest
from veridict.utils import sha256_hex

STANCES = ("SUPPORTS", "REFUTES", "ABSTAIN")
TIERS = ("W1b", "W2", "W3")
KINDS = ("verifier", "jury", "watcher", "adjudicator")


def _random_item(rng, i):
    stance = rng.choice(STANCES)
    conf = round(rng.uniform(0.1, 1.0), 2)
    fam = f"fam-{rng.randrange(3)}"
    item = EvidenceItem(
        evidence_id=sha256_hex(f"rnd|{i}")[:24], claim_id=f"claim-{rng.randrange(4)}",
        evidence_class=rng.choice(sorted(EVIDENCE_CLASSES)), tier=rng.choice(TIERS),
        producer={"kind": rng.choice(KINDS), "identity": f"p-{i}",
                  "version": f"{rng.randrange(3)}.{rng.randrange(9)}.0",
                  "family": fam},
        artifact_ref=f"art-{rng.randrange(5)}",
        reproducibility={"deterministic": rng.random() < 0.5,
                         "rerun_recipe": {"cmd": "pytest -q"} if rng.random() < 0.5 else None},
        stance=stance, confidence=conf, rationale=r"rationale ✓ with unicode — éè")
    return item


def test_evidence_schema_roundtrip_fixed_point():
    rng = random.Random(4242)
    for i in range(200):
        it = _random_item(rng, i)
        d = it.to_dict()
        again = EvidenceItem.from_dict(d)
        assert again.to_dict() == d, f"iteration {i}: schema roundtrip drift"
        # evidence_id is content-derived from the salted preimage — stable
        assert again.evidence_id == it.evidence_id


def test_random_audits_verify_cross_implementation(tmp_path):
    rng = random.Random(9001)
    for i in range(12):
        led = Ledger()
        ks = KeyStore(led)
        kid = ks.generate_and_enroll("fuzz")
        pol = PolicyDeclaration(policy_id="fuzz", mode="GATE", criticality=(),
                                thresholds=Thresholds(), divergence_tolerance=1 / 3)
        task = TaskManifest(task_id=f"fuzz-{i}", artifact_path="/nonexistent",
                            actor_identity="ai-dev",
                            intent_lines=("MACHINE: add computes the sum of two numbers",),
                            criticality=(), has_existing_tests=True, pytest_args=())
        claim = ClaimExtractor().extract(task, f"art-{i}")[0]
        led.append("claim.registered", SYSTEM_AUTHOR := ActorRef(
            kind="system", identity="veridict-core", version="0.1.0"),
            claim.to_dict())
        n_items = rng.randrange(1, 4)
        items = []
        for j in range(n_items):
            # W1a is reserved to built-in verifiers — fuzz juries stay W1b+ (§5.3)
            base = _random_item(rng, i * 10 + j)
            item = EvidenceItem(
                evidence_id=base.evidence_id, claim_id=claim.claim_id,
                evidence_class="JURY_OPINION", tier=rng.choice(("W2", "W3")),
                producer=base.producer, artifact_ref=f"art-{i}",
                reproducibility=base.reproducibility, stance=base.stance,
                confidence=base.confidence, rationale=base.rationale)
            items.append(item)
            led.append("evidence.recorded",
                       ActorRef(kind=item.producer["kind"],
                                identity=item.producer["identity"],
                                version=item.producer["version"]),
                       item.to_dict())
        adj = adjudicate(claim, items, pol)
        # D19: verifier reconciles policy_ref against the ledger's recorded policy
        __import__("veridict.policy", fromlist=["PolicyEngine"]).PolicyEngine(
            led).apply([claim], {claim.claim_id: items}, pol,
                       ActorRef(kind="system", identity="fuzz", version="1"))
        cert = __import__("veridict.certificate", fromlist=["CertificateIssuer"]) \
            .CertificateIssuer(led, ks, kid).issue(
                task=task, artifact_digest=f"art-{i}", policy=pol,
                claims=[claim], adjudications=[adj],
                evidence_by_claim={claim.claim_id: items}, jury_families=[],
                disclosure_level="REDACTED",
                scope_limits=["claim coverage is heuristic, not exhaustive"])
        lp = str(tmp_path / f"led{i}.jsonl")
        led.save(lp)
        cp = str(tmp_path / f"cert{i}.json")
        json.dump(cert, open(cp, "w"))
        ref = ref_verify(lp, cp)
        spec = spec_verify(lp, cp)
        assert ref == spec, (i, ref, spec)
        # the ledger itself must replay clean after save/load
        reloaded = Ledger.load(lp)
        ok, msg = reloaded.verify_chain()
        assert ok, (i, msg)
