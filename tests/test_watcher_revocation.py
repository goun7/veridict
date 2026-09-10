"""Watcher revocation (§6.6): a registry without revocation is a CA without
CRLs. Properties: forward-looking lifecycle (latest entry wins), routing
skips revoked watchers WITHOUT recording abstention, the marketplace index
refuses to list them, and certificates anchored BEFORE the revocation still
verify (no deletion, no retroactive invalidation)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.audit import AuditOrchestrator
from veridict.canary import build_orchestrator
from veridict.certificate import verify_certificate
from veridict.claim_extractor import ClaimExtractor
from veridict.jury import Opinion, ScriptedProvider
from veridict.keys import KeyStore
from veridict.ledger import Ledger
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.registry_index import build_index, validate_index
from veridict.schemas import TaskManifest
from veridict.watchers import ManifestRegistry, WatcherManifest, WatcherSession


def _manifest(wid="rev-w"):
    return WatcherManifest(
        watcher_id=wid, name="Revocable", version="1.0.0",
        producer={"identity": "w-" + wid, "maintainer": "m"},
        capabilities={"evidence_classes": ("JURY_OPINION",), "max_tier": "W2",
                      "subscribes_to": ("*",)},
        resource_class={"timeout_seconds": 1, "cost_budget": None,
                        "sandbox_level": "none"},
        integrity={"code_hash": "0" * 64, "update_policy": "pinned"})


def _session(led, ks, kid, wid="rev-w"):
    reg = ManifestRegistry(led, ks, kid)
    m = _manifest(wid)
    reg.register(m)
    return WatcherSession(m, lambda s, r: ("SUPPORTS", 0.9, "watcher report")), reg


def _policy():
    return PolicyDeclaration(policy_id="rev", mode="HYBRID", criticality=(),
                             thresholds=Thresholds(), divergence_tolerance=1 / 3)


def _task(tmp_path, tid):
    fixture = tmp_path / f"fix-{tid}"
    fixture.mkdir(exist_ok=True)
    (fixture / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (fixture / "test_calc.py").write_text(
        "from calc import add\n\n\ndef test_add():\n    assert add(1, 1) == 2\n")
    return TaskManifest(task_id=tid, artifact_path=str(fixture),
                        actor_identity="ai-dev",
                        intent_lines=("MACHINE: add computes the sum of two numbers",),
                        criticality=(), has_existing_tests=True, pytest_args=())


def _run(led, ks, kid, session, registry, tmp_path, tid):
    pol = _policy()
    orch = AuditOrchestrator(led, pol, JuryStub(), ks, kid,
                             watchers=(session,), registry=registry)
    return orch.run(_task(tmp_path, tid))


class JuryStub:
    """A minimal deterministic jury: one provider, always SUPPORTS."""

    def __init__(self):
        self.providers = [ScriptedProvider(family="a", identity="a-1",
                                           default=Opinion("SUPPORTS", 0.8, "ok"))]

    def evaluate(self, claim, digest):
        p = self.providers[0]
        it = p._item(claim, digest, p.default) if hasattr(p, "_item") else None
        if it is None:
            from veridict.schemas import EvidenceItem
            from veridict.utils import sha256_hex
            it = EvidenceItem(
                evidence_id=sha256_hex(f"stub|{claim.claim_id}")[:24],
                claim_id=claim.claim_id, evidence_class="JURY_OPINION",
                tier="W2", producer={"kind": "jury", "identity": p.identity,
                                     "version": "0.1.0", "family": p.family},
                artifact_ref=digest,
                reproducibility={"deterministic": False, "rerun_recipe": None},
                stance=p.default.stance, confidence=p.default.confidence,
                rationale=p.default.rationale)
        return [it], []


def test_revocation_lifecycle_latest_entry_wins():
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("reg")
    session, reg = _session(led, ks, kid)
    assert ManifestRegistry.lifecycle_status(led, "rev-w") == "active"
    entry = reg.revoke("rev-w", "key compromise")
    assert entry["entry_type"] == "watcher.revoked"
    assert entry["payload"]["revoked_manifest_digest"] == \
        session.manifest.manifest_digest()
    assert ManifestRegistry.lifecycle_status(led, "rev-w") == "revoked"
    assert not ManifestRegistry.is_active(led, "rev-w")
    # re-registration AFTER revocation flips back to active (latest wins)
    reg2 = ManifestRegistry(led, ks, kid)
    reg2.register(_manifest("rev-w"))
    assert ManifestRegistry.is_active(led, "rev-w")


def test_revoked_watcher_is_not_a_participant(tmp_path):
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("reg")
    session, reg = _session(led, ks, kid)

    # pass 1: active — watcher evidence lands
    _run(led, ks, kid, session, led, tmp_path, "t1")
    before = [e for e in led.query("evidence.recorded")
              if e["payload"]["producer"]["kind"] == "watcher"]
    assert before, "active watcher must contribute evidence"

    reg.revoke("rev-w", "key compromise")

    # pass 2: revoked — no new watcher evidence, no crash, audit still runs
    result = _run(led, ks, kid, session, led, tmp_path, "t2")
    after = [e for e in led.query("evidence.recorded")
             if e["payload"]["producer"]["kind"] == "watcher"]
    assert len(after) == len(before), "revoked watcher must contribute nothing"
    assert result["outcome"].per_claim, "audit itself continues"
    # pre-revocation evidence is NOT deleted (honesty — append-only)
    assert len(before) >= 1


def test_index_excludes_revoked_and_validate_enforces_it():
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("reg")
    session, reg = _session(led, ks, kid)
    idx = build_index(led)
    assert [w["watcher_id"] for w in idx["watchers"]] == ["rev-w"]
    assert validate_index(idx, led)["valid"]

    reg.revoke("rev-w", "key compromise")
    idx2 = build_index(led)
    assert idx2["watchers"] == [], "revoked watcher must not be listed"
    assert validate_index(idx2, led)["valid"]
    # an index that still lists the revoked watcher must NOT validate
    bad = dict(idx2, watchers=idx["watchers"])
    report = validate_index(bad, led)
    assert not report["valid"]


def test_certificate_anchored_before_revocation_still_verifies(tmp_path):
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("reg")
    session, reg = _session(led, ks, kid)
    result = _run(led, ks, kid, session, led, tmp_path, "t1")
    lp = str(tmp_path / "led.jsonl")
    cp = str(tmp_path / "cert.json")
    led.save(lp)
    json.dump(result["cert"], open(cp, "w"))
    assert verify_certificate(lp, cp)["valid"]
    # revoke AFTER issuance — the anchored prefix is untouched
    reg.revoke("rev-w", "key compromise")
    led.save(lp)
    assert verify_certificate(lp, cp)["valid"], \
        "revocation is forward-looking; anchored certificates stay valid"
