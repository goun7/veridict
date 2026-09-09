"""Audit orchestrator (§3 flow): extract → fleet → divergence → ladder → policy → cert."""
from __future__ import annotations

import hashlib
import os
import time

from .certificate import CertificateIssuer
from .claim_extractor import ClaimExtractor
from .divergence import compute_divergence
from .jury import Jury
from .keys import KeyStore
from .ladder import adjudicate
from .ledger import Ledger
from .policy import PolicyDeclaration, PolicyEngine
from .schemas import ActorRef, TaskManifest
from .utils import canonical_json, iter_python_files, sha256_hex
from .verifiers import StaticAnalyzerVerifier, TestExecutorVerifier

ESCALATION_ROUTE = "human-risk-owner"   # §6.1: the human is the risk owner


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact_digest(root: str) -> str:
    parts = []
    for rel in iter_python_files(root):
        parts.append({"path": rel, "sha256": _hash_file(os.path.join(root, rel))})
    return sha256_hex(canonical_json(parts))


class AuditOrchestrator:
    def __init__(self, ledger: Ledger, policy: PolicyDeclaration, jury: Jury,
                 keystore: KeyStore, key_id: str) -> None:
        self.ledger = ledger
        self.policy = policy
        self.jury = jury
        self.keystore = keystore
        self.key_id = key_id

    def run(self, task: TaskManifest, disclosure_level: str = "REDACTED") -> dict:
        start = time.time()
        digest = artifact_digest(task.artifact_path)
        engine_author = ActorRef(kind="policy_engine",
                                 identity="veridict-audit", version="0.1.0")
        self.ledger.append("task.started", engine_author,
                           {"task_id": task.task_id, "mode": self.policy.mode})
        self.ledger.append("actor.output", ActorRef(kind="actor",
                           identity=task.actor_identity, version="unknown"),
                           {"artifact_digest": digest, "task_id": task.task_id})
        extractor_author = ActorRef(kind="claim_extractor",
                                    identity="veridict-extractor", version="0.1.0")
        claims = ClaimExtractor().extract(task, digest)
        for c in claims:
            self.ledger.append("claim.registered", extractor_author, c.to_dict())

        test_v, static_v = TestExecutorVerifier(), StaticAnalyzerVerifier()
        evidence_by_claim: dict[str, list] = {}
        abstentions: list[str] = []
        for c in claims:
            items: list = []
            for producer in (test_v, static_v):
                ev = producer.produce(c, task)
                if ev is not None:
                    items.append(ev)
                    self.ledger.append("evidence.recorded", ActorRef(
                        kind="verifier", identity=ev.producer["identity"],
                        version=ev.producer["version"]), ev.to_dict())
            jury_items, jury_abstained = self.jury.evaluate(c, digest)
            abstentions.extend(jury_abstained)
            for ev in jury_items:
                self.ledger.append("evidence.recorded", ActorRef(
                    kind="jury", identity=ev.producer["identity"],
                    version=ev.producer["version"]), ev.to_dict())
            items.extend(jury_items)
            evidence_by_claim[c.claim_id] = items

        for c in claims:
            div = compute_divergence(evidence_by_claim[c.claim_id],
                                     self.policy.divergence_tolerance)
            if div == "SPLIT":
                self.ledger.append("divergence.flagged", ActorRef(
                    kind="divergence_detector", identity="veridict-divergence",
                    version="0.1.0"), {"claim_id": c.claim_id, "divergence": div})

        # Meta-claims (rule R2), one level, depth-budgeted (§7.2 #2).
        adjudications = [adjudicate(c, evidence_by_claim[c.claim_id], self.policy)
                         for c in claims]
        for c, a in zip(claims, adjudications):
            for meta in a.meta_claims:
                meta_claim = ClaimExtractor().make_claim(
                    task, digest, subject=meta["subject"],
                    predicate=meta["subject"].replace(":", "-"),
                    summary=f"meta: does machine evidence cover {meta['subject']}?",
                    verifiability="DOCTRINAL", falsifiable_by=("jury",),
                    critical_class=c.critical_class)
                self.ledger.append("claim.registered", extractor_author,
                                   meta_claim.to_dict())
                jury_items, abst = self.jury.evaluate(meta_claim, digest)
                abstentions.extend(abst)
                for ev in jury_items:
                    self.ledger.append("evidence.recorded", ActorRef(
                        kind="jury", identity=ev.producer["identity"],
                        version=ev.producer["version"]), ev.to_dict())
                evidence_by_claim[meta_claim.claim_id] = jury_items
                adjudications.append(adjudicate(meta_claim, jury_items, self.policy))

        for a in adjudications:
            if a.value == "ESCALATED":
                self.ledger.append("escalation.requested", ActorRef(
                    kind="adjudicator", identity="veridict-ladder", version="0.1.0"),
                    {"claim_id": a.claim_id, "route": ESCALATION_ROUTE,
                     "dossier_summary": "see risk_notes", "risk_notes": a.risk_notes})

        engine = PolicyEngine(self.ledger)
        outcome = engine.apply(claims, evidence_by_claim, self.policy, engine_author)

        issuer = CertificateIssuer(self.ledger, self.keystore, self.key_id)
        cert = issuer.issue(
            task=task, artifact_digest=digest, policy=self.policy, claims=claims,
            adjudications=adjudications, evidence_by_claim=evidence_by_claim,
            jury_families=sorted({p.family for p in self.jury.providers}),
            disclosure_level=disclosure_level,
            scope_limits=["doctrinal jury opinions are provider-dependent"])
        report = {"abstentions": sorted(set(abstentions)),
                  "duration_seconds": round(time.time() - start, 3),
                  "flags": outcome.flags, "task_id": task.task_id}
        return {"cert": cert, "outcome": outcome, "report": report}
