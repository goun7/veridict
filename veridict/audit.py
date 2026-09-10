"""Audit orchestrator (§3 flow): extract → fleet → divergence → ladder → policy → cert."""
from __future__ import annotations

import hashlib
import os
import time

from .calibration import apply_factor, update_calibration
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
from .watchers import run_session

ESCALATION_ROUTE = "human-risk-owner"   # §6.1: the human is the risk owner

# §4.4.5/§4.4.3 adjudicator author (calibration + deliberation round records).
ADJUDICATOR_AUTHOR = ActorRef(kind="adjudicator", identity="veridict-ladder",
                              version="0.2.0")


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
                 keystore: KeyStore, key_id: str, watchers: tuple = ()) -> None:
        self.ledger = ledger
        self.policy = policy
        self.jury = jury
        self.keystore = keystore
        self.key_id = key_id
        self.watchers = tuple(watchers)

    def _record(self, ev, author_kind: str) -> None:
        """Record evidence with the producer's calibration factor applied at
        record time (§4.4.5): W2/W3 confidence is discounted, tier/stance are
        byte-identical."""
        ev = apply_factor(ev, self.ledger)
        self.ledger.append("evidence.recorded", ActorRef(
            kind=author_kind, identity=ev.producer["identity"],
            version=ev.producer["version"]), ev.to_dict())

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
                    self._record(ev, "verifier")
                    items.append(ev)
            jury_items, jury_abstained = self.jury.evaluate(c, digest)
            abstentions.extend(jury_abstained)
            for ev in jury_items:
                self._record(ev, "jury")
            items.extend(jury_items)
            # Watcher routing (§5.3): third-party producers join the same
            # per-claim evidence set. TOP-LEVEL claims only — meta-claims are
            # internal depth-budget checks and get no watcher routing in v0.
            for session in self.watchers:
                if not session.matches(c):
                    continue
                watcher_ev = run_session(session, c, digest,
                                         artifact_path=task.artifact_path)
                if watcher_ev is None:
                    abstentions.append(session.manifest.watcher_id)
                    continue
                self._record(watcher_ev, "watcher")
                items.append(watcher_ev)
            evidence_by_claim[c.claim_id] = items

        # Divergence + deliberation (§4.4.3): a first-round SPLIT is flagged
        # (never hidden), then — policy permitting — ONE cross-visible jury
        # revision round runs. Watcher evidence is exempt from deliberation
        # (§4.4: it is the jury's mechanism) but joins the post-divergence.
        deliberated: set[str] = set()
        for c in claims:
            div = compute_divergence(evidence_by_claim[c.claim_id],
                                     self.policy.divergence_tolerance)
            if div != "SPLIT":
                continue
            self.ledger.append("divergence.flagged", ActorRef(
                kind="divergence_detector", identity="veridict-divergence",
                version="0.1.0"), {"claim_id": c.claim_id, "divergence": div})
            if self.policy.deliberation_rounds < 1:
                continue
            jury_first = [i for i in evidence_by_claim[c.claim_id]
                          if i.producer["kind"] == "jury"]
            if not jury_first:
                continue
            revised_items, delib_abst = self.jury.deliberate(
                c, digest, jury_first, self.policy.divergence_tolerance)
            abstentions.extend(delib_abst)
            for ev in revised_items:
                self._record(ev, "jury")
            items = [i for i in evidence_by_claim[c.claim_id]
                     if i.producer["kind"] != "jury"] + revised_items
            evidence_by_claim[c.claim_id] = items
            self.ledger.append("deliberation.rounded", ADJUDICATOR_AUTHOR, {
                "claim_id": c.claim_id,
                "first_round": [{"evidence_id": e.evidence_id, "stance": e.stance}
                                for e in jury_first],
                "revised": [{"evidence_id": e.evidence_id, "stance": e.stance}
                            for e in revised_items],
                "consensus": compute_divergence(items,
                                                self.policy.divergence_tolerance)})
            deliberated.add(c.claim_id)

        # Meta-claims (rule R2), one level, depth-budgeted (§7.2 #2).
        adjudications = [adjudicate(c, evidence_by_claim[c.claim_id], self.policy,
                                    first_round_split=c.claim_id in deliberated)
                         for c in claims]
        meta_claims: list = []
        for c, a in zip(claims, adjudications):
            for meta in a.meta_claims:
                meta_claim = ClaimExtractor().make_claim(
                    task, digest, subject=meta["subject"],
                    predicate=meta["subject"].replace(":", "-"),
                    summary=f"meta: does machine evidence cover {meta['subject']}?",
                    verifiability="DOCTRINAL", falsifiable_by=("jury",),
                    critical_class=c.critical_class)
                meta_claims.append(meta_claim)
                self.ledger.append("claim.registered", extractor_author,
                                   meta_claim.to_dict())
                jury_items, abst = self.jury.evaluate(meta_claim, digest)
                abstentions.extend(abst)
                for ev in jury_items:
                    self._record(ev, "jury")
                evidence_by_claim[meta_claim.claim_id] = jury_items
                adjudications.append(adjudicate(meta_claim, jury_items, self.policy))

        # Calibration (§4.4.5): once per run, AFTER adjudications — W1a machine
        # truth discounts contradicted W2/W3 producers' FUTURE confidence.
        # Meta-claims excluded: their evidence is the same top-level jury round.
        update_calibration(self.ledger, ADJUDICATOR_AUTHOR, claims, evidence_by_claim)

        for a in adjudications:
            if a.value == "ESCALATED":
                self.ledger.append("escalation.requested", ActorRef(
                    kind="adjudicator", identity="veridict-ladder", version="0.1.0"),
                    {"claim_id": a.claim_id, "route": ESCALATION_ROUTE,
                     "dossier_summary": "see risk_notes", "risk_notes": a.risk_notes})

        engine = PolicyEngine(self.ledger)
        # Meta-claims are adjudicated + ledgered, so they must also reach the
        # policy engine and the certificate — a REFUTED meta-claim that never
        # reaches GATE is a silent fail-open (§6 fail-closed).
        outcome = engine.apply(claims + meta_claims, evidence_by_claim,
                               self.policy, engine_author)

        issuer = CertificateIssuer(self.ledger, self.keystore, self.key_id)
        cert = issuer.issue(
            task=task, artifact_digest=digest, policy=self.policy,
            claims=claims + meta_claims,
            adjudications=adjudications, evidence_by_claim=evidence_by_claim,
            jury_families=sorted({p.family for p in self.jury.providers}),
            disclosure_level=disclosure_level,
            scope_limits=["doctrinal jury opinions are provider-dependent"])
        report = {"abstentions": sorted(set(abstentions)),
                  "duration_seconds": round(time.time() - start, 3),
                  "flags": outcome.flags, "task_id": task.task_id}
        return {"cert": cert, "outcome": outcome, "report": report}
