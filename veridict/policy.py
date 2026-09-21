"""Policy engine (§6): policy-is-data, evidence/decision separation, 4 modes."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from .ladder import adjudicate
from .ledger import Ledger
from .schemas import ActorRef, Claim, EvidenceItem, MODES
from .utils import payload_digest


@dataclass(frozen=True)
class Thresholds:
    min_jury_families: int = 2
    divergence_tolerance: float = 1 / 3
    min_w1_coverage: float = 0.8
    meta_claim_depth_budget: int = 2


@dataclass(frozen=True)
class PolicyDeclaration:
    policy_id: str
    mode: str                       # CERTIFICATE | GATE | WATCH | HYBRID
    criticality: tuple[str, ...]
    thresholds: Thresholds
    divergence_tolerance: float
    disclosure_level: str = "REDACTED"   # LOCAL_ONLY | REDACTED | FULL
    deliberation_rounds: int = 1    # §4.4.3: revision rounds after a SPLIT; 0 disables
    response_window_hours: int = 24  # §6.1: window before the R4 fail-safe fires

    @property
    def meta_claim_depth_budget(self) -> int:
        """Ladder-facing knob; derived so thresholds stays the single owner."""
        return self.thresholds.meta_claim_depth_budget

    def to_dict(self) -> dict:
        d = asdict(self)
        d["criticality"] = list(self.criticality)
        return d


def load_policy(src) -> PolicyDeclaration:
    """Load policy from a JSON file path or a plain dict (policy-is-data).

    Tolerant of old policy files: new knobs (e.g. deliberation_rounds) fall
    back to their declared defaults when absent.
    """
    if isinstance(src, str):
        with open(src, encoding="utf-8") as f:
            data = json.loads(f.read())
    else:
        data = dict(src)
    th = Thresholds(**data["thresholds"])
    return PolicyDeclaration(
        policy_id=data["policy_id"], mode=data["mode"],
        criticality=tuple(data["criticality"]), thresholds=th,
        divergence_tolerance=data["divergence_tolerance"],
        disclosure_level=data.get("disclosure_level", "REDACTED"),
        deliberation_rounds=data.get("deliberation_rounds", 1),
        response_window_hours=data.get("response_window_hours", 24))


@dataclass(frozen=True)
class AuditOutcome:
    mode: str
    blocked: bool
    coverage: float
    per_claim: dict            # claim_id -> {value, rung, divergence}
    flags: tuple[str, ...]
    policy_id: str
    policy_digest: str


class PolicyEngine:
    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger

    def apply(self, claims: list[Claim], evidence_by_claim: dict[str, list[EvidenceItem]],
              declaration: PolicyDeclaration, actor: ActorRef) -> AuditOutcome:
        if declaration.mode not in MODES:
            raise ValueError(f"unknown mode: {declaration.mode}")
        self._mismatched: list = []
        # Coverage must count only evidence bound to the artifact the claim is
        # about (audit F7), or a shared evidence pool inflates coverage from a
        # repo the claim never touched.
        def bound_ev(claim: Claim) -> list:
            ev = evidence_by_claim.get(claim.claim_id, [])
            if claim.derived_from is None:
                return ev
            return [e for e in ev if e.artifact_ref == claim.derived_from]
        mc = [c for c in claims if c.verifiability == "MACHINE_CHECKABLE"]
        covered = [c for c in mc
                   if any(e.tier in ("W1a", "W1b") for e in bound_ev(c))]
        coverage = (len(covered) / len(mc)) if mc else 1.0
        flags: list[str] = []
        # Per-claim verdicts are computed ONCE and reused for the blocking rule;
        # they finalize before the flags list so the decision record carries the
        # full flag set (divergence-split is a first-class flag).
        per_claim = {c.claim_id: self._per_claim(c, evidence_by_claim, declaration)
                     for c in claims}
        # Evidence that did not belong to the claim's artifact was excluded
        # before adjudication (F7). Surface it: silent exclusion would hide a
        # misbound pool behind a verdict computed on less evidence than the
        # caller believes it had. Advisory everywhere — the verdict itself is
        # already honest, since the ladder saw only bound evidence.
        for cid, eid, _ref in self._mismatched:
            flags.append(f"evidence-artifact-mismatch:{cid}:{eid}")
        if coverage < declaration.thresholds.min_w1_coverage:
            flags.append("coverage-below-threshold")
        for cid, per in per_claim.items():
            if per["divergence"] == "SPLIT":
                flags.append(f"divergence-split:{cid}")
        # A MACHINE_CHECKABLE claim that stays INCONCLUSIVE leaves GATE/HYBRID
        # with zero signal — flag it so the fail-closed decision sees it
        # (WATCH never blocks on flags: unchanged).
        for c in claims:
            if (c.verifiability == "MACHINE_CHECKABLE"
                    and per_claim[c.claim_id]["value"] == "INCONCLUSIVE"):
                flags.append(f"inconclusive-unresolved:{c.claim_id}")
        critical_bad = any(
            per_claim[c.claim_id]["value"] in ("REFUTED", "ESCALATED", "INCONCLUSIVE")
            for c in claims if c.critical_class in declaration.criticality)
        # Meta-claims are DOCTRINAL coverage questions opened BY the ladder
        # (R1/R2) exactly when a juror has already dissented. Their evidence
        # is that same jury round — no W1 truth backs them. Letting a juror's
        # refusal to answer its own coverage question block the gate would
        # hand the deciding vote to the dissenter and nullify §5.3 rule 2
        # (doctrine cannot overturn W1a): the real-LLM canary produced exactly
        # this — 3B jurors REFUTED every meta-claim with 'the digest provides
        # no information', and clean code was blocked. They are recorded,
        # flagged, and shown; they do not block.
        # Meta-ness is structural, not textual. The ladder produces its own
        # coverage meta-claims as Adjudication.meta_claims, whose subject is
        # "coverage-of:{predicate}" of the claim they cover; audit.py then
        # materializes each as a real DOCTRINAL claim whose predicate is the
        # subject with ":" -> "-" (ClaimExtractor slugs it). Detecting
        # meta-ness by testing whether an OPERATOR claim's own *predicate*
        # starts with "coverage-of-" instead let the audited AI's own intent
        # wording decide its own blocking status: the predicate comes from
        # ClaimExtractor._slug(intent_line), so 'DOCTRINE: coverage of payments
        # is sound' produced predicate 'coverage-of-payments-is-sound', and a
        # refuted top-level claim then blocked=False — only the advisory flag.
        # An operator claim is a claim about the artifact, not a meta-claim of
        # anything; a refuted one must block.
        #
        # So: a claim is meta only when the ladder actually recorded a
        # coverage subject for it — either directly ("coverage-of:{predicate}")
        # or in the slug form the materialized meta-claim carries. Both the
        # exclusion from any_refuted and the advisory flag then attach to the
        # ladder's own meta-claim, never to an operator claim that merely
        # named itself similarly.
        meta_subjects = {m["subject"] for c in claims
                         for m in per_claim[c.claim_id].get("meta_claims", ())}
        slug_subjects = {s.replace(":", "-") for s in meta_subjects}
        refuted_meta = [c.claim_id for c in claims
                        if c.verifiability == "DOCTRINAL"
                        and (f"coverage-of:{c.predicate}" in meta_subjects
                             or c.predicate in slug_subjects)
                        and per_claim[c.claim_id]["value"] == "REFUTED"]
        for cid in refuted_meta:
            flags.append(f"meta-coverage-unconfirmed:{cid}")
        top_level = [c for c in claims
                     if c.verifiability != "DOCTRINAL"
                     or (f"coverage-of:{c.predicate}" not in meta_subjects
                         and c.predicate not in slug_subjects)]
        # GATE/HYBRID block on ANY refuted TOP-LEVEL claim verdict: a gate that
        # lets a refuted machine claim through is not a gate (§6 fail-closed).
        any_refuted = any(per_claim[c.claim_id]["value"] == "REFUTED"
                          for c in top_level)
        # A meta-coverage flag is advisory, not a verdict (erratum D15, second
        # half). It is appended to `flags` above for visibility, but a flag
        # that blocks IS a verdict — and this one would hand the deciding
        # vote to the very dissenter §5.3 rule 2 refuses to honor. D15
        # excluded meta-claims from `any_refuted` yet left them inside
        # `flags`, and GATE/HYBRID block on any flag at all, so the exclusion
        # only held in CERTIFICATE mode. Measured: 3/3 clean cases still
        # blocked under HYBRID with a jury that refutes everything. The
        # fail-closed surface does not shrink — a refuted TOP-LEVEL claim
        # still blocks, and critical-class claims still block; only the
        # juror's refusal to answer its own coverage question stops deciding.
        blocking_flags = [f for f in flags
                          if not f.startswith("meta-coverage-unconfirmed:")]
        # decision (§6: separate evidence from decision)
        blocking = (declaration.mode in ("GATE", "HYBRID")
                    and (critical_bad or any_refuted or blocking_flags))
        blocked = bool(blocking)
        decision_kind = ("gate.blocked" if blocked else
                         "watch.observed" if declaration.mode == "WATCH" else "policy.passed")
        digest = payload_digest(declaration.to_dict())
        self.ledger.append("policy.decision", actor, {
            "decision_kind": decision_kind,
            "policy_id": declaration.policy_id,
            "policy_digest": digest,
            "mode": declaration.mode,
            "coverage": coverage,
            "flags": flags,
            "blocked": blocked,
        })
        return AuditOutcome(mode=declaration.mode, blocked=blocked, coverage=coverage,
                            per_claim=per_claim, flags=tuple(flags),
                            policy_id=declaration.policy_id, policy_digest=digest)

    def _per_claim(self, claim: Claim, evidence_by_claim: dict, declaration: PolicyDeclaration) -> dict:
        """Ladder-driven per-claim verdict (adjudicate duck-types the declaration).

        Evidence is bound to the artifact it was produced against. The ladder
        never inspects artifact_ref/derived_from (audit F7), so without this
        check evidence from repo Y verifies a claim about repo X wherever the
        evidence pool is assembled from a shared source or a federated ledger
        — watcher_stream materializes remote evidence with no artifact check.
        Excluding the mismatched item is fail-closed: the claim then has less
        evidence, never more, and a claim left with none lands in the R4
        fail-safe rather than passing on borrowed proof.
        """
        ev = evidence_by_claim.get(claim.claim_id, [])
        if claim.derived_from is not None:
            bound = []
            for e in ev:
                if e.artifact_ref == claim.derived_from:
                    bound.append(e)
                else:
                    self._mismatched.append((claim.claim_id, e.evidence_id,
                                             e.artifact_ref))
            ev = bound
        adjudication = adjudicate(claim, ev, declaration)
        return {"value": adjudication.value, "rung": adjudication.rung,
                "divergence": adjudication.divergence,
                "meta_claims": [dict(m) for m in adjudication.meta_claims]}
