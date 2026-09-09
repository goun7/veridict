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

    @property
    def meta_claim_depth_budget(self) -> int:
        """Ladder-facing knob; derived so thresholds stays the single owner."""
        return self.thresholds.meta_claim_depth_budget

    def to_dict(self) -> dict:
        d = asdict(self)
        d["criticality"] = list(self.criticality)
        return d


def load_policy(src) -> PolicyDeclaration:
    """Load policy from a JSON file path or a plain dict (policy-is-data)."""
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
        disclosure_level=data.get("disclosure_level", "REDACTED"))


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
        mc = [c for c in claims if c.verifiability == "MACHINE_CHECKABLE"]
        covered = [c for c in mc if any(e.tier in ("W1a", "W1b")
                                        for e in evidence_by_claim.get(c.claim_id, []))]
        coverage = (len(covered) / len(mc)) if mc else 1.0
        flags: list[str] = []
        # Per-claim verdicts are computed ONCE and reused for the blocking rule;
        # they finalize before the flags list so the decision record carries the
        # full flag set (divergence-split is a first-class flag).
        per_claim = {c.claim_id: self._per_claim(c, evidence_by_claim, declaration)
                     for c in claims}
        if coverage < declaration.thresholds.min_w1_coverage:
            flags.append("coverage-below-threshold")
        for cid, per in per_claim.items():
            if per["divergence"] == "SPLIT":
                flags.append(f"divergence-split:{cid}")
        critical_bad = any(
            per_claim[c.claim_id]["value"] in ("REFUTED", "ESCALATED", "INCONCLUSIVE")
            for c in claims if c.critical_class in declaration.criticality)
        # decision (§6: separate evidence from decision)
        blocking = (declaration.mode in ("GATE", "HYBRID")
                    and (critical_bad or flags))
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
        """Ladder-driven per-claim verdict (adjudicate duck-types the declaration)."""
        ev = evidence_by_claim.get(claim.claim_id, [])
        adjudication = adjudicate(claim, ev, declaration)
        return {"value": adjudication.value, "rung": adjudication.rung,
                "divergence": adjudication.divergence}
