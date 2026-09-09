"""Core data contracts (§4.2). Every contract carries schema_version."""
from __future__ import annotations

from dataclasses import asdict, dataclass

SCHEMA_VERSION = "1.0.0"

VERIFIABILITY = ("MACHINE_CHECKABLE", "DOCTRINAL", "MIXED")
TIERS = ("W1a", "W1b", "W2", "W3")
TIER_RANK = {"W1a": 3, "W1b": 2, "W2": 1, "W3": 0}  # rule R1: strict ordering
STANCES = ("SUPPORTS", "REFUTES")
EVIDENCE_CLASSES = ("TEST_EXECUTION", "REPRODUCIBLE_RUN", "FORMAL_PROOF",
                    "STATIC_ANALYSIS", "JURY_OPINION", "WATCHER_REPORT")
MODES = ("CERTIFICATE", "GATE", "WATCH", "HYBRID")
DIVERGENCE = ("UNANIMOUS", "MAJORITY", "SPLIT")


@dataclass(frozen=True)
class ActorRef:
    kind: str
    identity: str
    version: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Claim:
    claim_id: str
    task_id: str
    subject: str
    predicate: str
    scope: str
    summary: str
    derived_from: str            # artifact digest the claim is about
    verifiability: str           # MACHINE_CHECKABLE | DOCTRINAL | MIXED
    falsifiable_by: tuple[str, ...]
    critical_class: str | None
    status: str = "OPEN"         # OPEN | VERIFIED | REFUTED | INCONCLUSIVE | ESCALATED
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict:
        d = asdict(self)
        d["falsifiable_by"] = list(self.falsifiable_by)
        return d

    @staticmethod
    def from_dict(d: dict) -> "Claim":
        return Claim(
            claim_id=d["claim_id"], task_id=d["task_id"], subject=d["subject"],
            predicate=d["predicate"], scope=d["scope"], summary=d["summary"],
            derived_from=d["derived_from"], verifiability=d["verifiability"],
            falsifiable_by=tuple(d["falsifiable_by"]), critical_class=d["critical_class"],
            status=d["status"], schema_version=d.get("schema_version", SCHEMA_VERSION),
        )


@dataclass(frozen=True)
class EvidenceItem:
    evidence_id: str
    claim_id: str
    evidence_class: str          # one of EVIDENCE_CLASSES
    tier: str                    # W1a | W1b | W2 | W3
    producer: dict               # {kind, identity, version, family?}
    artifact_ref: str            # artifact digest the evidence was produced against
    reproducibility: dict        # {deterministic: bool, rerun_recipe: dict | None}
    stance: str                  # SUPPORTS | REFUTES
    confidence: float            # 0..1 (fixed 1.0 for W1a)
    schema_version: str = SCHEMA_VERSION

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "EvidenceItem":
        return EvidenceItem(**d)


@dataclass(frozen=True)
class TaskManifest:
    task_id: str
    artifact_path: str
    actor_identity: str          # identity of the AI under audit
    intent_lines: tuple[str, ...]
    criticality: tuple[str, ...]
    has_existing_tests: bool
    pytest_args: tuple[str, ...] = ()   # extra args for the executor (e.g. --ignore=...)
