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
    rationale: str = ""          # producer's already-computed why (dossier risk_frame input)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        # The tier/stance strings drive every branch of the adjudication
        # ladder and every count in divergence, via exact string equality.
        # An unregistered value — "W1A", "w1a ", "W1ax", "W2\n", "ABSTAIN", ""
        # — matches NONE of the buckets, so a refuting machine receipt with a
        # garbled tier becomes invisible: the ladder reads no W1a refutation,
        # I4's precondition never fires, and the verdict flips to VERIFIED
        # with the gate passing. The same garbling on a doctrinal refuter
        # erases the dissent and turns a SPLIT into UNANIMOUS. And divergence
        # counts every non-SUPPORTS item as a refutation, so "ABSTAIN" at W2
        # is counted as dissent while at W1a it verifies. Both directions.
        # EvidenceItem is the trust boundary: watcher_stream and certificate
        # materialize items from ledger/remote JSON via from_dict with no
        # other validation, so this is where fail-closed belongs.
        if self.tier not in TIERS:
            raise ValueError(
                f"evidence {self.evidence_id}: tier {self.tier!r} is not one "
                f"of {TIERS} — an unregistered tier is invisible to the ladder "
                "and silently flips verdicts rather than failing closed")
        if self.stance not in STANCES:
            raise ValueError(
                f"evidence {self.evidence_id}: stance {self.stance!r} is not "
                f"one of {STANCES} — an unregistered stance is coerced to "
                "either a silent verify or a phantom dissent")

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
