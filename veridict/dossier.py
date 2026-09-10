"""Dossier generator (§6.3): a VIEW over the ledger for the human risk owner.

The dossier is never separate truth: every sentence resolves to ledger entry
IDs (evidence_links), and the risk frame speaks in impact language built from
the REFUTES side's already-recorded rationales. On escalation the orchestrator
issues `dossier.issued`; the human returns a decision via resolve_dossier (§6.1)
or the window expires into the R4 fail-safe.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .ledger import Ledger
from .schemas import ActorRef, Claim, EvidenceItem
from .utils import sha256_hex

SCHEMA_VERSION = "1.0"

# §6.3: exactly these four options, verbatim.
OPTIONS = (
    {"id": "accept_with_risk", "label": "Accept with risk note",
     "consequence": "You own the residual risk; the risk frame above becomes "
                    "your exposure"},
    {"id": "demand_rerun", "label": "Demand independent rerun",
     "consequence": "A different jury/watcher set re-executes; rerun recipe "
                    "travels in the certificate"},
    {"id": "narrow_claim", "label": "Narrow or redefine the claim",
     "consequence": "The claim returns to the ladder with a tighter falsifiable "
                    "scope"},
    {"id": "reject", "label": "Reject the output",
     "consequence": "The work is not accepted; the ledger records your refusal"},
)

RISK_FRAME_PREFIX = "If the REFUTES side is right: "
RISK_FRAME_FALLBACK = "the claim's failure mode is unmitigated"

# §6.1 human decisions (Task 23); shared with resolve_dossier's validation.
DECISIONS = ("accept_with_risk", "demand_rerun", "narrow_claim", "reject")


def generate_dossier(claim: Claim, adjudication, evidence: list[EvidenceItem],
                     ledger: Ledger, policy, artifact_digest: str) -> dict:
    """Build the escalation dossier for one R3-escalated claim.

    A pure view: claim facts, verdict, the REFUTES side's impact frame, the 4
    options, the response-window default, and resolvable evidence links. The
    ledger parameter keeps the generator ledger-anchored (it is a view over
    THAT ledger's escalation, never a standalone document).
    """
    dossier_id = sha256_hex(f"{claim.claim_id}|{artifact_digest}")[:16]
    rationales: list[str] = []
    for e in evidence:
        if e.stance == "REFUTES" and e.rationale and e.rationale not in rationales:
            rationales.append(e.rationale)
    return {
        "schema_version": SCHEMA_VERSION,
        "dossier_id": dossier_id,
        "claim": {
            "claim_id": claim.claim_id,
            "predicate": claim.predicate,
            "summary": claim.summary,
            "verifiability": claim.verifiability,
            "verdict": adjudication.value,
            "rung": "R3",
            "divergence": adjudication.divergence,
        },
        "summary_page": (
            f"This claim could not be settled by machine evidence alone: "
            f"\"{claim.summary}\" ends at verdict {adjudication.value} at rung "
            "R3 — independent jurors split on the disagreement. A human risk "
            "owner must decide on the disagreement and the risk, not on code."),
        "risk_frame": (RISK_FRAME_PREFIX
                       + ("; ".join(rationales) if rationales
                          else RISK_FRAME_FALLBACK)),
        "options": [dict(o) for o in OPTIONS],
        "default": (f"No response within {policy.response_window_hours}h "
                    "triggers policy.fail_safe (R4): the gate stays blocked / "
                    "the certificate is stamped unresolved."),
        "evidence_links": _dedupe([claim.claim_id] + [e.evidence_id
                                                      for e in evidence]),
        "response_window_hours": policy.response_window_hours,
    }


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def render_markdown(dossier: dict) -> str:
    """Render the dossier as the human-readable markdown page (§6.3)."""
    c = dossier["claim"]
    lines = [
        f"# Dossier {dossier['dossier_id']}: {c['predicate']}",
        "",
        "## Summary",
        dossier["summary_page"],
        "",
        "## Risk frame",
        dossier["risk_frame"],
        "",
        "## Options",
    ]
    for i, o in enumerate(dossier["options"], start=1):
        lines.append(f"{i}. **{o['label']}** — {o['consequence']}")
    lines += ["", "## Default", dossier["default"], "", "## Evidence links"]
    lines += [f"- {link}" for link in dossier["evidence_links"]]
    return "\n".join(lines) + "\n"


def dossier_for(ledger: Ledger, claim_id: str) -> dict | None:
    """Latest `dossier.issued` payload for the claim (reversed scan)."""
    for e in reversed(ledger.query("dossier.issued")):
        if e["payload"]["claim"]["claim_id"] == claim_id:
            return e["payload"]
    return None


def resolve_dossier(ledger: Ledger, dossier_id: str, decision: str,
                    decided_by: str, risk_note: str = "") -> dict:
    """Human decision return (§6.1): append `escalation.resolved`.

    The human is the risk owner — the ledger records WHO decided, WHICH of the
    4 options, and the risk note they accepted under. Unknown decisions and
    unknown dossiers are rejected before anything is written (a resolution
    for a dossier that was never issued would fabricate human authority).
    """
    if decision not in DECISIONS:
        raise ValueError(f"unknown decision: {decision!r} — expected one of "
                         f"{DECISIONS}")
    if not any(e["payload"].get("dossier_id") == dossier_id
               for e in ledger.query("dossier.issued")):
        raise ValueError(f"unknown dossier_id: {dossier_id!r} — no "
                         f"dossier.issued entry carries it")
    return ledger.append(
        "escalation.resolved",
        ActorRef(kind="human", identity=decided_by, version="user"),
        {"dossier_id": dossier_id, "decision": decision, "decided_by": decided_by,
         "risk_note": risk_note,
         "ts": datetime.now(timezone.utc).isoformat()})


def apply_fail_safe(ledger: Ledger, dossier_id: str, actor: ActorRef) -> dict:
    """R4 fail-safe (§6.1): window expired / no human — never a silent pass.

    Appends `policy.fail_safe` with the fixed consequence: the GATE stays
    blocked, the CERTIFICATE is stamped unresolved. Refuses unknown dossiers
    for the same fabricated-authority reason as resolve_dossier.
    """
    if not any(e["payload"].get("dossier_id") == dossier_id
               for e in ledger.query("dossier.issued")):
        raise ValueError(f"unknown dossier_id: {dossier_id!r} — no "
                         f"dossier.issued entry carries it")
    return ledger.append(
        "policy.fail_safe", actor,
        {"dossier_id": dossier_id,
         "consequence": "gate_stays_blocked_or_certificate_stamped_unresolved",
         "ts": datetime.now(timezone.utc).isoformat()})
