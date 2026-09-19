"""Certificate → settlement claim bridge (prototype).

Grok's inference, coded: the gap in the agent economy is between "payment
happened" and "the work was provably done". Veridict's certificate is
exactly the second half. This module is the bridge — it turns an
offline-verifiable certificate into a *settlement claim* that a payment
layer can evaluate without trusting the agent, the caller, or us.

Scope (honest boundary):
  - This is a CLAIM generator, not a payment executor. It does not move
    money, sign transactions, or talk to any chain. It produces a
    machine-checkable authorization whose validity is recomputable from
    the ledger alone.
  - The policy is explicit and local: which verdict/risk combinations
    authorize release. Nothing is implicit. (Amounts are deliberately NOT
    here: mapping acceptance to a price is the payment layer's bookkeeping,
    not this protocol's. This module answers 'was the work provably done',
    not 'how much does it cost'.)
  - **This module does not verify the certificate.** It evaluates one
    that the caller already verified (`veridict verify`, or the spec
    verifier from the standard alone). Two parties who disagree about
    validity must settle that before calling this — the claim assumes a
    verified input, and a forged cert would produce a forged claim.

Known limit: the shipped dogfood certificate carries stub-a/stub-b
jurors (both real families, so the diversity rule passes, but neither is
an LLM). A settlement claim resting on it is a *demo of the bridge*, not
evidence about real work. The real artifact is
scripts/canary_real_llm.py with both VERIDICT_JURY_URL* set.

Why this and not a token: the trust asset is the offline-verifiable
certificate. A payment layer that ignores it can be fooled by a lying
agent ("payment for work never done"); one that consumes it cannot be —
the certificate's verdicts recompute against a hash chain the agent
cannot retroactively edit. Money follows the trust; it does not gate it.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SettlementPolicy:
    """Local, auditable rules mapping a certificate to a release decision.

    Every field is a claim about what 'good enough to pay' means here.
    The policy itself is part of the claim digest, so the caller cannot
    silently swap in a more permissive one after seeing the verdict.
    """
    # verdicts that authorize release (default: only full verification)
    accept_verdicts: tuple[str, ...] = ("VERIFIED",)
    # maximum risk level willing to settle (low < medium < high)
    max_risk: str = "low"
    # minimum jury diversity — §5.2: one family is self-preference
    min_jury_families: int = 2
    # fraction of claims that must be accepted
    min_claim_coverage: float = 1.0

    def digest(self) -> str:
        body = json.dumps({
            "accept_verdicts": list(self.accept_verdicts),
            "max_risk": self.max_risk,
            "min_jury_families": self.min_jury_families,
            "min_claim_coverage": self.min_claim_coverage,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()


_RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# The digest covers every field except itself. If claim_digest were part of
# its own preimage, mutating any other field and recomputing would still
# match — the binding would be cosmetic. Excluding it makes the digest a
# real integrity check: change any field, and it no longer recomputes.
_DIGEST_FIELDS = ("cert_id", "task_id", "artifact_digest", "valid", "reasons",
                  "accepted_claims", "total_claims", "jury_families",
                  "risk_level", "policy_digest")


def _claim_digest(fields: dict[str, Any]) -> str:
    body = {k: fields.get(k) for k in _DIGEST_FIELDS}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


@dataclass
class SettlementClaim:
    """A release authorization derived from a certificate.

    valid == False with reasons means the work did NOT qualify — the
    payment layer must not release. It is never the absence of a claim:
    a refusal is an artifact this protocol produces deliberately, so a
    dropped message cannot turn into a silent pass.
    """
    cert_id: str
    task_id: str
    artifact_digest: str
    valid: bool
    reasons: list[str] = field(default_factory=list)
    accepted_claims: int = 0
    total_claims: int = 0
    jury_families: list[str] = field(default_factory=list)
    risk_level: str = ""
    policy_digest: str = ""
    claim_digest: str = ""

    def to_json(self) -> str:
        return json.dumps(self.__dict__, sort_keys=True, separators=(",", ":"))


def build_settlement_claim(cert: dict[str, Any],
                           policy: SettlementPolicy | None = None) -> SettlementClaim:
    """Evaluate a certificate against a settlement policy.

    The certificate is NOT trusted as a bag of fields: the caller must
    have verified it first (`veridict verify` or the spec verifier).
    This function only decides whether a *verified* certificate
    qualifies for release — it performs no cryptography of its own.
    """
    p = policy or SettlementPolicy()
    reasons: list[str] = []

    claims = cert.get("claims", [])
    verdicts = [c.get("verdict_value") for c in claims]
    accepted = sum(1 for v in verdicts if v in p.accept_verdicts)
    coverage = accepted / len(claims) if claims else 0.0

    families = cert.get("jury_composition", {}).get("families", [])
    risk = cert.get("risk_level", "high")  # unknown risk fails closed

    if not claims:
        reasons.append("certificate has no claims — nothing was adjudicated")
    if coverage < p.min_claim_coverage:
        reasons.append(f"claim coverage {coverage:.2f} < {p.min_claim_coverage:.2f}")
    if len(set(families)) < p.min_jury_families:
        reasons.append(f"jury families {len(set(families))} < {p.min_jury_families}"
                       " (single-family verdict is self-preference, §5.2)")
    if _RISK_ORDER.get(risk, 3) > _RISK_ORDER.get(p.max_risk, 0):
        reasons.append(f"risk {risk} exceeds policy maximum {p.max_risk}")

    valid = not reasons
    sc = SettlementClaim(
        cert_id=cert.get("cert_id", ""),
        task_id=cert.get("subject", {}).get("task_id", ""),
        artifact_digest=cert.get("subject", {}).get("artifact_digest", ""),
        valid=valid,
        reasons=reasons,
        accepted_claims=accepted,
        total_claims=len(claims),
        jury_families=sorted(set(families)),
        risk_level=risk,
        policy_digest=p.digest(),
    )
    sc.claim_digest = _claim_digest(sc.__dict__)
    return sc


def verify_settlement_claim(claim: dict[str, Any], cert: dict[str, Any],
                            policy: SettlementPolicy | None = None) -> dict[str, Any]:
    """Reconcile a presented claim against the certificate it rests on.

    A payment layer cannot trust the claim as a bag of fields — the agent
    that produced the work has every reason to forge it. This recomputes
    the claim from the certificate and the policy, and says whether the
    presented one matches. Nothing about the presented claim is trusted
    except its identity (which cert it claims to be about).

    The caller MUST have already verified the certificate itself
    (`veridict verify` or the spec verifier). This function only answers
    'does this claim follow from that cert under this policy' — a claim
    reconciling against a *forged* certificate reconciles just fine, and
    that is by design: verification of the cert is a separate,
    composable step, and conflating the two is how silent passes happen.
    """
    p = policy or SettlementPolicy()
    expected = build_settlement_claim(cert, p)

    cid = claim.get("claim_digest", "")
    presented_valid = claim.get("valid")

    # Integrity of the presented artifact, recomputed from ITS OWN fields:
    # a claim whose stored digest does not match its contents was edited
    # after issuance (or fabricated). Without this check, an attacker can
    # flip `valid` and keep the original digest — the digest comparison
    # below alone would not notice.
    recomputed = _claim_digest(claim)
    self_consistent = (recomputed == cid)
    # Does the presented claim match what this cert+policy actually yields?
    matches_certificate = (cid == expected.claim_digest)

    valid = (self_consistent and matches_certificate
             and presented_valid is True and expected.valid is True)

    reasons: list[str] = []
    if not self_consistent:
        reasons.append("claim_digest does not recompute from the claim's own"
                       " fields — the claim was edited after issuance")
    if not matches_certificate:
        reasons.append("claim does not follow from this certificate under"
                       " this policy — the cert, the policy, or the verdicts"
                       " are not what the claim rests on")
    if presented_valid is not expected.valid:
        reasons.append(f"presented valid={presented_valid} but the certificate"
                       f" yields valid={expected.valid}")
    if not expected.valid:
        reasons.extend(expected.reasons)

    return {
        "valid": valid,
        "reasons": reasons,
        "expected_cert_id": expected.cert_id,
        "presented_cert_id": claim.get("cert_id", ""),
        "expected_digest": expected.claim_digest,
    }
