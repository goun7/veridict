"""Blind heterogeneous jury (§5.2). Members never see each other's doctrine."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

import httpx

from .schemas import ActorRef, Claim, EvidenceItem
from .utils import sha256_hex

EID_SALT = "veridict-jury-v1"


@dataclass(frozen=True)
class Opinion:
    stance: str          # SUPPORTS | REFUTES
    confidence: float    # 0..1
    rationale: str


class ProviderError(Exception):
    pass


class ScriptedProvider:
    """Deterministic provider for tests/offline CI runs.

    `revise` (optional) is the §4.4.3 deliberation hook: it receives the OTHER
    providers' first-round opinions (identity-labeled dicts) and returns a
    revised Opinion. Without it, the provider keeps its first-round opinion.
    """
    def __init__(self, family: str, identity: str, default: Opinion,
                 responses: dict[str, Opinion] | None = None, version: str = "0.1.0",
                 fn=None, revise=None):
        self.family = family
        self.identity = identity
        self.version = version
        self.default = default
        self.responses = responses or {}
        self.fn = fn
        self.revise = revise

    def doctrine(self, claim_summary: str, artifact_digest: str) -> Opinion:
        if self.fn is not None:
            return self.fn(claim_summary)
        return self.responses.get(claim_summary, self.default)


class OpenAICompatProvider:
    """Any OpenAI-compatible chat endpoint; expects strict-JSON opinion back."""
    def __init__(self, family: str, identity: str, version: str = "0.1.0",
                 base_url: str | None = None):
        self.family = family
        self.identity = identity
        self.version = version
        self.base_url = base_url or os.environ["VERIDICT_JURY_URL"]
        self.api_key = os.environ.get("VERIDICT_JURY_KEY", "")
        self.model = os.environ.get("VERIDICT_JURY_MODEL", "gpt-4o-mini")

    def doctrine(self, claim_summary: str, artifact_digest: str) -> Opinion:
        prompt = (
            "You are an independent audit juror. You see ONE claim and an artifact "
            "digest. You do NOT see other jurors' opinions. Respond ONLY with JSON: "
            '{"stance": "SUPPORTS"|"REFUTES", "confidence": 0..1, "rationale": "..."}\n'
            f"Claim: {claim_summary}\nArtifact digest: {artifact_digest}")
        try:
            resp = httpx.post(
                self.base_url.rstrip("/") + "/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json={"model": self.model,
                      "messages": [{"role": "user", "content": prompt}],
                      "temperature": 0},
                timeout=60)
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            data = json.loads(content)
            stance = data["stance"]
            if stance not in ("SUPPORTS", "REFUTES"):
                raise ProviderError(f"bad stance: {stance}")
            return Opinion(stance, float(data["confidence"]), str(data["rationale"]))
        except (httpx.HTTPError, KeyError, ValueError, TypeError, IndexError) as exc:
            raise ProviderError(str(exc)) from exc


class Jury:
    def __init__(self, providers: list) -> None:
        families = {p.family for p in providers}
        if len(providers) < 2 or len(families) < 2:
            raise ValueError("jury requires >=2 providers from >=2 distinct families (§5.2)")
        self.providers = providers

    def evaluate(self, claim: Claim, artifact_digest: str) -> tuple[list[EvidenceItem], list[str]]:
        items: list[EvidenceItem] = []
        abstained: list[str] = []
        for p in self.providers:                     # sequential, isolated: blind by construction
            try:
                op = p.doctrine(claim.summary, artifact_digest)
            except ProviderError:
                abstained.append(p.identity)         # abstain ≠ refute: no evidence item
                continue
            items.append(self._build_item(claim, artifact_digest, p, op))
        return items, abstained

    def _build_item(self, claim: Claim, artifact_digest: str, provider,
                    opinion: Opinion, round_salt: str = EID_SALT) -> EvidenceItem:
        author = ActorRef(kind="jury", identity=provider.identity,
                          version=provider.version).to_dict()
        author["family"] = provider.family
        return EvidenceItem(
            evidence_id=sha256_hex(f"{round_salt}|{claim.claim_id}"
                                   f"|{provider.identity}")[:24],
            claim_id=claim.claim_id, evidence_class="JURY_OPINION", tier="W2",
            producer=author, artifact_ref=artifact_digest,
            reproducibility={"deterministic": False, "rerun_recipe": None},
            stance=opinion.stance, confidence=opinion.confidence,
            rationale=opinion.rationale)

    def deliberate(self, claim: Claim, artifact_digest: str,
                   first_items: list[EvidenceItem],
                   tolerance: float) -> tuple[list[EvidenceItem], list[str]]:
        """Cross-visible revision round (§4.4.3) — the ONE blindness exception.

        Only called after a first-round SPLIT. Each provider sees the OTHER
        first-round opinions (identity-labeled, self excluded) and may revise;
        without a revise hook the provider keeps its first-round opinion. The
        first-round items stay in the ledger untouched.
        """
        by_identity = {p.identity: p for p in self.providers}
        packets: dict[str, list[dict]] = {
            p.identity: [{"identity": it.producer["identity"],
                          "family": it.producer.get("family"),
                          "stance": it.stance, "confidence": it.confidence,
                          "rationale": ""}
                         for it in first_items
                         if it.producer["identity"] != p.identity]
            for p in self.providers}
        revised: list[EvidenceItem] = []
        abstained: list[str] = []
        for p in self.providers:
            try:
                first = next(it for it in first_items
                             if it.producer["identity"] == p.identity)
                op = p.revise(packets[p.identity]) if p.revise is not None \
                    else Opinion(first.stance, first.confidence, first.rationale)
            except (StopIteration, ProviderError):
                abstained.append(p.identity)
                continue
            revised.append(self._build_item(claim, artifact_digest, p, op,
                                            round_salt=f"{EID_SALT}-r2"))
        return revised, abstained
