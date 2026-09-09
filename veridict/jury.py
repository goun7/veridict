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
    """Deterministic provider for tests/offline CI runs."""
    def __init__(self, family: str, identity: str, default: Opinion,
                 responses: dict[str, Opinion] | None = None, version: str = "0.1.0",
                 fn=None):
        self.family = family
        self.identity = identity
        self.version = version
        self.default = default
        self.responses = responses or {}
        self.fn = fn

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
            author = ActorRef(kind="jury", identity=p.identity, version=p.version).to_dict()
            author["family"] = p.family
            items.append(EvidenceItem(
                evidence_id=sha256_hex(f"{EID_SALT}|{claim.claim_id}|{p.identity}")[:24],
                claim_id=claim.claim_id, evidence_class="JURY_OPINION", tier="W2",
                producer=author, artifact_ref=artifact_digest,
                reproducibility={"deterministic": False, "rerun_recipe": None},
                stance=op.stance, confidence=op.confidence))
        return items, abstained
