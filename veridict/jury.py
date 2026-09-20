"""Blind heterogeneous jury (§5.2). Members never see each other's doctrine.

Calibration layer (added 0.4.0, grounded in the LLM-as-judge literature):

- **Self-preference exclusion** — an AI from the same model family as the
  audited artifact's author cannot sit on its jury (self-enhancement bias:
  Zheng et al., arXiv:2306.05685; self-preference bias: Watai et al.,
  arXiv:2410.21819). The author's family is declared by the auditor
  (`author_family` / VERIDICT_ACTOR_FAMILY); undeclared means no exclusion.
- **Evidence-first (MEC)** — jurors must list concrete observations BEFORE
  rating (Multiple Evidence Calibration, Wang et al., arXiv:2305.17926).
- **Sample calibration** — optional repeated independent calls
  (VERIDICT_JURY_SAMPLES>1, temperature floored at 0.7 so repeats are
  genuinely sampled): strict-majority stance wins, confidence is discounted
  by the agreement fraction, and a split with no majority abstains
  ("sample-split") instead of silently averaging an inconsistency.
"""
from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass

import httpx

from .schemas import ActorRef, Claim, EvidenceItem
from .utils import sha256_hex

EID_SALT = "veridict-jury-v1"

# Guards on source text passed to jurors: unbounded context would break
# small local models (and cost on hosted ones), and a juror does not need
# every file to judge one claim.
_MAX_SOURCE_BYTES = 6000
_MAX_SOURCE_FILES = 6


def _read_sources(artifact_dir: str | None) -> str | None:
    """Bounded read of the artifact's own source, for the jury's doctrine.

    A digest alone tells a juror nothing about the code, so a doctrine
    call without source text asks the model to judge a hash — which the
    real-LLM canary showed it refuses ('the digest provides no information'),
    producing refusals that read as refutations. This reads the artifact's
    own .py files, bounded in both count and bytes, so a juror judging a
    claim can actually see the thing the claim is about.
    """
    if not artifact_dir:
        return None
    try:
        names = sorted(os.listdir(artifact_dir))
    except OSError:
        return None
    chunks: list[str] = []
    total = 0
    taken = 0
    for name in names:
        if taken >= _MAX_SOURCE_FILES or total >= _MAX_SOURCE_BYTES:
            break
        if not name.endswith(".py") or name.startswith("test_"):
            continue
        path = os.path.join(artifact_dir, name)
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                text = f.read(_MAX_SOURCE_BYTES - total)
        except OSError:
            continue
        if not text.strip():
            continue
        chunks.append(f"--- {name} ---\n{text}")
        total += len(text)
        taken += 1
    if not chunks:
        return None
    return "\n\n".join(chunks)


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

    def doctrine(self, claim_summary: str, artifact_digest: str,
                 sources: str | None = None) -> Opinion:
        if self.fn is not None:
            return self.fn(claim_summary)
        return self.responses.get(claim_summary, self.default)


class OpenAICompatProvider:
    """Any OpenAI-compatible chat endpoint; expects strict-JSON opinion back."""
    def __init__(self, family: str, identity: str, version: str = "0.1.0",
                 base_url: str | None = None, api_key: str | None = None,
                 model: str | None = None):
        # Explicit params exist because a two-FAMILY jury genuinely needs
        # two credentials: before this, VERIDICT_JURY_URL2 jurors silently
        # borrowed provider 1's key and model — "heterogeneous jury" was
        # then one model answering itself through two gateways.
        self.family = family
        self.identity = identity
        self.version = version
        self.base_url = base_url or os.environ["VERIDICT_JURY_URL"]
        self.api_key = (api_key if api_key is not None
                        else os.environ.get("VERIDICT_JURY_KEY", ""))
        self.model = (model if model is not None
                      else os.environ.get("VERIDICT_JURY_MODEL", "gpt-4o-mini"))

    # -- calibration knobs (env so CI workflows can set them per-run) ----
    def _samples(self) -> int:
        try:
            return max(1, int(os.environ.get("VERIDICT_JURY_SAMPLES", "1")))
        except ValueError:
            return 1

    def _temperature(self, samples: int) -> float:
        env = os.environ.get("VERIDICT_JURY_TEMPERATURE")
        if env is not None:
            try:
                return float(env)
            except ValueError:
                pass
        # Repeated calls at temperature 0 return identical strings — they
        # measure nothing. If samples are requested, actually sample.
        return 0.0 if samples <= 1 else 0.7

    def doctrine(self, claim_summary: str, artifact_digest: str,
                 sources: str | None = None) -> Opinion:
        n = self._samples()
        if n <= 1:
            return self._one(claim_summary, artifact_digest, self._temperature(n),
                             sources)
        ops: list[Opinion] = []
        temp = self._temperature(n)
        for _ in range(n):
            ops.append(self._one(claim_summary, artifact_digest, temp, sources))
        counts = Counter(o.stance for o in ops)
        top_stance, top_n = counts.most_common(1)[0]
        if top_n * 2 <= n:                       # no strict majority
            # Honest degradation: an unresolved sample split is NOT evidence.
            raise ProviderError(f"sample-split, no majority: {dict(counts)}")
        agree = top_n / n
        same = [o.confidence for o in ops if o.stance == top_stance]
        conf = (sum(same) / len(same)) * agree
        base_rationale = next(o.rationale for o in ops if o.stance == top_stance)
        note = f" [sample-calibration: {top_n}/{n} {top_stance}]"
        return Opinion(top_stance, conf, base_rationale + note)

    def _timeout(self) -> float:
        """Per-call timeout. Configurable because a small local model can
        legitimately take minutes on the evidence-first prompt, while a
        hosted endpoint that slow is a broken endpoint — the same default
        serves the common case and the env knob serves the edge."""
        try:
            return max(10.0, float(os.environ.get("VERIDICT_JURY_TIMEOUT", "60")))
        except ValueError:
            return 60.0

    def _one(self, claim_summary: str, artifact_digest: str,
             temperature: float, sources: str | None = None) -> Opinion:
        # The artifact's source is included when available: a juror judging
        # a claim about code must see the code. Without it the model sees
        # only a digest, which carries no information about the code, and
        # the real-LLM canary showed the outcome — refusals dressed as
        # refutations ('the digest does not provide any information about
        # the function'). Abstention is the honest answer to a claim you
        # cannot evidence; this makes the claim evidencable instead.
        source_block = (f"\n\nArtifact source (authoritative — judge against "
                        f"this, not against assumptions):\n{sources}"
                        if sources else "")
        prompt = (
            "You are an independent audit juror. You see ONE claim and the "
            "artifact it is about. You do NOT see other jurors' opinions. "
            "Respond ONLY with JSON: "
            '{"evidence": ["<concrete observation>", "..."], '
            '"stance": "SUPPORTS"|"REFUTES", "confidence": 0..1, "rationale": "..."}\n'
            "List at least two concrete observations in `evidence` BEFORE deciding "
            "— evidence first, verdict second. Quote what you actually see in "
            "the source; if the source does not settle the claim, REFUTE with "
            "low confidence and say so — do not guess.\n"
            f"Claim: {claim_summary}\nArtifact digest: {artifact_digest}"
            f"{source_block}")
        try:
            resp = httpx.post(
                self.base_url.rstrip("/") + "/chat/completions",
                headers=({"Authorization": f"Bearer {self.api_key}"}
                         if self.api_key else {}),
                json={"model": self.model,
                      "messages": [{"role": "user", "content": prompt}],
                      "temperature": temperature},
                timeout=self._timeout())
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            data = json.loads(content)
            stance = data["stance"]
            if stance not in ("SUPPORTS", "REFUTES"):
                raise ProviderError(f"bad stance: {stance}")
            rationale = str(data["rationale"])
            evidence = data.get("evidence")
            if evidence is not None:
                # MEC shape check: non-empty list of real observations.
                if (not isinstance(evidence, list) or len(evidence) < 2
                        or not all(isinstance(e, str) and e.strip()
                                   for e in evidence)):
                    raise ProviderError(f"bad evidence: {evidence!r}")
                rationale = "evidence: " + "; ".join(
                    e.strip() for e in evidence) + " | " + rationale
            else:
                # Legacy single-rationale replies stay acceptable (a strict
                # reject would silently shrink juries in the field), but the
                # receipt records that this opinion was NOT evidence-first.
                rationale += " [no-evidence-field]"
            return Opinion(stance, float(data["confidence"]), rationale)
        except Exception as exc:   # noqa: BLE001 — transport AND contract
            # failures must degrade to ProviderError (an abstaining juror),
            # never crash the audit. Found by the local-mock e2e test: an
            # unset VERIDICT_JURY_KEY used to raise an uncaught
            # httpcore.LocalProtocolError ("Bearer " with an empty token).
            raise ProviderError(str(exc)) from exc


class Jury:
    def __init__(self, providers: list, *, author_family: str | None = None) -> None:
        # Self-preference exclusion (see module docstring): a juror from the
        # audited author's own model family must not rate the author's work.
        # The filter runs BEFORE the >=2-family validation — if the author's
        # family was all the jury had, the jury fails closed (ValueError),
        # it never quietly shrinks to a conflicted panel.
        self.excluded: list = []
        if author_family:
            af = author_family.strip().lower()
            kept = []
            for p in providers:
                if p.family.strip().lower() == af:
                    self.excluded.append(p)
                else:
                    kept.append(p)
            providers = kept
        families = {p.family for p in providers}
        if len(providers) < 2 or len(families) < 2:
            raise ValueError("jury requires >=2 providers from >=2 distinct families (§5.2)")
        self.providers = providers

    def evaluate(self, claim: Claim, artifact_digest: str,
                artifact_dir: str | None = None
                ) -> tuple[list[EvidenceItem], list[str]]:
        items: list[EvidenceItem] = []
        abstained: list[str] = [f"{p.identity} (self-preference: "
                                f"author family '{p.family}')"
                                for p in self.excluded]
        # The jury's doctrine is only meaningful if a juror can see what it
        # is judging. Without source text a juror sees a digest — a hash
        # says nothing about the code — and the real-LLM canary showed the
        # result: REFUTES with rationale 'the digest does not provide any
        # information', i.e. a rejection of the question rather than the
        # code. Passing source text is opt-in (audit sets it) and bounded.
        sources = _read_sources(artifact_dir) if artifact_dir else None
        for p in self.providers:                     # sequential, isolated: blind by construction
            try:
                op = p.doctrine(claim.summary, artifact_digest, sources)
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
            except StopIteration:
                # no first-round item to revise — abstain (erases nothing:
                # this producer contributed no first-round opinion)
                abstained.append(p.identity)
                continue
            keep = Opinion(first.stance, first.confidence, first.rationale)
            revise = getattr(p, "revise", None)
            if revise is None:
                op = keep
            else:
                try:
                    op = revise(packets[p.identity])
                except Exception:
                    # §9.2: an erroring revision hook degrades to
                    # keep-opinion. Abstaining here would silently erase the
                    # producer's first-round REFUTES from the superseded
                    # basis — a fail-open the standard forbids.
                    op = keep
            revised.append(self._build_item(claim, artifact_digest, p, op,
                                            round_salt=f"{EID_SALT}-r2"))
        return revised, abstained
