"""Deterministic claim extraction (§5.5 Phase 1: rule-based layer).

Intent grammar:  MACHINE[(class)]: <statement>  |  DOCTRINE[(class)]: <statement>
The Actor never writes claims directly (§4.2) — it submits intent lines in
task manifest; this extractor converts them into falsifiable Claims.
"""
from __future__ import annotations

import re

from .schemas import Claim, TaskManifest
from .utils import sha256_hex

_LINE = re.compile(r"^\s*(MACHINE|DOCTRINE)(?:\(([a-z0-9_-]+)\))?\s*:\s*(.+?)\s*$")


def _slug(text: str) -> str:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return "-".join(words[:8])


class ClaimExtractor:
    def extract(self, task: TaskManifest, artifact_digest: str) -> list[Claim]:
        claims: list[Claim] = []
        seen: set[str] = set()
        for line in task.intent_lines:
            m = _LINE.match(line)
            if not m:
                raise ValueError(f"invalid intent line: {line!r}")
            kind, cls, body = m.group(1), m.group(2), m.group(3)
            claim = self.make_claim(
                task, artifact_digest, subject="intent", predicate=_slug(body),
                summary=body, verifiability="MACHINE_CHECKABLE" if kind == "MACHINE"
                else "DOCTRINAL", falsifiable_by=("test_execution", "static_analysis")
                if kind == "MACHINE" else ("jury",), critical_class=cls)
            # Belt-and-braces: the summary-keyed id makes accidental duplicates
            # (identical intent line submitted twice) collide on purpose.
            if claim.claim_id in seen:
                raise ValueError(
                    f"duplicate claim_id {claim.claim_id} — identical intent "
                    "line submitted twice")
            seen.add(claim.claim_id)
            claims.append(claim)
        if task.has_existing_tests:
            claims.append(self.make_claim(
                task, artifact_digest, subject="repo",
                predicate="existing-test-suite-passes", summary="existing test suite passes",
                verifiability="MACHINE_CHECKABLE", falsifiable_by=("test_execution",),
                critical_class=None))
        claims.append(self.make_claim(
            task, artifact_digest, subject="repo",
            predicate="forbidden-constructs-absent",
            summary="no bare except / eval / exec introduced",
            verifiability="MACHINE_CHECKABLE", falsifiable_by=("static_analysis",),
            critical_class=None))
        return claims

    def make_claim(self, task: TaskManifest, digest: str, subject: str, predicate: str,
                   summary: str, verifiability: str, falsifiable_by: tuple[str, ...],
                   critical_class: str | None) -> Claim:
        # Key on the exact intent text, not the truncated slug: two distinct
        # long intents can share an 8-word predicate, and a predicate-keyed id
        # would merge them into one claim (verify would then REJECT honest
        # certificates and a GATE could evade a REFUTES).
        claim_id = sha256_hex(f"{task.task_id}|{summary}|{verifiability}")[:16]
        return Claim(
            claim_id=claim_id, task_id=task.task_id, subject=subject,
            predicate=predicate, scope="repo", summary=summary,
            derived_from=digest, verifiability=verifiability,
            falsifiable_by=falsifiable_by, critical_class=critical_class)
