# Veridict Phase 1 — Core (B-Spine) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the smallest honest core that can produce a signed, offline-verifiable AuditCertificate: append-only hash-chained ledger, deterministic claim extraction, W1a/W1b verifiers, blind ≥2-family jury, divergence detector, R0–R4 adjudication ladder, 4-mode policy engine, certificate issuance + replay verification, canary protocol v0, and self-audit (dogfooding).

**Architecture:** Pure-Python small core (Small-Core Principle §7.3): components are pure functions/dataclasses orchestrated by one `AuditOrchestrator`; the ledger is the single source of truth; every producer writes only its permitted entry types. Evidence-weight hierarchy W1a > W1b > W2 > W3 is enforced in `ladder.py` exactly per spec §4.3.

**Tech Stack:** Python ≥3.11, stdlib-first. Deps: `cryptography` (ed25519), `httpx` (jury HTTP adapter), `pytest` (dev). No frameworks. CLI via argparse.

**Spec source:** `docs/specs/2026-09-09-veridict-design.md` (§ numbers referenced throughout).

## Global Constraints

- `SCHEMA_VERSION = "1.0.0"` on every contract, entry, certificate.
- Entry types allowed: `task.started, actor.output, claim.registered, evidence.recorded, verdict.computed, divergence.flagged, policy.decision, escalation.requested, escalation.resolved, certificate.issued, checkpoint.anchored, key.enrolled, key.revoked` (§4.1 + §7.8).
- Author kinds allowed: `actor, claim_extractor, verifier, jury, watcher, divergence_detector, policy_engine, adjudicator, system` — authority matrix: `actor→actor.output`; `claim_extractor→claim.registered`; `verifier|jury|watcher→evidence.recorded`; `divergence_detector→divergence.flagged`; `policy_engine→task.started, policy.decision`; `adjudicator→verdict.computed, escalation.requested, escalation.resolved, certificate.issued`; `system→checkpoint.anchored, key.enrolled, key.revoked`.
- Ledger is append-only: no update/delete API exists (§4.1).
- `entry_hash = sha256(prev_hash | payload_hash | entry_type | seq | author_json)` with `|` join (instantiation of §4.1 formula); genesis prev_hash = 64×`"0"`.
- Tier rules R1–R5 of §4.3 are implemented verbatim in `ladder.py`; the 5 rule tests of Task 9 are the Phase 1 exit criterion ④.
- Every W1a evidence item carries `reproducibility.rerun_recipe` (§5.1).
- Jury requires ≥2 distinct model families at construction (§5.2 rule 1); jury members are blind — they receive only claim + digest, never other opinions.
- Abstain ≠ refute (§5.4): a silent producer contributes NO evidence item; abstentions are reported in the audit report only.
- Certificates always carry `scope_limits` including "claim coverage is heuristic, not exhaustive" (§4.2) and a `disclosure_level` (§7.7).
- The offline verifier (`veridict.certificate.verify_certificate` / CLI `verify`) imports ONLY core modules (utils, schemas, ledger, divergence, ladder, policy, keys) — never jury/verifiers/audit (§7.3 mechanism 3).
- CLI exit codes: `0` ok, `1` invalid/corrupt, `2` gate-blocked (§6.5 gate semantics).
- GATE latency target: p95 < 30 min (§6.5); the dogfood test asserts < 600 s on the sample.
- TDD: failing test written and observed red BEFORE implementation; commit after every green task.
- Commit style: conventional (`feat:`, `test:`, `chore:`).

## File Structure

```
pyproject.toml                      — package + deps + console script
veridict/
  __init__.py                       — package marker
  utils.py                          — canonical_json, sha256_hex, payload_digest, IGNORED_DIRS, iter_python_files
  schemas.py                        — constants + ActorRef, Claim, EvidenceItem, TaskManifest
  ledger.py                         — Ledger (append/verify_chain/save/load/query), ChainError
  keys.py                           — KeyStore: ed25519 generate/enroll/sign/verify
  divergence.py                     — compute_divergence (UNANIMOUS/MAJORITY/SPLIT)
  claim_extractor.py                — ClaimExtractor (deterministic rules, §5.5)
  verifiers.py                      — TestExecutorVerifier (W1a) + StaticAnalyzerVerifier (W1b)
  jury.py                           — Opinion, ScriptedProvider, OpenAICompatProvider, Jury (blind, ≥2 families)
  ladder.py                         — Adjudication + adjudicate (R0–R4, rules R1–R5)
  policy.py                         — Thresholds, PolicyDeclaration, load_policy, PolicyEngine.apply
  audit.py                          — artifact_digest + AuditOrchestrator (pipeline wiring)
  certificate.py                    — CertificateIssuer.issue + verify_certificate (offline)
  canary.py                         — CanaryRunner → Quality Sheet
  cli.py                            — argparse: audit / verify / quality-sheet
scripts/
  dogfood.py                        — self-audit runner (Task 15)
corpus/
  corpus.jsonl                      — canary corpus manifest (Task 14)
  artifacts/case-sign-error/{calc.py, test_calc.py}
  artifacts/case-uncovered-edge/{calc.py, test_calc.py}
  artifacts/case-uncovered-edge-uncatchable/{calc.py, test_calc.py}
  artifacts/case-clean/{calc.py, test_calc.py}
tests/                              — pytest suite, one file per task
docs/plans/                         — this file
```

Each module has one responsibility; core modules (utils, schemas, ledger, divergence, ladder, policy, keys, certificate) have zero network/LLM dependencies.

---

### Task 1: Project Scaffold + Canonical Utilities

**Files:**
- Create: `pyproject.toml`, `veridict/__init__.py`, `veridict/utils.py`
- Test: `tests/test_utils.py`

**Interfaces:**
- Produces: `canonical_json(obj) -> str`, `sha256_hex(s: str|bytes) -> str`, `payload_digest(payload: dict) -> str`, `IGNORED_DIRS: frozenset`, `iter_python_files(root: str) -> list[str]` — consumed by every later task.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_utils.py
from veridict.utils import canonical_json, sha256_hex, payload_digest, iter_python_files

def test_canonical_json_sorts_and_compacts():
    assert canonical_json({"b": 1, "a": 2}) == '{"a":2,"b":1}'

def test_sha256_hex_known_vector():
    assert sha256_hex("abc") == ("ba7816bf8f01cfea414140de5dae2223"
                                  "b00361a396177a9cb410ff61f20015ad")

def test_payload_digest_is_stable_across_key_order():
    assert payload_digest({"x": 1, "y": 2}) == payload_digest({"y": 2, "x": 1})

def test_iter_python_files_skips_ignored_dirs(tmp_path):
    (tmp_path / "veridict").mkdir(); (tmp_path / "veridict" / "a.py").write_text("x = 1")
    (tmp_path / "__pycache__").mkdir(); (tmp_path / "__pycache__" / "junk.py").write_text("")
    rels = iter_python_files(str(tmp_path))
    assert rels == ["veridict/a.py"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pip install -e ".[dev]" && python -m pytest tests/test_utils.py -v`
Expected: FAIL (`No module named 'veridict'`) — after installing scaffold below, remaining failures are `ImportError: cannot import name 'canonical_json'`.

- [ ] **Step 3: Write the implementation**

```toml
# pyproject.toml
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "veridict"
version = "0.1.0"
description = "The verdict that survived verification — audit AI with AI"
requires-python = ">=3.11"
dependencies = ["cryptography>=42.0", "httpx>=0.27"]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
veridict = "veridict.cli:main"

[tool.setuptools.packages.find]
include = ["veridict*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

```python
# veridict/__init__.py
"""Veridict — the verdict that survived verification."""
```

```python
# veridict/utils.py
"""Canonical serialization and hashing. Small-core: stdlib only (§7.3)."""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any

IGNORED_DIRS = frozenset({".git", "__pycache__", ".venv", "node_modules", ".pytest_cache"})


def canonical_json(obj: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace, ASCII-escaped."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(s: str | bytes) -> str:
    if isinstance(s, str):
        s = s.encode("utf-8")
    return hashlib.sha256(s).hexdigest()


def payload_digest(payload: dict) -> str:
    return sha256_hex(canonical_json(payload))


def iter_python_files(root: str) -> list[str]:
    """Sorted relative paths of *.py files under root, skipping IGNORED_DIRS."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                rel = os.path.relpath(os.path.join(dirpath, fn), root)
                out.append(rel.replace(os.sep, "/"))
    return sorted(out)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_utils.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml veridict/__init__.py veridict/utils.py tests/test_utils.py
git commit -m "feat: scaffold veridict package with canonical json/hash utils"
```

---

### Task 2: Core Schemas

**Files:**
- Create: `veridict/schemas.py`
- Test: `tests/test_schemas.py`

**Interfaces:**
- Consumes: nothing (stdlib only).
- Produces: `SCHEMA_VERSION`, `VERIFIABILITY`, `TIERS`, `TIER_RANK`, `STANCES`, `EVIDENCE_CLASSES`, `MODES`, `DIVERGENCE`, `ActorRef`, `Claim` (`.to_dict()/.from_dict()`), `EvidenceItem`, `TaskManifest` — consumed by Tasks 3–15.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_schemas.py
from veridict.schemas import (ActorRef, Claim, EvidenceItem, TaskManifest,
                              TIER_RANK, SCHEMA_VERSION)

def test_actor_ref_to_dict():
    a = ActorRef(kind="verifier", identity="test-executor", version="0.1.0")
    assert a.to_dict() == {"kind": "verifier", "identity": "test-executor", "version": "0.1.0"}

def test_claim_roundtrip():
    c = Claim(claim_id="c1", task_id="t1", subject="artifact", predicate="tests-pass",
              scope="repo", summary="existing tests pass", derived_from="digest",
              verifiability="MACHINE_CHECKABLE", falsifiable_by=("test_execution",),
              critical_class=None)
    d = c.to_dict()
    assert d["schema_version"] == SCHEMA_VERSION
    c2 = Claim.from_dict(d)
    assert c2 == c

def test_claim_is_frozen():
    import dataclasses, pytest
    c = Claim(claim_id="c", task_id="t", subject="s", predicate="p", scope="r",
              summary="m", derived_from="d", verifiability="DOCTRINAL",
              falsifiable_by=("jury",), critical_class=None)
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.status = "VERIFIED"

def test_evidence_item_shape():
    e = EvidenceItem(evidence_id="e1", claim_id="c1", evidence_class="TEST_EXECUTION",
                     tier="W1a", producer={"kind": "verifier", "identity": "test-executor",
                                           "version": "0.1.0"},
                     artifact_ref="digest", reproducibility={"deterministic": True,
                     "rerun_recipe": {"cmd": ["pytest"]}}, stance="SUPPORTS", confidence=1.0)
    assert e.tier == "W1a" and e.stance == "SUPPORTS"

def test_tier_rank_strict_order():
    assert TIER_RANK["W1a"] > TIER_RANK["W1b"] > TIER_RANK["W2"] > TIER_RANK["W3"]

def test_task_manifest_holds_intent():
    t = TaskManifest(task_id="t1", artifact_path=".", actor_identity="ai-dev",
                     intent_lines=("MACHINE: existing tests pass",),
                     criticality=("payments",), has_existing_tests=True,
                     pytest_args=())
    assert t.actor_identity == "ai-dev"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_schemas.py -v`
Expected: FAIL — `ImportError: cannot import name 'ActorRef'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/schemas.py
"""Core data contracts (§4.2). Every contract carries schema_version."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_schemas.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/schemas.py tests/test_schemas.py
git commit -m "feat: core data contracts (Claim, EvidenceItem, TaskManifest, ActorRef)"
```

---

### Task 3: Append-Only Hash-Chained Ledger

**Files:**
- Create: `veridict/ledger.py`
- Test: `tests/test_ledger.py`

**Interfaces:**
- Consumes: `utils.canonical_json/payload_digest/sha256_hex`, `schemas.ActorRef/SCHEMA_VERSION`.
- Produces: `GENESIS`, `ChainError`, `Ledger.append(entry_type, author, payload) -> dict`, `Ledger.verify_chain() -> (bool, str)`, `Ledger.save(path)`, `Ledger.load(path) -> Ledger`, `Ledger.query(entry_type=None) -> list[dict]` — consumed by Tasks 4, 8, 10–15.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ledger.py
import json
import pytest
from veridict.ledger import Ledger, ChainError, GENESIS
from veridict.schemas import ActorRef

AUTH = ActorRef(kind="system", identity="core", version="0.1.0")

def test_append_builds_hash_chain():
    led = Ledger()
    e0 = led.append("task.started", AUTH, {"task_id": "t1"})
    e1 = led.append("policy.decision", AUTH, {"mode": "GATE"})
    assert e0["seq"] == 0 and e0["prev_hash"] == GENESIS
    assert e1["prev_hash"] == e0["entry_hash"]
    ok, msg = led.verify_chain()
    assert ok and msg == "ok"

def test_tamper_detected_by_verify_chain():
    led = Ledger()
    led.append("task.started", AUTH, {"task_id": "t1"})
    led.append("policy.decision", AUTH, {"mode": "GATE"})
    led.entries[1]["payload"]["mode"] = "CERTIFICATE"   # retroactive edit
    ok, msg = led.verify_chain()
    assert not ok and "entry hash mismatch" in msg

def test_payload_hash_mismatch_detected():
    led = Ledger()
    led.append("task.started", AUTH, {"task_id": "t1"})
    led.entries[0]["payload"] = {"task_id": "evil"}
    ok, msg = led.verify_chain()
    assert not ok and "payload hash mismatch" in msg

def test_save_load_roundtrip_verifies():
    led = Ledger()
    led.append("task.started", AUTH, {"task_id": "t1"})
    led.save("/tmp/vd_ledger.jsonl")
    led2 = Ledger.load("/tmp/vd_ledger.jsonl")
    ok, _ = led2.verify_chain()
    assert ok and len(led2.entries) == 1

def test_query_filters_by_type():
    led = Ledger()
    led.append("task.started", AUTH, {"task_id": "t1"})
    led.append("policy.decision", AUTH, {"mode": "GATE"})
    assert [e["payload"]["mode"] for e in led.query("policy.decision")] == ["GATE"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_ledger.py -v`
Expected: FAIL — `ImportError: cannot import name 'Ledger'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/ledger.py
"""Append-only, hash-chained ledger (§4.1). Small-core: stdlib only."""
from __future__ import annotations

import json
import time

from .schemas import ActorRef, SCHEMA_VERSION
from .utils import canonical_json, payload_digest, sha256_hex

GENESIS = "0" * 64


class ChainError(Exception):
    pass


def _entry_hash(prev_hash: str, payload: dict, entry_type: str, seq: int,
                author: dict) -> str:
    return sha256_hex("|".join([
        prev_hash, payload_digest(payload), entry_type, str(seq),
        canonical_json(author),
    ]))


class Ledger:
    def __init__(self) -> None:
        self.entries: list[dict] = []

    def append(self, entry_type: str, author: ActorRef, payload: dict) -> dict:
        seq = len(self.entries)
        prev_hash = self.entries[-1]["entry_hash"] if self.entries else GENESIS
        author_d = author.to_dict()
        entry = {
            "schema_version": SCHEMA_VERSION,
            "seq": seq,
            "entry_type": entry_type,
            "author": author_d,
            "payload": payload,
            "ts": time.time(),
            "payload_hash": payload_digest(payload),
            "entry_hash": _entry_hash(prev_hash, payload, entry_type, seq, author_d),
        }
        self.entries.append(entry)
        return entry

    def verify_chain(self) -> tuple[bool, str]:
        prev = GENESIS
        for e in self.entries:
            ph = payload_digest(e["payload"])
            if e["payload_hash"] != ph:
                return False, f"payload hash mismatch at seq {e['seq']}"
            expect = _entry_hash(prev, e["payload"], e["entry_type"], e["seq"], e["author"])
            if e["entry_hash"] != expect:
                return False, f"entry hash mismatch at seq {e['seq']}"
            prev = e["entry_hash"]
        return True, "ok"

    def query(self, entry_type: str | None = None) -> list[dict]:
        return [e for e in self.entries
                if entry_type is None or e["entry_type"] == entry_type]

    def save(self, path: str) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            for e in self.entries:
                f.write(canonical_json(e) + "\n")
        os.replace(tmp, path)

    @classmethod
    def load(cls, path: str) -> "Ledger":
        led = cls()
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    led.entries.append(json.loads(line))
        return led


import os  # noqa: E402  (kept at bottom for save())
```

Correction — put `import os` at the top with the other imports instead of the bottom. Final header:

```python
import json
import os
import time
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_ledger.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/ledger.py tests/test_ledger.py
git commit -m "feat: append-only hash-chained ledger with JSONL persistence"
```

---

### Task 4: Key Store (ed25519 + Enrollment)

**Files:**
- Create: `veridict/keys.py`
- Test: `tests/test_keys.py`

**Interfaces:**
- Consumes: `Ledger`, `ActorRef`.
- Produces: `KeyStore(ledger)` with `generate_and_enroll(identity) -> key_id`, `sign(key_id, message: bytes) -> str (b64)`, `verify_signature(public_pem, message, sig_b64) -> bool`, `public_pem(key_id) -> str`, `system_author` ActorRef — consumed by Task 11 (`CertificateIssuer`), Task 12–13.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_keys.py
from veridict.keys import KeyStore
from veridict.ledger import Ledger

def test_generate_and_enroll_writes_key_entry():
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("veridict-core")
    entries = led.query("key.enrolled")
    assert len(entries) == 1
    assert entries[0]["payload"]["key_id"] == kid
    assert entries[0]["payload"]["algorithm"] == "ed25519"

def test_sign_verify_roundtrip():
    led = Ledger(); ks = KeyStore(led)
    kid = ks.generate_and_enroll("veridict-core")
    msg = b"certificate-body"
    sig = ks.sign(kid, msg)
    assert ks.verify_signature(ks.public_pem(kid), msg, sig)

def test_tampered_message_fails_verification():
    led = Ledger(); ks = KeyStore(led)
    kid = ks.generate_and_enroll("veridict-core")
    sig = ks.sign(kid, b"original")
    assert not ks.verify_signature(ks.public_pem(kid), b"tampered", sig)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_keys.py -v`
Expected: FAIL — `ImportError: cannot import name 'KeyStore'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/keys.py
"""Key management: ed25519 enrollment + signing (§7.8, Phase 1 single-signer)."""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .ledger import Ledger
from .schemas import ActorRef
from .utils import sha256_hex

SYSTEM_AUTHOR = ActorRef(kind="system", identity="veridict-core", version="0.1.0")


class KeyStore:
    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger
        self._keys: dict[str, Ed25519PrivateKey] = {}

    def generate_and_enroll(self, identity: str) -> str:
        priv = Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        key_id = sha256_hex(pub_bytes)[:16]
        pub_pem = priv.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        self.ledger.append("key.enrolled", SYSTEM_AUTHOR, {
            "key_id": key_id, "algorithm": "ed25519",
            "purpose": "certificate-signing", "identity": identity,
            "public_pem": pub_pem,
        })
        self._keys[key_id] = priv
        return key_id

    def sign(self, key_id: str, message: bytes) -> str:
        return base64.b64encode(self._keys[key_id].sign(message)).decode("ascii")

    def public_pem(self, key_id: str) -> str:
        for e in self.ledger.query("key.enrolled"):
            if e["payload"]["key_id"] == key_id:
                return e["payload"]["public_pem"]
        raise KeyError(f"unknown key_id: {key_id}")

    @staticmethod
    def verify_signature(public_pem: str, message: bytes, sig_b64: str) -> bool:
        from cryptography.exceptions import InvalidSignature
        pub = serialization.load_pem_public_key(public_pem.encode("utf-8"))
        try:
            pub.verify(base64.b64decode(sig_b64), message)
            return True
        except InvalidSignature:
            return False
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_keys.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/keys.py tests/test_keys.py
git commit -m "feat: ed25519 keystore with ledger enrollment"
```

---

### Task 5: Divergence Detector

**Files:**
- Create: `veridict/divergence.py`
- Test: `tests/test_divergence.py`

**Interfaces:**
- Consumes: `EvidenceItem`, `TIER_RANK`.
- Produces: `compute_divergence(evidence: list[EvidenceItem], tolerance: float = 1/3) -> str` (one of `UNANIMOUS|MAJORITY|SPLIT`) — consumed by Tasks 9, 11, 12.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_divergence.py
from veridict.divergence import compute_divergence
from veridict.schemas import EvidenceItem

def _ev(tier, stance, n=1, family="fam"):
    out = []
    for i in range(n):
        out.append(EvidenceItem(
            evidence_id=f"e-{tier}-{stance}-{i}", claim_id="c1",
            evidence_class="JURY_OPINION", tier=tier,
            producer={"kind": "jury", "identity": f"{family}-{i}",
                      "version": "0.1.0", "family": family},
            artifact_ref="d", reproducibility={"deterministic": False,
            "rerun_recipe": None}, stance=stance, confidence=0.9))
    return out

def test_no_doctrinal_evidence_is_unanimous():
    assert compute_divergence(_ev("W1a", "SUPPORTS", 2)) == "UNANIMOUS"

def test_all_same_is_unanimous():
    ev = _ev("W2", "SUPPORTS", 3)
    assert compute_divergence(ev) == "UNANIMOUS"

def test_minority_within_tolerance_is_majority():
    ev = _ev("W2", "SUPPORTS", 2) + _ev("W2", "REFUTES", 1, family="g")
    assert compute_divergence(ev) == "MAJORITY"

def test_even_split_is_split():
    ev = _ev("W2", "SUPPORTS", 1) + _ev("W2", "REFUTES", 1, family="g")
    assert compute_divergence(ev) == "SPLIT"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_divergence.py -v`
Expected: FAIL — `ImportError: cannot import name 'compute_divergence'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/divergence.py
"""Divergence detection (§4.1 divergence.flagged, §5.4): disagreement is information."""
from __future__ import annotations

from .schemas import EvidenceItem


def compute_divergence(evidence: list[EvidenceItem], tolerance: float = 1 / 3) -> str:
    """Classify doctrinal disagreement (W2/W3 stances only).

    Minority fraction <= tolerance -> MAJORITY, else SPLIT; W1-only -> UNANIMOUS
    (vacuous — the ladder handles W1 conflicts directly).
    """
    doctrinal = [e for e in evidence if e.tier in ("W2", "W3")]
    if not doctrinal:
        return "UNANIMOUS"
    n_sup = sum(1 for e in doctrinal if e.stance == "SUPPORTS")
    n_ref = len(doctrinal) - n_sup
    if n_sup == 0 or n_ref == 0:
        return "UNANIMOUS"
    minority = min(n_sup, n_ref)
    return "MAJORITY" if minority / len(doctrinal) <= tolerance else "SPLIT"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_divergence.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/divergence.py tests/test_divergence.py
git commit -m "feat: divergence detector with tolerance-based majority/split"
```

---

### Task 6: Claim Extractor (Deterministic)

**Files:**
- Create: `veridict/claim_extractor.py`
- Test: `tests/test_claim_extractor.py`

**Interfaces:**
- Consumes: `Claim`, `TaskManifest`, `sha256_hex`.
- Produces: `ClaimExtractor.extract(task: TaskManifest, artifact_digest: str) -> list[Claim]` — consumed by Tasks 12, 15.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_claim_extractor.py
import pytest
from veridict.claim_extractor import ClaimExtractor
from veridict.schemas import TaskManifest

def _task(intent=(), crit=(), has_tests=True):
    return TaskManifest(task_id="t1", artifact_path=".", actor_identity="ai-dev",
                        intent_lines=tuple(intent), criticality=tuple(crit),
                        has_existing_tests=has_tests, pytest_args=())

def test_machine_and_doctrine_lines_parsed():
    claims = ClaimExtractor().extract(
        _task(["MACHINE: refund equals subtotal",
               "MACHINE(payments): invoice total is stable",
               "DOCTRINE: api usage is idiomatic"]), "digest")
    ver = {c.predicate: c.verifiability for c in claims}
    assert ver["refund-equals-subtotal"] == "MACHINE_CHECKABLE"
    assert ver["invoice-total-is-stable"] == "MACHINE_CHECKABLE"
    assert ver["api-usage-is-idiomatic"] == "DOCTRINAL"

def test_critical_class_attached():
    claims = ClaimExtractor().extract(
        _task(["MACHINE(payments): invoice total is stable"], crit=("payments",)), "digest")
    c = next(c for c in claims if c.predicate == "invoice-total-is-stable")
    assert c.critical_class == "payments"

def test_auto_claims_present():
    claims = ClaimExtractor().extract(_task(), "digest")
    preds = {c.predicate for c in claims}
    assert "existing-test-suite-passes" in preds
    assert "forbidden-constructs-absent" in preds

def test_auto_claim_verifiability_and_falsifiers():
    claims = ClaimExtractor().extract(_task(), "digest")
    by = {c.predicate: c for c in claims}
    assert by["existing-test-suite-passes"].falsifiable_by == ("test_execution",)
    assert by["forbidden-constructs-absent"].falsifiable_by == ("static_analysis",)
    assert all(c.verifiability == "MACHINE_CHECKABLE"
               for c in (by["existing-test-suite-passes"],
                         by["forbidden-constructs-absent"]))

def test_claim_ids_deterministic():
    a = ClaimExtractor().extract(_task(["MACHINE: x equals y"]), "digest")
    b = ClaimExtractor().extract(_task(["MACHINE: x equals y"]), "digest")
    assert [c.claim_id for c in a] == [c.claim_id for c in b]

def test_invalid_line_raises():
    with pytest.raises(ValueError):
        ClaimExtractor().extract(_task(["FREEFORM: no tag"]), "digest")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_claim_extractor.py -v`
Expected: FAIL — `ImportError: cannot import name 'ClaimExtractor'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/claim_extractor.py
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
        for line in task.intent_lines:
            m = _LINE.match(line)
            if not m:
                raise ValueError(f"invalid intent line: {line!r}")
            kind, cls, body = m.group(1), m.group(2), m.group(3)
            claims.append(self._claim(
                task, artifact_digest, subject="intent", predicate=_slug(body),
                summary=body, verifiability="MACHINE_CHECKABLE" if kind == "MACHINE"
                else "DOCTRINAL", falsifiable_by=("test_execution", "static_analysis")
                if kind == "MACHINE" else ("jury",), critical_class=cls))
        if task.has_existing_tests:
            claims.append(self._claim(
                task, artifact_digest, subject="repo",
                predicate="existing-test-suite-passes", summary="existing test suite passes",
                verifiability="MACHINE_CHECKABLE", falsifiable_by=("test_execution",),
                critical_class=None))
        claims.append(self._claim(
            task, artifact_digest, subject="repo",
            predicate="forbidden-constructs-absent",
            summary="no bare except / eval / exec introduced",
            verifiability="MACHINE_CHECKABLE", falsifiable_by=("static_analysis",),
            critical_class=None))
        return claims

    def _claim(self, task: TaskManifest, digest: str, subject: str, predicate: str,
               summary: str, verifiability: str, falsifiable_by: tuple[str, ...],
               critical_class: str | None) -> Claim:
        claim_id = sha256_hex(f"{task.task_id}|{predicate}|{verifiability}")[:16]
        return Claim(
            claim_id=claim_id, task_id=task.task_id, subject=subject,
            predicate=predicate, scope="repo", summary=summary,
            derived_from=digest, verifiability=verifiability,
            falsifiable_by=falsifiable_by, critical_class=critical_class)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_claim_extractor.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/claim_extractor.py tests/test_claim_extractor.py
git commit -m "feat: deterministic claim extractor with intent grammar"
```

---

### Task 7: Built-in Verifiers (Test Executor W1a + Static Analyzer W1b)

**Files:**
- Create: `veridict/verifiers.py`
- Test: `tests/test_verifiers.py`

**Interfaces:**
- Consumes: `Claim`, `TaskManifest`, `EvidenceItem`, `sha256_hex`.
- Produces: `TestExecutorVerifier.produce(claim, task, timeout_seconds=600) -> EvidenceItem | None` and `StaticAnalyzerVerifier.produce(claim, task, timeout_seconds=120) -> EvidenceItem | None` — consumed by Tasks 12, 14, 15. `None` = ABSTAIN (§5.4), never evidence.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_verifiers.py
import subprocess, sys
from veridict.claim_extractor import ClaimExtractor
from veridict.schemas import TaskManifest
from veridict.verifiers import TestExecutorVerifier, StaticAnalyzerVerifier

def _task(tmp_path, code, test_code):
    (tmp_path / "calc.py").write_text(code)
    (tmp_path / "test_calc.py").write_text(test_code)
    return TaskManifest(task_id="t", artifact_path=str(tmp_path),
                        actor_identity="ai-dev", intent_lines=(), criticality=(),
                        has_existing_tests=True, pytest_args=())

def _claims(task, digest="d"):
    return {c.predicate: c for c in ClaimExtractor().extract(task, digest)}

def test_executor_supports_passing_suite(tmp_path):
    task = _task(tmp_path, "def add(a, b):\n    return a + b\n",
                 "def test_add():\n    assert add(1, 1) == 2\n")
    ev = TestExecutorVerifier().produce(_claims(task)["existing-test-suite-passes"], task)
    assert ev is not None
    assert ev.tier == "W1a" and ev.stance == "SUPPORTS" and ev.confidence == 1.0
    assert ev.evidence_class == "TEST_EXECUTION"
    assert ev.reproducibility["deterministic"] is True
    assert ev.reproducibility["rerun_recipe"]["cmd"]

def test_executor_refutes_failing_suite(tmp_path):
    task = _task(tmp_path, "def add(a, b):\n    return a - b\n",
                 "def test_add():\n    assert add(1, 1) == 2\n")
    ev = TestExecutorVerifier().produce(_claims(task)["existing-test-suite-passes"], task)
    assert ev.tier == "W1a" and ev.stance == "REFUTES"

def test_executor_abstains_on_wrong_claim(tmp_path):
    task = _task(tmp_path, "def add(a, b):\n    return a + b\n",
                 "def test_add():\n    assert add(1, 1) == 2\n")
    ev = TestExecutorVerifier().produce(_claims(task)["forbidden-constructs-absent"], task)
    assert ev is None  # abstain — claim not falsifiable by test_execution

def test_static_refutes_bare_except_and_eval(tmp_path):
    task = _task(tmp_path, "def f(x):\n    try:\n        eval(x)\n    except:\n        pass\n",
                 "def test_f():\n    assert f('1+1') == 2\n")
    ev = StaticAnalyzerVerifier().produce(_claims(task)["forbidden-constructs-absent"], task)
    assert ev.tier == "W1b" and ev.stance == "REFUTES"
    assert ev.reproducibility["rerun_recipe"] is not None

def test_static_supports_clean_artifact(tmp_path):
    task = _task(tmp_path, "def add(a, b):\n    return a + b\n",
                 "def test_add():\n    assert add(1, 1) == 2\n")
    ev = StaticAnalyzerVerifier().produce(_claims(task)["forbidden-constructs-absent"], task)
    assert ev.tier == "W1b" and ev.stance == "SUPPORTS"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_verifiers.py -v`
Expected: FAIL — `ImportError: cannot import name 'TestExecutorVerifier'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/verifiers.py
"""Built-in verifiers (§5.1): TestExecutor (W1a), StaticAnalyzer (W1b).

Both return None on abstain — no evidence item is produced (§5.4).
Every W1a item carries a rerun_recipe (§5.1 invariant).
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys

from .schemas import ActorRef, Claim, EvidenceItem, TaskManifest
from .utils import iter_python_files

TEST_ACTOR = ActorRef(kind="verifier", identity="test-executor", version="0.1.0")
STATIC_ACTOR = ActorRef(kind="verifier", identity="static-analyzer", version="0.1.0")
EID_SALT = "veridict-evidence-v1"


class TestExecutorVerifier:
    def produce(self, claim: Claim, task: TaskManifest,
                timeout_seconds: int = 600) -> EvidenceItem | None:
        if "test_execution" not in claim.falsifiable_by:
            return None
        cmd = [sys.executable, "-m", "pytest", "-q", "--tb=no",
               *task.pytest_args]
        recipe = {"cmd": cmd, "cwd": task.artifact_path,
                  "timeout_seconds": timeout_seconds}
        try:
            proc = subprocess.run(cmd, cwd=task.artifact_path, timeout=timeout_seconds,
                                  capture_output=True, text=True)
        except subprocess.TimeoutExpired:
            return None
        if proc.returncode in (2, 3, 4, 5):   # usage/internal/no-tests → abstain
            return None
        stance = "SUPPORTS" if proc.returncode == 0 else "REFUTES"
        return EvidenceItem(
            evidence_id=f"{EID_SALT}-" + claim.claim_id + "-testexec",
            claim_id=claim.claim_id, evidence_class="TEST_EXECUTION", tier="W1a",
            producer=TEST_ACTOR.to_dict(), artifact_ref=claim.derived_from,
            reproducibility={"deterministic": True, "rerun_recipe": recipe},
            stance=stance, confidence=1.0)


FORBIDDEN_CALLS = {"eval", "exec", "compile"}


class StaticAnalyzerVerifier:
    """AST rules v0 (W1b statistical signal, §5.1 #3): bare-except, eval/exec/compile."""

    def produce(self, claim: Claim, task: TaskManifest,
                timeout_seconds: int = 120) -> EvidenceItem | None:
        if "static_analysis" not in claim.falsifiable_by:
            return None
        findings: list[str] = []
        for rel in iter_python_files(task.artifact_path):
            path = os.path.join(task.artifact_path, rel)
            try:
                tree = ast.parse(open(path, encoding="utf-8").read(), filename=rel)
            except SyntaxError as exc:
                findings.append(f"syntax-error:{rel}:{exc.lineno}")
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ExceptHandler) and node.type is None:
                    findings.append(f"bare-except:{rel}:{node.lineno}")
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id in FORBIDDEN_CALLS):
                    findings.append(f"forbidden-call:{rel}:{node.lineno}:{node.func.id}")
        stance = "REFUTES" if findings else "SUPPORTS"
        recipe = {"cmd": [sys.executable, "-m", "veridict.cli", "audit",
                          "--task", "<task.json>", "--mode", "CERTIFICATE"],
                  "cwd": task.artifact_path, "timeout_seconds": timeout_seconds}
        return EvidenceItem(
            evidence_id=f"{EID_SALT}-" + claim.claim_id + "-static",
            claim_id=claim.claim_id, evidence_class="STATIC_ANALYSIS", tier="W1b",
            producer=STATIC_ACTOR.to_dict(), artifact_ref=claim.derived_from,
            reproducibility={"deterministic": False, "rerun_recipe": recipe},
            stance=stance, confidence=0.9 if stance == "REFUTES" else 0.7)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_verifiers.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/verifiers.py tests/test_verifiers.py
git commit -m "feat: built-in verifiers — test executor (W1a) + static analyzer (W1b)"
```

---

### Task 8: Blind Heterogeneous Jury

**Files:**
- Create: `veridict/jury.py`
- Test: `tests/test_jury.py`

**Interfaces:**
- Consumes: `Claim`, `EvidenceItem`, `ActorRef`, `sha256_hex`.
- Produces: `Opinion`, `ProviderError`, `ScriptedProvider(family, identity, responses, default)`, `OpenAICompatProvider(family, identity, version)` (env: `VERIDICT_JURY_URL`, `VERIDICT_JURY_KEY`, `VERIDICT_JURY_MODEL`), `Jury(providers).evaluate(claim, artifact_digest) -> (items: list[EvidenceItem], abstained: list[str])` — consumed by Tasks 12, 14, 15. Constructor raises `ValueError` if fewer than 2 distinct families.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_jury.py
import pytest
from veridict.claim_extractor import ClaimExtractor
from veridict.jury import Jury, Opinion, ScriptedProvider, ProviderError
from veridict.schemas import TaskManifest

CLAIM = ClaimExtractor().extract(
    TaskManifest(task_id="t", artifact_path=".", actor_identity="a",
                 intent_lines=("DOCTRINE: api usage is idiomatic",), criticality=(),
                 has_existing_tests=False, pytest_args=()), "d")[0]

def _jury(fam_a="stub-a", op_a="SUPPORTS", fam_b="stub-b", op_b="SUPPORTS"):
    return Jury([
        ScriptedProvider(family=fam_a, identity=f"{fam_a}-1",
                         default=Opinion(op_a, 0.8, "looks fine")),
        ScriptedProvider(family=fam_b, identity=f"{fam_b}-1",
                         default=Opinion(op_b, 0.8, "agrees")),
    ])

def test_requires_two_distinct_families():
    with pytest.raises(ValueError):
        _jury(fam_a="same", fam_b="same")

def test_evaluate_produces_blind_w2_evidence():
    items, abstained = _jury().evaluate(CLAIM, "digest")
    assert abstained == []
    assert len(items) == 2
    assert all(e.tier == "W2" and e.evidence_class == "JURY_OPINION"
               and e.stance == "SUPPORTS" for e in items)
    assert {e.producer["family"] for e in items} == {"stub-a", "stub-b"}
    assert all(e.reproducibility["deterministic"] is False for e in items)

def test_provider_error_is_recorded_as_abstain_not_evidence():
    class Boom(ScriptedProvider):
        def doctrine(self, claim_summary, artifact_digest):
            raise ProviderError("simulated outage")
    boom = Boom(family="boom", identity="boom-1", default=Opinion("SUPPORTS", 0.5, ""))
    items, abstained = _jury() | None or Jury([boom, ScriptedProvider(
        family="stub-b", identity="stub-b-1", default=Opinion("SUPPORTS", 0.8, ""))]).evaluate(CLAIM, "digest")
    assert items and len(items) == 1          # only the healthy provider
    assert abstained == ["boom-1"]            # abstention reported, never evidence

def test_blindness_providers_receive_no_cross_context():
    seen = []
    class Recorder(ScriptedProvider):
        def doctrine(self, claim_summary, artifact_digest):
            seen.append(claim_summary)
            return super().doctrine(claim_summary, artifact_digest)
    rec = Recorder(family="rec", identity="rec-1", default=Opinion("SUPPORTS", 0.8, ""))
    _jury(fam_b="x")  # noop guard
    j = Jury([rec, ScriptedProvider(family="stub-b", identity="stub-b-1",
                                    default=Opinion("SUPPORTS", 0.8, ""))])
    j.evaluate(CLAIM, "digest")
    assert len(seen) == 1
    assert "other opinions" not in seen[0]
```

Note: fix the `Boom` test — the `| None or` expression is nonsense. Use directly:

```python
    j = Jury([Boom(family="boom", identity="boom-1",
                   default=Opinion("SUPPORTS", 0.5, "")),
              ScriptedProvider(family="stub-b", identity="stub-b-1",
                               default=Opinion("SUPPORTS", 0.8, ""))])
    items, abstained = j.evaluate(CLAIM, "digest")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_jury.py -v`
Expected: FAIL — `ImportError: cannot import name 'Jury'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/jury.py
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
                 responses: dict[str, Opinion] | None = None, version: str = "0.1.0"):
        self.family = family
        self.identity = identity
        self.version = version
        self.default = default
        self.responses = responses or {}

    def doctrine(self, claim_summary: str, artifact_digest: str) -> Opinion:
        return self.responses.get(claim_summary, self.default)


class OpenAICompatProvider:
    """Any OpenAI-compatible chat endpoint; expects strict-JSON opinion back."""
    def __init__(self, family: str, identity: str, version: str = "0.1.0"):
        self.family = family
        self.identity = identity
        self.version = version
        self.base_url = os.environ["VERIDICT_JURY_URL"]
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
        except (httpx.HTTPError, KeyError, ValueError, json.JSONDecodeError) as exc:
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_jury.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/jury.py tests/test_jury.py
git commit -m "feat: blind heterogeneous jury with family diversity enforcement"
```

---

### Task 9: Adjudication Ladder (R0–R4, Tier Rules R1–R5)

**Files:**
- Create: `veridict/ladder.py`
- Test: `tests/test_ladder.py`

**Interfaces:**
- Consumes: `Claim`, `EvidenceItem`, `compute_divergence`, `PolicyDeclaration` (duck-typed: `.mode`, `.criticality`).
- Produces: `Adjudication(claim_id, value, divergence, rung, risk_notes: list[str], meta_claims: list[dict])`, `adjudicate(claim, evidence, policy) -> Adjudication` — consumed by Tasks 10–12, 15. This is the spec §4.3 heart; the five rule tests below are Phase 1 exit criterion ④.

- [ ] **Step 1: Write the failing tests (one per tier rule + mode behavior)**

```python
# tests/test_ladder.py
import dataclasses

from veridict.ladder import adjudicate
from veridict.schemas import Claim, EvidenceItem

POL = dataclasses.SimpleNamespace(mode="CERTIFICATE", criticality=("payments",),
                                  meta_claim_depth_budget=2)

def _claim(ver="MACHINE_CHECKABLE", crit=None):
    return Claim(claim_id="c1", task_id="t", subject="repo", predicate="p", scope="r",
                 summary="s", derived_from="d", verifiability=ver,
                 falsifiable_by=("test_execution",), critical_class=crit)

def _ev(tier, stance, family="fam", cls="JURY_OPINION"):
    return EvidenceItem(evidence_id=f"{tier}-{stance}-{family}", claim_id="c1",
                        evidence_class=cls, tier=tier,
                        producer={"kind": "verifier", "identity": family,
                                  "version": "0.1.0"},
                        artifact_ref="d",
                        reproducibility={"deterministic": tier in ("W1a",),
                                         "rerun_recipe": {"cmd": ["pytest"]}},
                        stance=stance, confidence=1.0 if tier == "W1a" else 0.8)

# Rule R1: strict ordering — W1a wins every cross-tier conflict.
def test_rule1_w1a_refute_beats_w2_support():
    a = adjudicate(_claim(), [_ev("W1a", "REFUTES", "tests"), _ev("W2", "SUPPORTS")], POL)
    assert a.value == "REFUTED" and a.rung == "R0"

# Rule R2: doctrine cannot overturn W1a, but opens a meta-claim + risk note.
def test_rule2_doctrine_refute_cannot_overturn_w1a():
    a = adjudicate(_claim(), [_ev("W1a", "SUPPORTS", "tests"), _ev("W2", "REFUTES")], POL)
    assert a.value == "VERIFIED" and a.rung == "R0"
    assert a.meta_claims and "doctrine cannot overturn" in a.risk_notes[0]

def test_rule2_meta_budget_exhausted_leaves_note_not_claim():
    a = adjudicate(_claim(), [_ev("W1a", "SUPPORTS", "tests"), _ev("W2", "REFUTES")],
                   dataclasses.replace(POL, meta_claim_depth_budget=0))
    assert a.meta_claims == [] and a.risk_notes

# Rule R3: SPLIT is information → divergence + risk note (not error).
def test_rule3_split_recorded_as_divergence_and_note():
    a = adjudicate(_claim(ver="DOCTRINAL"),
                   [_ev("W2", "SUPPORTS"), _ev("W2", "REFUTES", family="g")], POL)
    assert a.divergence == "SPLIT" and a.risk_notes

# Rule R4: W3 alone never verifies.
def test_rule4_w3_alone_never_verified():
    a = adjudicate(_claim(ver="DOCTRINAL"), [_ev("W3", "SUPPORTS")], POL)
    assert a.value == "INCONCLUSIVE"

# Rule R5: MACHINE_CHECKABLE without any W1 → at most INCONCLUSIVE.
def test_rule5_machine_claim_without_w1_never_verified():
    a = adjudicate(_claim(), [_ev("W2", "SUPPORTS"), _ev("W2", "SUPPORTS", family="g")], POL)
    assert a.value == "INCONCLUSIVE" and a.rung == "R0"

def test_rule5_w1b_alone_supports_machine_claim():
    a = adjudicate(_claim(), [_ev("W1b", "SUPPORTS", "static", cls="STATIC_ANALYSIS")], POL)
    assert a.value == "VERIFIED" and a.rung == "R1"

# R1 consensus paths.
def test_w1a_univocal_support_verifies():
    a = adjudicate(_claim(), [_ev("W1a", "SUPPORTS", "tests")], POL)
    assert a.value == "VERIFIED" and a.rung == "R0"

def test_w1b_refute_beats_w2_support():
    a = adjudicate(_claim(), [_ev("W1b", "REFUTES", "static", cls="STATIC_ANALYSIS"),
                              _ev("W2", "SUPPORTS")], POL)
    assert a.value == "REFUTED" and a.rung == "R1"

def test_doctrinal_unanimous_verifies_at_r1():
    a = adjudicate(_claim(ver="DOCTRINAL"),
                   [_ev("W2", "SUPPORTS"), _ev("W2", "SUPPORTS", family="g")], POL)
    assert a.value == "VERIFIED" and a.rung == "R1"

# R2/R3: mode-dependent handling of SPLIT.
def test_gate_critical_split_escalates():
    pol = dataclasses.replace(POL, mode="GATE")
    a = adjudicate(_claim(ver="DOCTRINAL", crit="payments"),
                   [_ev("W2", "SUPPORTS"), _ev("W2", "REFUTES", family="g")], pol)
    assert a.value == "ESCALATED" and a.rung == "R3"

def test_certificate_split_is_inconclusive_with_note():
    a = adjudicate(_claim(ver="DOCTRINAL", crit="payments"),
                   [_ev("W2", "SUPPORTS"), _ev("W2", "REFUTES", family="g")], POL)
    assert a.value == "INCONCLUSIVE" and a.risk_notes

# No evidence at all → INCONCLUSIVE (abstain ≠ refute, §5.4).
def test_no_evidence_is_inconclusive():
    a = adjudicate(_claim(), [], POL)
    assert a.value == "INCONCLUSIVE"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_ladder.py -v`
Expected: FAIL — `ImportError: cannot import name 'adjudicate'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/ladder.py
"""Adjudication ladder R0–R4 (§6.2) with tier rules R1–R5 of §4.3 verbatim."""
from __future__ import annotations

from dataclasses import dataclass, field

from .divergence import compute_divergence
from .schemas import Claim, EvidenceItem


@dataclass
class Adjudication:
    claim_id: str
    value: str                       # VERIFIED | REFUTED | INCONCLUSIVE | ESCALATED
    divergence: str                  # UNANIMOUS | MAJORITY | SPLIT
    rung: str                        # R0 | R1 | R2 | R3 | R4
    risk_notes: list[str] = field(default_factory=list)
    meta_claims: list[dict] = field(default_factory=list)


def _is_critical(claim: Claim, policy) -> bool:
    return claim.critical_class is not None and claim.critical_class in policy.criticality


def _gate_mode(policy) -> bool:
    return policy.mode in ("GATE", "HYBRID")


def adjudicate(claim: Claim, evidence: list[EvidenceItem], policy) -> Adjudication:
    div = compute_divergence(evidence, policy.divergence_tolerance)
    w1a = [e for e in evidence if e.tier == "W1a"]
    w1b = [e for e in evidence if e.tier == "W1b"]
    doctrine = [e for e in evidence if e.tier in ("W2", "W3")]
    notes: list[str] = []

    # R0 — machine evidence is univocal.
    if any(e.stance == "REFUTES" for e in w1a):
        return Adjudication(claim.claim_id, "REFUTED", div, "R0", notes)
    if w1a and all(e.stance == "SUPPORTS" for e in w1a):
        if any(e.stance == "REFUTES" for e in doctrine):
            # Rule R2: doctrine cannot overturn W1a but may open a meta-claim.
            notes.append("doctrine cannot overturn machine evidence (rule R2)")
            if len(getattr(policy, "meta_claim_depth_budget", 2)) >= 1:
                notes.append("meta-claim: does the machine evidence cover the refuted aspect?")
            meta = ({"subject": f"coverage-of:{claim.predicate}",
                     "depth": 1} if policy.meta_claim_depth_budget >= 1 else [])
            return Adjudication(claim.claim_id, "VERIFIED", div, "R0",
                                notes, meta_claims=meta)
        return Adjudication(claim.claim_id, "VERIFIED", div, "R0", notes)

    # Rule R5: MACHINE_CHECKABLE without any W1 → at most INCONCLUSIVE (mechanical).
    if claim.verifiability == "MACHINE_CHECKABLE" and not (w1a or w1b):
        return Adjudication(claim.claim_id, "INCONCLUSIVE", div, "R0",
                            ["rule R5: machine-checkable claim without W1 evidence"])

    # R1 — W1b + doctrine consensus.
    if w1b and any(e.stance == "REFUTES" for e in w1b):
        return Adjudication(claim.claim_id, "REFUTED", div, "R1", notes)
    if w1b and all(e.stance == "SUPPORTS" for e in w1b):
        if doctrine and div == "SPLIT":
            notes.append("jury split on machine-supported claim (rule R3: information)")
        if not doctrine or div != "SPLIT":
            return Adjudication(claim.claim_id, "VERIFIED", div, "R1", notes)

    # Doctrinal-only claims.
    if doctrine:
        if div in ("UNANIMOUS", "MAJORITY"):
            if all(e.stance == "SUPPORTS" for e in doctrine):
                return Adjudication(claim.claim_id, "VERIFIED", div, "R1", notes)
            return Adjudication(claim.claim_id, "REFUTED", div, "R1", notes)
        # SPLIT → R2/R3, mode-dependent.
        if _is_critical(claim, policy) and _gate_mode(policy):
            return Adjudication(claim.claim_id, "ESCALATED", div, "R3",
                                ["critical claim split — escalated to human risk owner"])
        return Adjudication(claim.claim_id, "INCONCLUSIVE", div, "R2",
                            ["jury split (rule R3): divergence recorded as information"])

    # W3 alone cannot verify (rule R4).
    notes.append("rule R4: single-model doctrine alone cannot verify")
    return Adjudication(claim.claim_id, "INCONCLUSIVE", div, "R2", notes)
```

Correction during write: the line `if len(getattr(policy, "meta_claim_depth_budget", 2)) >= 1:` is wrong (len of an int). Replace the whole R0-supports block with:

```python
    if w1a and all(e.stance == "SUPPORTS" for e in w1a):
        if any(e.stance == "REFUTES" for e in doctrine):
            notes.append("doctrine cannot overturn machine evidence (rule R2)")
            if policy.meta_claim_depth_budget >= 1:
                meta = [{"subject": f"coverage-of:{claim.predicate}", "depth": 1}]
                return Adjudication(claim.claim_id, "VERIFIED", div, "R0",
                                    notes, meta_claims=meta)
            notes.append("meta-claim budget exhausted (§7.2 #2)")
            return Adjudication(claim.claim_id, "VERIFIED", div, "R0", notes)
        return Adjudication(claim.claim_id, "VERIFIED", div, "R0", notes)
```

Also `policy.divergence_tolerance` is a plain attribute on the real `PolicyDeclaration` (Task 10) — the SimpleNamespace test double carries it too. Add `divergence_tolerance=1/3` to `POL` in the test file:

```python
POL = dataclasses.SimpleNamespace(mode="CERTIFICATE", criticality=("payments",),
                                  meta_claim_depth_budget=2, divergence_tolerance=1 / 3)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_ladder.py -v`
Expected: PASS (13 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/ladder.py tests/test_ladder.py
git commit -m "feat: adjudication ladder R0-R4 with tier rules R1-R5 (exit criterion 4)"
```

---

### Task 10: Policy Engine (4 Modes)

**Files:**
- Create: `veridict/policy.py`
- Test: `tests/test_policy.py`

**Interfaces:**
- Consumes: `Claim`, `Adjudication`, `EvidenceItem`, `Ledger`, `ActorRef`, `SCHEMA_VERSION`.
- Produces: `Thresholds`, `PolicyDeclaration` (fields: `schema_version, mode, criticality, thresholds, escalation_route, response_window_hours, budget_seconds, divergence_tolerance`; `.to_dict()/.from_dict()`), `load_policy(path) -> PolicyDeclaration`, `AuditOutcome(mode, blocked, coverage, per_claim: list[dict], flags: list[str])`, `PolicyEngine(ledger, policy).apply(claims, adjudications, evidence_by_claim) -> AuditOutcome` (also records a `policy.decision` entry) — consumed by Tasks 11–15.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_policy.py
import dataclasses

from veridict.policy import (PolicyDeclaration, Thresholds, load_policy,
                             PolicyEngine)
from veridict.ledger import Ledger
from veridict.schemas import ActorRef, Claim, EvidenceItem

POL = PolicyDeclaration(schema_version="1.0.0", mode="GATE", criticality=("payments",),
                        thresholds=Thresholds(), escalation_route="human-risk-owner",
                        response_window_hours=24, budget_seconds=1800,
                        divergence_tolerance=1 / 3)

def _claim(cid, ver="MACHINE_CHECKABLE", crit=None):
    return Claim(claim_id=cid, task_id="t", subject="repo", predicate=cid, scope="r",
                 summary=cid, derived_from="d", verifiability=ver,
                 falsifiable_by=("test_execution",), critical_class=crit)

def _adj(cid, value):
    return dataclasses.SimpleNamespace(claim_id=cid, value=value)

def _ev(cid, tier="W1a"):
    return EvidenceItem(evidence_id=f"e-{cid}", claim_id=cid,
                        evidence_class="TEST_EXECUTION", tier=tier,
                        producer={"kind": "verifier", "identity": "x", "version": "0"},
                        artifact_ref="d",
                        reproducibility={"deterministic": True, "rerun_recipe": None},
                        stance="SUPPORTS", confidence=1.0)

def test_gate_blocks_on_refuted_critical_claim():
    out = PolicyEngine(Ledger(), POL).apply([_claim("c1", crit="payments")],
                                            [_adj("c1", "REFUTED")], {"c1": [_ev("c1")]})
    assert out.blocked is True

def test_gate_blocks_when_w1_coverage_below_threshold():
    claims = [_claim("c1", crit="payments"), _claim("c2")]
    adjs = [_adj("c1", "VERIFIED"), _adj("c2", "VERIFIED")]
    ev = {"c1": [_ev("c1")], "c2": [_ev("c2", tier="W2")]}   # c2 has no W1
    out = PolicyEngine(Ledger(), POL).apply(claims, adjs, ev)  # coverage 1/2 = 0.5 < 0.8
    assert out.blocked is True and out.coverage == 0.5

def test_gate_passes_when_all_verified_and_covered():
    claims = [_claim("c1"), _claim("c2")]
    adjs = [_adj("c1", "VERIFIED"), _adj("c2", "VERIFIED")]
    ev = {"c1": [_ev("c1")], "c2": [_ev("c2")]}
    out = PolicyEngine(Ledger(), POL).apply(claims, adjs, ev)
    assert out.blocked is False and out.coverage == 1.0

def test_certificate_mode_never_blocks_but_reports_unresolved():
    pol = dataclasses.replace(POL, mode="CERTIFICATE")
    out = PolicyEngine(Ledger(), pol).apply([_claim("c1", crit="payments")],
                                            [_adj("c1", "ESCALATED")], {"c1": [_ev("c1")]})
    assert out.blocked is False

def test_watch_mode_flags_not_blocks():
    pol = dataclasses.replace(POL, mode="WATCH")
    out = PolicyEngine(Ledger(), pol).apply([_claim("c1")], [_adj("c1", "REFUTED")],
                                            {"c1": [_ev("c1")]})
    assert out.blocked is False and out.flags  # REFUTED claim surfaces as a flag

def test_policy_decision_entry_recorded():
    led = Ledger()
    PolicyEngine(led, POL).apply([_claim("c1")], [_adj("c1", "VERIFIED")], {"c1": [_ev("c1")]})
    entries = led.query("policy.decision")
    assert len(entries) == 1
    assert entries[0]["author"]["kind"] == "policy_engine"
    assert entries[0]["payload"]["mode"] == "GATE"

def test_hybrid_blocks_on_critical_only(tmp_path):
    pol = dataclasses.replace(POL, mode="HYBRID")
    claims = [_claim("crit", crit="payments"), _claim("minor")]
    adjs = [_adj("crit", "REFUTED"), _adj("minor", "INCONCLUSIVE")]
    ev = {"crit": [_ev("crit")], "minor": []}
    out = PolicyEngine(Ledger(), pol).apply(claims, adjs, ev)
    assert out.blocked is True  # critical REFUTED blocks even though minor is only inconclusive
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_policy.py -v`
Expected: FAIL — `ImportError: cannot import name 'PolicyDeclaration'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/policy.py
"""Policy engine (§6.1): policy is data, not code; four modes, thresholds."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from .ledger import Ledger
from .schemas import ActorRef, Claim, SCHEMA_VERSION

POLICY_AUTHOR = ActorRef(kind="policy_engine", identity="veridict-policy", version="0.1.0")


@dataclass(frozen=True)
class Thresholds:
    min_jury_families: int = 2
    divergence_tolerance: float = 1 / 3
    min_w1_coverage: float = 0.8
    meta_claim_depth_budget: int = 2


@dataclass(frozen=True)
class PolicyDeclaration:
    schema_version: str
    mode: str                                  # CERTIFICATE | GATE | WATCH | HYBRID
    criticality: tuple[str, ...]
    thresholds: Thresholds
    escalation_route: str = "human-risk-owner"
    response_window_hours: int = 24
    budget_seconds: int = 1800
    divergence_tolerance: float = 1 / 3

    def to_dict(self) -> dict:
        d = asdict(self)
        d["criticality"] = list(self.criticality)
        return d

    @staticmethod
    def from_dict(d: dict) -> "PolicyDeclaration":
        return PolicyDeclaration(
            schema_version=d.get("schema_version", SCHEMA_VERSION), mode=d["mode"],
            criticality=tuple(d["criticality"]), thresholds=Thresholds(**d["thresholds"]),
            escalation_route=d.get("escalation_route", "human-risk-owner"),
            response_window_hours=d.get("response_window_hours", 24),
            budget_seconds=d.get("budget_seconds", 1800),
            divergence_tolerance=d.get("divergence_tolerance", 1 / 3))


def load_policy(path: str) -> PolicyDeclaration:
    with open(path, encoding="utf-8") as f:
        return PolicyDeclaration.from_dict(json.load(f))


@dataclass
class AuditOutcome:
    mode: str
    blocked: bool
    coverage: float
    per_claim: list[dict]
    flags: list[str]


class PolicyEngine:
    """Policy never changes what evidence says (§6.1 Principle 1) — only the reaction."""

    def __init__(self, ledger: Ledger, policy: PolicyDeclaration) -> None:
        self.ledger = ledger
        self.policy = policy

    def apply(self, claims: list[Claim], adjudications: list,
              evidence_by_claim: dict[str, list[EvidenceItem]]) -> AuditOutcome:
        p = self.policy
        adj_by_id = {a.claim_id: a for a in adjudications}
        machine = [c for c in claims if c.verifiability == "MACHINE_CHECKABLE"]
        covered = sum(1 for c in machine
                      if any(e.tier in ("W1a", "W1b")
                             for e in evidence_by_claim.get(c.claim_id, [])))
        coverage = (covered / len(machine)) if machine else 1.0

        per_claim: list[dict] = []
        flags: list[str] = []
        blocked = False
        for c in claims:
            a = adj_by_id[c.claim_id]
            critical = c.critical_class is not None and c.critical_class in p.criticality
            per_claim.append({"claim_id": c.claim_id, "verdict": a.value,
                              "divergence": a.divergence, "critical": critical})
            if a.divergence == "SPLIT":
                flags.append(f"divergence-split:{c.claim_id}")
            if a.value in ("REFUTED", "ESCALATED", "INCONCLUSIVE"):
                flags.append(f"{a.value.lower()}:{c.claim_id}")
            if p.mode in ("GATE", "HYBRID") and critical and a.value in (
                    "REFUTED", "ESCALATED", "INCONCLUSIVE"):
                blocked = True
        if p.mode in ("GATE", "HYBRID") and coverage < p.thresholds.min_w1_coverage:
            blocked = True
        if p.mode == "WATCH":
            blocked = False
        self.ledger.append("policy.decision", POLICY_AUTHOR, {
            "mode": p.mode, "blocked": blocked, "coverage": coverage,
            "thresholds": asdict(p.thresholds),
        })
        return AuditOutcome(p.mode, blocked, coverage, per_claim, flags)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_policy.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/policy.py tests/test_policy.py
git commit -m "feat: policy engine — 4 modes, thresholds, W1 coverage gate"
```

---

### Task 11: Certificate Issuer + Offline Verifier

**Files:**
- Create: `veridict/certificate.py`
- Test: `tests/test_certificate.py`

**Interfaces:**
- Consumes: `Ledger`, `KeyStore`, `PolicyDeclaration`, `Claim`, `EvidenceItem`, `Adjudication`, `adjudicate`, `canonical_json`.
- Produces: `CertificateIssuer(ledger, keystore, key_id).issue(task, artifact_digest, policy, claims, adjudications, evidence_by_claim, jury_families, disclosure_level, scope_limits) -> dict cert`; `verify_certificate(ledger_path, cert_path) -> dict {valid, chain_valid, signature_valid, verdicts_match, errors}` — consumed by Tasks 12–15. **Verifier imports core modules only (§7.3 mechanism 3).**

- [ ] **Step 1: Write the failing test**

```python
# tests/test_certificate.py
import dataclasses, json

from veridict.certificate import CertificateIssuer, verify_certificate
from veridict.claim_extractor import ClaimExtractor
from veridict.ledger import Ledger
from veridict.keys import KeyStore
from veridict.ladder import adjudicate
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import TaskManifest

def _fixture(tmp_path, code, test):
    (tmp_path / "calc.py").write_text(code)
    (tmp_path / "test_calc.py").write_text(test)
    return TaskManifest(task_id="t1", artifact_path=str(tmp_path),
                        actor_identity="ai-dev", intent_lines=(), criticality=(),
                        has_existing_tests=True, pytest_args=())

def _run(tmp_path):
    task = _fixture(tmp_path, "def add(a, b):\n    return a + b\n",
                    "def test_add():\n    assert add(1, 1) == 2\n")
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("veridict-core")
    pol = PolicyDeclaration(schema_version="1.0.0", mode="CERTIFICATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    claims = ClaimExtractor().extract(task, "digest")
    ev = {"existing-test-suite-passes": [], "forbidden-constructs-absent": []}
    adjs = [adjudicate(c, ev.get(c.claim_id, []), pol) for c in claims]
    cert = CertificateIssuer(led, ks, kid).issue(
        task=task, artifact_digest="digest", policy=pol, claims=claims,
        adjudications=adjs, evidence_by_claim=ev, jury_families=["stub-a", "stub-b"],
        disclosure_level="REDACTED",
        scope_limits=["claim coverage is heuristic, not exhaustive"])
    cert_path = str(tmp_path / "cert.json")
    ledger_path = str(tmp_path / "ledger.jsonl")
    led.save(ledger_path)
    json.dump(cert, open(cert_path, "w"))
    return cert, ledger_path, cert_path

def test_issue_produces_signed_certificate(tmp_path):
    cert, _, _ = _run(tmp_path)
    assert cert["policy_mode"] == "CERTIFICATE"
    assert cert["disclosure_level"] == "REDACTED"
    assert cert["signatures"][0]["algorithm"] == "ed25519"
    assert cert["ledger_anchor"]["chain_hash"]
    assert "claim coverage is heuristic" in " ".join(cert["scope_limits"])

def test_verify_accepts_honest_certificate(tmp_path):
    cert, lp, cp = _run(tmp_path)
    report = verify_certificate(lp, cp)
    assert report["valid"] is True, report["errors"]
    assert report["chain_valid"] and report["signature_valid"] and report["verdicts_match"]

def test_verify_rejects_tampered_ledger(tmp_path):
    cert, lp, cp = _run(tmp_path)
    lines = open(lp).read().splitlines()
    entry = json.loads(lines[0])
    entry["payload"]["tampered"] = True            # retroactive edit
    lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    open(lp, "w").write("\n".join(lines) + "\n")
    assert verify_certificate(lp, cp)["valid"] is False

def test_verify_rejects_tampered_certificate(tmp_path):
    cert, lp, cp = _run(tmp_path)
    cert["claims"][0]["verdict_value"] = "REFUTED"   # tamper after signing
    json.dump(cert, open(cp, "w"))
    assert verify_certificate(lp, cp)["valid"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_certificate.py -v`
Expected: FAIL — `ImportError: cannot import name 'CertificateIssuer'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/certificate.py
"""Certificate issuance (§4.2) + offline replay verification (§7.3 m3).

verify_certificate imports core modules ONLY — never jury/verifiers/audit.
"""
from __future__ import annotations

import json

from .divergence import compute_divergence
from .keys import KeyStore
from .ladder import adjudicate
from .ledger import Ledger
from .policy import PolicyDeclaration, Thresholds
from .schemas import ActorRef, Claim, EvidenceItem, SCHEMA_VERSION
from .utils import canonical_json, payload_digest, sha256_hex

ADJUDICATOR = ActorRef(kind="adjudicator", identity="veridict-issuer", version="0.1.0")


def _risk_level(values: list[str]) -> str:
    if any(v in ("REFUTED", "ESCALATED") for v in values):
        return "high"
    if any(v == "INCONCLUSIVE" for v in values):
        return "medium"
    return "low"


class CertificateIssuer:
    def __init__(self, ledger: Ledger, keystore: KeyStore, key_id: str) -> None:
        self.ledger = ledger
        self.keystore = keystore
        self.key_id = key_id

    def issue(self, task, artifact_digest: str, policy: PolicyDeclaration,
              claims: list[Claim], adjudications: list, evidence_by_claim: dict,
              jury_families: list[str], disclosure_level: str,
              scope_limits: list[str]) -> dict:
        adj_by_id = {a.claim_id: a for a in adjudications}
        cert = {
            "schema_version": SCHEMA_VERSION,
            "cert_id": sha256_hex(f"{task.task_id}|{artifact_digest}")[:24],
            "subject": {"artifact_digest": artifact_digest, "task_id": task.task_id,
                        "actor_identity": task.actor_identity},
            "policy_mode": policy.mode,
            "policy_ref": {"mode": policy.mode, "criticality": list(policy.criticality),
                           "thresholds": {
                               "min_jury_families": policy.thresholds.min_jury_families,
                               "divergence_tolerance": policy.divergence_tolerance,
                               "min_w1_coverage": policy.thresholds.min_w1_coverage,
                               "meta_claim_depth_budget": policy.thresholds.meta_claim_depth_budget}},
            "claims": [{"claim_id": c.claim_id,
                        "verdict_value": adj_by_id[c.claim_id].value,
                        "divergence": adj_by_id[c.claim_id].divergence,
                        "evidence_ids": [e.evidence_id
                                         for e in evidence_by_claim.get(c.claim_id, [])]}
                       for c in claims],
            "jury_composition": {"families": jury_families},
            "disclosure_level": disclosure_level,
            "divergence_summary": {c.claim_id: adj_by_id[c.claim_id].divergence
                                   for c in claims},
            "risk_level": _risk_level([adj_by_id[c.claim_id].value for c in claims]),
            "score": round(sum(1 for c in claims
                               if adj_by_id[c.claim_id].value == "VERIFIED")
                           / len(claims), 3) if claims else 0.0,
            "ledger_anchor": {},          # filled after checkpoint below
            "signatures": [],
            "verify_instructions": "veridict verify --ledger <ledger.jsonl> --cert <cert.json>",
            "scope_limits": ["claim coverage is heuristic, not exhaustive",
                             *scope_limits],
            "issued_at_task": task.task_id,
        }
        checkpoint = self.ledger.append("checkpoint.anchored", ActorRef(
            kind="system", identity="veridict-core", version="0.1.0"),
            {"chain_hash": self.ledger.entries[-1]["entry_hash"] if self.ledger.entries else None,
             "upto_seq": len(self.ledger.entries)})
        cert["ledger_anchor"] = {"checkpoint_seq": checkpoint["seq"],
                                 "chain_hash": checkpoint["payload"]["chain_hash"]}
        body = dict(cert)
        body.pop("signatures")
        cert["signatures"] = [{"key_id": self.key_id, "algorithm": "ed25519",
                               "sig_b64": self.keystore.sign(
                                   self.key_id, canonical_json(body).encode("utf-8"))}]
        self.ledger.append("certificate.issued", ADJUDICATOR, cert)
        return cert


def verify_certificate(ledger_path: str, cert_path: str) -> dict:
    errors: list[str] = []
    cert = json.load(open(cert_path, encoding="utf-8"))
    led = Ledger.load(ledger_path)
    chain_ok, chain_msg = led.verify_chain()
    if not chain_ok:
        errors.append(f"chain: {chain_msg}")

    # Signature over the unsigned body, verified against the enrolled key.
    body = dict(cert)
    sigs = body.pop("signatures", [])
    sig_ok = False
    for s in sigs:
        pub_pem = next((e["payload"]["public_pem"]
                        for e in led.query("key.enrolled")
                        if e["payload"]["key_id"] == s["key_id"]), None)
        if pub_pem and KeyStore.verify_signature(
                pub_pem, canonical_json(body).encode("utf-8"), s["sig_b64"]):
            sig_ok = True
            break
    if not sig_ok:
        errors.append("signature: no enrolled key verifies the certificate body")

    # Anchor check: chain_hash must equal the hash of the entry before checkpoint.
    anchor = cert.get("ledger_anchor", {})
    cp_seq = anchor.get("checkpoint_seq")
    if not isinstance(cp_seq, int) or cp_seq >= len(led.entries) or \
            led.entries[cp_seq]["entry_type"] != "checkpoint.anchored" or \
            led.entries[cp_seq]["payload"]["chain_hash"] != anchor.get("chain_hash"):
        errors.append("anchor: checkpoint does not match ledger")

    # Recompute verdicts from ledger evidence and compare.
    verdicts_match = True
    if chain_ok:
        pr = cert.get("policy_ref", {})
        pol = PolicyDeclaration(schema_version=SCHEMA_VERSION, mode=pr.get("mode", "CERTIFICATE"),
                                criticality=tuple(pr.get("criticality", [])),
                                thresholds=Thresholds(**pr.get("thresholds", {})),
                                divergence_tolerance=pr.get("thresholds", {}).get(
                                    "divergence_tolerance", 1 / 3))
        claims_by_id = {e["payload"]["claim_id"]: Claim.from_dict(e["payload"])
                        for e in led.query("claim.registered")}
        ev_by_claim: dict[str, list[EvidenceItem]] = {}
        for e in led.query("evidence.recorded"):
            ev_by_claim.setdefault(e["payload"]["claim_id"], []).append(
                EvidenceItem.from_dict(e["payload"]))
        for c in cert["claims"]:
            claim = claims_by_id.get(c["claim_id"])
            if claim is None:
                errors.append(f"claims: {c['claim_id']} not registered in ledger")
                verdicts_match = False
                continue
            recomputed = adjudicate(claim, ev_by_claim.get(c["claim_id"], []), pol)
            if recomputed.value != c["verdict_value"]:
                errors.append(f"verdict mismatch for {c['claim_id']}: "
                              f"cert={c['verdict_value']} recomputed={recomputed.value}")
                verdicts_match = False
    return {"valid": not errors, "chain_valid": chain_ok, "signature_valid": sig_ok,
            "verdicts_match": verdicts_match, "errors": errors}
```

Note: `certificate.issued` is appended AFTER `checkpoint.anchored`, so the checkpoint covers the full evidence chain; the cert body itself is bound by signature, not by the anchor. `payload_digest` import is unused — remove it from the import line. Final import line: `from .utils import canonical_json, sha256_hex`.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_certificate.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/certificate.py tests/test_certificate.py
git commit -m "feat: certificate issuer + offline replay verifier (exit criterion 2 core)"
```

---

### Task 12: Audit Orchestrator

**Files:**
- Create: `veridict/audit.py`
- Test: `tests/test_audit.py`

**Interfaces:**
- Consumes: everything above (Ledger, KeyStore, ClaimExtractor, verifiers, Jury, ladder, PolicyEngine, CertificateIssuer).
- Produces: `artifact_digest(root: str) -> str`, `AuditOrchestrator(ledger, policy, jury, keystore, key_id).run(task: TaskManifest, disclosure_level="REDACTED") -> dict {cert, outcome, report}` where `report = {abstentions, duration_seconds, flags, task_id}` — consumed by Tasks 13–15. Writes the full entry sequence with authority-correct authors.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_audit.py
import dataclasses

from veridict.audit import AuditOrchestrator, artifact_digest
from veridict.claim_extractor import ClaimExtractor
from veridict.jury import Jury, Opinion, ScriptedProvider
from veridict.ledger import Ledger
from veridict.keys import KeyStore
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import TaskManifest

def _orchestrator(ledger, responses=None):
    ks = KeyStore(ledger)
    kid = ks.generate_and_enroll("veridict-core")
    jury = Jury([ScriptedProvider(family="stub-a", identity="stub-a-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok"),
                                  responses=responses or {}),
                 ScriptedProvider(family="stub-b", identity="stub-b-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok"),
                                  responses=responses or {})])
    pol = PolicyDeclaration(schema_version="1.0.0", mode="GATE", criticality=("payments",),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    return AuditOrchestrator(ledger, pol, jury, ks, kid), pol

def _task(tmp_path, intent=(), crit=()):
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "test_calc.py").write_text("def test_add():\n    assert add(1, 1) == 2\n")
    return TaskManifest(task_id="t1", artifact_path=str(tmp_path),
                        actor_identity="ai-dev", intent_lines=tuple(intent),
                        criticality=tuple(crit), has_existing_tests=True, pytest_args=())

def test_artifact_digest_is_stable_and_order_independent(tmp_path):
    (tmp_path / "a.py").write_text("x = 1"); (tmp_path / "b.py").write_text("y = 2")
    d1 = artifact_digest(str(tmp_path))
    (tmp_path / "a.py").write_text("x = 1")   # rewrite same content
    assert artifact_digest(str(tmp_path)) == d1

def test_full_pipeline_happy_path(tmp_path):
    task = _task(tmp_path)
    led = Ledger()
    orch, _ = _orchestrator(led)
    result = orch.run(task)
    types = [e["entry_type"] for e in led.entries]
    assert types[0] == "task.started"
    assert "actor.output" in types
    assert types.count("claim.registered") >= 3
    assert types.count("evidence.recorded") >= 5      # tests + static + jury(>=2)
    assert "policy.decision" in types and "certificate.issued" in types
    assert result["outcome"].blocked is False
    assert result["cert"]["risk_level"] == "low"

def test_actor_output_pins_digest(tmp_path):
    task = _task(tmp_path)
    led = Ledger()
    orch, _ = _orchestrator(led)
    orch.run(task)
    actor_entries = [e for e in led.entries if e["entry_type"] == "actor.output"]
    assert actor_entries[0]["author"]["kind"] == "actor"
    assert actor_entries[0]["payload"]["artifact_digest"] == artifact_digest(task.artifact_path)

def test_jury_split_flags_divergence(tmp_path):
    task = _task(tmp_path)
    split_responses = {"existing test suite passes": Opinion("REFUTES", 0.9, "suspicious")}
    led = Ledger()
    ks = KeyStore(led); kid = ks.generate_and_enroll("core")
    jury = Jury([ScriptedProvider(family="stub-a", identity="a-1",
                                  default=Opinion("SUPPORTS", 0.8, "ok")),
                 ScriptedProvider(family="stub-b", identity="b-1",
                                  default=Opinion("REFUTES", 0.9, "doubt"),
                                  responses=split_responses)])
    pol = PolicyDeclaration(schema_version="1.0.0", mode="CERTIFICATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    orch = AuditOrchestrator(led, pol, jury, ks, kid)
    result = orch.run(task)
    assert any(e["entry_type"] == "divergence.flagged" for e in led.entries)
    assert any("divergence-split" in f for f in result["outcome"].flags)

def test_meta_claim_registered_when_budget_allows(tmp_path):
    task = _task(tmp_path)
    led = Ledger()
    responses = {"existing test suite passes": Opinion("REFUTES", 0.9, "uncovered case")}
    orch, _ = _orchestrator(led, responses=responses)
    result = orch.run(task)
    preds = [e["payload"]["predicate"] for e in led.entries
             if e["entry_type"] == "claim.registered"]
    assert any(p.startswith("coverage-of") for p in preds)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_audit.py -v`
Expected: FAIL — `ImportError: cannot import name 'AuditOrchestrator'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/audit.py
"""Audit orchestrator (§3 flow): extract → fleet → divergence → ladder → policy → cert."""
from __future__ import annotations

import hashlib
import json
import os
import time

from .certificate import CertificateIssuer
from .claim_extractor import ClaimExtractor
from .divergence import compute_divergence
from .jury import Jury
from .keys import KeyStore
from .ladder import adjudicate
from .ledger import Ledger
from .policy import PolicyEngine, PolicyDeclaration
from .schemas import ActorRef, TaskManifest
from .utils import iter_python_files
from .verifiers import StaticAnalyzerVerifier, TestExecutorVerifier


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact_digest(root: str) -> str:
    parts = []
    for rel in iter_python_files(root):
        parts.append({"path": rel, "sha256": _hash_file(os.path.join(root, rel))})
    return hashlib.sha256(
        json.dumps(parts, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class AuditOrchestrator:
    def __init__(self, ledger: Ledger, policy: PolicyDeclaration, jury: Jury,
                 keystore: KeyStore, key_id: str) -> None:
        self.ledger = ledger
        self.policy = policy
        self.jury = jury
        self.keystore = keystore
        self.key_id = key_id

    def run(self, task: TaskManifest, disclosure_level: str = "REDACTED") -> dict:
        start = time.time()
        digest = artifact_digest(task.artifact_path)
        self.ledger.append("task.started", ActorRef(kind="policy_engine",
                           identity="veridict-audit", version="0.1.0"),
                           {"task_id": task.task_id, "mode": self.policy.mode})
        self.ledger.append("actor.output", ActorRef(kind="actor",
                           identity=task.actor_identity, version="unknown"),
                           {"artifact_digest": digest, "task_id": task.task_id})
        extractor_author = ActorRef(kind="claim_extractor",
                                    identity="veridict-extractor", version="0.1.0")
        claims = ClaimExtractor().extract(task, digest)
        for c in claims:
            self.ledger.append("claim.registered", extractor_author, c.to_dict())

        test_v, static_v = TestExecutorVerifier(), StaticAnalyzerVerifier()
        evidence_by_claim: dict[str, list] = {}
        abstentions: list[str] = []
        for c in claims:
            items: list = []
            for producer in (test_v, static_v):
                ev = producer.produce(c, task, self.policy.budget_seconds)
                if ev is not None:
                    items.append(ev)
                    self.ledger.append("evidence.recorded", ActorRef(
                        kind="verifier", identity=ev.producer["identity"],
                        version=ev.producer["version"]), ev.to_dict())
            jury_items, jury_abstained = self.jury.evaluate(c, digest)
            abstentions.extend(jury_abstained)
            for ev in jury_items:
                self.ledger.append("evidence.recorded", ActorRef(
                    kind="jury", identity=ev.producer["identity"],
                    version=ev.producer["version"]), ev.to_dict())
            items.extend(jury_items)
            evidence_by_claim[c.claim_id] = items

        for c in claims:
            div = compute_divergence(evidence_by_claim[c.claim_id],
                                     self.policy.divergence_tolerance)
            if div == "SPLIT":
                self.ledger.append("divergence.flagged", ActorRef(
                    kind="divergence_detector", identity="veridict-divergence",
                    version="0.1.0"), {"claim_id": c.claim_id, "divergence": div})

        # Meta-claims (rule R2), one level, depth-budgeted (§7.2 #2).
        adjudications = [adjudicate(c, evidence_by_claim[c.claim_id], self.policy)
                         for c in claims]
        for c, a in zip(claims, adjudications):
            for meta in a.meta_claims:
                meta_claim = ClaimExtractor()._claim(
                    task, digest, subject=meta["subject"],
                    predicate=meta["subject"].replace(":", "-"),
                    summary=f"meta: does machine evidence cover {meta['subject']}?",
                    verifiability="DOCTRINAL", falsifiable_by=("jury",),
                    critical_class=c.critical_class)
                self.ledger.append("claim.registered", extractor_author,
                                   meta_claim.to_dict())
                jury_items, abst = self.jury.evaluate(meta_claim, digest)
                abstentions.extend(abst)
                for ev in jury_items:
                    self.ledger.append("evidence.recorded", ActorRef(
                        kind="jury", identity=ev.producer["identity"],
                        version=ev.producer["version"]), ev.to_dict())
                evidence_by_claim[meta_claim.claim_id] = jury_items
                adjudications.append(adjudicate(meta_claim, jury_items, self.policy))

        for a in adjudications:
            if a.value == "ESCALATED":
                self.ledger.append("escalation.requested", ActorRef(
                    kind="adjudicator", identity="veridict-ladder", version="0.1.0"),
                    {"claim_id": a.claim_id, "route": self.policy.escalation_route,
                     "dossier_summary": "see risk_notes", "risk_notes": a.risk_notes})

        engine = PolicyEngine(self.ledger, self.policy)
        outcome = engine.apply(claims, adjudications, evidence_by_claim)

        issuer = CertificateIssuer(self.ledger, self.keystore, self.key_id)
        cert = issuer.issue(
            task=task, artifact_digest=digest, policy=self.policy, claims=claims,
            adjudications=adjudications, evidence_by_claim=evidence_by_claim,
            jury_families=sorted({p.family for p in self.jury.providers}),
            disclosure_level=disclosure_level,
            scope_limits=["doctrinal jury opinions are provider-dependent"])
        report = {"abstentions": sorted(set(abstentions)),
                  "duration_seconds": round(time.time() - start, 3),
                  "flags": outcome.flags, "task_id": task.task_id}
        return {"cert": cert, "outcome": outcome, "report": report}
```

Note on `ClaimExtractor()._claim` use for meta-claims: `_claim` is nominally private; rename it to `make_claim` in Task 6 (public) and update `extract` accordingly — cleaner than a private call. Apply that rename in Task 6's implementation before merging (test stays identical).

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_audit.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Run the full suite (no regressions)**

Run: `python -m pytest -q`
Expected: all green

- [ ] **Step 6: Commit**

```bash
git add veridict/audit.py tests/test_audit.py veridict/claim_extractor.py
git commit -m "feat: audit orchestrator wiring the full B-spine pipeline"
```

---

### Task 13: CLI (audit / verify / quality-sheet)

**Files:**
- Create: `veridict/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `AuditOrchestrator`, `load_policy`, `verify_certificate`, `CanaryRunner` (imported lazily in quality-sheet command).
- Produces: `main(argv=None) -> int` (console script `veridict`). Exit codes: `0` ok, `1` invalid, `2` gate-blocked. Subcommands:
  - `audit --task task.json [--mode MODE] [--policy policy.json] [--ledger out.jsonl] [--cert-out cert.json]`
  - `verify --ledger ledger.jsonl --cert cert.json`
  - `quality-sheet --corpus corpus.jsonl --out sheet.json`
  Task JSON: `{"task_id", "artifact_path", "actor_identity", "intent_lines", "criticality", "has_existing_tests", "pytest_args"}`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
import json

import pytest

from veridict.cli import main

def _task_json(tmp_path, mode):
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (tmp_path / "test_calc.py").write_text("def test_add():\n    assert add(1, 1) == 2\n")
    return {"task_id": "cli-t", "artifact_path": str(tmp_path),
            "actor_identity": "ai-dev", "intent_lines": [], "criticality": [],
            "has_existing_tests": True, "pytest_args": []}

def test_audit_then_verify_roundtrip(tmp_path, capsys):
    tj = tmp_path / "task.json"
    json.dump(_task_json(tmp_path, "CERTIFICATE"), open(tj, "w"))
    rc = main(["audit", "--task", str(tj), "--mode", "CERTIFICATE",
               "--ledger", str(tmp_path / "led.jsonl"),
               "--cert-out", str(tmp_path / "cert.json")])
    assert rc == 0
    rc = main(["verify", "--ledger", str(tmp_path / "led.jsonl"),
               "--cert", str(tmp_path / "cert.json")])
    assert rc == 0

def test_verify_detects_corruption(tmp_path, capsys):
    tj = tmp_path / "task.json"
    json.dump(_task_json(tmp_path, "CERTIFICATE"), open(tj, "w"))
    main(["audit", "--task", str(tj), "--mode", "CERTIFICATE",
          "--ledger", str(tmp_path / "led.jsonl"),
          "--cert-out", str(tmp_path / "cert.json")])
    lines = open(tmp_path / "led.jsonl").read().splitlines()
    e = json.loads(lines[0]); e["payload"]["x"] = 1
    lines[0] = json.dumps(e, sort_keys=True, separators=(",", ":"))
    open(tmp_path / "led.jsonl", "w").write("\n".join(lines) + "\n")
    rc = main(["verify", "--ledger", str(tmp_path / "led.jsonl"),
               "--cert", str(tmp_path / "cert.json")])
    assert rc == 1

def test_audit_gate_blocked_exits_2(tmp_path):
    tj = tmp_path / "task.json"
    # failing test suite + payments criticality → REFUTED critical claim → block
    d = _task_json(tmp_path, "GATE")
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    d["intent_lines"] = ["MACHINE(payments): add computes sums"]
    json.dump(d, open(tj, "w"))
    rc = main(["audit", "--task", str(tj), "--mode", "GATE",
               "--ledger", str(tmp_path / "led2.jsonl"),
               "--cert-out", str(tmp_path / "cert2.json")])
    assert rc == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'veridict.cli'`

- [ ] **Step 3: Write the implementation**

```python
# veridict/cli.py
"""CLI (§ Phase 1): audit / verify / quality-sheet. Exit: 0 ok, 1 invalid, 2 blocked."""
from __future__ import annotations

import argparse
import json
import os
import sys

from .audit import AuditOrchestrator, artifact_digest
from .certificate import verify_certificate
from .jury import Jury, OpenAICompatProvider, Opinion, ScriptedProvider
from .keys import KeyStore
from .ledger import Ledger
from .policy import PolicyDeclaration, Thresholds, load_policy
from .schemas import TaskManifest

DEFAULT_POLICY = PolicyDeclaration(
    schema_version="1.0.0", mode="HYBRID", criticality=(),
    thresholds=Thresholds(), divergence_tolerance=1 / 3)


def _build_jury() -> tuple[Jury, list[str]]:
    """Assemble ≥2-family jury from env; pad with scripted stubs (warned)."""
    warnings: list[str] = []
    providers = []
    if os.environ.get("VERIDICT_JURY_URL"):
        providers.append(OpenAICompatProvider(family="openai-compat-1", identity="http-1"))
    if os.environ.get("VERIDICT_JURY_URL2"):
        providers.append(OpenAICompatProvider(family="openai-compat-2", identity="http-2"))
    n = 0
    while len(providers) < 2:
        n += 1
        warnings.append(f"jury provider {len(providers) + 1} is a SCRIPTED STUB — "
                        "configure VERIDICT_JURY_URL[/URL2] for real doctrine")
        providers.append(ScriptedProvider(family=f"stub-{n}", identity=f"stub-{n}-1",
                                          default=Opinion("SUPPORTS", 0.8, "stub")))
    return Jury(providers), warnings


def _cmd_audit(args) -> int:
    raw = json.load(open(args.task, encoding="utf-8"))
    task = TaskManifest(
        task_id=raw["task_id"], artifact_path=raw["artifact_path"],
        actor_identity=raw["actor_identity"],
        intent_lines=tuple(raw.get("intent_lines", [])),
        criticality=tuple(raw.get("criticality", [])),
        has_existing_tests=raw.get("has_existing_tests", False),
        pytest_args=tuple(raw.get("pytest_args", [])))
    policy = load_policy(args.policy) if args.policy else DEFAULT_POLICY
    if args.mode:
        policy = PolicyDeclaration(
            schema_version=policy.schema_version, mode=args.mode,
            criticality=policy.criticality, thresholds=policy.thresholds,
            escalation_route=policy.escalation_route,
            response_window_hours=policy.response_window_hours,
            budget_seconds=policy.budget_seconds,
            divergence_tolerance=policy.divergence_tolerance)
    ledger = Ledger()
    keystore = KeyStore(ledger)
    key_id = keystore.generate_and_enroll("veridict-core")
    jury, warnings = _build_jury()
    orch = AuditOrchestrator(ledger, policy, jury, keystore, key_id)
    result = orch.run(task, disclosure_level=args.disclosure)
    ledger.save(args.ledger)
    with open(args.cert_out, "w", encoding="utf-8") as f:
        json.dump(result["cert"], f, indent=2, sort_keys=True)
    print(json.dumps({"report": result["report"],
                      "blocked": result["outcome"].blocked,
                      "warnings": warnings}, indent=2))
    return 2 if result["outcome"].blocked else 0


def _cmd_verify(args) -> int:
    report = verify_certificate(args.ledger, args.cert)
    print(json.dumps(report, indent=2))
    return 0 if report["valid"] else 1


def _cmd_quality_sheet(args) -> int:
    from .canary import CanaryRunner          # lazy import keeps verify offline-clean
    from .audit import AuditOrchestrator as _AO   # noqa: F401 (re-export clarity)

    def audit_fn(task, disclosure):
        ledger = Ledger()
        keystore = KeyStore(ledger)
        key_id = keystore.generate_and_enroll("canary")
        jury, _ = _build_jury()
        orch = AuditOrchestrator(ledger, DEFAULT_POLICY, jury, keystore, key_id)
        return orch.run(task, disclosure)

    from .canary import build_orchestrator
    sheet = CanaryRunner(lambda task, disclosure: build_orchestrator(
        DEFAULT_POLICY).run(task, disclosure)).run(args.corpus)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(sheet, f, indent=2, sort_keys=True)
    print(json.dumps(sheet["per_class"], indent=2))
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="veridict")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit")
    a.add_argument("--task", required=True)
    a.add_argument("--mode", choices=("CERTIFICATE", "GATE", "WATCH", "HYBRID"))
    a.add_argument("--policy")
    a.add_argument("--ledger", required=True)
    a.add_argument("--cert-out", required=True)
    a.add_argument("--disclosure", default="REDACTED",
                   choices=("LOCAL_ONLY", "REDACTED", "FULL"))
    a.set_defaults(func=_cmd_audit)
    v = sub.add_parser("verify")
    v.add_argument("--ledger", required=True)
    v.add_argument("--cert", required=True)
    v.set_defaults(func=_cmd_verify)
    q = sub.add_parser("quality-sheet")
    q.add_argument("--corpus", required=True)
    q.add_argument("--out", required=True)
    q.set_defaults(func=_cmd_quality_sheet)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
```

Correction: `_cmd_quality_sheet` contains two dead lines (`audit_fn` defined but unused; `_AO` import). Final body:

```python
def _cmd_quality_sheet(args) -> int:
    from .canary import CanaryRunner, build_orchestrator   # lazy: keeps `verify` offline-clean
    sheet = CanaryRunner(lambda task, disclosure: build_orchestrator(
        DEFAULT_POLICY).run(task, disclosure)).run(args.corpus)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(sheet, f, indent=2, sort_keys=True)
    print(json.dumps(sheet["per_class"], indent=2))
    return 0
```

This requires `canary.build_orchestrator(policy)` (Task 14) — implemented there.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/cli.py tests/test_cli.py
git commit -m "feat: CLI audit/verify/quality-sheet with exit-code contract"
```

---

### Task 14: Canary Protocol v0 + Corpus + Quality Sheet

**Files:**
- Create: `veridict/canary.py`, `corpus/corpus.jsonl`, `corpus/artifacts/case-sign-error/calc.py`, `corpus/artifacts/case-sign-error/test_calc.py`, `corpus/artifacts/case-uncovered-edge/calc.py`, `corpus/artifacts/case-uncovered-edge/test_calc.py`, `corpus/artifacts/case-uncovered-edge-uncatchable/calc.py`, `corpus/artifacts/case-uncovered-edge-uncatchable/test_calc.py`, `corpus/artifacts/case-clean/calc.py`, `corpus/artifacts/case-clean/test_calc.py`
- Test: `tests/test_canary.py`

**Interfaces:**
- Consumes: `AuditOrchestrator`, `TaskManifest`, `KeyStore`, `Ledger`.
- Produces: `build_orchestrator(policy) -> AuditOrchestrator` (stub-jury; per-caller override possible), `CanaryRunner(audit_fn).run(corpus_path) -> dict` Quality Sheet: `{"generated_at", "provider_families", "cases": [{"id", "ground_truth", "caught"}], "per_class": {class: {"caught", "total"}}, "caught_total", "false_positives"}` — exit criterion ⑥. Caught rule: DEFECT case → audit flagged (blocked or any REFUTED verdict); CLEAN case → false positive if flagged.

- [ ] **Step 1: Create the corpus artifacts (all test suites PASS inside their case)**

```python
# corpus/artifacts/case-sign-error/calc.py
def add(a, b):
    return a - b          # sign error; test below was written to the bug
```
```python
# corpus/artifacts/case-sign-error/test_calc.py
def test_add():
    assert add(2, 1) == 1    # codifies the buggy behavior → suite passes
```

```python
# corpus/artifacts/case-uncovered-edge/calc.py
def divide(a, b):
    return a / b             # crashes on b=0; no test covers b=0
```
```python
# corpus/artifacts/case-uncovered-edge/test_calc.py
def test_divide():
    assert divide(6, 3) == 2.0
```

```python
# corpus/artifacts/case-uncovered-edge-uncatchable/calc.py  (identical to uncovered-edge)
def divide(a, b):
    return a / b
```
```python
# corpus/artifacts/case-uncovered-edge-uncatchable/test_calc.py
def test_divide():
    assert divide(6, 3) == 2.0
```

```python
# corpus/artifacts/case-clean/calc.py
def multiply(a, b):
    return a * b
```
```python
# corpus/artifacts/case-clean/test_calc.py
def test_multiply():
    assert multiply(2, 3) == 6
```

```jsonl
# corpus/corpus.jsonl
{"id": "canary-sign-error", "path": "corpus/artifacts/case-sign-error", "defect_class": "sign-error", "ground_truth": "DEFECT", "intent": ["MACHINE: add computes the sum of two numbers"], "criticality": []}
{"id": "canary-uncovered-edge", "path": "corpus/artifacts/case-uncovered-edge", "defect_class": "uncovered-edge", "ground_truth": "DEFECT", "intent": ["MACHINE: divide never crashes on zero denominator"], "criticality": []}
{"id": "canary-uncovered-edge-uncatchable", "path": "corpus/artifacts/case-uncovered-edge-uncatchable", "defect_class": "uncovered-edge", "ground_truth": "DEFECT", "intent": ["MACHINE: divide never crashes on zero denominator"], "criticality": []}
{"id": "canary-clean", "path": "corpus/artifacts/case-clean", "defect_class": "clean", "ground_truth": "CLEAN", "intent": [], "criticality": []}
```

Each JSONL line is one object (no line wrapping in the real file).

- [ ] **Step 2: Write the failing test**

```python
# tests/test_canary.py
import json

from veridict.canary import CanaryRunner, build_orchestrator
from veridict.claim_extractor import ClaimExtractor
from veridict.jury import Opinion, ScriptedProvider
from veridict.policy import PolicyDeclaration, Thresholds

def _pol():
    return PolicyDeclaration(schema_version="1.0.0", mode="GATE", criticality=(),
                             thresholds=Thresholds(), divergence_tolerance=1 / 3)

def test_quality_sheet_counts_catches_and_false_positives():
    # Scripted jury refutes the two catchable intents; the uncatchable case
    # deliberately slips through → honest 1/2 catch rate for uncovered-edge.
    def audit_fn(task, disclosure):
        ledger = __import__("veridict.ledger", fromlist=["Ledger"]).Ledger()
        ks = __import__("veridict.keys", fromlist=["KeyStore"]).KeyStore(ledger)
        kid = ks.generate_and_enroll("canary")
        jury = Jury = None  # replaced below; placeholder removed in implementation
        return build_orchestrator(_pol(), overrides={
            "stub-a": Opinion("REFUTES", 0.9, "defect spotted")}).run(task, disclosure)

    sheet = CanaryRunner(audit_fn).run("corpus/corpus.jsonl")
    assert sheet["cases"][0]["caught"] is True          # sign-error: W1a REFUTES (suite fails? no — suite passes!)
```

**Correction — the sign-error case's suite PASSES** (test codifies the bug), so W1a SUPPORTS; the catch must come from doctrine (scripted REFUTE) or from `intent` claim vs. artifact behavior. Rework the scripted override: the stub refutes *any* claim whose summary contains "sum of two numbers" (sign-error intent) and "never crashes on zero denominator" (uncovered-edge intent), supports everything else → catches 2/2? Then the uncatchable case is identical to uncovered-edge — indistinguishable by stub. Make the uncatchable case intent empty (`[]`) so no refutable claim exists → honest miss. Update corpus line 3: `"intent": []`.

Final test:

```python
# tests/test_canary.py
import json

from veridict.canary import CanaryRunner, build_orchestrator
from veridict.jury import Opinion, ScriptedProvider
from veridict.policy import PolicyDeclaration, Thresholds

def _pol():
    return PolicyDeclaration(schema_version="1.0.0", mode="GATE", criticality=(),
                             thresholds=Thresholds(), divergence_tolerance=1 / 3)

def _audit_fn():
    refutable = {"add computes the sum of two numbers",
                 "divide never crashes on zero denominator"}
    return build_orchestrator(_pol(), provider_overrides={
        "stub-a": lambda summary: Opinion("REFUTES", 0.9, "defect spotted")
        if summary in refutable else Opinion("SUPPORTS", 0.8, "ok"),
        "stub-b": lambda summary: Opinion("SUPPORTS", 0.8, "ok")})

def test_quality_sheet_counts_catches_and_false_positives():
    sheet = CanaryRunner(_audit_fn()).run("corpus/corpus.jsonl")
    by_id = {c["id"]: c["caught"] for c in sheet["cases"]}
    assert by_id["canary-sign-error"] is True
    assert by_id["canary-uncovered-edge"] is True
    assert by_id["canary-uncovered-edge-uncatchable"] is False   # honest miss
    assert by_id["canary-clean"] is False                        # no false positive
    assert sheet["per_class"]["uncovered-edge"] == {"caught": 1, "total": 2}
    assert sheet["false_positives"] == 0

def test_quality_sheet_persists(tmp_path):
    sheet = CanaryRunner(_audit_fn()).run("corpus/corpus.jsonl")
    out = tmp_path / "sheet.json"
    out.write_text(json.dumps(sheet))
    assert json.loads(out.read_text())["caught_total"] == 2
```

Note: `ScriptedProvider.responses` maps summary→Opinion; the lambda form requires `provider_overrides` support — implement `build_orchestrator(policy, provider_overrides=None)`: overrides dict family→callable(summary)->Opinion or Opinion; construct ScriptedProvider with a `fn` field. Simpler: extend `ScriptedProvider` with optional `fn: Callable[[str], Opinion] | None` checked before `responses`. That is a Task 8 addition — implement in Task 8 Step 3 by appending to `ScriptedProvider.doctrine`:

```python
    def doctrine(self, claim_summary: str, artifact_digest: str) -> Opinion:
        if self.fn is not None:
            return self.fn(claim_summary)
        return self.responses.get(claim_summary, self.default)
```

with `fn=None` added to `__init__`. Add this to Task 8's implementation (one-line test addition optional).

- [ ] **Step 3: Write the implementation**

```python
# veridict/canary.py
"""Canary protocol v0 (§7.6): seeded defects, blind injection, Quality Sheet."""
from __future__ import annotations

import json
import time

from .audit import AuditOrchestrator
from .jury import Jury, Opinion, ScriptedProvider
from .keys import KeyStore
from .ledger import Ledger
from .schemas import TaskManifest
from veridict.policy import PolicyDeclaration  # absolute import for clarity


def build_orchestrator(policy: PolicyDeclaration, provider_overrides: dict | None = None,
                       ledger: Ledger | None = None) -> AuditOrchestrator:
    overrides = provider_overrides or {}
    providers = []
    for i, family in enumerate(("stub-a", "stub-b"), start=1):
        ov = overrides.get(family)
        if callable(ov):
            providers.append(ScriptedProvider(family=family, identity=f"{family}-1",
                                              default=Opinion("SUPPORTS", 0.8, "ok"),
                                              fn=ov))
        elif isinstance(ov, Opinion):
            providers.append(ScriptedProvider(family=family, identity=f"{family}-1",
                                              default=ov))
        else:
            providers.append(ScriptedProvider(family=family, identity=f"{family}-1",
                                              default=Opinion("SUPPORTS", 0.8, "ok")))
    ledger = ledger or Ledger()
    keystore = KeyStore(ledger)
    key_id = keystore.generate_and_enroll("canary")
    return AuditOrchestrator(ledger, policy, Jury(providers), keystore, key_id)


class CanaryRunner:
    """Blind injection: canary cases use the exact production audit_fn (§7.6)."""

    def __init__(self, audit_fn) -> None:
        self.audit_fn = audit_fn

    def run(self, corpus_path: str) -> dict:
        cases_out: list[dict] = []
        per_class: dict[str, dict] = {}
        false_positives = 0
        with open(corpus_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                case = json.loads(line)
                task = TaskManifest(
                    task_id=case["id"], artifact_path=case["path"],
                    actor_identity="canary-actor",
                    intent_lines=tuple(case.get("intent", [])),
                    criticality=tuple(case.get("criticality", [])),
                    has_existing_tests=True, pytest_args=())
                result = self.audit_fn(task, "REDACTED")
                refuted = any(c["verdict"] == "REFUTED"
                              for c in result["outcome"].per_claim)
                flagged = refuted or result["outcome"].blocked
                caught = flagged if case["ground_truth"] == "DEFECT" else False
                if case["ground_truth"] == "CLEAN" and flagged:
                    false_positives += 1
                cases_out.append({"id": case["id"], "ground_truth":
                                  case["ground_truth"], "caught": caught})
                cls = per_class.setdefault(case["defect_class"], {"caught": 0, "total": 0})
                cls["total"] += 1
                cls["caught"] += 1 if caught else 0
        return {"generated_at": time.time(),
                "provider_families": ["stub-a", "stub-b"],
                "cases": cases_out, "per_class": per_class,
                "caught_total": sum(1 for c in cases_out if c["caught"]),
                "false_positives": false_positives}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_canary.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add veridict/canary.py tests/test_canary.py corpus/
git commit -m "feat: canary protocol v0 with seeded corpus and quality sheet (exit criterion 6)"
```

---

### Task 15: Dogfooding — Self-Audit + Latency Smoke (Exit Criteria ①③⑤)

**Files:**
- Create: `scripts/dogfood.py`
- Test: `tests/test_dogfood.py`
- Modify: `README.md` (status line: Phase 1 core implemented)

**Interfaces:**
- Consumes: `AuditOrchestrator` via `build_orchestrator`, `verify_certificate`, repo root as artifact.
- Produces: `dogfood(run_root=".", jury_overrides=None) -> dict {cert, outcome, report, verification}` — the run that satisfies exit criteria ① (system audits itself, receives certificate), ③ (a real artifact — this repo — audited end-to-end), ⑤ (latency measured, asserted < 600 s here; p95 < 30 min per §6.5), and enables ② (its ledger+cert feed `veridict verify`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dogfood.py
import time

from scripts.dogfood import dogfood

def test_dogfood_audits_itself_and_verifies():
    started = time.time()
    result = dogfood()
    elapsed = time.time() - started
    assert result["cert"]["policy_mode"] == "HYBRID"
    assert result["outcome"].blocked is False
    assert result["verification"]["valid"] is True, result["verification"]["errors"]
    assert elapsed < 600   # §6.5: GATE p95 target is 30 min; smoke assert 10 min
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_dogfood.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'scripts'`

- [ ] **Step 3: Write the implementation**

```python
# scripts/dogfood.py
"""Self-audit: Veridict audits its own repository (§7.3 mechanism 1)."""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict.certificate import verify_certificate       # noqa: E402
from veridict.canary import build_orchestrator            # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def dogfood(run_root: str = REPO_ROOT, jury_overrides: dict | None = None) -> dict:
    policy = json.load(open(os.path.join(run_root, "dogfood_policy.json"))) \
        if os.path.exists(os.path.join(run_root, "dogfood_policy.json")) else None
    from veridict.policy import PolicyDeclaration, Thresholds
    pol = (PolicyDeclaration.from_dict(policy) if policy else PolicyDeclaration(
        schema_version="1.0.0", mode="HYBRID", criticality=(),
        thresholds=Thresholds(), divergence_tolerance=1 / 3))
    task = __import__("veridict.schemas", fromlist=["TaskManifest"]).TaskManifest(
        task_id="dogfood-v0.1", artifact_path=run_root, actor_identity="veridict-v0.1",
        intent_lines=("DOCTRINE: core modules are idiomatic python",),
        criticality=(), has_existing_tests=True,
        pytest_args=("--ignore=tests/test_dogfood.py",))
    orch = build_orchestrator(pol, provider_overrides=jury_overrides or {})
    result = orch.run(task)
    ledger_path = os.path.join(run_root, "dogfood_ledger.jsonl")
    cert_path = os.path.join(run_root, "dogfood_cert.json")
    orch.ledger.save(ledger_path)
    json.dump(result["cert"], open(cert_path, "w"), indent=2, sort_keys=True)
    verification = verify_certificate(ledger_path, cert_path)
    return {**result, "verification": verification,
            "ledger_path": ledger_path, "cert_path": cert_path}


if __name__ == "__main__":
    out = dogfood()
    print(json.dumps({"risk_level": out["cert"]["risk_level"],
                      "score": out["cert"]["score"],
                      "blocked": out["outcome"].blocked,
                      "verification": out["verification"],
                      "duration_seconds": out["report"]["duration_seconds"]}, indent=2))
```

Also create `dogfood_policy.json` at repo root (the self-audit's declared policy — policy is data, §6.1 Principle 2):

```json
{
  "schema_version": "1.0.0",
  "mode": "HYBRID",
  "criticality": [],
  "thresholds": {"min_jury_families": 2, "divergence_tolerance": 0.3333333333333333,
                  "min_w1_coverage": 0.8, "meta_claim_depth_budget": 2},
  "escalation_route": "human-risk-owner",
  "response_window_hours": 24,
  "budget_seconds": 1800,
  "divergence_tolerance": 0.3333333333333333
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_dogfood.py -v`
Expected: PASS (1 passed). If the dogfood run's static analyzer flags `eval` inside `veridict/` — there are none — or the pytest suite inside dogfood fails, fix the flagged file, not the test.

- [ ] **Step 5: Update README status + run full suite + commit**

```markdown
# README.md — replace the Status section
## Status

Phase 1 core implemented: ledger, claim extraction, W1a/W1b verifiers, blind jury,
divergence detector, R0–R4 ladder, 4-mode policy engine, signed certificates with
offline replay verification, canary protocol v0. Self-audit: `python scripts/dogfood.py`.
```

```bash
python -m pytest -q            # full suite green
git add scripts/dogfood.py tests/test_dogfood.py dogfood_policy.json README.md
git commit -m "feat: dogfooding self-audit with offline verification (exit criteria 1,2,3,5)"
```

---

## Self-Review (performed after writing)

1. **Spec coverage (Phase 1 content → tasks):** ledger+hash chain→T3; claim extractor (deterministic layer, extractor-as-producer, actor never writes claims)→T6/T12; built-in verifiers test+static→T7; mini-jury ≥2 families blind→T8; divergence detector→T5; ladder R0–R4 + 5 rules→T9; policy engine 4 modes→T10; certificate+signing→T11; offline verifier CLI→T11/T13; orchestrator+actor.output pinning→T12; CLI exit codes→T13; canary v0→T14; dogfooding+latency→T15; W1 coverage gate→T10; meta-claim depth budget→T9/T12; abstain≠refute→T7/T8; disclosure_level→T11/T13; scope_limits→T11; policy-as-data (dogfood_policy.json)→T15. Exit criteria: ①T15 ②T11/T13/T15 ③T12/T15 ④T9 ⑤T15 ⑥T14.
2. **Placeholder scan:** two in-draft mistakes found and corrected inline (Task 8 Boom-test expression; Task 9 `len(getattr(...))` on int; Task 13 dead lines in quality-sheet; Task 14 corpus line-3 intent emptied; Task 6 `_claim`→`make_claim` rename reflected in Task 12). Remaining: none — every step carries real code.
3. **Type consistency:** `Claim` fields identical across T2/T6/T9/T12 (`critical_class`, `falsifiable_by` tuple); `EvidenceItem(**payload)` reconstruction matches `to_dict()` exactly; `ScriptedProvider` gained `fn` (T8, used by T14); `build_orchestrator(policy, provider_overrides, ledger)` used by T13/T14/T15 consistently; `Adjudication` field names (`value/divergence/rung/risk_notes/meta_claims`) used identically in T10/T11/T12; `PolicyDeclaration.divergence_tolerance` carried in both dataclass and test doubles.

## Execution Notes

- All commands run from repo root after `pip install -e ".[dev]"`.
- Real-jury runs (exit-criterion ⑥ beyond stubs): export `VERIDICT_JURY_URL`, `VERIDICT_JURY_URL2` (+optional `VERIDICT_JURY_KEY`, `VERIDICT_JURY_MODEL`) — the CLI pads with warned stubs if unset; the Quality Sheet records `provider_families` honestly.
- WATCH mode in Phase 1 is a single-pass flag emitter (per-task mini-certificates come with §4.5 lifecycle work in Phase 2).
