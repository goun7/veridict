"""Deterministic property fuzzing (Phase 3 stretch, zero new dependencies).

Randomized-but-seeded round-trip and tamper probes over the ledger core:
byte-exact serialization for arbitrary evidence shapes, and tamper detection
for arbitrary in-place mutations. 150 iterations per property — cheap, but it
covers shapes the hand-written tests never think to try.
"""
import copy
import json
import random

from veridict.ledger import Ledger
from veridict.schemas import ActorRef, Claim, EvidenceItem

TIERS = ("W1a", "W1b", "W2", "W3")
CLASSES = ("TEST_EXECUTION", "REPRODUCIBLE_RUN", "FORMAL_PROOF",
           "STATIC_ANALYSIS", "JURY_OPINION", "WATCHER_REPORT")
STANCES = ("SUPPORTS", "REFUTES")


def _random_evidence(rng: random.Random, i: int) -> EvidenceItem:
    tier = rng.choice(TIERS)
    return EvidenceItem(
        evidence_id=f"ev{i:04d}", claim_id=rng.choice(["c1", "c2", "c3"]),
        evidence_class=rng.choice(CLASSES), tier=tier,
        producer={"kind": rng.choice(["verifier", "jury", "watcher"]),
                  "identity": f"producer-{rng.randint(0, 5)}",
                  "version": rng.choice(["0.1.0", "0.2.0", "9"]),
                  "family": f"fam-{rng.randint(0, 3)}"},
        artifact_ref=rng.choice(["digest-a", "digest-b", ""]),
        reproducibility={"deterministic": tier in ("W1a", "W1b"),
                         "rerun_recipe": None if rng.random() < 0.7
                         else {"cmd": "pytest -x"}},
        stance=rng.choice(STANCES),
        confidence=round(rng.random(), 6),
        rationale=rng.choice(["", "rc=0", "shell=True at deploy.py:3", "üzüm"]))
    # note: non-ASCII rationale exercises the ASCII-escaping rule (§2.1)


def _random_claim(rng: random.Random, i: int) -> Claim:
    return Claim(claim_id=f"c{i}", task_id=f"t{rng.randint(0, 2)}",
                 subject=f"s{rng.randint(0, 3)}",
                 predicate=f"pred-{rng.randint(0, 9)}", scope="repo",
                 summary=f"claim body {i} — éğik", derived_from="digest",
                 verifiability=rng.choice(["MACHINE_CHECKABLE", "DOCTRINAL",
                                           "MIXED"]),
                 falsifiable_by=("test",), critical_class=None)


def test_roundtrip_property_150_shapes(tmp_path):
    rng = random.Random(20260910)
    for i in range(150):
        led = Ledger()
        led.append("claim.registered", ActorRef(kind="system", identity="core", version="1"),
                   _random_claim(rng, i % 3).to_dict())
        led.append("evidence.recorded",
                   ActorRef(kind="system", identity="core", version="1"),
                   _random_evidence(rng, i).to_dict())
        path = str(tmp_path / f"led{i}.jsonl")
        led.save(path)
        reloaded = Ledger.load(path)
        for original, roundtripped in zip(led.entries, reloaded.entries):
            assert original == roundtripped, f"iteration {i}: entry drift"
        # payload → schema → payload stays canonical-stable
        ev = EvidenceItem.from_dict(reloaded.entries[-1]["payload"])
        assert ev.to_dict() == reloaded.entries[-1]["payload"]


def test_tamper_property_150_mutations_always_detected(tmp_path):
    rng = random.Random(20260911)
    undetected = []
    for i in range(150):
        led = Ledger()
        for j in range(4):
            led.append("evidence.recorded",
                       ActorRef(kind="system", identity="core", version="1"),
                       _random_evidence(rng, j).to_dict())
        path = str(tmp_path / f"tam{i}.jsonl")
        led.save(path)
        lines = open(path, encoding="utf-8").read().splitlines()
        victim = rng.randrange(len(lines))
        entry = json.loads(lines[victim])
        field = rng.choice(["ts", "entry_type", "author", "payload",
                            "payload_hash", "prev_hash", "entry_hash"])
        if field == "ts":
            entry[field] = "2030-01-01T00:00:00"
        elif field == "payload":
            key = rng.choice(list(entry["payload"].keys()))
            entry["payload"][key] = f"tampered-{i}"
        elif field == "author":
            entry[field] = {"kind": "evil", "identity": "mallory", "version": "0"}
        else:
            # "f"*64 (not GENESIS "0"*64): a prev_hash mutation on seq 0 would
            # otherwise be a vacuous no-op, not an undetected tamper
            entry[field] = ("f" * 64) if field != "entry_type" else "evil.entry"
        lines[victim] = json.dumps(entry)
        (tmp_path / f"tam{i}.jsonl").write_text("\n".join(lines) + "\n",
                                                encoding="utf-8")
        reloaded = Ledger.load(path)
        chain_ok, _detail = reloaded.verify_chain()
        if not chain_ok:
            continue
        undetected.append((i, field))
    assert not undetected, f"tamper went undetected: {undetected[:5]}"
