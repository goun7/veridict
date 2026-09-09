import json
import pytest
from veridict.ledger import Ledger, ChainError, GENESIS, _entry_hash
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

def test_prev_hash_field_tamper_detected():
    led = Ledger()
    led.append("task.started", AUTH, {"task_id": "t1"})
    led.append("policy.decision", AUTH, {"mode": "GATE"})
    led.entries[1]["prev_hash"] = "f" * 64      # stored linkage falsified
    ok, msg = led.verify_chain()
    assert not ok and "prev_hash mismatch" in msg

def test_forged_consistent_entry_detected_by_payload_hash():
    # Attacker edits payload AND recomputes entry_hash consistently —
    # the stale stored payload_hash is what catches them (its reason to exist).
    led = Ledger()
    led.append("task.started", AUTH, {"task_id": "t1"})
    led.entries[0]["payload"] = {"task_id": "evil"}
    led.entries[0]["entry_hash"] = _entry_hash(
        GENESIS, led.entries[0]["payload"], led.entries[0]["entry_type"],
        led.entries[0]["seq"], led.entries[0]["author"])
    ok, msg = led.verify_chain()
    assert not ok and "payload hash mismatch" in msg

def test_empty_ledger_verifies():
    ok, msg = Ledger().verify_chain()
    assert ok and msg == "ok"
