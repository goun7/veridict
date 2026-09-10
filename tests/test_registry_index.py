"""Marketplace manifest index (Task 28, §5.5): build/validate the static JSON
circulation format for watcher manifests, exported from an append-only ledger
and verifiable offline."""
import json
from datetime import datetime

import pytest

from tests.test_watchers import _manifest, _registry
from veridict.cli import main
from veridict.ledger import Ledger
from veridict.registry_index import (build_index, export_index, load_index,
                                     validate_index)


def _two_watcher_ledger() -> Ledger:
    reg, led = _registry()
    reg.register(_manifest())
    reg.register(_manifest(watcher_id="net-2", name="Network Watcher",
                           producer={"identity": "net-watcher",
                                     "maintainer": "example-org"}))
    return led


def test_build_index_shape():
    led = _two_watcher_ledger()
    idx = build_index(led)
    assert idx["schema_version"] == "1.0"
    datetime.fromisoformat(idx["generated_at"])          # an ISO timestamp
    watchers = {w["watcher_id"]: w for w in idx["watchers"]}
    assert set(watchers) == {"sec-1", "net-2"}
    w = watchers["sec-1"]
    assert w["name"] == "Security Watcher"
    assert w["version"] == "0.1.0"
    assert w["producer"] == {"identity": "sec-watcher",
                             "maintainer": "example-org"}
    assert w["capabilities"]["max_tier"] == "W1b"
    assert w["resource_class"]["timeout_seconds"] == 30
    assert w["integrity"]["update_policy"] == "manual"
    assert len(w["manifest_digest"]) == 64
    seq = next(e["seq"] for e in led.query("watcher.registered")
               if e["payload"]["manifest"]["watcher_id"] == "sec-1")
    assert w["registered_seq"] == seq


def test_build_index_latest_registration_wins():
    reg, led = _registry()
    reg.register(_manifest(name="First"))
    reg.register(_manifest(name="Second"))
    idx = build_index(led)
    assert len(idx["watchers"]) == 1
    w = idx["watchers"][0]
    assert w["name"] == "Second"
    assert w["registered_seq"] == led.query("watcher.registered")[-1]["seq"]


def test_validate_index_honest_ledger_is_valid():
    led = _two_watcher_ledger()
    report = validate_index(build_index(led), led)
    assert report == {"valid": True, "errors": []}


def test_validate_index_catches_tampered_digest():
    led = _two_watcher_ledger()
    idx = build_index(led)
    idx["watchers"][0]["manifest_digest"] = "f" * 64
    report = validate_index(idx, led)
    assert report["valid"] is False
    assert any("sec-1" in e or "net-2" in e for e in report["errors"])


def test_validate_index_catches_broken_signature_only():
    # Digests still match; only the enrolled-key signature fails — the (c)
    # check must fire on its own.
    led = _two_watcher_ledger()
    idx = build_index(led)
    led.entries[-1]["payload"]["signature"]["sig_b64"] = "not-a-signature"
    report = validate_index(idx, led)
    assert report["valid"] is False
    assert any("sec-1" in e or "net-2" in e for e in report["errors"])


def test_validate_index_flags_unknown_watcher():
    led = _two_watcher_ledger()
    idx = build_index(led)
    idx["watchers"].append({**idx["watchers"][0], "watcher_id": "ghost"})
    report = validate_index(idx, led)
    assert report["valid"] is False
    assert any("ghost" in e for e in report["errors"])


def test_export_load_roundtrip(tmp_path):
    led = _two_watcher_ledger()
    path = str(tmp_path / "index.json")
    export_index(led, path)
    loaded = load_index(path)
    fresh = build_index(led)
    loaded.pop("generated_at"), fresh.pop("generated_at")  # wall-clock differs
    assert loaded == fresh


def test_load_index_malformed_json_raises_valueerror(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_index(str(path))


def test_cli_index_prints_json_and_writes_out(tmp_path, capsys):
    led_path = tmp_path / "led.jsonl"
    _two_watcher_ledger().save(str(led_path))
    out_path = tmp_path / "idx.json"
    rc = main(["index", "--ledger", str(led_path), "--out", str(out_path)])
    assert rc == 0
    printed = json.loads(capsys.readouterr().out)
    assert {w["watcher_id"] for w in printed["watchers"]} == {"sec-1", "net-2"}
    on_disk = json.loads(out_path.read_text(encoding="utf-8"))
    assert on_disk["schema_version"] == "1.0"


def test_cli_index_validate_rc0_on_honest_ledger(tmp_path, capsys):
    led_path = tmp_path / "led.jsonl"
    _two_watcher_ledger().save(str(led_path))
    rc = main(["index", "--ledger", str(led_path), "--validate"])
    assert rc == 0
    assert json.loads(capsys.readouterr().out) == {"valid": True, "errors": []}


def test_cli_index_validate_rc1_on_inconsistent_ledger(tmp_path, capsys):
    led = _two_watcher_ledger()
    led.entries[-1]["payload"]["manifest"]["name"] = "Evil"   # retroactive edit
    led_path = tmp_path / "led.jsonl"
    led.save(str(led_path))
    rc = main(["index", "--ledger", str(led_path), "--validate"])
    assert rc == 1
    report = json.loads(capsys.readouterr().out)
    assert report["valid"] is False and report["errors"]
