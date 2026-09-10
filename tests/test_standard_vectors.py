"""Standard v1.0.0 test vectors (Phase 3, exit criterion ① substrate).

The checked-in vectors pin the standard's OFFLINE VERIFICATION semantics as
executable, language-neutral evidence: any independent implementation must
reach `expected_verify.json` from `ledger.jsonl` + `certificate.json` alone.
The regeneration test guards the reference implementation against silent
nondeterminism (fixed ts, fixed ed25519 seed — see
scripts/build_test_vectors.py).
"""
import os
import subprocess
import sys

from veridict.certificate import verify_certificate
from veridict.ledger import Ledger

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VEC = os.path.join(REPO, "docs", "standard-test-vectors")


def test_vectors_verify_to_expected():
    report = verify_certificate(os.path.join(VEC, "ledger.jsonl"),
                                os.path.join(VEC, "certificate.json"))
    import json
    expected = json.load(open(os.path.join(VEC, "expected_verify.json")))
    assert report == expected
    assert report["valid"] is True


def test_vector_chain_verifies_standalone():
    led = Ledger.load(os.path.join(VEC, "ledger.jsonl"))
    ok, msg = led.verify_chain()
    assert ok, msg
    # the vector ledger is fully pinned: all ts values are the fixed strings
    assert {e["ts"][:10] for e in led.entries} == {"2026-09-10"}


def test_regeneration_is_byte_deterministic(tmp_path):
    import hashlib
    env = dict(os.environ, VECTOR_OUT=str(tmp_path))
    subprocess.run([sys.executable,
                    os.path.join(REPO, "scripts", "build_test_vectors.py")],
                   check=True, env=env, capture_output=True)
    for name in ("ledger.jsonl", "certificate.json", "expected_verify.json"):
        pinned = hashlib.sha256(
            open(os.path.join(VEC, name), "rb").read()).hexdigest()
        rebuilt = hashlib.sha256(
            open(os.path.join(tmp_path, name), "rb").read()).hexdigest()
        assert pinned == rebuilt, name


def test_spec_only_verifier_reproduces_the_verdict(tmp_path):
    """Exit criterion ① rehearsal: a verifier written against the STANDARD
    alone (examples/spec_verifier.py — zero veridict imports) must reach the
    same verdict from the vectors, and must REJECT a tampered ledger."""
    vec = VEC
    rc = subprocess.run(
        [sys.executable, os.path.join(REPO, "examples", "spec_verifier.py"),
         "--ledger", os.path.join(vec, "ledger.jsonl"),
         "--cert", os.path.join(vec, "certificate.json"),
         "--expected", os.path.join(vec, "expected_verify.json")],
        capture_output=True).returncode
    assert rc == 0

    # negative: flip a payload byte in a COPY — the spec verifier must reject
    import json
    ledger_copy = tmp_path / "ledger.jsonl"
    lines = open(os.path.join(vec, "ledger.jsonl"),
                 encoding="utf-8").read().splitlines()
    entry = json.loads(lines[1])
    entry["payload"]["key_id"] = "tampered-key-id"
    lines[1] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    ledger_copy.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rc = subprocess.run(
        [sys.executable, os.path.join(REPO, "examples", "spec_verifier.py"),
         "--ledger", str(ledger_copy),
         "--cert", os.path.join(vec, "certificate.json")],
        capture_output=True).returncode
    assert rc == 1
