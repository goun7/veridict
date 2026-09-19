"""Spec-vs-production verifier parity + tamper resistance (issue #1 exit criterion).

The certificate's whole value is "anyone can verify this offline". That is
only true if a verifier built from the standard ALONE — examples/spec_verifier.py,
which reads the schemas and vectors, not veridict/ — agrees with the production
verifier on every input, including adversarial ones.

This test is the issue #1 trip: if the two ever diverge, one of them is wrong
about the standard, and that is an errata-grade finding.
"""
from __future__ import annotations

import base64
import copy
import json
import os
import secrets
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "examples"))

from spec_verifier import verify_certificate as spec_verify  # noqa: E402
from veridict.certificate import verify_certificate as ref_verify  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "..", "docs", "standard-test-vectors")
LEDGER = os.path.join(FIX, "ledger.jsonl")
CERT = os.path.join(FIX, "certificate.json")


def _run(tmp_path, entries, cert):
    lp = tmp_path / "l.jsonl"
    with lp.open("w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
    cp = tmp_path / "c.json"
    cp.write_text(json.dumps(cert))
    s = spec_verify(str(lp), str(cp))
    r = ref_verify(str(lp), str(cp))
    return s.get("valid"), r.get("valid")


@pytest.fixture(scope="module")
def ledger_entries():
    with open(LEDGER) as f:
        return [json.loads(line) for line in f]


@pytest.fixture(scope="module")
def cert_json():
    with open(CERT) as f:
        return json.load(f)


def test_clean_fixtures_agree(tmp_path, ledger_entries, cert_json):
    """The published fixtures: both verifiers must say valid."""
    assert _run(tmp_path, ledger_entries, cert_json) == (True, True)


def _tamper(entries, entry_type, field, value):
    out = copy.deepcopy(entries)
    for x in out:
        if x.get("entry_type") == entry_type:
            x[field] = value(x[field]) if callable(value) else value
            break
    return out


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda e, c: _tamper(e, "evidence.recorded", "payload",
                                      lambda p: {**p, "injected": "x"}), id="payload"),
    pytest.param(lambda e, c: _tamper(e, "evidence.recorded", "entry_hash", "a" * 64),
                 id="entry-hash"),
    pytest.param(lambda e, c: _tamper(e, "evidence.recorded", "prev_hash", "f" * 64),
                 id="prev-hash-link"),
])
def test_ledger_tamper_rejected_by_both(tmp_path, ledger_entries, cert_json, mutate):
    """A mutated ledger must fail BOTH verifiers, identically."""
    assert _run(tmp_path, mutate(ledger_entries, cert_json), cert_json) == (False, False)


@pytest.mark.parametrize("mutate", [
    pytest.param(lambda c: {**c, "signatures": [
        {**c["signatures"][0],
         "sig_b64": base64.b64encode(secrets.token_bytes(64)).decode()}]},
        id="bad-signature"),
    pytest.param(lambda c: {**c, "signatures": [
        {**c["signatures"][0], "key_id": "deadbeefdeadbeef"}]},
        id="unknown-key-id"),
    pytest.param(lambda c: {**c, "policy_mode": "TAMPERED"}, id="cert-body"),
])
def test_cert_tamper_rejected_by_both(tmp_path, ledger_entries, cert_json, mutate):
    """A mutated certificate must fail BOTH verifiers, identically."""
    assert _run(tmp_path, ledger_entries, mutate(cert_json)) == (False, False)


def test_spec_verifier_reads_no_veridict_source():
    """spec_verifier must not import the production verifier it is being
    compared against — that would make the parity test circular."""
    import spec_verifier
    src = open(spec_verifier.__file__).read()
    assert "from veridict" not in src, "spec_verifier imports production code"
    assert "import veridict" not in src, "spec_verifier imports production code"
