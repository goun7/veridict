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


def test_out_of_preimage_change_is_accepted_by_both(tmp_path, ledger_entries,
                                                    cert_json):
    """Negative control for the tamper tests above.

    A field outside the entry-hash preimage is not protected evidence, so
    BOTH verifiers must still accept the ledger. If either flips to False,
    it started hashing fields the spec does not cover — a silent
    conformance drift between the two implementations. And if any tamper
    test above ever passes, the mutation stopped touching the preimage
    and is proving nothing. Both directions of this boundary are worth
    pinning; a one-sided tamper suite cannot detect the second.
    """
    out = copy.deepcopy(ledger_entries)
    for x in out:                        # a field no preimage in §2.3 consumes
        x["harmless_extra_field"] = "not-digested"
        break
    assert _run(tmp_path, out, cert_json) == (True, True)


def test_unknown_entry_type_is_accepted_by_both(tmp_path, ledger_entries,
                                                cert_json):
    """An entry_type outside the core registry must verify GREEN on both.

    This is the mirror of Tamga's ERRATUM E1(a): their spec listed op
    values as restricted while production accepted an unknown op and
    verified GREEN — intentional forward-compatibility, but the spec's
    language did not say so, so an independent verifier could lawfully
    read the restriction as normative and reject the same chain.

    Ours is now documented (erratum D13): the registry is open by design,
    extensions must be namespaced 'extension.*'. This test pins the
    behavior so a later tightening — making the enum closed — shows up
    as a deliberate break, not a silent conformance drift. Both
    directions matter: if the spec verifier ever rejects what production
    accepts, the two have diverged.
    """
    out = copy.deepcopy(ledger_entries)
    last = out[-1]
    ext = {
        **last,
        "entry_type": "extension.experimental",
        "payload": {"note": "forward-compatible extension entry"},
        # the copied entry carries its own seq; the appended entry must claim
        # its true position, or the seq==position check rejects it. That
        # rejection would be correct — see test_seq_field_must_equal_position
        # — but this test is about the entry_type registry being open, not
        # about seq discipline, so give the extension its own honest seq.
        "seq": len(out),
        # and it must chain from the last entry, not from the entry it copied.
        "prev_hash": last["entry_hash"],
    }
    out.append(ext)
    # chain links must be recomputed for the appended entry. The rebuild must
    # keep the fixtures' pinned timestamps: the certificate's signature covers
    # the anchor's chain_hash, which pins the state of the prefix — and that
    # state is a function of ts. Rebuilding with live time would re-hash every
    # entry and detach the pin, so the anchor check compares against a prefix
    # the pinned signature never covered.
    from veridict.ledger import Ledger, _entry_hash
    from veridict.utils import payload_digest
    led = Ledger()
    for e in out:
        entry = dict(e)
        entry["payload_hash"] = payload_digest(entry["payload"])
        entry["entry_hash"] = _entry_hash(
            entry["prev_hash"], entry["payload"], entry["entry_type"],
            entry["seq"], entry["author"], entry["ts"], entry["schema_version"])
        led.entries.append(entry)
    s, r = _run(tmp_path, led.entries, cert_json)
    assert (s, r) == (True, True), \
        "an extension entry_type must verify GREEN on both verifiers"
