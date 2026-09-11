"""JSON Schema contracts (published under docs/schemas/) must accept every
REAL artifact the system produces — the shipped watcher manifests, the
dogfood ledger (every entry), and the dogfood certificate. A schema that
drifts from reality fails here before any implementer sees it.

Dogfood artifacts are validated when they exist and SKIPPED when they do
not: this module is also collected by dogfood's own inner pytest
(scripts/dogfood.py audits the repo suite as W1a evidence), where the
repo-root artifacts do not exist yet — reading them there would refute
dogfood's W1a evidence and turn the main certificate HIGH (a
self-referential deadlock). In a plain full-suite run, test_dogfood (d < j)
writes the artifacts before this module validates them; CI's dedicated
schema step runs after the dogfood receipt step and always has them."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

jsonschema = pytest.importorskip("jsonschema")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMAS = os.path.join(REPO, "docs", "schemas")


def _load(name):
    with open(os.path.join(SCHEMAS, name), encoding="utf-8") as f:
        return json.load(f)


def _validator(schema):
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


def _ship_manifests():
    """The three shipped example watchers each carry a manifest dict."""
    sys.path.insert(0, os.path.join(REPO, "watchers"))
    out = []
    for mod in ("security_watcher", "compliance_watcher", "cost_watcher"):
        m = __import__(mod)
        out.append((mod, m.MANIFEST.to_dict()))
    return out


def test_shipped_watcher_manifests_validate():
    schema = _validator(_load("veridict-watcher-manifest-1.0.schema.json"))
    for name, manifest in _ship_manifests():
        schema.validate(manifest), name


def _dogfood_artifacts():
    """Return (ledger_path, cert_path) for the repo-root dogfood run, or None.

    The artifacts exist iff a dogfood run has completed in this process tree
    (test_dogfood's module fixture, or CI's dogfood receipt step). Inside
    dogfood's own inner pytest they do not exist yet — that context is
    skipped rather than fabricated (see module docstring)."""
    ledger = os.path.join(REPO, "dogfood_ledger.jsonl")
    cert = os.path.join(REPO, "dogfood_cert.json")
    if os.path.exists(ledger) and os.path.exists(cert):
        return ledger, cert
    return None


def test_dogfood_ledger_entries_validate():
    artifacts = _dogfood_artifacts()
    if artifacts is None:
        pytest.skip("dogfood artifacts not produced yet (inner-pytest context)")
    schema = _validator(_load("veridict-ledger-entry-1.0.schema.json"))
    from veridict.ledger import Ledger
    led = Ledger.load(artifacts[0])
    assert len(led.entries) > 20
    for i, entry in enumerate(led.entries):
        schema.validate(entry), f"entry {i} ({entry['entry_type']})"


def test_dogfood_certificate_validates():
    artifacts = _dogfood_artifacts()
    if artifacts is None:
        pytest.skip("dogfood artifacts not produced yet (inner-pytest context)")
    schema = _validator(_load("veridict-certificate-1.0.schema.json"))
    with open(artifacts[1], encoding="utf-8") as f:
        cert = json.load(f)
    schema.validate(cert)


def test_tampered_manifest_rejected_by_schema():
    schema = _validator(_load("veridict-watcher-manifest-1.0.schema.json"))
    name, manifest = _ship_manifests()[0]
    bad = dict(manifest, capabilities=dict(manifest["capabilities"],
                                           max_tier="W1a"))   # the forbidden tier
    with pytest.raises(jsonschema.ValidationError):
        schema.validate(bad)
    bad2 = dict(manifest, integrity=dict(manifest["integrity"],
                                         code_hash="zz"))    # not sha256 hex
    with pytest.raises(jsonschema.ValidationError):
        schema.validate(bad2)
