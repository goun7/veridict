"""SPDX 3.0.1 AI-profile projection: validity against the OFFICIAL schema,
determinism, digest binding, and honesty of the profile claims."""
import hashlib
import json
import os
import sys

import jsonschema
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict import export as X

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_PATH = os.path.join(REPO, "docs", "data", "spdx-3.0.1-json-schema.json")
# Pin of the official model as fetched 2026-09-15 from
# https://spdx.org/schema/3.0.1/spdx-json-schema.json. Changing this file
# means deliberately switching SPDX model versions — update the constant
# AND the docs note in the same change, never silently.
SCHEMA_SHA256 = ("582c64e809d5b3ef9bd0c4de13a32391b47b0284"
                 "a3e8d199569fb96f649234b1")


@pytest.fixture(scope="module")
def issued_pair(tmp_path_factory):
    from veridict.audit import AuditOrchestrator
    from veridict.jury import Jury, Opinion, ScriptedProvider
    from veridict.keys import KeyStore
    from veridict.ledger import Ledger
    from veridict.policy import PolicyDeclaration, Thresholds
    from veridict.schemas import TaskManifest
    task = TaskManifest(task_id="spdx-t", artifact_path=REPO,
                        actor_identity="spdx-test",
                        intent_lines=("DOCTRINE: interop without inflation",),
                        criticality=(), has_existing_tests=False, pytest_args=())
    pol = PolicyDeclaration(policy_id="spdx-policy", mode="CERTIFICATE",
                            criticality=(), thresholds=Thresholds(),
                            divergence_tolerance=1 / 3)
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("spdx-test")
    jury = Jury([
        ScriptedProvider(family="f1", identity="j1",
                         default=Opinion("SUPPORTS", 0.9, "imported")),
        ScriptedProvider(family="f2", identity="j2",
                         default=Opinion("SUPPORTS", 0.9, "on disk"))])
    result = AuditOrchestrator(led, pol, jury, ks, kid).run(task)
    lp = str(tmp_path_factory.mktemp("s") / "led.jsonl")
    led.save(lp)
    with open(lp) as f:
        entries = [json.loads(line) for line in f if line.strip()]
    return entries, result["cert"]


@pytest.fixture(scope="module")
def schema():
    raw = open(SCHEMA_PATH, "rb").read()
    assert hashlib.sha256(raw).hexdigest() == SCHEMA_SHA256, (
        "docs/data/spdx-3.0.1-json-schema.json no longer matches the pinned "
        "official model — re-pin deliberately, not by editing this test")
    return json.loads(raw)


def _validate(schema, doc):
    errs = list(jsonschema.Draft202012Validator(schema).iter_errors(doc))
    if errs:
        raise AssertionError(json.dumps(
            [{"path": e.json_path, "msg": e.message[:200]} for e in errs[:5]],
            indent=2))


def test_validates_against_official_schema(schema, issued_pair):
    entries, cert = issued_pair
    _validate(schema, X.to_spdx(cert, entries))


def test_valid_with_anchor_sidecar(schema, issued_pair):
    entries, cert = issued_pair
    anchor = {"anchor_version": "veridict-anchor-1", "bound": {}, "digest": "x",
              "rekor": {"server": "https://rekor.sigstore.io", "uuid": "u",
                        "entry": {"logIndex": 2844439400}}}
    _validate(schema, X.to_spdx(cert, entries, anchor=anchor))


def test_deterministic(issued_pair):
    entries, cert = issued_pair
    a = json.dumps(X.to_spdx(cert, entries), sort_keys=True)
    b = json.dumps(X.to_spdx(cert, entries), sort_keys=True)
    assert a == b


def test_binds_certificate_by_digest(issued_pair):
    entries, cert = issued_pair
    doc = X.to_spdx(cert, entries)
    pkg = next(n for n in doc["@graph"] if n["type"] == "ai_AIPackage")
    assert pkg["verifiedUsing"][0]["hashValue"] == cert["subject"]["artifact_digest"]
    cert_ref = next(r for r in pkg["externalRef"]
                    if r["externalRefType"] == "certificationReport")
    want = hashlib.sha256(X._canonical(cert)).hexdigest()
    assert want in cert_ref["comment"]


def test_anchor_attached_only_when_given(issued_pair):
    entries, cert = issued_pair
    bare = X.to_spdx(cert, entries)
    pkg = next(n for n in bare["@graph"] if n["type"] == "ai_AIPackage")
    assert not any("transparency-log" in r.get("comment", "")
                   for r in pkg["externalRef"])


def test_refuses_without_issuance(issued_pair):
    entries, cert = issued_pair
    with pytest.raises(ValueError, match="certificate.issued"):
        X.to_spdx(cert, [])


def test_profile_claim_is_honest(issued_pair):
    entries, cert = issued_pair
    doc = X.to_spdx(cert, entries)
    text = json.dumps(doc)
    # "ai" conformance is claimed; the only ai_* properties we ship must
    # carry their SPDX semantics — never our audit verdicts.
    assert '"ai"' in text
    assert "ai_safetyRiskAssessment" not in text   # different semantics: refused
    assert "ai_typeOfModel" not in text            # we audit outputs, not models
    assert "ai_energyConsumption" not in text
    doc_el = next(n for n in doc["@graph"] if n["type"] == "SpdxDocument")
    assert "ai" in doc_el["profileConformance"]
    # every audit semantic rides on Annotation/Relationship elements
    anns = [n for n in doc["@graph"] if n["type"] == "Annotation"]
    assert any("risk_level=" in a["statement"] for a in anns)
