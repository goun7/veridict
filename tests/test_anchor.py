"""External anchoring: the Rekor contract, the crypto verification, the
refusals.

The canned Rekor responses are RECORDED from the live public-good instance
(2026-09-14): a protocol probe, plus this module's own publish() round-trip.
They are not invented payloads — the point of the anchor is that nobody has
to invent log responses.

`anchor.verify` is pure-offline (only the pinned Rekor key is trusted);
`publish` needs a log, so its test runs against a recorded transcript.
"""
import base64
import copy
import hashlib
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict import anchor
from veridict.certificate import verify_certificate

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# --------------------------------------------------------------------------
# fixtures: real dogfood cert + ledger (already in .gitignore-free form?
# dogfood_* ARE gitignored — regenerate in-process instead, offline)

@pytest.fixture(scope="module")
def dogfood_pair(tmp_path_factory):
    """A real cert produced by the real pipeline, offline (scripted jury)."""
    from veridict.audit import AuditOrchestrator
    from veridict.claim_extractor import ClaimExtractor
    from veridict.jury import Jury, Opinion, ScriptedProvider
    from veridict.keys import KeyStore
    from veridict.ledger import Ledger
    from veridict.policy import PolicyDeclaration, Thresholds
    from veridict.schemas import TaskManifest

    task = TaskManifest(task_id="anchor-t", artifact_path=REPO,
                        actor_identity="anchor-test",
                        intent_lines=("DOCTRINE: the anchor module exists",),
                        criticality=(), has_existing_tests=False, pytest_args=())
    pol = PolicyDeclaration(policy_id="p", mode="CERTIFICATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("anchor-test")
    jury = Jury([
        ScriptedProvider(family="f1", identity="j1",
                         default=Opinion("SUPPORTS", 0.9, "it is imported")),
        ScriptedProvider(family="f2", identity="j2",
                         default=Opinion("SUPPORTS", 0.9, "file is on disk")),
    ])
    result = AuditOrchestrator(led, pol, jury, ks, kid).run(task)
    lp = str(tmp_path_factory.mktemp("a") / "led.jsonl")
    cp = str(tmp_path_factory.mktemp("a") / "cert.json")
    led.save(lp)
    with open(cp, "w") as f:
        json.dump(result["cert"], f)
    with open(lp) as f:
        entries = [json.loads(line) for line in f if line.strip()]
    return entries, result["cert"]


# canned live-recorded Rekor response for digest=sha256(b"probe")
PROBE_UUID = ("108e9186e8c5677ab3349b84a96c6e933b7afbfee46c0b9a632a3184ac2d"
              "250a509c6ff5a8cd2902")
PROBE_ENTRY = {
    "body": ("eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3B"
             "lYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdW"
             "UiOiJiYTljNzM2ZjE5ZTdmNjBiN2Y2NzY0YWRiMGI3OTA4YzBhMmIzOTRlMDliN"
             "mMwOTg2MzUyOGM3ZjJiYzg2MDk1In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6I"
             "k1FWUNJUURpTVVTRlQzWWw1cU5wQ3RCd3A3NHFlOGNYWk5qcloyL0tlN09lRW5kT"
             "UNnSWhBSTZ5UzZoTkRRWjB5d211Q3Q2MUdGNXRMaW0wYUYvUmsxSUR3aXY4YlJvS"
             "yIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCUVZVSk1TVU"
             "1nUzBWWkxTMHRMUzBLVFVacmQwVjNXVWhMYjFwSmVtb3dRMEZSV1VsTGIxcEplbW"
             "93UkVGUlkwUlJaMEZGY0VwcE9XNXdWRnBKVkRjNVMyTlBOekl5U1hOVGVIUlFVUz"
             "lqVkFvNWJFbHhlbVpuTm1JclYyaGtNMHRqYUd4bk1EZE5NRUZKVkhWQ1pYVnlkRT"
             "A0V0V4M1VtcEZRa3dyTnpSRldWZDVlVFpGWVdKNWRXUjNQVDBLTFMwdExTMUZUa1"
             "FnVUZWQ1RFbERJRXRGV1MwdExTMHRDZz09In19fX0="),
    "integratedTime": 1789463462,
    "logID": "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
    "logIndex": 2842832428,
    "verification": {
        "inclusionProof": {
            "checkpoint": ("rekor.sigstore.dev - 1193050959916656506\n"
                           "2720928182\n2ozcl0kIbSuvQ5zcxPrDRLKp75feZAei66NO5"
                           "Rb8rWA=\n\n\u2014 rekor.sigstore.dev wNI9ajBGAiEA"
                           "nXYnFk74mIscH+XMjRR/ecozEq+lw5cn/ug25yoX/cMCIQCjA"
                           "OcGM7V2QcX6Oh9k2oLpZp01TqvwndGBLAvzGVOPKA==\n"),
            "hashes": ["bb14e5dd13a312c025d143b3dcf51279ff8bbfbd1147ff203ac26"
                       "dc4cb94f966"],
            "logIndex": 2720928166,
            "rootHash": ("da8cdc9749086d2baf439cdcc4fac344b2a9ef97de6407a2eba"
                         "34ee516fcad60"),
            "treeSize": 2720928182},
        "signedEntryTimestamp": ("MEUCICBaRNbf/BvUqA+Zvgbb5KpKNnjLpj6qfuy2Owf"
                                 "EYvbCAiEAmsEXNvwBHsPB5JPs+/8fps84U6wu1X9W3O"
                                 "t5CfRhFVs=")}}


class _FakeResp:
    def __init__(self, payload, status=201):
        self._p, self.status_code, self.text = payload, status, json.dumps(payload)

    def json(self):
        return self._p


@pytest.fixture()
def live_log(monkeypatch):
    """A faithful Rekor: computes uuid=treeID||leaf||treeID over whatever it
    accepts, signs the canonical SET and a signed checkpoint note with a
    throwaway key whose PEM the test injects as the 'pin'."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.serialization import (Encoding,
                                                              PublicFormat)
    log_key = ec.generate_private_key(ec.SECP256R1())
    pin_pem = log_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    tree_id = "108e9186e8c5677a"
    state = {"index": 4242}

    class Post:
        def __call__(self, url, json=None, timeout=None, **kw):
            body = anchor._canonical(json)
            leaf = hashlib.sha256(b"\x00" + body).hexdigest()
            uuid = f"{tree_id}{leaf}{tree_id}"
            entry = {"body": base64.b64encode(body).decode(),
                     "integratedTime": 1789000000,
                     "logID": "c0d2" * 16,
                     "logIndex": state["index"]}
            set_sig = log_key.sign(
                hashlib.sha256(anchor._canonical(entry)).digest(),
                ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            head = ("fake.rekor - 0\n1\n"
                    + base64.b64encode(b"\x11" * 32).decode())
            note_sig = log_key.sign(hashlib.sha256(
                (head + "\n").encode()).digest(),
                ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            entry["verification"] = {
                "signedEntryTimestamp": base64.b64encode(set_sig).decode(),
                "inclusionProof": {
                    "checkpoint": head + "\n\n\u2014 fake "
                    + base64.b64encode(b"\xc0\xd2\x3d\x6a"
                                       + note_sig).decode() + "\n",
                    "hashes": [], "logIndex": 0,
                    "rootHash": (b"\x11" * 32).hex(), "treeSize": 1}}
            state["index"] += 1
            return _FakeResp({uuid: entry})

    monkeypatch.setattr("httpx.post", Post())
    return pin_pem


def test_bound_fields_and_digest_round_trip(dogfood_pair):
    entries, cert = dogfood_pair
    bound = anchor.bound_fields(cert)
    assert bound["cert_id"] == cert["cert_id"]
    assert bound["chain_hash"] == cert["ledger_anchor"]["chain_hash"]
    d1, d2 = anchor.anchor_digest(bound), anchor.anchor_digest(bound)
    assert d1 == d2 and len(d1) == 64


def test_publish_then_verify_happy_path(dogfood_pair, live_log, monkeypatch):
    entries, cert = dogfood_pair
    sidecar = anchor.publish(entries, cert)
    res = anchor.verify(sidecar, cert, rekor_key_pem=live_log)
    assert res["valid"], res["errors"]
    assert res["summary"]["cert_id"] == cert["cert_id"]
    assert res["summary"]["checkpoint_seq"] == cert["ledger_anchor"]["checkpoint_seq"]


def test_publish_refuses_chain_disagreement(dogfood_pair, live_log):
    entries, cert = copy.deepcopy(dogfood_pair)   # module fixture: never mutate
    cp_seq = cert["ledger_anchor"]["checkpoint_seq"]
    for e in entries:
        if e.get("seq") == cp_seq:
            e["payload"]["chain_hash"] = "00" * 32
    with pytest.raises(RuntimeError, match="disagrees"):
        anchor.publish(entries, cert)


def test_verify_rejects_wrong_cert(dogfood_pair, live_log):
    entries, cert = dogfood_pair
    sidecar = anchor.publish(entries, cert)
    other = copy.deepcopy(cert)
    other["cert_id"] = "9" * 24
    res = anchor.verify(sidecar, other, rekor_key_pem=live_log)
    assert not res["valid"]
    assert any("does not match the certificate" in e for e in res["errors"])


def test_verify_detects_tampered_entry_body(dogfood_pair, live_log):
    entries, cert = dogfood_pair
    sidecar = anchor.publish(entries, cert)
    body = json.loads(base64.b64decode(sidecar["rekor"]["entry"]["body"]))
    body["spec"]["data"]["hash"]["value"] = "f" * 64      # swap the digest
    sidecar["rekor"]["entry"]["body"] = base64.b64encode(
        json.dumps(body).encode()).decode()
    res = anchor.verify(sidecar, cert, rekor_key_pem=live_log)
    assert not res["valid"]
    assert any("SET signature" in e for e in res["errors"])


def test_verify_pins_unknown_log_key(dogfood_pair, live_log):
    entries, cert = dogfood_pair
    sidecar = anchor.publish(entries, cert)
    from cryptography.hazmat.primitives.asymmetric import ec
    stranger = ec.generate_private_key(ec.SECP256R1())
    pem = stranger.public_key().public_bytes(
        __import__("cryptography.hazmat.primitives.serialization",
                   fromlist=["Encoding"]).Encoding.PEM,
        __import__("cryptography.hazmat.primitives.serialization",
                   fromlist=["PublicFormat"]).PublicFormat.SubjectPublicKeyInfo
    ).decode()
    res = anchor.verify(sidecar, cert, rekor_key_pem=pem)
    assert not res["valid"]
    assert any("SET signature" in e for e in res["errors"])


def test_live_recorded_probe_crypto_verifies_against_real_pin():
    """The PROBE fixture above is genuine recorded traffic from the public-
    good Rekor instance: crypto-only checks (SET, checkpoint note, uuid/leaf
    identity, root cross-check) must pass with the pinned real key."""
    sidecar = {"anchor_version": anchor.ANCHOR_TYPE,
               "rekor": {"server": anchor.REKOR_SERVER,
                         "uuid": PROBE_UUID, "entry": copy.deepcopy(PROBE_ENTRY)},
               "bound": {"anchor": anchor.ANCHOR_TYPE, "cert_id": "",
                         "key_id": "", "checkpoint_seq": None,
                         "chain_hash": ""},
               "digest": hashlib.sha256(b"probe").hexdigest()}
    res = anchor.verify(sidecar)             # cert=None: crypto-only;
    assert res["valid"], res["errors"]       # default pin = the REAL Rekor key


def test_pinned_key_matches_tuf_sha256():
    """If this fails, the log key rotated — run REFRESH_RECIPE and update the
    pin. A stale pin fails CLOSED (verification refuses), it never trusts."""
    digest = hashlib.sha256(anchor.REKOR_PUBLIC_KEY_PEM.encode()).hexdigest()
    assert digest == "dce5ef715502ec9f3cdfd11f8cc384b31a6141023d3e7595e9908a81cb6241bd"


def test_dogfood_certificate_still_verifies():
    """Anchor work must not disturb the core offline path at all."""
    lp, cp = os.path.join(REPO, "dogfood_ledger.jsonl"), \
        os.path.join(REPO, "dogfood_cert.json")
    if not (os.path.exists(lp) and os.path.exists(cp)):
        pytest.skip("dogfood files are local CI artifacts")
    assert verify_certificate(lp, cp)["valid"]
