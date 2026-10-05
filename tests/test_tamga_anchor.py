"""The mesh-local anchor transport: Veridict checkpoint -> Tamga ledger.

Where test_anchor.py pins the Rekor contract against RECORDED live-log
responses, this suite pins the other half of the mesh's anchor layer: the
transport that commits the same checkpoint binding into a Tamga-grammar
hash-chained ledger (TamgaProtocol, the mesh's permanent proof-anchor layer
per the TAMGA-MESH connection matrix).

Three properties, in the repo's fail-before/pass-after style:
  1. publish -> verify roundtrips, with the L1 node-cosign exercised
  2. tampering fails closed — a mutated ledger line or a swapped binding is
     detected, never a silent pass (the anchor's whole purpose)
  3. the ledger this module writes verifies under TAMGA'S OWN verifier —
     not by our assertion, but by running tamga_runner.py ledger-verify as a
     subprocess. That test skips when TamgaProtocol is not installed on the
     machine (e.g. this repo's public CI, which has no mesh siblings); on the
     mesh it runs for real, including a cryptography-written node_sig verified
     by Tamga's PyNaCl path — cross-library Ed25519 interop.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from veridict import anchor, tamga_anchor
from veridict.utils import sha256_hex

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The mesh sibling: ../TamgaProtocol relative to this repo (the symlink
# 00_TAMGA-MESH/tamga -> 05_acik_kaynak/TamgaProtocol is the canonical path).
TAMGA_ROOT = os.environ.get("VERIDICT_TAMGA_ROOT") or os.path.join(
    os.path.dirname(REPO), "TamgaProtocol")

GENESIS = "0" * 64


@pytest.fixture(scope="module")
def dogfood_pair(tmp_path_factory):
    """A real cert + ledger from the real pipeline, offline (scripted jury)."""
    from veridict.audit import AuditOrchestrator
    from veridict.jury import Jury, Opinion, ScriptedProvider
    from veridict.keys import KeyStore
    from veridict.ledger import Ledger
    from veridict.policy import PolicyDeclaration, Thresholds
    from veridict.schemas import TaskManifest

    task = TaskManifest(task_id="tamga-anchor-t", artifact_path=REPO,
                        actor_identity="tamga-anchor-test",
                        intent_lines=("DOCTRINE: the tamga anchor module exists",),
                        criticality=(), has_existing_tests=False, pytest_args=())
    pol = PolicyDeclaration(policy_id="p", mode="CERTIFICATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("tamga-anchor-test")
    jury = Jury([
        ScriptedProvider(family="f1", identity="j1",
                         default=Opinion("SUPPORTS", 0.9, "it is imported")),
        ScriptedProvider(family="f2", identity="j2",
                         default=Opinion("SUPPORTS", 0.9, "file is on disk")),
    ])
    result = AuditOrchestrator(led, pol, jury, ks, kid).run(task)
    lp = str(tmp_path_factory.mktemp("t") / "led.jsonl")
    cp = str(tmp_path_factory.mktemp("t") / "cert.json")
    led.save(lp)
    with open(cp, "w") as f:
        json.dump(result["cert"], f)
    with open(lp) as f:
        entries = [json.loads(line) for line in f if line.strip()]
    return entries, result["cert"]


def _node_key():
    """A throwaway ed25519 node key for the L1 cosign (raw 32 bytes)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.generate().private_bytes_raw()


# --------------------------------------------------------------------------
# 1. roundtrip
# --------------------------------------------------------------------------

def test_publish_verify_roundtrip(dogfood_pair, tmp_path):
    entries, cert = dogfood_pair
    ledger = str(tmp_path / "anchor.jsonl")
    sidecar = tamga_anchor.publish(entries, cert, ledger)

    assert sidecar["anchor_version"] == tamga_anchor.TAMGA_ANCHOR_VERSION
    # same binding the rekor transport pins — one statement, two surfaces
    assert sidecar["bound"] == anchor.bound_fields(cert)
    assert sidecar["digest"] == anchor.anchor_digest(anchor.bound_fields(cert))

    res = tamga_anchor.verify(sidecar, cert)
    assert res["valid"], res["errors"]
    s = res["summary"]
    assert s["cert_id"] == cert["cert_id"]
    assert s["checkpoint_seq"] == cert["ledger_anchor"]["checkpoint_seq"]
    assert s["chain_hash"] == cert["ledger_anchor"]["chain_hash"]
    assert s["records"] == 1 and s["seq"] == 1
    assert s["tip"] == sidecar["tamga"]["h"]

    # the on-disk line is Tamga grammar: genesis prev, 1-based seq, jcs body
    line = json.loads(open(ledger).readline())
    assert line["prev"] == GENESIS and line["seq"] == 1
    assert line["op"] == tamga_anchor.TAMGA_OP
    assert line["bound"] == anchor.bound_fields(cert)


def test_node_cosign_roundtrips(dogfood_pair, tmp_path):
    """The L1 node-cosign: a record signed here verifies under the chain."""
    entries, cert = dogfood_pair
    ledger = str(tmp_path / "anchor.jsonl")
    sidecar = tamga_anchor.publish(entries, cert, ledger,
                                   node_key=_node_key())
    res = tamga_anchor.verify(sidecar, cert)
    assert res["valid"], res["errors"]
    assert res["summary"]["node_signed"] is True
    line = json.loads(open(ledger).readline())
    assert "node_id" in line and "node_sig" in line
    # node_id is inside the hash input, node_sig outside — recomputing h with
    # the cosign fields stripped must still match the recorded h
    body = {k: v for k, v in line.items() if k not in ("h", "node_sig")}
    assert tamga_anchor.record_hash(line["prev"], body) == line["h"]


def test_two_anchors_chain_together(dogfood_pair, tmp_path):
    """Appending into an existing ledger extends the chain, not restarts it."""
    entries, cert = dogfood_pair
    ledger = str(tmp_path / "anchor.jsonl")
    sc1 = tamga_anchor.publish(entries, cert, ledger)
    sc2 = tamga_anchor.publish(entries, cert, ledger)
    assert sc2["tamga"]["seq"] == 2
    lines = [json.loads(l) for l in open(ledger) if l.strip()]
    assert len(lines) == 2
    assert lines[1]["prev"] == lines[0]["h"]
    # both anchors still verify against the same chain
    assert tamga_anchor.verify(sc1, cert)["valid"]
    assert tamga_anchor.verify(sc2, cert)["valid"]


# --------------------------------------------------------------------------
# 2. tamper / refusal — fail closed, never a silent pass
# --------------------------------------------------------------------------

def test_tampered_ledger_line_detected(dogfood_pair, tmp_path):
    entries, cert = dogfood_pair
    ledger = str(tmp_path / "anchor.jsonl")
    sidecar = tamga_anchor.publish(entries, cert, ledger)
    assert tamga_anchor.verify(sidecar, cert)["valid"]

    # flip one payload bit: the recorded h no longer recomputes
    lines = open(ledger).read().splitlines()
    tampered = json.loads(lines[0])
    tampered["bound"]["cert_id"] = tampered["bound"]["cert_id"] + "x"
    lines[0] = json.dumps(tampered, sort_keys=True)
    with open(ledger, "w") as f:
        f.write("\n".join(lines) + "\n")
    res = tamga_anchor.verify(sidecar, cert)
    assert not res["valid"]
    assert any("does not recompute" in e for e in res["errors"])


def test_broken_seq_is_detected(dogfood_pair, tmp_path):
    entries, cert = dogfood_pair
    ledger = str(tmp_path / "anchor.jsonl")
    sidecar = tamga_anchor.publish(entries, cert, ledger)

    lines = open(ledger).read().splitlines()
    rec = json.loads(lines[0])
    rec["seq"] = 7                                   # out of chain order
    lines[0] = json.dumps(rec, sort_keys=True)
    with open(ledger, "w") as f:
        f.write("\n".join(lines) + "\n")
    res = tamga_anchor.verify(sidecar, cert)
    assert not res["valid"]
    assert any("chain broken" in e for e in res["errors"])


def test_sidecar_rebind_to_other_cert_is_refused(dogfood_pair, tmp_path):
    """A sidecar presented against a DIFFERENT certificate does not verify."""
    from veridict.audit import AuditOrchestrator
    from veridict.jury import Jury, Opinion, ScriptedProvider
    from veridict.keys import KeyStore
    from veridict.ledger import Ledger
    from veridict.policy import PolicyDeclaration, Thresholds
    from veridict.schemas import TaskManifest

    entries, cert = dogfood_pair
    ledger = str(tmp_path / "anchor.jsonl")
    sidecar = tamga_anchor.publish(entries, cert, ledger)

    led2 = Ledger()
    ks2 = KeyStore(led2)
    kid2 = ks2.generate_and_enroll("other")
    jury = Jury([ScriptedProvider(family="f1", identity="j1",
                                  default=Opinion("SUPPORTS", 0.9, "stub")),
                 ScriptedProvider(family="f2", identity="j2",
                                  default=Opinion("SUPPORTS", 0.9, "stub"))])
    pol = PolicyDeclaration(policy_id="p2", mode="CERTIFICATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    task = TaskManifest(task_id="other-t", artifact_path=REPO,
                        actor_identity="other",
                        intent_lines=("DOCTRINE: unrelated",),
                        criticality=(), has_existing_tests=False, pytest_args=())
    other = AuditOrchestrator(led2, pol, jury, ks2, kid2).run(task)["cert"]
    assert other["cert_id"] != cert["cert_id"]

    res = tamga_anchor.verify(sidecar, other)
    assert not res["valid"]
    assert any("does not match the certificate" in e for e in res["errors"])


def test_publish_refuses_unseen_checkpoint(dogfood_pair, tmp_path):
    """No checkpoint in the ledger -> refusal, mirroring anchor.publish."""
    entries, cert = dogfood_pair
    bound = anchor.bound_fields(cert)
    truncated = [e for e in entries
                 if e.get("seq") < bound["checkpoint_seq"]]
    with pytest.raises(RuntimeError, match="refusing to anchor"):
        tamga_anchor.publish(truncated, cert, str(tmp_path / "a.jsonl"))


def test_jcs_rejects_floats():
    """The serializer stays narrower than full RFC 8785 on purpose — a float
    would serialize Python-specifically and break hash parity with Tamga."""
    with pytest.raises(ValueError, match="floats are rejected"):
        tamga_anchor.jcs({"x": 1.0})


def test_jcs_utf16_key_order():
    """Key order is UTF-16 code units (RFC 8785 §3.2.3), not code points."""
    out = tamga_anchor.jcs({"_": 1, "\u00e9": 2})
    assert out == '{"_":1,"\\u00e9":2}'


# --------------------------------------------------------------------------
# 3. parity: Tamga's OWN verifier on a ledger this module wrote
# --------------------------------------------------------------------------

def _tamga_available() -> tuple[bool, str]:
    """Is the mesh sibling runnable here? Returns (ok, interpreter).

    The interpreter must have BOTH PyNaCl (Tamga's dep) and cryptography
    (this repo's signing dep) — this repo's venv lacks PyNaCl, so the shared
    system python3 is the mesh host's working choice.
    """
    runner = os.path.join(TAMGA_ROOT, "tamga_runner.py")
    if not (os.path.isdir(TAMGA_ROOT) and os.path.isfile(runner)):
        return False, ""
    for interp in (sys.executable, "python3"):
        r = subprocess.run([interp, "-c", "import nacl, cryptography"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return True, interp
    return False, ""


_TAMGA_OK, _TAMGA_PY = _tamga_available()


@pytest.mark.skipif(not _TAMGA_OK,
                    reason=f"TamgaProtocol not runnable from {TAMGA_ROOT} "
                           "(mesh sibling; absent in this repo's public CI)")
@pytest.mark.parametrize("node_signed", [False, True],
                         ids=["unsigned", "node-cosigned"])
def test_tamga_native_verifier_accepts_veridict_anchor(dogfood_pair, tmp_path,
                                                       node_signed):
    """The ledger this module writes verifies under Tamga's own chain
    verifier — the interop claim, machine-checked rather than asserted.

    With node_signed=True the record's ed25519 cosign is produced by
    Veridict's `cryptography` and checked by Tamga's PyNaCl path: cross-
    library Ed25519 agreement on the exact bytes both projects hash.
    """
    entries, cert = dogfood_pair
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    ledger = str(pkg / "ledger.jsonl")
    tamga_anchor.publish(entries, cert, ledger,
                         node_key=_node_key() if node_signed else None)

    runner = os.path.join(TAMGA_ROOT, "tamga_runner.py")
    r = subprocess.run([_TAMGA_PY, runner, "ledger-verify", str(pkg)],
                       capture_output=True, text=True,
                       cwd=TAMGA_ROOT)
    assert r.returncode == 0, r.stderr or r.stdout
    report = json.loads(r.stdout)
    assert report["ok"] is True, report
    assert report["lines"] == 1
    # the tip Tamga computes must equal the h this module recorded
    line = json.loads(open(ledger).readline())
    assert report["head"] == line["h"]
