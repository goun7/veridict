"""Mesh-local anchor transport: pin a Veridict checkpoint to a Tamga ledger.

`veridict/anchor.py` pins a certificate's checkpoint to Sigstore Rekor — a
PUBLIC, EXTERNAL transparency log. This module is the same hardening against
the mesh's OWN permanent proof-anchor layer, TamgaProtocol
(``05_acik_kaynak/TamgaProtocol``): the checkpoint binding {cert_id, key_id,
checkpoint_seq, chain_hash} is committed as one record of a **Tamga
hash-chained ledger**, verifiable offline by anyone — and, because the record
follows Tamga's chain grammar byte-for-byte, re-verifiable by Tamga's OWN
``ledger-verify`` without Tamga having to know Veridict exists.

Why this bridge (mesh position). The TAMGA-MESH connection matrix names
TamgaProtocol the persistent proof-anchor layer and Veridict the audit/jury
proof layer, but the channel between them was documented as ONE-DIRECTIONAL
and UNVERIFIED (docs/notes/agent-interop-log.md): Tamga's ``sovereign_verify``
wrapper calls ``veridict verify``; nothing ever closed the loop back, and no
receipt ever confirmed the messages landed. This transport closes it in code:
a Veridict certificate now commits itself into the anchor layer's grammar, so
the relationship is machine-checked in both directions instead of asserted in
prose.

Tamga chain rules reproduced here (RFC-003 D5/D7/D8, from
TamgaProtocol/tamga_runner.py ``_verify_chain`` / ``_ledger_append_impl``):

  * record = {op, <payload>, seq, prev, ts[, node_id], h[, node_sig]}
  * seq is 1-based; the first record's prev is 64 hex zeros (genesis)
  * h = sha256( prev + jcs(record_without_h_and_node_sig) )   — node_id IS
    inside the hash input (it binds the cosigning node identity to the
    record), node_sig is OUTSIDE (it signs h, so it cannot hash itself)
  * jcs is RFC 8785 canonical JSON (TamgaProtocol/tamga_canon.py)
  * node_sig = ed25519(node_id_privkey, h.encode())  — L1 node-cosign layer

Compatibility scope, stated honestly. ``tamga_canon.jcs`` implements the full
RFC 8785 number and ordering rules; this serializer is deliberately NARROWER:
anchor records contain only ASCII strings and small integers, so ECMAScript
number formatting never applies. Anything outside that class (floats, bytes,
non-string keys) is REJECTED rather than silently serialized — the same
fail-closed discipline ``tamga_canon`` applies to NaN/Infinity. The parity
test in tests/test_tamga_anchor.py is the machine-checked half of that claim:
it round-trips this module's ledger through Tamga's own verifier (skip when
TamgaProtocol is absent, e.g. in this repo's public CI).

Write-gate boundary. Tamga's own append path refuses ops absent from its
emitter registry (triple-scope layer 1). This module writes the ledger file
directly and does NOT impersonate a Tamga emitter: it uses a self-labeling op
(``veridict.anchor``) so an auditor scanning the chain sees exactly what the
line is. Tamga's ``_verify_chain`` treats ``op`` as opaque data, so the chain
verifies green; a receiver running Tamga's optional ``unknown_ops()`` policy
will see the foreign op and make its own abstain/warn/reject call (receiver
decision, by design — the same E1(a) freedom Veridict's own D13 abstain
follows). Mesh operators who want these records inside a Tamga-managed
package ledger should register the emitter there; ``publish(op=...)`` accepts
a registered name for exactly that case.
"""
from __future__ import annotations

import hashlib
import json
import os
import time

from . import anchor
from .utils import sha256_hex

TAMGA_ANCHOR_VERSION = "veridict-anchor-tamga-1"
TAMGA_OP = "veridict.anchor"
GENESIS_PREV = "0" * 64
_SAFE_INT_LIMIT = 2 ** 53          # ECMAScript safe-integer bound (RFC 8785)

_ESCAPE = {"\\": "\\\\", '"': '\\"', "\b": "\\b", "\f": "\\f",
           "\n": "\\n", "\r": "\\r", "\t": "\\t"}


# --------------------------------------------------------------------------
# RFC 8785 canonical JSON (scoped: ASCII strings + small ints; see header)
# --------------------------------------------------------------------------

def jcs(obj) -> str:
    """RFC 8785 canonical serialization for the anchor record class.

    Returns a str (Tamga's convention — callers encode it), byte-compatible
    with TamgaProtocol/tamga_canon.jcs on every value this module can emit —
    and it can emit nothing else: floats, bytes and non-string keys raise
    rather than serialize into a hash only this serializer could reproduce.
    """
    return _jcs(obj)


def _jcs(obj) -> str:
    if obj is None:
        return "null"
    if obj is True:                     # before int: bool is an int subclass
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        if abs(obj) >= _SAFE_INT_LIMIT:
            raise ValueError(f"jcs: integer {obj} outside the ECMAScript "
                             "safe-integer range (RFC 8785 §3.2.2.2)")
        return str(obj)
    if isinstance(obj, float):
        raise ValueError("jcs: floats are rejected by the anchor serializer "
                         "— ECMAScript number formatting is not implemented "
                         "here and a Python-specific serialization would "
                         "break cross-language hash parity (tamga_canon "
                         "divergence, found by an outside auditor)")
    if isinstance(obj, str):
        return _jcs_str(obj)
    if isinstance(obj, dict):
        if not all(isinstance(k, str) for k in obj):
            raise ValueError("jcs: non-string object keys are not JSON")
        # RFC 8785 §3.2.3: member order by UTF-16 code unit sequence.
        parts = []
        for k in sorted(obj, key=lambda s: s.encode("utf-16-le")):
            parts.append(_jcs_str(k) + ":" + _jcs(obj[k]))
        return "{" + ",".join(parts) + "}"
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(_jcs(v) for v in obj) + "]"
    raise TypeError(f"jcs: unsupported type {type(obj).__name__}")


def _jcs_str(s: str) -> str:
    out = ['"']
    for ch in s:
        esc = _ESCAPE.get(ch)
        if esc is not None:
            out.append(esc)
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        elif ord(ch) < 0x80:
            out.append(ch)
        else:
            cp = ord(ch)
            if cp > 0xFFFF:                       # astral → UTF-16 surrogate pair
                cp -= 0x10000
                out.append(f"\\u{0xD800 + (cp >> 10):04x}"
                           f"\\u{0xDC00 + (cp & 0x3FF):04x}")
            else:
                out.append(f"\\u{cp:04x}")
    out.append('"')
    return "".join(out)


# --------------------------------------------------------------------------
# Tamga chain rules (RFC-003)
# --------------------------------------------------------------------------

def record_hash(prev: str, rec: dict) -> str:
    """h = sha256(prev + jcs(rec)); h and node_sig are outside the hash input
    (node_id stays inside — the chain binds the cosigning node identity)."""
    body = {k: v for k, v in rec.items() if k not in ("h", "node_sig")}
    return hashlib.sha256((prev + jcs(body)).encode("utf-8")).hexdigest()

def read_ledger(path) -> list[dict]:
    """Stream the ledger as parsed records, mirroring Tamga's _ledger_lines.
    An unparseable line becomes a sentinel {} — the chain check then flags it
    broken (fail-closed) instead of crashing the reader."""
    recs = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except Exception:
                recs.append({})
    return recs


def verify_chain(records: list[dict]) -> tuple[str | None, list[str]]:
    """Reproduce Tamga's _verify_chain: strict seq/prev/h from genesis.

    Returns (tip, errors). Any break fails the WHOLE chain — a record after a
    broken link is not trusted, exactly as in Tamga's own verifier.
    """
    prev_h, errors, n = GENESIS_PREV, [], 0
    for rec in records:
        n += 1
        if not isinstance(rec, dict) or "h" not in rec:
            errors.append(f"chain broken at seq {n}: no h field")
            return None, errors
        if rec.get("prev") != prev_h:
            errors.append(f"chain broken at seq {n}: prev mismatch")
            return None, errors
        if rec.get("seq") != n:
            errors.append(f"chain broken at seq {n}: expected seq {n}, "
                          f"record claims {rec.get('seq')!r}")
            return None, errors
        if rec["h"] != record_hash(prev_h, rec):
            errors.append(f"chain broken at seq {n}: h does not recompute")
            return None, errors
        if "node_sig" in rec and not verify_node_sig(rec):
            errors.append(f"chain broken at seq {n}: node_sig invalid")
            return None, errors
        prev_h = rec["h"]
    return prev_h, errors


def verify_node_sig(rec: dict) -> bool:
    """L1 node-cosign: did node_sig sign h under node_id's ed25519 key?

    Signed here with ``cryptography``, verified by Tamga with PyNaCl — both
    are plain RFC 8032 Ed25519, so signatures cross-verify (the parity test
    proves it against Tamga's own verifier, not by assertion).
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey)
        node_id = rec.get("node_id")
        sig = rec.get("node_sig")
        h = rec.get("h")
        if not (isinstance(node_id, str) and isinstance(sig, str)
                and isinstance(h, str)):
            return False
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(node_id))
        pub.verify(bytes.fromhex(sig), h.encode("utf-8"))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def _append_record(ledger_path: str, payload: dict, *,
                   node_key: bytes | str | None = None) -> dict:
    """Append one record in Tamga grammar: seq/prev/ts/h[/node_id/node_sig].

    Streaming, like Tamga's append: the previous tip is found by scanning for
    the last record carrying an h; if the file has lines but no valid tip the
    append is REFUSED (a broken chain must not be extended).
    """
    rec = dict(payload)
    last_h, n = None, 0
    if os.path.exists(ledger_path):
        with open(ledger_path, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                n += 1
                try:
                    cand = json.loads(line)
                    if isinstance(cand, dict) and cand.get("h"):
                        last_h = cand["h"]
                except Exception:
                    pass
    if last_h is None and n > 0:
        raise RuntimeError("tamga ledger tail has no valid head record — "
                           "refusing to extend a broken chain")
    prev = last_h if last_h is not None else GENESIS_PREV
    rec["seq"] = n + 1
    rec["prev"] = prev
    rec["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    if node_key is not None:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey)
        if isinstance(node_key, str):
            node_key = bytes.fromhex(node_key)
        priv = Ed25519PrivateKey.from_private_bytes(node_key)
        # node_id BEFORE h: the chain binds the node identity to the record
        rec["node_id"] = priv.public_key().public_bytes_raw().hex()
        h = record_hash(prev, rec)
        rec["node_sig"] = priv.sign(h.encode("utf-8")).hex()
        rec["h"] = h
    else:
        rec["h"] = record_hash(prev, rec)
    line = jcs(rec)
    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    try:
        os.chmod(ledger_path, 0o600)         # Tamga's own ledger is 0600
    except OSError:
        pass
    return rec


# --------------------------------------------------------------------------
# publish
# --------------------------------------------------------------------------

def publish(ledger_entries: list[dict], cert: dict, ledger_path: str, *,
            node_key: bytes | str | None = None,
            op: str = TAMGA_OP) -> dict:
    """Anchor the certificate's checkpoint into a Tamga-grammar ledger.

    The binding is the SAME one the Rekor transport pins
    (``anchor.bound_fields`` / ``anchor.anchor_digest``), so both anchors
    commit to identical bytes — a mesh member can check either and get the
    same statement. Raises RuntimeError when the checkpoint the cert claims
    cannot be located in the Veridict ledger, mirroring anchor.publish: we
    never anchor a binding we cannot see.
    """
    bound = anchor.bound_fields(cert)
    cp = anchor.locate_checkpoint(ledger_entries, bound)
    digest = anchor.anchor_digest(bound)
    rec = _append_record(ledger_path,
                         {"op": op, "bound": bound, "digest": digest},
                         node_key=node_key)
    return {"anchor_version": TAMGA_ANCHOR_VERSION,
            "tamga": {"ledger": ledger_path, "seq": rec["seq"],
                      "h": rec["h"], "node_signed": "node_sig" in rec},
            "bound": bound, "digest": digest}


# --------------------------------------------------------------------------
# verify (offline; only the ledger's own chain math is trusted)
# --------------------------------------------------------------------------

def verify(sidecar: dict, cert: dict | None = None) -> dict:
    """Check an anchor sidecar against the ledger file it names.

    Never raises on bad data — {valid, errors, summary}, like anchor.verify.
    The ledger is re-read and the FULL chain re-verified from genesis: a
    tampered ledger line, a swapped seq or a forged h all fail closed.
    """
    errors: list[str] = []
    if sidecar.get("anchor_version") != TAMGA_ANCHOR_VERSION:
        return {"valid": False,
                "errors": [f"not a tamga anchor sidecar "
                           f"(anchor_version={sidecar.get('anchor_version')!r})"],
                "summary": {}}
    t = sidecar.get("tamga") or {}
    bound = sidecar.get("bound") or {}
    digest = sidecar.get("digest", "")
    if cert is not None:
        expected = anchor.bound_fields(cert)
        if bound != expected:
            errors.append("anchor bound does not match the certificate "
                          f"(bound={bound.get('cert_id')} "
                          f"cert={expected['cert_id']})")
        if digest and digest != anchor.anchor_digest(expected):
            errors.append("anchor digest does not recompute from the binding")
    else:
        expected = bound

    ledger_path = t.get("ledger")
    seq = t.get("seq")
    if not ledger_path:
        return {"valid": False, "errors": errors + ["sidecar names no ledger"],
                "summary": {}}
    try:
        records = read_ledger(ledger_path)
    except OSError as exc:
        return {"valid": False, "errors": errors + [f"ledger unreadable: {exc}"],
                "summary": {}}

    # 1) the whole chain must verify — no trusting a record inside a broken
    # chain, and no skipping to the record we came for
    tip, chain_errors = verify_chain(records)
    if chain_errors:
        return {"valid": False,
                "errors": errors + chain_errors,
                "summary": {}}

    # 2) the named record must exist and be exactly what the sidecar claims
    rec = next((r for r in records if r.get("seq") == seq), None)
    if rec is None:
        return {"valid": False,
                "errors": errors + [f"no record at seq {seq} in {ledger_path}"],
                "summary": {}}
    if rec.get("h") != t.get("h"):
        errors.append("record h at the anchored seq disagrees with the sidecar")
    if rec.get("bound") != expected:
        errors.append("ledger record does not bind this certificate's fields")
    if rec.get("digest") != digest:
        errors.append("ledger record's digest disagrees with the sidecar")
    if cert is not None and digest and rec.get("digest") != anchor.anchor_digest(expected):
        errors.append("ledger record's digest does not recompute from the binding")
    if not isinstance(seq, int) or seq < 1:
        errors.append("sidecar seq must be a positive integer")

    summary = {"cert_id": expected.get("cert_id"),
               "checkpoint_seq": expected.get("checkpoint_seq"),
               "chain_hash": expected.get("chain_hash"),
               "digest": anchor.anchor_digest(expected) if expected else digest,
               "ledger": ledger_path, "seq": seq, "h": rec.get("h"),
               "tip": tip, "records": len(records),
               "node_signed": "node_sig" in rec,
               "anchor_op": rec.get("op")}
    return {"valid": not errors, "errors": errors, "summary": summary}
