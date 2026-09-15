"""External anchoring of certificate checkpoints to a transparency log.

The design doc (docs/specs/2026-09-09-veridict-design.md, checkpoint section)
called this hardening out from day one: "periodically publish checkpoint
hashes to an external anchor (timestamping/notary service — not blockchain,
just external pinning)". This module does exactly that against Sigstore
Rekor's public-good transparency log (RFC 6962-family, the Certificate
Transparency model): one SHA-256 digest binding {cert_id, key_id,
checkpoint_seq, chain_hash} goes to the log; the log's signature over the
canonicalized entry (the SET) comes back. Offline verification after that
needs NO trust in us: the pinned Rekor key proves the entry existed in the
public tree at the recorded time.

Threat model note (why an ephemeral ECDSA key is enough): Rekor's
hashedrekord verifier rejects Ed25519 (upstream hash-dispatch quirk), and
the anchor is an EXISTENCE attestation — authority over the certificate
never leaves the enrolled Ed25519 key that signed it. Anyone, including an
attacker, can anchor any digest; that launders nothing, because a forged
certificate fails `veridict verify` on its own signature. The anchor only
adds: "this exact checkpoint existed publicly at time T".

Contract pinned against the live public-good instance on 2026-09-14 (see
tests/test_anchor.py fixtures — recorded responses, not invented ones):
  * POST /api/v1/log/entries, FLAT body: {apiVersion, kind, spec}
    (a wrapped map returns "kind in body is required")
  * spec.signature: {content: <b64 DER ECDSA-P256 PREHASHED over the
    digest BYTES>, publicKey.content: <b64 SPKI PEM>} — Ed25519 keys are
    rejected by this endpoint variant
  * SET verifies over canonicalized {"body","integratedTime","logID",
    "logIndex"} JSON, ECDSA-P256-SHA256
  * checkpoint note signature: base64 blob with a 4-byte prefix; the DER
    after it verifies (prehashed) over sha256(note-head + "\\n")
  * inclusion proofs use Trillian's tiled Merkle tree — this module
    therefore checks the structural leaf/uuid/root identities and both
    log signatures; full path folding is left to Rekor-aware verifiers.
"""
from __future__ import annotations

import base64
import hashlib
import json

from .utils import sha256_hex

REKOR_SERVER = "https://rekor.sigstore.dev"
ANCHOR_TYPE = "veridict-anchor-1"
# Pinned from Sigstore TUF (tuf-repo-cdn.sigstore.dev, targets 5.targets.json,
# target "rekor.pub", sha256 dce5ef71…): fetching targets directly from the
# TUF *targets* metadata (a signed document) on rotation — see
# REFRESH_RECIPE below. Rotation: python3 -m veridict.anchor refresh-keys
REFRESH_RECIPE = (
    "1) GET https://tuf-repo-cdn.sigstore.dev/5.targets.json  "
    "2) read signed.targets['rekor.pub'].hashes.sha256  "
    "3) GET https://tuf-repo-cdn.sigstore.dev/targets/<sha256>.rekor.pub  "
    "4) re-verify sha256, update REKOR_PUBLIC_KEY_PEM below")
REKOR_PUBLIC_KEY_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwr\n"
    "kBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==\n"
    "-----END PUBLIC KEY-----\n")


def _canonical(obj) -> bytes:
    """Sorted-key compact JSON — byte-compatible with the canonicalization
    Rekor signs for the SET (proven against the live log, see module
    docstring)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def bound_fields(cert: dict) -> dict:
    anchor = cert.get("ledger_anchor") or {}
    key_id = ""
    sigs = cert.get("signatures") or []
    if sigs:
        key_id = sigs[0].get("key_id", "")
    return {"anchor": ANCHOR_TYPE, "cert_id": cert.get("cert_id", ""),
            "key_id": key_id,
            "checkpoint_seq": anchor.get("checkpoint_seq"),
            "chain_hash": anchor.get("chain_hash", "")}


def anchor_digest(bound: dict) -> str:
    return sha256_hex(_canonical(bound))


def leaf_hash(body: bytes) -> bytes:
    """RFC 6962 Merkle leaf: SHA256(0x00 || data). Confirmed against the
    live log: Rekor's entry UUID is hex(treeID || leaf || treeID)."""
    return hashlib.sha256(b"\x00" + body).digest()


def _ecdsa_verify(pem: str, signature: bytes, msg: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, utils
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    pub = load_pem_public_key(pem.encode())
    try:
        pub.verify(signature, hashlib.sha256(msg).digest(),
                   ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False
    except Exception:                                  # malformed sig etc.
        return False


def _b64(s: str) -> bytes:
    return base64.b64decode(s)


# --------------------------------------------------------------------------
# publish

def publish(ledger_entries: list[dict], cert: dict, *,
            rekor_url: str = REKOR_SERVER, timeout: float = 60.0) -> dict:
    """Anchor the certificate's checkpoint to Rekor. Raises RuntimeError on
    any rejection — callers decide whether an anchor failure is fatal.

    `ledger_entries` is the parsed ledger; the checkpoint entry at
    cert.ledger_anchor.checkpoint_seq must carry the chain_hash the cert
    claims — we refuse to anchor a binding we cannot see in the ledger.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
    from cryptography.hazmat.primitives import hashes, serialization
    import httpx

    bound = bound_fields(cert)
    cp = next((e for e in ledger_entries
               if e.get("seq") == bound["checkpoint_seq"]
               and e.get("entry_type") == "checkpoint.anchored"), None)
    if cp is None:
        raise RuntimeError(f"no checkpoint.anchored entry at seq "
                           f"{bound['checkpoint_seq']} — refusing to anchor")
    if cp.get("payload", {}).get("chain_hash") != bound["chain_hash"]:
        raise RuntimeError("ledger chain_hash at checkpoint_seq disagrees "
                           "with the certificate — refusing to anchor")
    digest = anchor_digest(bound)

    priv = ec.generate_private_key(ec.SECP256R1())     # ephemeral; see header
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    der_sig = priv.sign(bytes.fromhex(digest),
                        ec.ECDSA(asym_utils.Prehashed(hashes.SHA256())))
    body = {"apiVersion": "0.0.1", "kind": "hashedrekord",
            "spec": {"data": {"hash": {"algorithm": "sha256", "value": digest}},
                     "signature": {"content": base64.b64encode(der_sig).decode(),
                                   "publicKey": {"content": base64.b64encode(
                                       pub_pem.encode()).decode()}}}}
    resp = httpx.post(rekor_url.rstrip("/") + "/api/v1/log/entries",
                      json=body, timeout=timeout)
    if resp.status_code not in (200, 201):
        raise RuntimeError(f"rekor rejected the anchor "
                           f"(HTTP {resp.status_code}): {resp.text[:200]}")
    entry_map = resp.json()
    (uuid, entry), = entry_map.items()
    return {"anchor_version": ANCHOR_TYPE,
            "rekor": {"server": rekor_url, "uuid": uuid, "entry": entry},
            "bound": bound, "digest": digest}


# --------------------------------------------------------------------------
# verify (offline; only the pinned key is trusted)

def verify(sidecar: dict, cert: dict | None = None, *,
           rekor_key_pem: str = REKOR_PUBLIC_KEY_PEM) -> dict:
    """Check every cryptographic claim of an anchor. Returns
    {valid, errors[], summary{}} — never raises on bad data.

    With a certificate: full check (binding to THAT cert + log crypto).
    With cert=None: crypto-only — proves the sidecar is a genuine Rekor
    commitment to `sidecar.digest`, without claiming what it binds.
    """
    errors: list[str] = []
    r = (sidecar.get("rekor") or {})
    entry = r.get("entry") or {}
    bound = sidecar.get("bound") or {}
    digest = sidecar.get("digest", "")

    if cert is not None:
        # 1) the binding must be exactly the certificate we were given
        expected = bound_fields(cert)
        if bound != expected:
            errors.append("anchor bound does not match the certificate "
                          f"(bound={bound.get('cert_id')} cert={expected['cert_id']})")
        if digest and digest != anchor_digest(expected):
            errors.append("anchor digest does not recompute from the binding")
    else:
        expected = bound

    body_b64 = entry.get("body", "")
    try:
        body = base64.b64decode(body_b64)
        body_obj = json.loads(body)
    except Exception as exc:
        return {"valid": False, "errors": errors + [f"entry body undecodable: {exc}"],
                "summary": {}}
    h = body_obj.get("spec", {}).get("data", {}).get("hash", {})
    if h.get("value") != digest:
        errors.append("entry hash does not match the anchor digest")
    if body_obj.get("kind") != "hashedrekord":
        errors.append(f"unexpected entry kind {body_obj.get('kind')!r}")

    ver = entry.get("verification") or {}
    proof = ver.get("inclusionProof") or {}
    note = proof.get("checkpoint", "")
    head, sep, rest = note.partition("\n\n")
    if not sep:
        errors.append("checkpoint note malformed")
        return {"valid": False, "errors": errors, "summary": {}}
    lines = head.split("\n")
    if len(lines) != 3:
        errors.append("checkpoint note must have origin/size/root lines")
        return {"valid": False, "errors": errors, "summary": {}}
    tree_size = lines[1].strip()
    root_b64 = lines[2].strip()
    try:
        root_from_note = base64.b64decode(root_b64).hex()
    except Exception:
        root_from_note = ""
    if root_from_note and root_from_note != proof.get("rootHash"):
        errors.append("proof rootHash disagrees with the signed checkpoint")
    if tree_size.isdigit() and int(tree_size) <= int(proof.get("logIndex", -1)):
        errors.append("proof logIndex is not inside the signed tree")

    # 2) UUID structure: treeID || leaf || treeID (live-log convention)
    uuid = r.get("uuid", "")
    leaf_hex = leaf_hash(body).hex()
    if len(uuid) == 96 and uuid[16:80] != leaf_hex:
        errors.append("uuid does not embed the entry's Merkle leaf hash")

    # 3) SET: Rekor's signature over the canonicalized 4-field entry
    set_b64 = ver.get("signedEntryTimestamp", "")
    msg = _canonical({"body": body_b64,
                      "integratedTime": entry.get("integratedTime"),
                      "logID": entry.get("logID"),
                      "logIndex": entry.get("logIndex")})
    if not set_b64 or not _ecdsa_verify(rekor_key_pem, _b64(set_b64), msg):
        errors.append("SET signature does not verify against the pinned Rekor key")

    # 4) checkpoint (STH) signature: 4-byte prefix, DER over head+newline
    try:
        sig_line = rest.strip()                       # "— rekor.sigstore.dev <b64>"
        blob = _b64(sig_line.split(" ")[-1])
        ok_note = _ecdsa_verify(rekor_key_pem, blob[4:], (head + "\n").encode())
    except Exception:
        ok_note = False
    if not ok_note:
        errors.append("checkpoint note signature does not verify against the "
                      "pinned Rekor key")

    summary = {"cert_id": expected["cert_id"],
               "checkpoint_seq": expected["checkpoint_seq"],
               "chain_hash": expected["chain_hash"],
               "digest": anchor_digest(expected),
               "logIndex": entry.get("logIndex"),
               "integratedTime": entry.get("integratedTime"),
               "server": r.get("server"), "uuid": uuid,
               "tree_size_at_anchor": tree_size}
    return {"valid": not errors, "errors": errors, "summary": summary}
