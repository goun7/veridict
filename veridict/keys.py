"""Key management: ed25519 enrollment + signing (§7.8, Phase 1 single-signer)."""
from __future__ import annotations

import base64
import json
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .ledger import Ledger
from .schemas import ActorRef
from .utils import sha256_hex

SYSTEM_AUTHOR = ActorRef(kind="system", identity="veridict-core", version="0.1.0")


class KeyStore:
    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger
        self._keys: dict[str, Ed25519PrivateKey] = {}

    def generate_and_enroll(self, identity: str) -> str:
        priv = Ed25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        key_id = sha256_hex(pub_bytes)[:16]
        pub_pem = priv.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
        self.ledger.append("key.enrolled", SYSTEM_AUTHOR, {
            "key_id": key_id, "algorithm": "ed25519",
            "purpose": "certificate-signing", "identity": identity,
            "public_pem": pub_pem,
        })
        self._keys[key_id] = priv
        return key_id

    def sign(self, key_id: str, message: bytes) -> str:
        return base64.b64encode(self._keys[key_id].sign(message)).decode("ascii")

    def export_key_file(self, key_id: str, path: str) -> str:
        """Persist the private key for signers that must survive a process
        boundary (the registry CLI). The ledger only ever holds the PUBLIC
        half; the owner of this file holds signing power over the registry.
        Created with 0600 permissions."""
        priv = self._keys[key_id]
        private_pem = priv.private_bytes(
            Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode("utf-8")
        import os as _os
        fd = _os.open(path, _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC, 0o600)
        with _os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"key_id": key_id, "private_pem": private_pem}, f)
        return path

    def load_key_file(self, path: str) -> str:
        """Load a previously exported private key into this store."""
        import json as _json
        with open(path, encoding="utf-8") as f:
            data = _json.load(f)
        priv = serialization.load_pem_private_key(
            data["private_pem"].encode("utf-8"), password=None)
        self._keys[data["key_id"]] = priv
        return data["key_id"]

    def public_pem(self, key_id: str) -> str:
        for e in self.ledger.query("key.enrolled"):
            if e["payload"]["key_id"] == key_id:
                return e["payload"]["public_pem"]
        raise KeyError(f"unknown key_id: {key_id}")

    @staticmethod
    def verify_signature(public_pem: str, message: bytes, sig_b64: str) -> bool:
        try:
            pub = serialization.load_pem_public_key(public_pem.encode("utf-8"))
            sig = base64.b64decode(sig_b64, validate=True)
            pub.verify(sig, message)
            return True
        except (InvalidSignature, binascii.Error, ValueError, TypeError):
            return False
