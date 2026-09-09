"""Key management: ed25519 enrollment + signing (§7.8, Phase 1 single-signer)."""
from __future__ import annotations

import base64
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
