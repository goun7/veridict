"""Watcher platform contracts (§5.3): signed manifests + blind sessions.

Watchers are third-party producers. They can NEVER produce W1a (tier ceiling),
they are blind (see only claim summary + artifact digest), and they have
authority over NOTHING except the evidence items they return to the
orchestrator (which records them as evidence.recorded).
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass

from .keys import KeyStore
from .ledger import Ledger
from .schemas import ActorRef, Claim, EVIDENCE_CLASSES, EvidenceItem
from .utils import canonical_json, payload_digest, sha256_hex

EID_SALT = "veridict-watcher-v1"
ALLOWED_MAX_TIERS = ("W1b", "W2", "W3")


@dataclass(frozen=True)
class WatcherManifest:
    watcher_id: str
    name: str
    version: str
    producer: dict                # {identity, maintainer} — no anonymous watchers
    capabilities: dict            # {evidence_classes: tuple, max_tier, subscribes_to: tuple}
    resource_class: dict          # {timeout_seconds, cost_budget, sandbox_level}
    integrity: dict               # {code_hash, update_policy}

    def __post_init__(self) -> None:
        cap = self.capabilities
        if cap["max_tier"] not in ALLOWED_MAX_TIERS:
            raise ValueError(
                f"watcher max_tier must be one of {ALLOWED_MAX_TIERS} (W1a is "
                "machine evidence — reserved to built-in verifiers, §5.3)")
        bad = [c for c in cap["evidence_classes"] if c not in EVIDENCE_CLASSES]
        if bad:
            raise ValueError(f"unknown evidence classes: {bad}")
        if not self.producer.get("identity") or not self.producer.get("maintainer"):
            raise ValueError("watcher producer requires identity + maintainer "
                             "(no anonymous watchers)")
        if not self.watcher_id:
            raise ValueError("watcher_id required")

    def to_dict(self) -> dict:
        d = asdict(self)
        d["capabilities"]["evidence_classes"] = list(self.capabilities["evidence_classes"])
        d["capabilities"]["subscribes_to"] = list(self.capabilities["subscribes_to"])
        return d

    @staticmethod
    def from_dict(d: dict) -> "WatcherManifest":
        return WatcherManifest(
            watcher_id=d["watcher_id"], name=d["name"], version=d["version"],
            producer=d["producer"],
            capabilities={"evidence_classes": tuple(d["capabilities"]["evidence_classes"]),
                          "max_tier": d["capabilities"]["max_tier"],
                          "subscribes_to": tuple(d["capabilities"]["subscribes_to"])},
            resource_class=d["resource_class"], integrity=d["integrity"])

    def manifest_digest(self) -> str:
        return payload_digest(self.to_dict())


REGISTRY_AUTHOR = ActorRef(kind="watcher_registry", identity="veridict-registry",
                           version="0.2.0")


class ManifestRegistry:
    """Registration contract: signed manifests live in the append-only ledger.

    The signature covers ONLY the canonical manifest body (not the digest/
    signature wrapper), so a retroactive body edit breaks both the stored
    digest and the signature — and verify_manifest reports both honestly.
    """

    def __init__(self, ledger: Ledger, keystore: KeyStore, key_id: str) -> None:
        self.ledger = ledger
        self.keystore = keystore
        self.key_id = key_id

    def register(self, manifest: WatcherManifest) -> dict:
        body = manifest.to_dict()
        sig = self.keystore.sign(self.key_id, canonical_json(body).encode("utf-8"))
        return self.ledger.append("watcher.registered", REGISTRY_AUTHOR, {
            "manifest": body,
            "manifest_digest": manifest.manifest_digest(),
            "signature": {"key_id": self.key_id, "algorithm": "ed25519",
                          "sig_b64": sig},
        })

    @staticmethod
    def get_manifest(ledger: Ledger, watcher_id: str) -> WatcherManifest | None:
        for e in reversed(ledger.query("watcher.registered")):
            if e["payload"]["manifest"]["watcher_id"] == watcher_id:
                return WatcherManifest.from_dict(e["payload"]["manifest"])
        return None

    @staticmethod
    def verify_manifest(ledger: Ledger, watcher_id: str) -> dict:
        errors: list[str] = []
        entry = next((e for e in reversed(ledger.query("watcher.registered"))
                      if e["payload"]["manifest"]["watcher_id"] == watcher_id), None)
        if entry is None:
            return {"valid": False, "signature_valid": False,
                    "errors": [f"watcher {watcher_id} not registered"]}
        body = entry["payload"]["manifest"]
        # Entry-level integrity first: a retroactive edit ANYWHERE in the
        # payload (manifest body or wrapper) stales the stored payload_hash.
        if payload_digest(entry["payload"]) != entry["payload_hash"]:
            errors.append(f"ledger payload hash mismatch at seq {entry['seq']}")
        digest = entry["payload"]["manifest_digest"]
        if payload_digest(body) != digest:
            errors.append("manifest digest mismatch")
        sig = entry["payload"]["signature"]
        pub = next((e2["payload"]["public_pem"] for e2 in ledger.query("key.enrolled")
                    if e2["payload"]["key_id"] == sig["key_id"]), None)
        sig_ok = bool(pub) and KeyStore.verify_signature(
            pub, canonical_json(body).encode("utf-8"), sig["sig_b64"])
        if not sig_ok:
            errors.append("signature: no enrolled key verifies the manifest body")
        try:
            WatcherManifest.from_dict(body)   # re-validate invariants post-tamper
        except (ValueError, KeyError, TypeError) as exc:
            # A structurally MALFORMED body (not just a tampered one) must
            # surface as an error line — never crash the verifier.
            errors.append(f"invalid manifest: {type(exc).__name__}: {exc}")
        return {"valid": not errors, "signature_valid": sig_ok, "errors": errors}


class WatcherSession:
    """Runtime binding of a manifest to a doctrine function (the watcher's code).

    The session is the authority boundary: whatever the fn returns is clamped
    to the manifest's max_tier ceiling and evidence_class before it can
    become an evidence item (§5.3). fn sees (claim_summary, artifact REFERENCE)
    — the path when the caller supplies one, else the digest — and NOTHING of
    any other producer's output (blindness, §5.3).
    """

    def __init__(self, manifest: WatcherManifest, doctrine_fn) -> None:
        self.manifest = manifest
        self.doctrine_fn = doctrine_fn

    def matches(self, claim: Claim) -> bool:
        subs = self.manifest.capabilities["subscribes_to"]
        if "*" in subs:
            return True
        hay = f"{claim.predicate} {claim.summary} {claim.critical_class or ''}".lower()
        return any(s.lower() in hay for s in subs)


_CEILING_TIER = {"W1b": "W1b", "W2": "W2", "W3": "W3"}  # never W1a — §5.3 ceiling


def run_session(session: WatcherSession, claim: Claim, artifact_digest: str,
                artifact_path: str | None = None,
                timeout_seconds: float | None = None) -> EvidenceItem | None:
    """Blind single-watcher run. Abstain (None) on error/None/bad output (§5.4).

    The fn receives (claim.summary, artifact REFERENCE): the artifact path when
    the caller supplies one, else the digest — "claim + artifact references"
    (§5.3). Blindness means no other producers' outputs, not reference-freeness.
    Deadline (§5.3 resource_class): the manifest's timeout_seconds applies when
    the caller passes none; expiry → abstain (a slow watcher is not a refuting
    one). With no deadline the fn runs inline on the calling thread.
    """
    deadline = timeout_seconds
    if deadline is None:
        deadline = session.manifest.resource_class.get("timeout_seconds") or 0
    try:
        if deadline and deadline > 0:
            executor = ThreadPoolExecutor(max_workers=1)
            try:
                future = executor.submit(session.doctrine_fn, claim.summary,
                                         artifact_path or artifact_digest)
                out = future.result(timeout=deadline)
            finally:
                executor.shutdown(wait=False)   # never join a hung watcher
        else:
            out = session.doctrine_fn(claim.summary, artifact_path or artifact_digest)
        if out is None:
            return None
        stance, confidence, rationale = out
        conf = max(0.0, min(1.0, float(confidence)))
    except Exception:            # noqa: BLE001 — a crashing watcher must abstain, never crash the audit
        return None
    if stance not in ("SUPPORTS", "REFUTES"):
        return None
    cap = session.manifest.capabilities
    m = session.manifest
    tier = _CEILING_TIER[cap["max_tier"]]
    evidence_class = cap["evidence_classes"][0]
    return EvidenceItem(
        evidence_id=sha256_hex(f"{EID_SALT}|{claim.claim_id}|{m.watcher_id}")[:24],
        claim_id=claim.claim_id, evidence_class=evidence_class, tier=tier,
        producer={"kind": "watcher", "identity": m.producer["identity"],
                  "version": m.version, "family": m.watcher_id},
        artifact_ref=artifact_digest,
        reproducibility={"deterministic": tier == "W1b", "rerun_recipe": None},
        stance=stance, confidence=conf, rationale=rationale)
