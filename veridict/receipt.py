"""Signed receipts for agent work — the "proof-of-done" layer (§receipt).

An audit certificate (certificate.py) answers "was this artifact sound under
this policy". A receipt answers the narrower, more common question a paying
party actually asks: "did the agent do the thing it claims it did, and can
I check that myself?".

A receipt is a small, self-contained signed document:

  - ``content_digest`` — sha256 over the canonical achievement payload
    (statement + evidence lines). It recomputes from the receipt's OWN
    fields, so anyone can confirm the receipt binds to what it certifies
    without trusting the issuer.
  - ``cert_id`` — derived from the subject fields exactly the way an audit
    certificate's id is, so ONE standalone verifier
    (verify_certificate_standalone) serves both document kinds.
  - ``signatures`` — ed25519 over the canonical body, verified against the
    public key embedded in the receipt. The private half never leaves the
    issuer's machine; only its verifier ships.
  - ``issued_at`` — an ISO-8601 UTC timestamp inside the signed body, so the
    signature binds issuance order, not just content.

Receipts live in the same append-only, hash-chained ledger as audits, which
makes issuance and revocation independently auditable: revocation appends a
``receipt.revoked`` entry and never rewrites the receipt, so a revoked
receipt still carries an intact signature and a discoverable disavowal.

Privacy / custody note: this module creates LOCAL document-signing keys
(ed25519 over the workspace ledger). It does not create, import, or use any
blockchain key, connects to no network, and touches no payment rail.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from .keys import KeyStore
from .ledger import ChainError, Ledger
from .schemas import SCHEMA_VERSION, ActorRef
from .utils import canonical_json, sha256_hex

RECEIPT_TYPE = "veridict-receipt-v1"
SYSTEM_AUTHOR = ActorRef(kind="system", identity="veridict-receipt", version="0.1.0")


class ReceiptError(Exception):
    """A malformed request the issuer refuses to silently paper over."""


def content_digest(achievement: str, evidence: list[str]) -> str:
    """sha256 over the canonical achievement payload — the binding a third
    party recomputes from the receipt alone."""
    return sha256_hex(canonical_json(
        {"achievement": achievement, "evidence": list(evidence)}))


class ReceiptWorkspace:
    """A directory holding one issuer's ledger and signing key.

    Layout::

        home/
          ledger.jsonl      append-only hash-chained ledger
          keys/issuer.json  the issuer's PRIVATE signing key, mode 0600

    The key file is the custody boundary: whoever can read it can issue and
    revoke receipts for this workspace. It is created 0600 and is never
    returned by any tool, logged, or transmitted. Only the PUBLIC half is
    written into the ledger (key.enrolled) and into receipts.
    """

    def __init__(self, home: str) -> None:
        self.home = home
        self.ledger_path = os.path.join(home, "ledger.jsonl")
        self._key_path = os.path.join(home, "keys", "issuer.json")

    @classmethod
    def resolve(cls, home: str | None) -> "ReceiptWorkspace":
        """Pick the workspace: the explicit path, else $VERIDICT_HOME, else
        a .veridict dir in the current working directory."""
        if home:
            return cls(home)
        env = os.environ.get("VERIDICT_HOME")
        return cls(env if env else os.path.join(os.getcwd(), ".veridict"))

    def ledger(self) -> Ledger:
        os.makedirs(self.home, exist_ok=True)
        if os.path.exists(self.ledger_path):
            return Ledger.load(self.ledger_path)
        return Ledger()

    def save(self, ledger: Ledger) -> None:
        os.makedirs(self.home, exist_ok=True)
        ledger.save(self.ledger_path)

    def issuer_key(self, ledger: Ledger, identity: str) -> tuple[KeyStore, str]:
        """Return (keystore, key_id) for this workspace's issuer identity.

        First call generates a key, enrolls ONLY the public half in the
        ledger, and persists the private half at 0600 so the identity
        survives a process boundary. Later calls reload it — one stable
        issuer identity per workspace."""
        ks = KeyStore(ledger)
        key_dir = os.path.dirname(self._key_path)
        if os.path.exists(self._key_path):
            key_id = ks.load_key_file(self._key_path)
            # The enrolled public half must already be in this chain, or the
            # key file is from a different ledger: refuse rather than sign
            # with a key the chain cannot vouch for.
            try:
                ks.public_pem(key_id)
            except KeyError as exc:
                raise ReceiptError(
                    f"issuer key {key_id} is not enrolled in this ledger — "
                    f"the workspace key file belongs to another ledger; "
                    f"remove {self._key_path} to reinitialize") from exc
            return ks, key_id
        os.makedirs(key_dir, exist_ok=True)
        key_id = ks.generate_and_enroll(identity)
        ks.export_key_file(key_id, self._key_path)
        return ks, key_id


def issue_receipt(workspace: ReceiptWorkspace, achievement: str,
                  actor_identity: str, evidence: list[str] | None = None,
                  issuer_identity: str = "veridict-receipt",
                  criticality: tuple[str, ...] = ()) -> dict:
    """Issue a signed receipt for one achievement. Returns the receipt.

    ``achievement`` is the falsifiable statement ("deployed api v2 to
    staging", "paid invoice 1042"). ``evidence`` are the human/machine
    grounds the issuer relied on — recorded, not trusted: the receipt binds
    their hash, it does not adjudicate their truth. That distinction is the
    entire point: a receipt is proof of record, and the ledger is what makes
    the record tamper-evident.
    """
    if not isinstance(achievement, str) or not achievement.strip():
        raise ReceiptError("achievement is required — the falsifiable "
                           "statement the receipt certifies")
    if len(achievement) > 4096:
        raise ReceiptError("achievement exceeds 4096 chars — a receipt is a "
                           "record, not a document")
    ev = [str(x) for x in (evidence or []) if str(x).strip()]
    if actor_identity and not isinstance(actor_identity, str):
        raise ReceiptError("actor_identity must be a string")

    ledger = workspace.ledger()
    ks, key_id = workspace.issuer_key(ledger, issuer_identity)
    digest = content_digest(achievement, ev)
    task_id = f"receipt-{digest[:16]}"

    # The request is logged BEFORE the receipt exists, so the chain records
    # what was asked for and in what order — the same ordering discipline the
    # audit ledger applies to claims.
    ledger.append("receipt.requested", SYSTEM_AUTHOR, {
        "task_id": task_id, "actor_identity": actor_identity,
        "achievement": achievement, "evidence": ev,
        "content_digest": digest, "criticality": list(criticality)})

    receipt = {
        "schema_version": SCHEMA_VERSION,
        "certificate_type": RECEIPT_TYPE,
        "cert_id": sha256_hex(f"{task_id}|{digest}")[:24],
        "subject": {"artifact_digest": digest, "task_id": task_id,
                    "actor_identity": actor_identity},
        "achievement": achievement,
        "evidence": ev,
        "criticality": list(criticality),
        "issuer": {"identity": issuer_identity, "key_id": key_id},
        "issued_at": datetime.now(timezone.utc).isoformat(),
        # Self-containment: the public verifier and the issuance time travel
        # inside the document, both inside the signature. Without them a
        # third party holding only this file cannot check anything.
        "public_key": {"key_id": key_id, "algorithm": "ed25519",
                       "public_pem": ks.public_pem(key_id)},
        "verify_instructions": "veridict verify <receipt.json>",
        "signatures": [],
    }
    body = dict(receipt)
    body.pop("signatures")
    receipt["signatures"] = [{"key_id": key_id, "algorithm": "ed25519",
                              "sig_b64": ks.sign(key_id,
                                                 canonical_json(body).encode("utf-8"))}]
    ledger.append("receipt.issued", SYSTEM_AUTHOR, receipt)
    workspace.save(ledger)
    return receipt


def _receipt_revoked(ledger: Ledger, cert_id: str) -> str | None:
    for e in ledger.query("receipt.revoked"):
        if e["payload"].get("cert_id") == cert_id:
            reason = str(e["payload"].get("reason", "")).strip()
            return reason or "revoked by issuer (no reason recorded)"
    return None


def verify_receipt(cert_path: str, ledger_path: str | None = None) -> dict:
    """Verify a receipt — standalone from the file alone, or fully when the
    issuer's ledger is supplied.

    Standalone proves what the document can prove on its own (content hash,
    signature, timestamp) and reports verdict-replay and revocation as
    ``unknown`` rather than assuming them. With a ledger it additionally
    checks the chain, that the receipt was actually issued into that chain,
    and that it has not been revoked.
    """
    from .certificate import verify_certificate_standalone

    report = verify_certificate_standalone(cert_path)
    with open(cert_path, encoding="utf-8") as f:
        receipt = json.load(f)
    ctype = receipt.get("certificate_type")
    if ctype != RECEIPT_TYPE:
        report["errors"].append(
            f"receipt: certificate_type {ctype!r} is not {RECEIPT_TYPE!r}")
        report["valid"] = False

    if not ledger_path:
        report["revoked"] = None
        return report

    sub = {"chain_valid": None, "issued": None, "revoked": None}
    try:
        ledger = Ledger.load(ledger_path)
    except (ChainError, OSError, json.JSONDecodeError) as exc:
        report["errors"].append(f"ledger: cannot load: {type(exc).__name__}: {exc}")
        report["valid"] = False
        report.update(sub)
        return report
    chain_ok, chain_msg = ledger.verify_chain()
    sub["chain_valid"] = chain_ok
    if not chain_ok:
        report["errors"].append(f"chain: {chain_msg}")

    issued = any(e["entry_type"] == "receipt.issued"
                 and e["payload"].get("cert_id") == receipt.get("cert_id")
                 for e in ledger.entries)
    sub["issued"] = issued
    if not issued:
        report["errors"].append(
            "receipt: no matching receipt.issued entry in this ledger — the "
            "receipt was not issued into the chain you supplied")
    reason = _receipt_revoked(ledger, receipt.get("cert_id"))
    sub["revoked"] = bool(reason)
    if reason:
        report["errors"].append(f"revoked: {reason}")
    report["revoked"] = sub["revoked"]
    # Standalone verification has no chain to check, so it leaves this
    # absent; with the ledger supplied it becomes the chain's own verdict.
    report["chain_valid"] = chain_ok
    report["valid"] = report["valid"] and chain_ok and issued and not sub["revoked"]
    return report


def revoke_receipt(workspace: ReceiptWorkspace, cert_id: str, reason: str,
                   issuer_identity: str = "veridict-receipt") -> dict:
    """Append a receipt.revoked entry. Idempotent in status; the entry is
    never a rewrite, so the receipt's signature stays intact and the
    disavowal stays auditable."""
    if not isinstance(cert_id, str) or not cert_id.strip():
        raise ReceiptError("cert_id is required")
    ledger = workspace.ledger()
    # Enrolling/loading the issuer key keeps the workspace's custody story
    # uniform: the same identity that issues is the identity that revokes.
    workspace.issuer_key(ledger, issuer_identity)
    entry = ledger.append("receipt.revoked", SYSTEM_AUTHOR, {
        "cert_id": cert_id, "reason": str(reason or "").strip(),
        "revoked_at": datetime.now(timezone.utc).isoformat()})
    workspace.save(ledger)
    return {"cert_id": cert_id, "seq": entry["seq"],
            "reason": str(reason or "").strip()}


def list_receipts(workspace: ReceiptWorkspace, include_revoked: bool = True,
                  limit: int = 100) -> list[dict]:
    """Enumerate issued receipts newest-first, each annotated with its
    revocation status from the same chain."""
    ledger = workspace.ledger()
    revoked_ids = {e["payload"].get("cert_id")
                   for e in ledger.query("receipt.revoked")}
    out = []
    for e in reversed(ledger.query("receipt.issued")):
        p = e["payload"]
        item = {"cert_id": p.get("cert_id"),
                "actor_identity": p.get("subject", {}).get("actor_identity"),
                "achievement": p.get("achievement"),
                "issued_at": p.get("issued_at"),
                "seq": e["seq"],
                "revoked": p.get("cert_id") in revoked_ids}
        if not include_revoked and item["revoked"]:
            continue
        out.append(item)
        if len(out) >= limit:
            break
    return out
