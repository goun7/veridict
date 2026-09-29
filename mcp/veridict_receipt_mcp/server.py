"""veridict-receipt-mcp — signed proof-of-done for AI agents.

An agent does work, then needs to hand its principal a receipt that the
principal can verify WITHOUT trusting the agent or the platform. This MCP
server exposes four tools over the Veridict receipt layer:

  issue    — issue a signed, self-contained receipt for one achievement
  verify   — verify a receipt from the file (or the JSON) alone
  revoke   — append a revocation to the issuer's append-only ledger
  list     — enumerate issued receipts with their revocation status

Every receipt carries its own content hash (recomputable by anyone), an
ed25519 signature over the canonical body verified against the public key
embedded in the receipt, and a signed issuance timestamp. `verify` needs
nothing but the receipt — no ledger, no network, no account.

Design note (same rule as the audit adapter): this is a THIN TRANSPORT. All
semantics live in the veridict runtime core (stdlib-only); the MCP layer
never re-implements signing, hashing, or revocation — it delegates, and
reports errors as JSON rather than raising over the protocol.

Custody: the workspace holds one LOCAL document-signing key (ed25519) at
mode 0600. It is not a blockchain key, it touches no payment rail, and only
its PUBLIC half ever appears in a receipt or the ledger.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from typing import List, Optional

# MCP SDK is optional at import time so the transport stays testable without
# it; the server only starts when the SDK is present. The SDK renamed
# FastMCP -> MCPServer in v2 (the v1 alias moved), so both are tried.
try:
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore  # v1
except ImportError:
    try:
        from mcp.server.mcpserver import MCPServer as _Server  # type: ignore  # v2
    except ImportError as exc:  # pragma: no cover
        sys.stderr.write(
            "veridict-receipt-mcp needs the MCP SDK: pip install mcp\n"
            f"(import failed: {exc})\n")
        sys.exit(2)

# The server needs two imports: the MCP SDK (`mcp`) and the runtime core
# (`veridict.*`). `veridict` is importable wherever veridict-standard is
# installed (pip install veridict-standard / pip install -e .); the transport
# package `veridict_receipt_mcp` is importable because `mcp/` is on the path —
# the documented launchers arrange that: `python mcp/run_server.py` (adds
# mcp/ only) or `python -m veridict_receipt_mcp.server` from mcp/.
#
# Deliberately NOT done: inserting the REPO ROOT into sys.path. The repo has
# an `mcp/` directory, so a repo-root entry makes `import mcp` resolve to
# that directory instead of the installed MCP SDK, breaking
# `from mcp.server.fastmcp import FastMCP` for any later import. Keeping the
# SDK resolvable matters more than supporting a bare uninstalled checkout —
# which the README already covers with `pip install -e .`.
from veridict.receipt import (ReceiptError, ReceiptWorkspace, issue_receipt,
                              list_receipts, revoke_receipt, verify_receipt)

mcp = _Server("veridict-receipt")

# The tool named `list` shadows the builtin; the typing aliases keep every
# annotation resolvable regardless of definition order.
_StrList = List[str]


def _default_workspace() -> str:
    return os.environ.get("VERIDICT_HOME") or os.path.join(os.getcwd(), ".veridict")


def _materialize(cert) -> str:
    """Accept a path, a JSON string, or a parsed object; return a path.

    An agent often holds the receipt content rather than a filesystem path
    (it was returned by `issue` or fetched over a wire), so the verifier
    meets the caller where it is. The temp file is the verifier's only
    input, keeping the standalone property honest: verification reads one
    document and nothing else."""
    if isinstance(cert, dict):
        fd, path = tempfile.mkstemp(prefix="veridict-verify-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cert, f, sort_keys=True)
        return path
    if isinstance(cert, str):
        stripped = cert.strip()
        if stripped.startswith("{"):
            return _materialize(json.loads(stripped))
        return cert
    raise ReceiptError("cert must be a path, a JSON string, or an object")


@mcp.tool()
def issue(achievement: str, actor_identity: str = "",
          evidence: Optional[_StrList] = None, workspace: Optional[str] = None,
          issuer_identity: str = "veridict-receipt",
          out: Optional[str] = None) -> str:
    """Issue a signed receipt proving an agent completed an achievement.

    achievement — the falsifiable statement ("deployed api v2 to staging",
                 "paid invoice 1042"). This is what the receipt certifies.
    actor_identity — the agent that did the work (recorded, not trusted).
    evidence — the grounds the issuer relied on (recorded; their hash is
               bound by the receipt, their truth is not adjudicated).

    The receipt is self-contained: its content hash, signature, and issuance
    timestamp all recompute from the file alone via the `verify` tool or
    `veridict verify <receipt.json>`.
    """
    try:
        ws = ReceiptWorkspace.resolve(workspace)
        receipt = issue_receipt(
            ws, achievement, actor_identity, evidence=evidence or [],
            issuer_identity=issuer_identity)
        path = out or os.path.join(ws.home, "receipts",
                                   receipt["cert_id"] + ".json")
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=2, sort_keys=True)
        return json.dumps({
            "ok": True, "cert_id": receipt["cert_id"], "receipt_path": path,
            "issued_at": receipt["issued_at"],
            "verify": f"veridict verify {path}",
            "verify_tool": {"tool": "verify", "cert": path}})
    except (ReceiptError, OSError, ValueError) as exc:
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


@mcp.tool()
def verify(cert, ledger: Optional[str] = None) -> str:
    """Verify a receipt — independently, from the receipt alone.

    cert — a path, a JSON string, or the parsed receipt object.
    ledger — optional path to the issuer's ledger. Without it, verification
             is standalone (content hash + signature + timestamp) and
             reports revocation as unknown; with it, the chain, the issuance
             entry, and the revocation status are also checked.

    Never raises: returns a JSON report. `valid` is true only when every
    check that could be run passed.
    """
    try:
        path = _materialize(cert)
        return json.dumps(verify_receipt(path, ledger))
    except (ReceiptError, OSError, json.JSONDecodeError, ValueError) as exc:
        return json.dumps({"ok": False, "valid": False,
                           "error": f"{type(exc).__name__}: {exc}"})


@mcp.tool()
def revoke(cert_id: str, reason: str = "", workspace: Optional[str] = None,
           issuer_identity: str = "veridict-receipt") -> str:
    """Revoke a receipt by appending a receipt.revoked entry.

    The receipt file is never modified, so its signature stays intact and
    the revocation stays independently auditable in the same hash-chained
    ledger that issued it. Verification with the ledger then reports the
    receipt invalid.
    """
    try:
        ws = ReceiptWorkspace.resolve(workspace)
        res = revoke_receipt(ws, cert_id, reason, issuer_identity=issuer_identity)
        return json.dumps({"ok": True, **res})
    except (ReceiptError, OSError, ValueError) as exc:
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


@mcp.tool()
def list(workspace: Optional[str] = None, active_only: bool = False,
         limit: int = 100) -> str:
    """List issued receipts, newest first, each with its revocation status.

    active_only — omit receipts the issuer has revoked.
    limit — cap on rows (1..1000).
    """
    try:
        ws = ReceiptWorkspace.resolve(workspace)
        rows = list_receipts(ws, include_revoked=not active_only,
                             limit=max(1, min(int(limit), 1000)))
        return json.dumps({"ok": True, "workspace": ws.home,
                           "count": len(rows), "receipts": rows})
    except (OSError, ValueError) as exc:
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
