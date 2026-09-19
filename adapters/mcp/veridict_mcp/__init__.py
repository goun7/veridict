"""Veridict MCP server — three tools over the protocol boundary.

record_evidence / verify_ledger / audit_artifact. Importing this package
requires the MCP SDK; without it the module exits 2 with a message rather
than raising (so a missing optional dep is disclosed, never silent).
"""
from .server import audit_artifact, mcp, record_evidence, verify_ledger

__all__ = ["mcp", "record_evidence", "verify_ledger", "audit_artifact"]
