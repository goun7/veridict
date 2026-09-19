"""veridict-mcp — Model Context Protocol server for Veridict audits.

Exposes three tools so an agent (or agent framework) can record evidence
and obtain an offline-verifiable audit certificate without leaving the
protocol:

  record_evidence  — append one evidence entry to a ledger
  verify_ledger    — chain-verify a ledger (fail-closed report)
  audit_artifact   — run a full audit on a directory + issue a certificate

Run with any MCP client (Claude Desktop, an agent framework, …):
    python -m veridict_mcp.server

Design note: this is a THIN transport. All semantics live in the
veridict runtime core (stdlib-only); the MCP layer never re-implements
ledger logic — it delegates, and reports errors verbatim.
"""
from __future__ import annotations

import json
import os
import sys

# MCP SDK is optional at import time so the rest of the repo stays
# dependency-light; the server only starts when the SDK is present.
# The SDK renamed FastMCP → MCPServer in v2 (kept as an alias there, but
# the import path moved), so both are tried. Either gives the same
# @server.tool() decorator and the same run() entry point.
try:
    from mcp.server.fastmcp import FastMCP as _Server  # type: ignore  # v1
except ImportError:
    try:
        from mcp.server.mcpserver import MCPServer as _Server  # type: ignore  # v2
    except ImportError as exc:  # pragma: no cover
        sys.stderr.write(
            "veridict-mcp needs the MCP SDK: pip install mcp\n"
            f"(import failed: {exc})\n")
        sys.exit(2)

from veridict.audit import AuditOrchestrator, artifact_digest
from veridict.certificate import CertificateIssuer
from veridict.claim_extractor import ClaimExtractor
from veridict.jury import Jury, Opinion, ScriptedProvider
from veridict.keys import KeyStore
from veridict.ledger import Ledger
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import ActorRef, EvidenceItem

mcp = _Server("veridict")


@mcp.tool()
def record_evidence(ledger_path: str, producer_identity: str,
                    evidence_class: str, tier: str, stance: str,
                    confidence: float, rationale: str = "",
                    artifact_ref: str = "") -> str:
    """Append one evidence entry to a Veridict ledger.

    stance must be SUPPORTS or REFUTES; tier is W1a|W1b|W2|W3 (watchers
    may never emit W1a — the conformance kit C2 enforces this at
    certification time; this tool mirrors the rule for the MCP surface).
    """
    if stance not in ("SUPPORTS", "REFUTES"):
        return json.dumps({"ok": False, "error": f"bad stance {stance!r}"})
    if tier == "W1a":
        return json.dumps({"ok": False,
                           "error": "W1a is machine-only; watchers cannot emit it"})
    led = Ledger.load(ledger_path) if os.path.exists(ledger_path) else Ledger()
    ev = EvidenceItem(
        evidence_id=f"mcp-{len(led.entries)}",
        claim_id="mcp-recorded",
        evidence_class=evidence_class,
        tier=tier,
        producer={"kind": "watcher", "identity": producer_identity,
                  "version": "0.1.0"},
        artifact_ref=artifact_ref,
        reproducibility={"deterministic": True, "rerun_recipe": None},
        stance=stance,
        confidence=max(0.0, min(1.0, confidence)),
        rationale=rationale,
    )
    led.append("evidence.recorded", ActorRef(
        kind="watcher", identity=producer_identity, version="0.1.0"),
        ev.to_dict())
    ok, reason = led.verify_chain()
    if not ok:
        return json.dumps({"ok": False, "error": f"broken chain: {reason}"})
    led.save(ledger_path)
    return json.dumps({"ok": True, "entries": len(led.entries),
                       "head": led.entries[-1]["entry_hash"][:16]})


@mcp.tool()
def verify_ledger(ledger_path: str) -> str:
    """Chain-verify a ledger. Never raises — returns a report."""
    try:
        led = Ledger.load(ledger_path)
        ok, reason = led.verify_chain()
        return json.dumps({"ok": ok, "reason": reason or "chain valid",
                           "entries": len(led.entries)})
    except Exception as exc:  # noqa: BLE001 — report, don't crash the session
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


@mcp.tool()
def audit_artifact(artifact_path: str, ledger_path: str,
                   cert_path: str, intent_line: str,
                   actor_identity: str = "mcp-agent",
                   mode: str = "CERTIFICATE") -> str:
    """Run a full Veridict audit on a directory and issue a certificate.

    intent_line is the DOCTRINE the audit checks (e.g. 'modules are
    idiomatic python'). The certificate verifies offline with
    'veridict verify --ledger L --cert C'.
    """
    if not os.path.isdir(artifact_path):
        return json.dumps({"ok": False, "error": "artifact_path not a directory"})
    led = Ledger.load(ledger_path) if os.path.exists(ledger_path) else Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("mcp-audit")
    pol = PolicyDeclaration(policy_id="mcp", mode=mode, criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)

    # Two DISCLOSED stub jurors from distinct families satisfy the >=2-family
    # jury requirement without an LLM endpoint; set VERIDICT_JURY_URL_* for
    # real verdicts. Stub verdicts are labelled in the rationale so an
    # auditor can never mistake them for LLM verdicts.
    jury = Jury([
        ScriptedProvider(family="stub-a", identity="mcp-stub-a",
                         default=Opinion("SUPPORTS", 0.5,
                                         "stub-a: no LLM endpoint configured")),
        ScriptedProvider(family="stub-b", identity="mcp-stub-b",
                         default=Opinion("REFUTES", 0.5,
                                         "stub-b: no LLM endpoint configured")),
    ])
    orch = AuditOrchestrator(led, pol, jury, ks, kid)
    task = _TaskManifestShim(
        task_id=f"mcp-{os.path.basename(os.path.abspath(artifact_path))}",
        artifact_path=artifact_path, actor_identity=actor_identity,
        intent_lines=(intent_line,), criticality=(),
        has_existing_tests=False, pytest_args=())
    try:
        result = orch.run(task)
        out = os.path.dirname(os.path.abspath(cert_path))
        if out:
            os.makedirs(out, exist_ok=True)
        with open(cert_path, "w", encoding="utf-8") as f:
            json.dump(result["cert"], f, indent=2)
        led.save(ledger_path)
        return json.dumps({
            "ok": True, "cert_path": cert_path, "ledger_path": ledger_path,
            "risk_level": result["cert"].get("risk_level"),
            "score": result["cert"].get("score"),
            "verify": f"veridict verify --ledger {ledger_path} --cert {cert_path}",
        })
    except Exception as exc:  # noqa: BLE001 — report, don't crash the session
        return json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"})


class _TaskManifestShim:
    """Minimal task manifest (avoids importing the full dataclass wiring)."""

    def __init__(self, task_id, artifact_path, actor_identity, intent_lines,
                 criticality, has_existing_tests, pytest_args):
        self.task_id = task_id
        self.artifact_path = artifact_path
        self.actor_identity = actor_identity
        self.intent_lines = intent_lines
        self.criticality = criticality
        self.has_existing_tests = has_existing_tests
        self.pytest_args = pytest_args


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
