"""Real-jury provider path, validated WITHOUT an API key.

`OpenAICompatProvider` (the "real jury" surface) is exercised end-to-end
against a local OpenAI-compatible HTTP stub: strict-JSON opinion parsing,
keyless operation (no auth header, no crash), auth propagation when a key
IS configured, ProviderError on HTTP/contract failures, and a full audit
run with one real-surface juror. The keyless tests pin a real defect found
while writing this suite: an unset VERIDICT_JURY_KEY used to raise an
uncaught httpcore.LocalProtocolError (illegal "Bearer " header) — a
misconfigured jury crashed the audit instead of abstaining.
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from veridict.claim_extractor import ClaimExtractor
from veridict.jury import (Jury, Opinion, OpenAICompatProvider,
                           ProviderError, ScriptedProvider)
from veridict.keys import KeyStore
from veridict.ledger import Ledger
from veridict.policy import PolicyDeclaration, Thresholds
from veridict.schemas import ActorRef, Claim, TaskManifest


class _Handler(BaseHTTPRequestHandler):
    responses = []          # list of (claim_substring, status, content); first match wins
    last_auth = None

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        _Handler.last_auth = self.headers.get("Authorization")
        status, content = (200, json.dumps(
            {"stance": "SUPPORTS", "confidence": 0.9, "rationale": "mock ok"}))
        for substring, st, ct in _Handler.responses:
            # body is JSON-encoded: the prompt's newline is the two-char
            # escape "\n", so match on the claim text without a newline
            if substring == "*" or f"Claim: {substring}" in body:
                status, content = st, ct
                break
        payload = json.dumps({"choices": [{"message": {"content": content}}]})
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload.encode())


@pytest.fixture()
def stub_server(monkeypatch):
    monkeypatch.delenv("VERIDICT_JURY_URL", raising=False)
    monkeypatch.delenv("VERIDICT_JURY_KEY", raising=False)
    _Handler.responses = []
    _Handler.last_auth = None
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def _provider(url):
    return OpenAICompatProvider(family="real-a", identity="real-1",
                                base_url=url)


def test_strict_json_opinion_parsed(stub_server):
    op = _provider(stub_server).doctrine("sum", "digest")
    assert op.stance == "SUPPORTS" and op.confidence == 0.9
    assert op.rationale == "mock ok"


def test_keyless_sends_no_auth_header(stub_server):
    _provider(stub_server).doctrine("sum", "digest")
    assert _Handler.last_auth is None


def test_key_is_sent_when_configured(stub_server, monkeypatch):
    monkeypatch.setenv("VERIDICT_JURY_KEY", "test-key")
    _provider(stub_server).doctrine("sum", "digest")
    assert _Handler.last_auth == "Bearer test-key"


def test_http_error_becomes_provider_error(stub_server):
    _Handler.responses = [("boom", 500, "internal")]
    with pytest.raises(ProviderError):
        _provider(stub_server).doctrine("boom", "digest")


def test_malformed_json_content_becomes_provider_error(stub_server):
    _Handler.responses = [("junk", 200, "this is not json")]
    with pytest.raises(ProviderError):
        _provider(stub_server).doctrine("junk", "digest")


def test_out_of_contract_stance_becomes_provider_error(stub_server):
    _Handler.responses = [("maybe", 200, json.dumps(
        {"stance": "MAYBE", "confidence": 0.5, "rationale": "no"}))]
    with pytest.raises(ProviderError):
        _provider(stub_server).doctrine("maybe", "digest")


def test_refutes_opinion_round_trips(stub_server):
    _Handler.responses = [("neg", 200, json.dumps(
        {"stance": "REFUTES", "confidence": 0.95, "rationale": "broken"}))]
    op = _provider(stub_server).doctrine("neg", "digest")
    assert (op.stance, op.confidence, op.rationale) == ("REFUTES", 0.95, "broken")


def test_real_provider_inside_a_full_audit(stub_server, tmp_path):
    """One real-surface juror + one scripted juror, full GATE audit, offline
    verify — the composition the production jury assembles."""
    from veridict.audit import AuditOrchestrator
    from veridict.certificate import verify_certificate

    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("e2e")
    pol = PolicyDeclaration(policy_id="real-jury", mode="GATE", criticality=(),
                            thresholds=Thresholds(), divergence_tolerance=1 / 3)
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    (fixture / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (fixture / "test_calc.py").write_text(
        "from calc import add\n\n\ndef test_add():\n    assert add(1, 1) == 2\n")
    task = TaskManifest(task_id="real-jury-e2e", artifact_path=str(fixture),
                        actor_identity="ai-dev",
                        intent_lines=("MACHINE: add computes the sum of two numbers",),
                        criticality=(), has_existing_tests=True, pytest_args=())
    claim = ClaimExtractor().extract(task, "digest-e2e")[0]
    led.append("claim.registered",
               ActorRef(kind="system", identity="c", version="1"),
               claim.to_dict())
    real = _provider(stub_server)
    stub = ScriptedProvider(family="stub-b", identity="stub-1",
                            default=Opinion("SUPPORTS", 0.8, "stub"))
    jury = Jury([real, stub])
    orch = AuditOrchestrator(led, pol, jury, ks, kid)
    result = orch.run(task, disclosure_level="REDACTED")
    verdicts = result["outcome"].per_claim          # claim_id -> {value, rung, divergence}
    assert verdicts, "audit completed with a real-surface juror"
    assert all(v["value"] in ("VERIFIED", "REFUTED", "INCONCLUSIVE", "ESCALATED")
               for v in verdicts.values())
    lp = str(tmp_path / "led.jsonl")
    cp = str(tmp_path / "cert.json")
    led.save(lp)
    json.dump(result["cert"], open(cp, "w"))
    assert verify_certificate(lp, cp)["valid"]
