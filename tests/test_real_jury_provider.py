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
    sequence = []           # when set: one canned content string per request, in order
    last_auth = None
    last_body = None

    def log_message(self, *a):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        _Handler.last_auth = self.headers.get("Authorization")
        _Handler.last_body = body
        if _Handler.sequence:
            status, content = 200, _Handler.sequence.pop(0)
        else:
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
    monkeypatch.delenv("VERIDICT_JURY_SAMPLES", raising=False)
    monkeypatch.delenv("VERIDICT_JURY_TEMPERATURE", raising=False)
    _Handler.responses = []
    _Handler.sequence = []
    _Handler.last_auth = None
    _Handler.last_body = None
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
    # Legacy replies (no `evidence` field) stay acceptable but the receipt
    # records that the opinion was NOT evidence-first (MEC, 2305.17926).
    assert op.rationale == "mock ok [no-evidence-field]"


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
    assert (op.stance, op.confidence) == ("REFUTES", 0.95)
    assert op.rationale.startswith("broken")


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


CLAIM_FOR_JURY = ClaimExtractor().extract(
    TaskManifest(task_id="tj", artifact_path=".", actor_identity="a",
                 intent_lines=("DOCTRINE: api usage is idiomatic",),
                 criticality=(), has_existing_tests=False,
                 pytest_args=()), "d")[0]


# ---------------------------------------------------------------------------
# Calibration layer (0.4.0): evidence-first parsing (MEC) and sample
# calibration. Sources: Wang et al. arXiv:2305.17926 (evidence before
# rating; order effects), Zheng et al. arXiv:2306.05685 (judge biases).

def _op(stance, conf, rationale="r", evidence=None):
    d = {"stance": stance, "confidence": conf, "rationale": rationale}
    if evidence is not None:
        d["evidence"] = evidence
    return json.dumps(d)


def test_evidence_first_opinion_folds_into_rationale(stub_server):
    _Handler.sequence = [_op("SUPPORTS", 0.9, "totals agree",
                             evidence=["tests pass on 3.12",
                                       "digest matches the repo head"])]
    op = _provider(stub_server).doctrine("sum", "digest")
    assert op.rationale == ("evidence: tests pass on 3.12; "
                            "digest matches the repo head | totals agree")
    assert "[no-evidence-field]" not in op.rationale


def test_evidence_field_validated(stub_server):
    for bad in ("only one observation",):
        _Handler.sequence = [_op("SUPPORTS", 0.9, evidence=[bad])]
        with pytest.raises(ProviderError):
            _provider(stub_server).doctrine("sum", "digest")
    _Handler.sequence = [_op("SUPPORTS", 0.9, evidence=["ok", "   "])]
    with pytest.raises(ProviderError):
        _provider(stub_server).doctrine("sum", "digest")


def test_single_sample_keeps_temperature_zero(stub_server):
    _provider(stub_server).doctrine("sum", "digest")
    assert json.loads(_Handler.last_body)["temperature"] == 0


def test_sample_majority_wins_and_discounts_confidence(stub_server, monkeypatch):
    monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "3")
    _Handler.sequence = [_op("SUPPORTS", 0.9, "a"),
                         _op("REFUTES", 0.99, "b"),
                         _op("SUPPORTS", 0.7, "c")]
    op = _provider(stub_server).doctrine("sum", "digest")
    assert op.stance == "SUPPORTS"
    # mean(0.9, 0.7) * 2/3 agreement
    assert abs(op.confidence - 0.8 * (2 / 3)) < 1e-9
    assert op.rationale.endswith("[sample-calibration: 2/3 SUPPORTS]")
    # repeats at temperature 0 measure nothing — the code must have sampled
    assert json.loads(_Handler.last_body)["temperature"] == 0.7


def test_sample_split_without_majority_abstains(stub_server, monkeypatch):
    monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "2")
    _Handler.sequence = [_op("SUPPORTS", 0.9), _op("REFUTES", 0.9)]
    with pytest.raises(ProviderError, match="sample-split"):
        _provider(stub_server).doctrine("sum", "digest")


def test_sample_split_never_becomes_fake_evidence(stub_server, monkeypatch):
    """An abstaining (split) juror adds NO evidence item — it must not even
    silently count as the average of its contradictory samples."""
    monkeypatch.setenv("VERIDICT_JURY_SAMPLES", "2")
    _Handler.sequence = [_op("SUPPORTS", 0.9), _op("REFUTES", 0.9)]
    real = _provider(stub_server)
    jury = Jury([real, ScriptedProvider(
        family="stub-x", identity="stub-x-1",
        default=Opinion("SUPPORTS", 0.8, "stub"))])
    items, abstained = jury.evaluate(CLAIM_FOR_JURY, "digest")
    assert {i.producer["identity"] for i in items} == {"stub-x-1"}
    assert abstained == ["real-1"]
