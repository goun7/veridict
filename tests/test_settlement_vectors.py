"""Settlement-claims conformance vectors — the payer-side bridge surface.

The certificate vectors pin offline CERTIFICATE verification; these pin the
next surface outwards — the CLAIM a payment layer consumes (issue #10 Lane 3,
`veridict settle`, and the cross-repo bridge a settlement layer exercises).
The contract: a claim must follow, field by field, from a certificate the
payer already verified; a forged or inflated claim is refused rather than
paid.

Cross-repo continuity (why these files exist): a bridge consumer in another
repo can pin this directory and detect drift in its OWN CI, without depending
on the producer's pipeline staying alive.
"""
import hashlib
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VEC = os.path.join(REPO, "docs", "standard-test-vectors", "settlement")
CERT_VECTOR = os.path.join(REPO, "docs", "standard-test-vectors",
                           "certificate.json")

# The digest preimage, stated independently of veridict.settlement so this
# test pins the STANDARD's formula, not the implementation's private helper.
_DIGEST_FIELDS = ("cert_id", "task_id", "artifact_digest", "valid", "reasons",
                  "accepted_claims", "total_claims", "jury_families",
                  "risk_level", "policy_digest")


def _std_digest(claim: dict) -> str:
    """Recompute claim_digest with stdlib only — what an independent
    settlement layer must reproduce from the standard alone."""
    body = {k: claim.get(k) for k in _DIGEST_FIELDS}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _load(name: str) -> dict:
    with open(os.path.join(VEC, name), encoding="utf-8") as f:
        return json.load(f)


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def test_honest_claim_reconciles_to_expected():
    from veridict.settlement import SettlementPolicy, verify_settlement_claim
    claim = _load("claim.json")
    with open(CERT_VECTOR, encoding="utf-8") as f:
        cert = json.load(f)
    report = verify_settlement_claim(claim, cert, SettlementPolicy())
    assert report == _load("expected_reconcile.json")
    assert report["valid"] is True
    assert report["reasons"] == []


def test_claim_digest_recomputes_with_stdlib_only():
    """An independent payer must be able to check claim integrity without
    importing veridict — the digest is the whole integrity story."""
    claim = _load("claim.json")
    assert _std_digest(claim) == claim["claim_digest"]


def test_claim_follows_from_the_certificate_vector():
    """Every derived field is recomputed from the certificate, never trusted
    as stored — the same class as D17: derived summary fields must recompute."""
    from veridict.settlement import SettlementPolicy, build_settlement_claim
    with open(CERT_VECTOR, encoding="utf-8") as f:
        cert = json.load(f)
    rebuilt = json.loads(
        build_settlement_claim(cert, SettlementPolicy()).to_json())
    assert rebuilt == _load("claim.json")


def test_regeneration_is_byte_deterministic(tmp_path):
    env = dict(os.environ, SETTLEMENT_VECTOR_OUT=str(tmp_path))
    subprocess.run([sys.executable,
                    os.path.join(REPO, "scripts", "build_settlement_vectors.py")],
                   check=True, env=env, capture_output=True)
    for rel in ("claim.json", "expected_reconcile.json", "expected_tamper.json",
                "tamper/edited_after_issuance.json",
                "tamper/verdict_flipped.json",
                "tamper/wrong_certificate.json",
                "tamper/coverage_inflated.json"):
        assert _sha256(os.path.join(VEC, rel)) == _sha256(
            os.path.join(tmp_path, rel)), rel


def test_every_tamper_case_is_refused():
    """A paying agent has every reason to forge. Each case is one forgery
    class; each must be refused (valid=False), and the refusal must come from
    the pinned rejection class, not from an unrelated accident."""
    from veridict.settlement import SettlementPolicy, verify_settlement_claim
    with open(CERT_VECTOR, encoding="utf-8") as f:
        cert = json.load(f)
    expected = _load("expected_tamper.json")
    for name, exp in expected.items():
        forged = _load(os.path.join("tamper", f"{name}.json"))
        # the forged file's own digest claim must still be honestly
        # self-consistent or honestly stale — pinned, not assumed
        assert _std_digest(forged) == forged["claim_digest"] \
            or not exp["self_consistent_digest"], name
        report = verify_settlement_claim(forged, cert, SettlementPolicy())
        assert report["valid"] is False, f"tamper {name} was ACCEPTED"
        assert report["expected_cert_id"] == exp["expected_cert_id"]
        assert report["presented_cert_id"] == exp["presented_cert_id"]
        assert (report["expected_digest"] == forged["claim_digest"]) \
            == exp["matches_certificate"], name


def test_rejection_reasons_are_reported_not_silent():
    """A refusal must be an artifact with reasons, never the absence of a
    claim — a dropped message cannot turn into a silent pass."""
    from veridict.settlement import SettlementPolicy, verify_settlement_claim
    with open(CERT_VECTOR, encoding="utf-8") as f:
        cert = json.load(f)
    forged = _load("tamper/coverage_inflated.json")
    report = verify_settlement_claim(forged, cert, SettlementPolicy())
    assert report["valid"] is False
    assert report["reasons"], "a refusal must carry reasons"


# The external-consumer lane: a bridge in another repo runs
# scripts/verify_settlement_vector.py (pure stdlib) against our pinned vector
# and gets a loud PASS/RED — bridge continuity does not depend on our
# pipeline alone. This is the concrete answer to "who pins the claims
# contract on the consumer side".

SELFTEST = os.path.join(REPO, "scripts", "verify_settlement_vector.py")


def test_external_selftest_passes_on_the_pinned_vector():
    rc = subprocess.run([sys.executable, SELFTEST, VEC],
                        capture_output=True, text=True, check=False)
    assert rc.returncode == 0, rc.stdout + rc.stderr
    assert rc.stdout.strip().startswith("PASS:"), rc.stdout


def test_external_selftest_is_independent_of_veridict():
    """The consumer script imports nothing from our package — it re-derives
    the claim from the standard. Agreement with the reference implementation
    is the real cross-implementation parity check (issue #1's spirit)."""
    with open(SELFTEST, encoding="utf-8") as f:
        body = f.read()
    assert "from veridict" not in body and "import veridict" not in body, \
        "the consumer selftest must be stdlib-only"


def test_external_selftest_fails_loud_on_a_corrupted_vector(tmp_path):
    """One red line must exit 1 — no silent pass, no partial success."""
    import shutil
    shutil.copytree(VEC, tmp_path / "settlement")
    shutil.copy(CERT_VECTOR, tmp_path / "certificate.json")
    claim_path = tmp_path / "settlement" / "claim.json"
    with open(claim_path, encoding="utf-8") as f:
        claim = json.load(f)
    claim["accepted_claims"] = 99          # inflate the work done
    with open(claim_path, "w", encoding="utf-8") as f:
        json.dump(claim, f, sort_keys=True)
    rc = subprocess.run([sys.executable, SELFTEST, str(tmp_path / "settlement")],
                        capture_output=True, text=True, check=False)
    assert rc.returncode == 1, "a corrupted vector must not pass"
    assert "RED" in rc.stdout, rc.stdout


def test_external_selftest_reports_a_missing_certificate(tmp_path):
    """A consumer who copies only the settlement directory gets a clear
    instruction, not a traceback."""
    import shutil
    shutil.copytree(VEC, tmp_path / "settlement")
    rc = subprocess.run([sys.executable, SELFTEST, str(tmp_path / "settlement")],
                        capture_output=True, text=True, check=False)
    assert rc.returncode == 1
    assert "certificate not found" in rc.stdout, rc.stdout
