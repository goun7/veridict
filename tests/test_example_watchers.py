from veridict.ledger import Ledger
from veridict.keys import KeyStore
from veridict.schemas import Claim
from veridict.watchers import ManifestRegistry, run_session

from watchers.security_watcher import MANIFEST as SEC_MANIFEST, SESSION as SEC_SESSION
from watchers.cost_watcher import MANIFEST as COST_MANIFEST, SESSION as COST_SESSION
from watchers.compliance_watcher import MANIFEST as COMP_MANIFEST, SESSION as COMP_SESSION


def _claim(summary, pred="p", ver="DOCTRINAL"):
    return Claim(claim_id="c", task_id="t", subject="s", predicate=pred, scope="r",
                 summary=summary, derived_from="d", verifiability=ver,
                 falsifiable_by=("watcher",), critical_class=None)


def _registry():
    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("watcher-registry")
    return ManifestRegistry(led, ks, kid), led


def test_all_example_manifests_register_and_verify():
    for m in (SEC_MANIFEST, COST_MANIFEST, COMP_MANIFEST):
        reg, led = _registry()
        reg.register(m)
        report = ManifestRegistry.verify_manifest(led, m.watcher_id)
        assert report["valid"] is True, report["errors"]


def test_security_watcher_flags_shell_true(tmp_path):
    (tmp_path / "deploy.py").write_text(
        "import subprocess\n"
        "def deploy(cmd):\n"
        "    return subprocess.run(cmd, shell=True)\n")
    ev = run_session(SEC_SESSION, _claim("payments path is secure", pred="payments-secure"),
                     "digest", artifact_path=str(tmp_path))
    assert ev is not None and ev.tier == "W1b" and ev.stance == "REFUTES"
    assert ev.evidence_class == "STATIC_ANALYSIS"


def test_security_watcher_supports_clean_artifact(tmp_path):
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    ev = run_session(SEC_SESSION, _claim("payments path is secure"), "d",
                     artifact_path=str(tmp_path))
    assert ev.stance == "SUPPORTS"


def test_cost_watcher_budget(tmp_path):
    (tmp_path / "big.py").write_text("x = 1\n" * 600)
    ev = run_session(COST_SESSION, _claim("cost stays under budget", pred="cost-budget"),
                     "d", artifact_path=str(tmp_path))
    assert ev.stance == "REFUTES"
    (tmp_path / "big.py").write_text("x = 1\n")
    ev2 = run_session(COST_SESSION, _claim("cost stays under budget", pred="cost-budget"),
                      "d", artifact_path=str(tmp_path))
    assert ev2.stance == "SUPPORTS"


def test_cost_watcher_never_matches_other_domains():
    assert not COST_SESSION.matches(_claim("payments path is secure"))
    assert COST_SESSION.matches(_claim("performance budget", pred="performance-budget"))


def test_compliance_w3_doctrinal(tmp_path):
    (tmp_path / "a.py").write_text("# SPDX-License-Identifier: Apache-2.0\nx = 1\n")
    ev = run_session(COMP_SESSION, _claim("repo is compliant"), "d",
                     artifact_path=str(tmp_path))
    assert ev.tier == "W3" and ev.stance == "SUPPORTS"
    (tmp_path / "b.py").write_text("y = 2\n")
    ev2 = run_session(COMP_SESSION, _claim("repo is compliant"), "d",
                      artifact_path=str(tmp_path))
    assert ev2.stance == "REFUTES"


def test_compliance_matches_everything():
    assert COMP_SESSION.matches(_claim("anything at all"))


def test_security_only_matches_subscribed_domains(tmp_path):
    assert not SEC_SESSION.matches(_claim("totally unrelated claim"))
    assert SEC_SESSION.matches(_claim("payments security review"))


def test_external_watcher_blind_session_platform_proof(tmp_path):
    # EXIT CRITERION ①: a watcher living OUTSIDE the core package runs a blind
    # session end-to-end — the core has no special-case for it; it participates
    # purely through a signed manifest + a doctrine function (§5.3).
    (tmp_path / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    ev = run_session(SEC_SESSION, _claim("security review of payments"), "digest50",
                     artifact_path=str(tmp_path))
    assert ev is not None and ev.producer["family"] == "example-security"
    assert SEC_SESSION.manifest.integrity["code_hash"] != "0" * 64   # self-pinned
