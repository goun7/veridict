"""Behavior + platform-contract tests for the five watcher-marketplace
examples (G2 growth: 3 → 8 shipped manifests).

Each test pins ONE doctrine behavior on a synthetic artifact — the same
receip culture as test_example_watchers.py: assertions ride real runs of
run_session / the conformance kit, never narrative.
"""
from veridict.conformance import run_conformance_suite
from veridict.schemas import Claim
from veridict.watchers import run_session

from watchers.license_scan_watcher import MANIFEST as LIC_MANIFEST, SESSION as LIC_SESSION
from watchers.secret_scan_watcher import MANIFEST as SEC2_MANIFEST, SESSION as SEC2_SESSION
from watchers.docker_watcher import MANIFEST as DOCKER_MANIFEST, SESSION as DOCKER_SESSION
from watchers.doc_sync_watcher import MANIFEST as DOC_MANIFEST, SESSION as DOC_SESSION
from watchers.sbom_watcher import MANIFEST as SBOM_MANIFEST, SESSION as SBOM_SESSION

ALL_NEW = (LIC_MANIFEST, SEC2_MANIFEST, DOCKER_MANIFEST, DOC_MANIFEST,
           SBOM_MANIFEST)


def _claim(summary, pred="p"):
    return Claim(claim_id="c", task_id="t", subject="s", predicate=pred, scope="r",
                 summary=summary, derived_from="d", verifiability="DOCTRINAL",
                 falsifiable_by=("watcher",), critical_class=None)


def test_new_watchers_pass_conformance_kit():
    for session in (LIC_SESSION, SEC2_SESSION, DOCKER_SESSION, DOC_SESSION,
                    SBOM_SESSION):
        report = run_conformance_suite(session)
        assert report["conformant"], (report["watcher_id"],
                                      [c for c in report["checks"]
                                       if not c["passed"]])


def test_license_scan_flags_missing_license(tmp_path):
    (tmp_path / "code.py").write_text("x = 1\n")
    ev = run_session(LIC_SESSION, _claim("artifact licensing is permissive",
                                         pred="license-scan"), "d",
                     artifact_path=str(tmp_path))
    assert ev is not None and ev.stance == "REFUTES"
    assert "no LICENSE file" in ev.rationale

    (tmp_path / "LICENSE").write_text(
        "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/\n")
    ev2 = run_session(LIC_SESSION, _claim("artifact licensing is permissive",
                                         pred="license-scan"), "d",
                      artifact_path=str(tmp_path))
    assert ev2.stance == "SUPPORTS"


def test_license_scan_vacuous_on_empty_artifact(tmp_path):
    ev = run_session(LIC_SESSION, _claim("licensing"), "d",
                     artifact_path=str(tmp_path))
    assert ev.stance == "SUPPORTS"    # empty artifact: question vacuous, not refuted


def test_secret_scan_flags_hardcoded_keys(tmp_path):
    (tmp_path / "conf.py").write_text(
        'API_KEY = "sk_test_51H8xKzLIVEKEY123456789012"\n')
    ev = run_session(SEC2_SESSION, _claim("no secrets are committed",
                                          pred="secret-scan"), "d",
                     artifact_path=str(tmp_path))
    assert ev is not None and ev.stance == "REFUTES" and ev.tier == "W1b"
    assert ev.evidence_class == "STATIC_ANALYSIS"

    (tmp_path / "conf.py").write_text('API_KEY = os.environ["API_KEY"]\n')
    ev2 = run_session(SEC2_SESSION, _claim("no secrets are committed",
                                           pred="secret-scan"), "d",
                      artifact_path=str(tmp_path))
    assert ev2.stance == "SUPPORTS"


def test_secret_scan_ignores_short_values(tmp_path):
    # an 8-char token must NOT trip the >=20-char high-confidence patterns
    (tmp_path / "s.py").write_text('secret_key = "short1234"\n')
    ev = run_session(SEC2_SESSION, _claim("no secrets are committed",
                                          pred="secret-scan"), "d",
                     artifact_path=str(tmp_path))
    assert ev.stance == "SUPPORTS"


def test_docker_watcher_flags_bad_dockerfile(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM ubuntu:latest\nRUN apt-get install -y curl\n")
    ev = run_session(DOCKER_SESSION, _claim("container build follows best "
                                            "practices", pred="docker-hygiene"),
                     "d", artifact_path=str(tmp_path))
    assert ev is not None and ev.stance == "REFUTES"
    assert ":latest" in ev.rationale

    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim@sha256:abc\n")
    ev2 = run_session(DOCKER_SESSION, _claim("container build follows best "
                                             "practices", pred="docker-hygiene"),
                      "d", artifact_path=str(tmp_path))
    assert ev2.stance == "SUPPORTS"


def test_doc_sync_flags_stale_test_counts(tmp_path):
    (tmp_path / "test_a.py").write_text("def test_one():\n    assert True\n"
                                        "def test_two():\n    assert True\n")
    (tmp_path / "README.md").write_text("We have 35 tests in the suite.\n")
    ev = run_session(DOC_SESSION, _claim("documentation counts are in sync",
                                         pred="doc-sync"), "d",
                     artifact_path=str(tmp_path))
    assert ev is not None and ev.stance == "REFUTES"
    assert "35 tests" in ev.rationale

    (tmp_path / "README.md").write_text("We have 2 tests in the suite.\n")
    ev2 = run_session(DOC_SESSION, _claim("documentation counts are in sync",
                                          pred="doc-sync"), "d",
                      artifact_path=str(tmp_path))
    assert ev2.stance == "SUPPORTS"


def test_sbom_flags_undeclared_imports(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests"]\n')
    (tmp_path / "app.py").write_text("import requests\nimport numpy\n")
    ev = run_session(SBOM_SESSION, _claim("all dependencies are declared in "
                                          "the SBOM", pred="sbom-spdx"), "d",
                     artifact_path=str(tmp_path))
    assert ev is not None and ev.stance == "REFUTES"
    assert "numpy" in ev.rationale

    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["requests", "numpy"]\n')
    ev2 = run_session(SBOM_SESSION, _claim("all dependencies are declared in "
                                           "the SBOM", pred="sbom-spdx"), "d",
                      artifact_path=str(tmp_path))
    assert ev2.stance == "SUPPORTS"


def test_sbom_local_package_not_third_party(tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (tmp_path / "app.py").write_text("from mypkg import thing\nimport requests\n")
    (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["requests"\n')
    ev = run_session(SBOM_SESSION, _claim("all dependencies are declared",
                                         pred="sbom-spdx"), "d",
                     artifact_path=str(tmp_path))
    assert ev.stance == "SUPPORTS"    # mypkg is the artifact's own package


def test_subscription_scopes_only_intended_claims():
    assert LIC_SESSION.matches(_claim("licensing check", pred="license"))
    assert not LIC_SESSION.matches(_claim("payments path is secure"))
    assert SEC2_SESSION.matches(_claim("security scan", pred="secret-scan"))
    assert DOCKER_SESSION.matches(_claim("deployment hygiene", pred="docker"))
    assert not DOCKER_SESSION.matches(_claim("cost stays under budget"))
    assert DOC_SESSION.matches(_claim("docs are current", pred="doc-sync"))
    assert SBOM_SESSION.matches(_claim("supply chain SBOM", pred="sbom"))
    assert not SBOM_SESSION.matches(_claim("payments path is secure"))


def test_code_hashes_self_pinned():
    for m in ALL_NEW:
        assert len(m.integrity["code_hash"]) == 64
        assert m.integrity["code_hash"] != "0" * 64
