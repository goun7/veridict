"""CLI surface stability contract (cross-project wrapper guard).

The Tamga sovereign_verify wrapper calls `veridict verify --ledger X --cert Y`
as its Veridict verification surface, and asked us not to break it silently.
Good-faith promises rot; this test turns the promise into a machine-checked
contract: if the flags change, this fails before any downstream wrapper
discovers it at runtime.

The fixtures are GENERATED, not shipped: dogfood_ledger.jsonl / dogfood_cert.json
are gitignored (regenerated locally per run), so a test depending on them
would fail in CI. Building a fresh ledger+cert here also proves the surface
works end-to-end, not just on one frozen artifact.

What is pinned:
  - the subcommand name (`verify`)
  - the required flags (`--ledger`, `--cert`) and their arity
  - the optional `--anchor` flag
  - exit code 0 + valid:true on a clean run
  - exit code != 0 + valid:false on a tampered ledger

What is deliberately NOT pinned: the JSON field set beyond `valid`, human
prose, and stdout formatting. Those are allowed to evolve; the wrapper is
expected to read `valid`, which is the normative field.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _build_fixture(tmp_path):
    """A minimal clean ledger + certificate, fresh per test.

    AuditOrchestrator.run returns a wrapper {cert, outcome, report}; the
    CLI consumes the inner cert. artifact_path must be a DIRECTORY — the
    pytest verifier chdirs into it (passing a file path raises
    NotADirectoryError from subprocess, which is easy to misread).
    """
    sys.path.insert(0, ROOT)
    from veridict.audit import AuditOrchestrator
    from veridict.jury import Jury, Opinion, ScriptedProvider
    from veridict.keys import KeyStore
    from veridict.ledger import Ledger
    from veridict.policy import PolicyDeclaration, Thresholds
    from veridict.schemas import TaskManifest

    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (pkg / "test_calc.py").write_text(
        "def test_add():\n    from calc import add\n    assert add(1, 2) == 3\n")

    led = Ledger()
    ks = KeyStore(led)
    kid = ks.generate_and_enroll("cli-surface-test")
    # Two STUB families — the surface is what is under test here, not the
    # jury. A real-LLM run belongs to scripts/canary_real_llm.py.
    jury = Jury([
        ScriptedProvider(family="stub-a", identity="a-1",
                         default=Opinion("SUPPORTS", 0.8, "stub")),
        ScriptedProvider(family="stub-b", identity="b-1",
                         default=Opinion("SUPPORTS", 0.8, "stub")),
    ])
    pol = PolicyDeclaration(policy_id="cli-surface", mode="CERTIFICATE",
                            criticality=(), thresholds=Thresholds(),
                            divergence_tolerance=1 / 3)
    task = TaskManifest(task_id="cli-surface-1", artifact_path=str(pkg),
                        actor_identity="actor",
                        intent_lines=["MACHINE: add computes the sum of two numbers"],
                        criticality=(), has_existing_tests=True, pytest_args=["-q"])
    result = AuditOrchestrator(led, pol, jury, ks, kid).run(task, "REDACTED")
    cert = result["cert"] if isinstance(result, dict) and "cert" in result else result

    ledger_path = tmp_path / "ledger.jsonl"
    cert_path = tmp_path / "cert.json"
    led.save(str(ledger_path))
    cert_path.write_text(json.dumps(cert, default=str))
    return str(ledger_path), str(cert_path)


def _run(args, module=False):
    """Invoke the CLI the way an external wrapper does.

    Two invocation styles are both in the wild and both must work:
    - the `veridict` console entrypoint (Tamga's wrapper)
    - `python -m veridict.cli` (Sester's wrapper)

    Note on measuring the exit code: NEVER pipe the output (`| tail`),
    because $? then reports the PIPE's status, not the CLI's — an rc=1
    rejection reads as rc=0. That trap caused a false GREEN in a
    downstream wrapper before it was caught. capture_output avoids it.
    """
    cmd = ([sys.executable, "-m", "veridict.cli"] if module else ["veridict"]) + args
    return subprocess.run(cmd, capture_output=True, text=True)


@pytest.mark.parametrize("module", [False, True],
                         ids=["entrypoint", "python-m-veridict-cli"])
def test_verify_subcommand_flags_are_stable(module):
    """--help must still show the flags an external wrapper depends on."""
    r = _run(["verify", "--help"], module=module)
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert "--ledger" in out, "--ledger flag missing (external wrappers depend on it)"
    assert "--cert" in out, "--cert flag missing (external wrappers depend on it)"
    # optional, but sovereign_verify may use it — its removal is a break too
    assert "--anchor" in out, "--anchor flag missing"


@pytest.mark.parametrize("module", [False, True],
                         ids=["entrypoint", "python-m-veridict-cli"])
def test_verify_exit_code_and_valid_field(tmp_path, module):
    """A clean fixture must verify with rc 0 and valid:true.

    An external wrapper (Tamga sovereign_verify, Sester bridges) keys off
    this exact behavior: rc=0 ⇒ GREEN, rc≠0 ⇒ RED. If the exit code
    changes or `valid` moves, both wrappers break — so both are pinned
    here, for BOTH invocation styles they use.
    """
    ledger, cert = _build_fixture(tmp_path)
    r = _run(["verify", "--ledger", ledger, "--cert", cert], module=module)
    assert r.returncode == 0, f"expected rc 0, got {r.returncode}: {r.stderr}"
    out = json.loads(r.stdout)
    assert out["valid"] is True, out
    assert out["chain_valid"] is True
    assert out["signature_valid"] is True


@pytest.mark.parametrize("module", [False, True],
                         ids=["entrypoint", "python-m-veridict-cli"])
def test_verify_rejects_a_broken_ledger(tmp_path, module):
    """The negative case a wrapper relies on: tampering ⇒ rc != 0 + valid false.

    sovereign_verify asserts RED on tamper; if verify ever returned rc 0 on
    a mutated ledger the wrapper's RED path would silently stop firing.

    Tamper targets a field that ENTERS the entry-hash preimage (payload),
    not an arbitrary one. Adding a field outside the preimage leaves the
    recomputed hash unchanged and legitimately still verifies — a tamper
    test that mutated such a field would be a false RED: it would pass
    while proving nothing. The companion test below pins that boundary.
    """
    ledger, cert = _build_fixture(tmp_path)
    lines = [json.loads(l) for l in open(ledger)]
    for e in lines:                      # corrupt the first evidence entry
        if e.get("entry_type") == "evidence.recorded":
            e["payload"]["injected"] = "tamper"
            break
    with open(ledger, "w") as f:
        for e in lines:
            f.write(json.dumps(e) + "\n")
    r = _run(["verify", "--ledger", ledger, "--cert", cert], module=module)
    assert r.returncode != 0, "tampered ledger must NOT exit 0"
    out = json.loads(r.stdout)
    assert out["valid"] is False, out


@pytest.mark.parametrize("module", [False, True],
                         ids=["entrypoint", "python-m-veridict-cli"])
def test_tamper_test_target_is_hash_covered(tmp_path, module):
    """Negative control for the tamper test above.

    A field OUTSIDE the hash preimage must still verify green: it is not
    evidence, and the standard does not claim to protect it. If this test
    ever goes RED, verify started hashing fields the spec does not cover —
    a silent conformance change in the other direction. If the tamper
    test above ever goes GREEN, the mutation stopped touching the
    preimage and is proving nothing. Both directions matter.
    """
    ledger, cert = _build_fixture(tmp_path)
    lines = [json.loads(l) for l in open(ledger)]
    lines[1]["harmless_extra_field"] = "not-in-preimage"   # not digested
    with open(ledger, "w") as f:
        for e in lines:
            f.write(json.dumps(e) + "\n")
    r = _run(["verify", "--ledger", ledger, "--cert", cert], module=module)
    assert r.returncode == 0, "out-of-preimage field must not break verification"
    out = json.loads(r.stdout)
    assert out["valid"] is True, out


@pytest.mark.parametrize("module", [False, True],
                         ids=["entrypoint", "python-m-veridict-cli"])
def test_verify_rejects_a_tampered_certificate(tmp_path, module):
    """The exact RED path Sester observed: 'no enrolled key verifies the
    certificate body'. A mutated cert must fail with rc != 0."""
    ledger, cert = _build_fixture(tmp_path)
    import copy
    broken = copy.deepcopy(json.load(open(cert)))
    broken["signature_b64"] = "AAAA"          # signature no longer matches
    with open(cert, "w") as f:
        json.dump(broken, f)
    r = _run(["verify", "--ledger", ledger, "--cert", cert], module=module)
    assert r.returncode != 0, "tampered cert must NOT exit 0"
    out = json.loads(r.stdout)
    assert out["valid"] is False
    assert out["signature_valid"] is False, out
