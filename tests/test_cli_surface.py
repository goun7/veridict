"""CLI surface stability contract (cross-project wrapper guard).

The Tamga sovereign_verify wrapper calls `veridict verify --ledger X --cert Y`
as its Veridict verification surface, and asked us not to break it silently.
Good-faith promises rot; this test turns the promise into a machine-checked
contract: if the flags change, this fails before any downstream wrapper
discovers it at runtime.

What is pinned:
  - the subcommand name (`verify`)
  - the required flags (`--ledger`, `--cert`) and their arity
  - the optional `--anchor` flag
  - exit code 0 + valid:true on the dogfood fixtures

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
CLI = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dogfood_ledger.jsonl")
# resolve via the installed entrypoint, exactly as an external caller would
_ARGS_BASE = ["verify", "--ledger", CLI,
              "--cert", os.path.join(ROOT, "dogfood_cert.json")]


def _run(args):
    return subprocess.run([sys.executable, "-m", "veridict"] if False else
                          ["veridict"] + args,
                          capture_output=True, text=True, cwd=ROOT)


def test_verify_subcommand_flags_are_stable():
    """--help must still show the flags an external wrapper depends on."""
    r = _run(["verify", "--help"])
    assert r.returncode == 0, r.stderr
    out = r.stdout
    assert "--ledger" in out, "--ledger flag missing (external wrappers depend on it)"
    assert "--cert" in out, "--cert flag missing (external wrappers depend on it)"
    # optional, but sovereign_verify may use it — its removal is a break too
    assert "--anchor" in out, "--anchor flag missing"


def test_verify_exit_code_and_valid_field():
    """The dogfood fixtures must verify clean, rc 0, valid:true.

    An external wrapper (Tamga sovereign_verify) keys off this exact
    behavior. If the fixtures stop verifying, or the exit code changes,
    or `valid` moves, the wrapper breaks — so all three are pinned here.
    """
    r = _run(_ARGS_BASE)
    assert r.returncode == 0, f"expected rc 0, got {r.returncode}: {r.stderr}"
    out = json.loads(r.stdout)
    assert out["valid"] is True, out
    assert out["chain_valid"] is True
    assert out["signature_valid"] is True


def test_verify_rejects_a_broken_ledger(tmp_path):
    """The negative case a wrapper relies on: tampering ⇒ rc != 0 + valid false.

    sovereign_verify asserts RED on tamper; if verify ever returned rc 0 on
    a mutated ledger the wrapper's RED path would silently stop firing.
    """
    ledger = tmp_path / "broken.jsonl"
    lines = [json.loads(l) for l in open(CLI)]
    lines[2]["payload"] = {"tampered": True}  # hash no longer re-derives
    with ledger.open("w") as f:
        for e in lines:
            f.write(json.dumps(e) + "\n")
    r = _run(["verify", "--ledger", str(ledger),
              "--cert", os.path.join(ROOT, "dogfood_cert.json")])
    assert r.returncode != 0, "tampered ledger must NOT exit 0"
    out = json.loads(r.stdout)
    assert out["valid"] is False, out
