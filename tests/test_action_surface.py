"""Action-surface contract: the two invocation styles must not diverge.

History earned this file: `actor-family` shipped only in the composite
action while the reusable workflow silently lacked it — exactly the kind
of drift a marketplace listing cannot afford (users follow whichever
README snippet they copied first). Inputs are now compared as SETS, the
anchor/verify wiring is asserted in both, and the Marketplace 125-char
description limit stays pinned (the listing draft once rejected 0.3.3
for exceeding it).
"""
import os

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _composite():
    return yaml.safe_load(open(os.path.join(REPO, "action.yml")))


def _reusable():
    doc = yaml.safe_load(open(os.path.join(
        REPO, ".github", "workflows", "veridict-audit.yml")))
    # PyYAML parses the `on:` key as boolean True (YAML 1.1) — GitHub Actions
    # accepts both; normalize so this test can never silently miss the block.
    if "on" not in doc and True in doc:
        doc["on"] = doc[True]
    return doc


def test_input_surfaces_identical():
    comp = set(_composite()["inputs"])
    reuse = set(_reusable()["on"]["workflow_call"]["inputs"])
    assert comp == reuse, (f"composite-only: {comp - reuse} | "
                           f"reusable-only: {reuse - comp}")


def test_anchor_wiring_in_both():
    for label, doc, job_key in (("composite", _composite(), "runs"),
                                ("reusable", _reusable(), "jobs")):
        body = str(doc[job_key])
        assert "--anchor ${{ inputs.anchor }}" in body, label
        assert "--anchor-required" in body, label
        assert "veridict-cert.json.anchor.json" in body, \
            f"{label}: offline verify must pick up the sidecar when present"


def test_actor_family_env_in_both():
    assert "VERIDICT_ACTOR_FAMILY" in str(_composite()["runs"])
    assert "VERIDICT_ACTOR_FAMILY" in str(_reusable()["jobs"])


def test_marketplace_description_limit():
    desc = _composite()["description"]
    assert len(desc) <= 125, f"Marketplace rejects >125 chars ({len(desc)})"


def test_new_inputs_have_defaults():
    for name, spec in _composite()["inputs"].items():
        assert "default" in spec, f"{name} must default (composite has no required-input UX)"
    for name, spec in _reusable()["on"]["workflow_call"]["inputs"].items():
        assert "default" in spec, name
        assert spec.get("required") is False, name   # all-optional contract
