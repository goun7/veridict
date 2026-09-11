# Contributing to Veridict

Veridict is the audit system whose core product is **trustworthy
inconclusiveness**. Contributions are held to the bar the system itself
audits to: falsifiable claims, evidence that survives verification, and no
silent passes.

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m pytest -q
```

Python 3.12+. The full suite (including the dogfood self-audit) runs in
about a minute.

## The per-contribution bar

1. **TDD.** New behavior lands with a test watched failing first.
2. **No self-merged reviews.** Every change gets an independent review
   pass; reviewer-found issues are fixed by the implementer, then
   re-reviewed.
3. **The verification mechanism gates every round** (see
   `docs/plans/`): full test suite (both `python -m pytest` and bare
   `pytest`) + fresh dogfood self-audit with a valid certificate + offline
   `veridict verify` + canary Quality Sheet (10 catches / 3 honest misses /
   0 false positives). If any leg is red, the round does not close.
4. **The five tier rules are non-negotiable** (spec §5.3): strict tier
   ordering, no doctrine-over-W1a, depth-budgeted meta-claims, SPLIT is
   information, W3 alone never verifies. There is no configuration that
   disables them, and patches that add one will be rejected.

## Contributing a watcher

A watcher is any checker you own, wrapped in a manifest and one function.
Your module lives OUTSIDE `veridict/`; the core has no special-case for
you — you are a participant, not a contributor to the core.

**1. The function** (`my_watcher.py`) — receives exactly
`(claim_summary, artifact_reference)` and nothing else (blindness is the
contract, §6.3); returns `(stance, confidence, rationale)` or `None` to
abstain. None/exception/bad-stance/malformed shape all degrade to abstain:

```python
def judge(claim_summary: str, artifact_reference: str):
    if my_checker.flagged(artifact_reference):
        return ("REFUTES", 0.9, "my_checker found a violation")
    return ("SUPPORTS", 0.6, "no findings")
```

**2. The manifest** (`manifest.json`) — MUST declare
`max_tier ∈ {W1b, W2, W3}` (W1a is forbidden to watchers by design — the
ceiling is structural), name a real `producer {identity, maintainer}` (no
anonymous watchers), and pin the sha256 of your module as `code_hash`:

```json
{"watcher_id": "your-watcher", "name": "Your Checker", "version": "1.0.0",
 "producer": {"identity": "your-org", "maintainer": "you"},
 "capabilities": {"evidence_classes": ["JURY_OPINION"], "max_tier": "W2",
                  "subscribes_to": ["*"]},
 "resource_class": {"timeout_seconds": 2, "cost_budget": null,
                    "sandbox_level": "none"},
 "integrity": {"code_hash": "<sha256 of my_watcher.py>",
               "update_policy": "pinned"}}
```

**3. Prove your contract** — all ten conformance checks must pass:

```bash
python - <<'PY'
import json
from veridict.conformance import run_conformance_suite
from veridict.watchers import WatcherManifest, WatcherSession
from my_watcher import judge

manifest = WatcherManifest.from_dict(json.load(open("manifest.json")))
result = run_conformance_suite(WatcherSession(manifest, judge))
print(result["conformant"])   # must be True — all ten checks
PY
```

A minimal reference implementation of a watcher module ships in
`watchers/security_watcher.py` (read it, then do it your way).

A watcher that abstains correctly under deadline expiry and exceptions is
worth more than one that never fails; the kit tests exactly that.

**4. Run it through the CLI** — the audit refuses a manifest whose
code_hash does not match the module, and revoked watchers are not
participants (§6.6):

```bash
veridict audit --task task.json --ledger led.jsonl --cert-out cert.json \
  --watcher manifest.json:my_watcher:judge
```

Register through `ManifestRegistry` in your own ledger for testing;
marketplace listing is a separate (Phase 3) governance step.

## Issuing certificates

Anything that issues certificates MUST carry the honesty clause — "claim
coverage is heuristic, not exhaustive" — as the first `scope_limits`
element, and MUST NOT resolve R3 escalations autonomously.

## Design documents

- Spec: `docs/specs/2026-09-09-veridict-design.md`
- Standard draft: `docs/specs/2026-09-10-veridict-standard-v1.0.md`
- Plans and receipts: `docs/plans/`

## License

Apache-2.0. By contributing you agree your contributions are licensed
under it.
