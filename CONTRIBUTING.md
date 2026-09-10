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

Python 3.14+. The full suite (including the dogfood self-audit) runs in
about a minute.

## The per-contribution bar

1. **TDD.** New behavior lands with a test watched failing first.
2. **No self-merged reviews.** Every change gets an independent review
   pass; reviewer-found issues are fixed by the implementer, then
   re-reviewed.
3. **The verification mechanism gates every round** (see
   `docs/plans/`): full test suite (both `python -m pytest` and bare
   `pytest`) + fresh dogfood self-audit with a valid certificate + offline
   `veridict verify` + canary Quality Sheet (2 catches, 0 false
   positives). If any leg is red, the round does not close.
4. **The five tier rules are non-negotiable** (spec §5.3): strict tier
   ordering, no doctrine-over-W1a, depth-budgeted meta-claims, SPLIT is
   information, W3 alone never verifies. There is no configuration that
   disables them, and patches that add one will be rejected.

## Contributing a watcher

1. Implement a `WatcherSession` bound to your `WatcherManifest`
   (see `watchers/security_watcher.py` for the minimal shape — your module
   lives OUTSIDE `veridict/`; the core has no special-case for you).
2. Your manifest MUST: declare `max_tier ∈ {W1b, W2, W3}` (W1a is
   forbidden to watchers by design), name a real `producer {identity,
   maintainer}` (no anonymous watchers), and pin its own `code_hash`.
3. Pass the conformance kit:
   `python -c "from veridict.conformance import run_conformance_suite; from your_module import SESSION; print(run_conformance_suite(SESSION))"`
   — all ten checks must pass.
4. Register through `ManifestRegistry` in your own ledger for testing;
   marketplace listing is a separate (Phase 3) governance step.
5. Blindness is the contract: your doctrine fn receives exactly
   `(claim_summary, artifact_reference)` and nothing else.

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
