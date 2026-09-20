# Name-space research — 2026-09-20

## Finding: an independent project uses the name "veridict"

`Mary1270/veridict` on GitHub (created 2026-09-15, Python) is an
independent, unrelated project: "The economically-accountable
adjudication protocol for autonomous agreements — a GenLayer Intelligent
Contract with a staked, commit-reveal jury layer."

It is **not a fork** of ours and does not reference our standard. It
targets GenLayer smart contracts, not evidence ledgers. The vocabulary
overlap (adjudication, jury, economic accountability) is coincidence of
domain, not derivation.

## What this changes

Nothing in code. The registration facts:

| Surface | Ours | Theirs |
|---|---|---|
| PyPI `veridict` | **not ours** — a third project owns it at 0.3.0 | not present |
| PyPI `veridict-standard` | **ours**, 1.0.0 | — |
| GitHub `goun7/veridict` | ours | `Mary1270/veridict` |
| Import/CLI name | `veridict` | — |

So the situation is: our **package** name (`veridict-standard`) is safe,
but the **bare word** "veridict" now names three things on PyPI and two on
GitHub. A user typing `pip install veridict` gets neither ours nor
Mary1270's.

## Why this is not an emergency

- Our published surface (Action, PyPI, docs) all say **veridict-standard**
  for the package and `veridict` for the CLI. That distinction is already
  load-bearing, not new.
- Their project does not implement our standard, so there is no
  correctness confusion — a consumer of theirs looking for ours would find
  a different product, not a wrong implementation of ours.
- The name is not trademarked by us and trademarking an open-source
  protocol name against another open-source project is not what this
  project is for.

## What we actually do about it

- Keep referring to the **standard** as "Veridict standard v1.0.0" and the
  package as `veridict-standard`. The disambiguation is already in place.
- Do NOT approach Mary1270 about the name. There is nothing to gain and
  the appearance of a large project pressuring a small one is a cost.
- If the bare `veridict` PyPI name ever becomes a real problem (someone
  squats it pointing at a misleading README), the response is a clearer
  package description, not a dispute.

This is recorded because the gap between "we own the name" and "we own
the package name" is exactly the kind of thing that surprises a project
two years later, and because the instinct to defend a name is usually
worse than the name collision.
