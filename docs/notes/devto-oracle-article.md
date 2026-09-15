# The oracle caught its own maker

*Draft for dev.to — follow-up post after the v0.5.0 launch note. Facts, numbers and
quotes below are all traceable to repo receipts (commit `51f41c0` era, 2026-09-15).*

---

I build [Veridict](https://github.com/goun7/veridict): an append-only, hash-chained
evidence ledger for auditing AI-generated work, with certificates you verify offline.
The house doctrine is *receipts, not narrative*. So when I decided the adjudication
ladder — the five-rule engine that decides whether evidence overrules a machine
verdict — deserved formal proofs, I set one hard rule for myself:

**The proofs may never bless the code. The code is the spec; the model must agree
with it. And agreement means a machine checks it, not a human reviewing prose.**

Here is what happened when I actually held myself to that.

## The setup

Two lanes, both in plain Lean 4.34 (core only — no Std, no Mathlib, no network at
build time):

1. **General theorems.** Seven invariants over evidence lists of *arbitrary* length:
   fail-safe-empty, no-silent-pass, W1a-decisiveness, *doctrine-can-never-topple-a-
   machine-evidence-verdict-at-R0*, the two escalation conditions, split visibility,
   the meta-budget rule. `decide` closes them after case-splitting the finite
   parameters — kernel-checked, no enumeration.
2. **The oracle.** The Python ladder ships with a bounded verification receipt:
   **28,080 sampled cases**, digests and all. I wrote a generator that emits the same
   table into a Lean file — first attempt as a list literal, which politely timed out
   the elaborator; the working encoding packs every row into **one 12-character
   string** (28,080 × 12 = 336,960 digits) with a partial decoder — then
   `native_decide` re-runs my Lean model against all 28,080 cases and demands `true`.
   The generated file is committed *and* regenerated in CI from the shipped Python,
   digest-tied to the receipt, so model-vs-code drift fails the build within minutes
   of being pushed.

## The oracle caught its own maker

The first meaningful oracle run failed. Not on a typo — on a **semantic divergence**
I was completely convinced I'd gotten right.

Python's R0 guard says: a policy doctrine can never overturn a machine verdict *as
long as no evidence refutes it* — refuting evidence at **any** tier counts. When I
ported the rule, I "knew" what it meant and wrote the refutation check against the
W1a tier only. A smaller, tidier model of a rule I'd read a hundred times. The
oracle found rows — real shipped-code rows, digest-anchored — where my model and the
implementation disagreed.

Nobody reviewing prose would ever have caught that. *I* didn't catch it; the
divergence survived my careful reading and died in under a minute of `native_decide`.
The fix moved the **model** (an `anyRef` flag, then `I2`/`I4` re-proved against it).
Python did not move. The receipt data did not move. That was the discipline: the
oracle is allowed to tell me I'm wrong, and I'm not allowed to shoot the messenger.

The general lane has its own honesty receipts. Measured `#print axioms`: two theorems
depend on **no axioms at all**; the rest on `[propext]`, or `[propext, Quot.sound]`.
`sorryAx`, `Classical.choice` and `native_decide` appear nowhere in the general lane —
`native_decide` is confined to the oracle, which is exactly the place an *enumeration*
belongs. The numbers are printed in the file headers and re-printed by CI on every
run. Receipts, not narrative — including about the proofs themselves.

## Then I proved the ledger itself

The second lane (`proofs/ledger/Chain.lean`, same doctrine) covers the hash-chained
append-only ledger — six theorems over chains of arbitrary length, proved by pure
structural induction (this time no `decide` and no truth table by design: relational
properties of unbounded lists aren't enumerable domains). The headline:

- **no valid ledger is ever rejected** — writer and reader agree by construction;
- **prefix validity is suffix-independent** — appending anything can never launder a
  corrupt prefix;
- **tamper-evidence, honestly formulated**: edit a stored payload without re-minting
  its digest and you're caught with *zero* assumptions; replace a link with a fully
  honest re-mint (fresh payload, fresh digest, fresh entry hash) and the *next raw
  link* still catches you — modulo exactly one hypothesis, `H r p' ≠ e.eh`, which
  sits in the theorem's statement in plain sight. That is where SHA-256's hardness
  enters the argument, and the proof makes no effort to pretend it proved something
  about hashes. The assumption has an address.

## What I'd tell you to copy

- **Pin the oracle to shipped artifacts, not to a test harness.** The Lean table is
  regenerated from the same code that computes the digest in the release receipt.
  If CI is green, the *published* behavior was re-checked.
- **Encode bounded data as one string.** List literals of 28k tuples die in the
  elaborator; a 336KB digit string with a 15-line decoder does not.
- **Case-split anything with quantifiers before `decide`.** `∀ d : Div` isn't
  decidable; `cases d <;> revert … <;> decide` is.
- **Write down what your proofs can't do.** Our anchor verification is ECDSA — a
  computational assumption. No structural proof discharges it, so we don't fake one;
  the roadmap says so verbatim, and the axiom audit says the rest.

The bug I didn't have: a mis-ported guard that would have made doctrine overrides
*stronger in the model than in reality* — the exact direction that quietly
over-certifies an audit standard. The tool that caught it cost one afternoon and
about 250 lines of Lean plus a generator.

Repo: [goun7/veridict](https://github.com/goun7/veridict) ·
proofs: `proofs/ladder/`, `proofs/ledger/` · CI: `proofs.yml` (three lanes).

---

*Suggested tags: lean, formal-methods, ai-safety, open-source, security*
