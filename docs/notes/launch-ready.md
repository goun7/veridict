# Launch kit — ready-to-paste (publishing requires the maintainer's accounts)

Prepared per maintainer decision (2026-09-10): publish NOW on Show HN +
Reddit. Everything below is final text; each block is copy-paste ready.
Suggested order: Show HN first (morning US time = 15:00-17:00 TRT for EU
evening traffic), Reddit r/MachineLearning or r/singularity 6-12h later,
dev.to same day as a canonical article.

---

## 1. Show HN

**Title (exactly):**

```
Show HN: Veridict – An audit standard for AI-generated work, verifiable offline
```

**Text (submit as a text post "Ask HN"-style; HN strips markdown — use plain
lines):**

```
Hi HN — Veridict is an Apache-2.0 protocol + reference implementation for auditing AI with AI when humans no longer can.

The problem it starts from: AI output already outgrows human review capacity, and agents coordinate through channels we didn't design (the recent agent-coordination incidents are the pattern). Our bet: don't wall off coordination — make the managed channel better than the covert one.

How it works:
- An append-only, hash-chained evidence ledger records every audit step. Every entry's hash binds its author, timestamp (ISO-8601 string — floats are too fragile to hash across languages), and parent.
- Claims are falsifiable; machine verifiers produce W1a evidence; a blind heterogeneous jury produces W2/W3 doctrine; an adjudication ladder (R0-R4) resolves — and doctrine can never overturn machine truth, while W3 alone can never verify.
- No evidence is never a pass: it is INCONCLUSIVE with a flag. There is no configuration in which silence looks like success.
- Critical splits escalate to a human dossier — the machine owns the verdict of intelligence, the human owns the verdict of responsibility.

The part we care most about: certificates verify OFFLINE without trusting the auditor. We publish language-neutral conformance test vectors, and a verifier implemented from the specification alone (zero imports of our code) that agrees with the reference on every failure mode we fuzzed. That cross-implementation parity is a permanent property in the suite now.

Receipts, regenerated on every push (not narrated):
- 220 tests across Python 3.12-3.14
- self-audit: the system audits itself and holds its own watchers to its own conformance kit
- 1500-ledger tamper soak: 100% detection, zero silent passes
- canary protocol with honest misses published: 9 catches / 3 misses / 0 false positives across 11 defect classes

One honest limitation to lead with: the shipped jury is a deterministic stub. The real-LLM provider path (OpenAI-compatible endpoint) is validated in CI against a local mock (strict-JSON parsing, auth, error degradation, full audit with a real-surface juror — 8 tests) — what is NOT yet done is a run against a real LLM endpoint, because that needs an API key and a budget (both $0 so far, deliberately).

What we want most from HN: someone to implement an independent verifier from the standard alone (https://github.com/goun7/veridict/issues/1). Where your implementation and ours disagree, either the standard is ambiguous or someone is wrong — both findings land in the standard's public errata ledger with credit.

Repo: https://github.com/goun7/veridict
Standard: https://goun7.github.io/veridict/standard.html
```

---

## 2. Reddit r/MachineLearning (or r/singularity) — post title + body

**Title:**

```
[R] Veridict: an append-only evidence ledger + blind jury protocol for auditing AI work when humans can't review it anymore
```

**Body:**

Use the same structure as the HN text but 30% shorter, open with the
agent-coordination hook (the security-talk story, explicitly secondhand),
and end with the Issue #1 challenge. Reddit rewards the "why should I
care" framing: every PR you merge today is audited by nobody.

---

## 3. dev.to article

Use `docs/notes/launch-story-draft.md` (already article-shaped) + add the
receipts table from the README. Set canonical_url to the dev.to post, then
link back from the repo README's "Public site" section once published.

---

## Posting checklist (maintainer, ~10 minutes)

1. Show HN: paste title + text → comment in-thread answering questions for the first 2 hours.
2. Reddit: paste → reply to top 3 comments.
3. dev.to: publish article → add link to README (PR to main).
4. After 24h: record stars/comments in docs/commercial-model.md G1 tracker.
5. Rule: reply to every technical criticism with either a test or an errata — never with prose alone.
