# Distribution plan — 2026-09-15 (honest funnel, ranked by ROI)

Diagnosis first, then the ranked moves. Numbers are cold facts from
`gh api`: 1★, 1 fork, 0 watchers; the 2026-09-13 launch post exists and
drew ~nothing. That is not evidence the artifact is bad — it is evidence
the channel mix is wrong **for a protocol**. Frameworks get stars from
demos; standards get adoption from three things only: citable artifacts,
peers who must interoperate, and deadlines. Everything below serves one
of those three. The success metric for this plan is NOT stars: it is
**the first stranger touching issue #1 or shipping a verifier** (Lane 1,
roadmap v2). Everything else is noise reduction.

## Ranked channels (effort × expected value)

### 1. arXiv preprint — the artifact the launch post was missing [HIGH]
A dev.to post is disposable; an arXiv ID is citable. The HANSARD /
AuditWeave / VCT cluster shows this exact audience is active and
publishing weekly; our differentiator (four kernel-checked CI lanes +
executable conformance kit + a real oracle-caught divergence anecdote)
is publishable material as-is. Draft: `paper-draft-veridict-2026.md`
(this directory). Before submitting: maintainer trims, LaTeX (or arXiv
markdown via pandoc), endorsement if account lacks it (cs.CR is
endorsed-gated for new authors — a prior author of any cited 2026 paper
can endorse; channel 2 warms exactly that relationship). Cost: ~1 day.
KPI: citations/reads are slow; the point is that channels 2–4 below can
then link `arxiv.org/abs/…` instead of a repo.

### 2. Direct peer engagement with the converging papers [HIGH, tiny]
Three short emails to the authors whose critiques our theorems answer.
This is the single most under-used lever in indie standards work, and
the doctrine makes the ask honest (we are not asking for praise; we are
offering the executable answer to their stated problem):

> **To HANSARD authors (Varlamis, Sardianos et al.):** "Your v1 abstract
> says the target failure is attribution laundering enabled because
> 'the record is produced by the suspects.' We shipped an executable
> answer to the recording half: an append-only evidence ledger + an
> offline-verifiable certificate (Apache-2.0, stdlib-only core), whose
> structural layer is machine-checked in four Lean lanes — headline
> theorem (A4): a wrong binding invalidates the audit even under valid
> ECDSA, i.e. colluding log infrastructure cannot launder a verdict.
> 28,080-case oracle with the divergence it actually caught, public
> conformance vectors, and a spec-only verifier reaching identical
> verdicts. Repo: github.com/goun7/veridict · proofs.yml run logs ·
> docs/verifier-onboarding.md. If any of this is useful to HANSARD v2 —
> or if we misread your architecture — the issue tracker is open."

Same pattern, one paragraph each, for AuditWeave (2607.09682) and VCT
(2606.23003) authors. Cost: ~1h total. Even a 1-in-3 reply converts a
competitor into a cross-reference — the coin standard-land actually runs
on.

### 3. OpenSSF rooms [MEDIUM-HIGH]
The SLSA community (meetings + slsa-dev) and the AI-GBOM / ML-security
community-of-groups are where "SLSA-for-AI-work-product" — the open
niche verified in the landscape note — becomes somebody's agenda item.
Offer a 15-minute slot: "offline-verifiable certificates for AI claim
audits, kernel-checked; VSA/SPDX exports already ship." Cost: 1 talk
prep + meeting-slot wait (2–4 weeks). Their adoption of our vocabulary
> our vocabulary of theirs.

### 4. Hacker News — second attempt, right payload [MEDIUM]
The 09-13 post was a *launch* story; HN ignores launches. What HN's
security/PL subs eat: "The oracle caught its own maker" (the Lean
truth-table divergence anecdote + axiom-audit receipts). Post **after**
arXiv exists (first comment links it). Weekday 14:00–16:00 UTC. Do not
argue adoption in comments; answer Lean and CT questions only. Cost: 30
min + the draft already in `devto-oracle-article.md` (retune title).

### 5. r/netsec + lobste.rs [MEDIUM-LOW, cheap]
The oracle article is technically substantive enough for r/netsec's
no-self-promo rule *if* framed as methodology write-up (repo link at
bottom, per subreddit convention). lobste.rs needs an account; security
+ theory tags fit. Cost: 15 min each. Low ceiling, real floor.

### 6. awesome-list pipeline [LOW each, compounding]
PR #123 (awesome-ai-agents-security) open, updated with today's
receipts. Add at most one more per week in-class
(awesome-supply-chain-security, awesome-llm-security; the landscape
note's "micro-clones" thread also collects these links). Cost: 20
min/list. Marketplace listing already live + Latest badge verified.

### 7. Regulatory rail, scheduled [LOW now, HIGH later — calendar it]
Article 12 (record-keeping) + Article 19 (automatically generated
logs) bind Annex III high-risk systems from **2027-08**; the aiact
watcher already reduces them to file-shape checks. Two pages
("Art. 12/19 → append-only + offline replay mapping") addressed to
JTC21 AHAG participants is the move *when the discussion is live* —
mid-2027. Not now: no audience has budget attention before then.
Add to calendar as 2027-03 reminder.

## Do-not-do list (each tested or reasoned, save the record)
- More dev.to cadence: the channel saturated at n=1; repetition reads
  as marketing and costs credibility.
- Paid promotion, X threads, Discord/Telegram servers: wrong market
  segment (auditors and log-nerds do not join communities for ledgers;
  they clone repos).
- Hosted dashboard: explicitly de-scoped pre-G2 in roadmap v2 —
  unchanged.

## Honest probability statement
Most likely outcome of channels 1–6 executed fully: still small. But
the failure mode flips: currently nobody *can* find a reason to trust
the project beyond the README; after 1–2 there will be a citable
artifact and at least one external expert who read the threat model
line-by-line. Exit criterion ① (independent verifier) needs exactly one
person of that second kind. Cost of trying: under three days.

Weekly KPI check (every Sun, log in this file): new mentions of
`veridict-standard`/repo outside our own accounts (GitHub code search +
mention bot issue), arXiv reads (post-submission), #1/#10 activity,
stars/forks delta. Six weeks post-preprint with zero external touches →
re-position toward integration-first (PR upstream: Rekor/witness
compat shim, SLSA VSA profile) and say so here.

## Log
- 2026-09-15: plan written. Baseline: 1★/1 fork/0 watchers. Paper
  draft in progress (this directory). HANSARD + 2609.12002 abstracts
  re-verified against arXiv tonight; threat counters from the landscape
  note (ledger+anchor lanes) landed same day with green CI.
