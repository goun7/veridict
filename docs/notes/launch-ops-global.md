# Launch operations — everything the MAINTAINER does (global)

Veridict is a GLOBAL project. This file is the single checklist of human
actions: publishing (needs your accounts — no agent can post as you) and
account setup. Code-side kit lives in `docs/notes/launch-ready.md`
(paste-ready texts). Nothing here costs money; items are ordered by
dependency.

## A. One-time accounts (~30 min total)

| # | Account | Why | Notes |
|---|---|---|---|
| A1 | Hacker News account (news.ycombinator.com) | Show HN post — the launch ignition | Any age works; new accounts can post Show HN immediately |
| A2 | Reddit account | r/MachineLearning + r/singularity posts | Check each sub's self-promo rules before posting; participate in comments, don't dump-and-run |
| A3 | dev.to account | Canonical long-form article | Set `canonical_url` to the dev.to post itself; link back to repo + Pages site |
| A4 | (later, post-G1) X/Twitter + LinkedIn | Sustained distribution | NOT for launch day — one channel at a time; HN first |
| A5 | (later, on inbound) A support inbox | Enterprise inquiries need a destination | Free: a dedicated email alias or GitHub Discussions (already free on the repo — prefer Discussions first) |

No account needed for: GitHub repo (exists), Pages site (live),
Sponsors (**deactivated** pending tax advice — do NOT open until advised).

## B. Launch-day publishing (~10 min of clicks + 2h of presence)

Order matters (attention compounds):

1. **Show HN** — paste `launch-ready.md` §1 (title exactly). Morning US
   time = **15:00–17:00 TRT** for EU-evening overlap.
2. **First 2 hours: live in the thread.** Answer every question; the
   project's rule applies to you too — technical criticism gets a test or
   an errata, never prose alone.
3. **+6–12h: Reddit** — paste §2 (30% shorter variant). Reply to top 3
   comments. Note the agent-coordination hook is explicitly secondhand.
4. **Same day: dev.to** — publish §3 (`launch-story-draft.md` + README
   receipts table). Link back from README "Public site" section.
5. **+24h: fill the G1 tracker** (`docs/commercial-model.md`): stars,
   comments, Issue #1 signups per channel.

## C. Donation rails (multi-chain, from your phantom wallet)

You supply the addresses; the agent wires them. Status:

| Chain | Address | Status |
|---|---|---|
| EVM | — | PENDING from maintainer |
| Solana | — | PENDING from maintainer |
| TRC-20 | — | PENDING from maintainer |

On receipt: FUNDING.yml `custom` block activates per chain (one commit),
commercial-model rail row flips to live. Sponsors stays OFF until your tax
consultation concludes — that decision is recorded in FUNDING.yml so a
future you (or contributor) doesn't "helpfully" re-enable it.

## D. What you NEVER need to do

- Post to HN/Reddit via automation or via the agent — founder voice only.
- Pay for anything: CI, Pages, Scorecard, soak, Sponsors-free donations
  are all $0. First optional spend is post-G2 (domain).
- Open a foreign company or a Sponsors payout account before the tax
  consult. The model is designed to earn $0–small while you decide.

## E. After G1 trips (≥500 stars or ≥3 external contributors)

1. Unlock paid launch content + conference budget (commercial-model G1).
2. Prioritize Issue #1 (independent verifier) support — a stuck verifier
   author gets same-day standard clarification (errata if needed).
3. Review the strategy memo (`docs/notes/strategy-deep-review.md`) — it
   ranks what to build next by revenue-fit.
