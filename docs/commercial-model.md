# Commercial model — open core under a zero-capital constraint

Principle: **the money follows the trust; it never gates the trust.** The
open core stays Apache-2.0 forever (standard, ledger core, offline verifier).
Revenue attaches where humans are irreplaceable — the same place the protocol
puts them: risk ownership and certification.

## The constraint that shapes everything

Starting capital: zero. Therefore every cost-bearing item is deferred behind
an explicit *interest gate* (measurable community demand), and every
capital-free lever is pulled early. GitHub provides CI, hosting of the spec,
issues and discussions at $0; the product itself runs in the adopter's CI,
not on our servers.

## Revenue streams, ranked by fit and capital need

| Stream | Capital need | When | Why it fits the ethics |
|---|---|---|---|
| **Watcher certification** | $0 (review time only) | after ≥10 community manifests | We are PAID TO REJECT. Income depends on failing bad watchers — the incentive aligns with the no-silent-pass invariant instead of against it |
| **Enterprise adoption support** | $0 | immediately on first inbound inquiry — inbox is LIVE: repo Discussions (enabled 2026-09-13), seeded thread "Adopting Veridict in your CI" | Consulting on embedding Veridict in a company's CI: policy tuning, audit pipelines, verifier integration |
| **Crypto donations** (multi-chain: Solana + EVM + BTC + Sui + TRC-20 all LIVE in FUNDING.yml as of 2026-09-12 — receive-only, no signing authority; TRC-20 standard address chosen over GasFree for universal exchange acceptance) | $0 | LIVE (decision 2026-09-10, fully activated 2026-09-12) | Global donors pick their cheapest rail; no custody, no payout setup, no tax-setup friction. Honest note: the tax character of income does not change with the rail — declaration goes through a professional once amounts matter |
| **GitHub Sponsors** | $0 | DEACTIVATED by decision (2026-09-11) — pending professional tax advice; handle reserved in FUNDING.yml | Sponsors stays off until a tax professional is consulted; crypto is the active rail meanwhile |
| **Hosted platform / SaaS** | HIGH (servers, ops) | **gated** — see below | The deferred prize: hosted registries, continuous dogfood, dashboards. Only worth building when demand exists |
| **Certification authority** (formal body) | MEDIUM | long-term | The endgame: Veridict-as-standard needs an issuer of watcher certificates, the way TLS needs CAs |

## Interest gates (spend only when these trip)

| Gate | Metric | Unlocks |
|---|---|---|
| G1 — awareness | ≥500 stars or ≥3 external contributors | paid launch content; conference talk budget |
| G2 — adoption | ≥10 real watcher manifests or ≥3 companies running audits | dedicated maintainer time; sponsored infra (free tiers first) |
| G3 — revenue signal | first paid certification or support contract | hosted-platform MVP (smallest viable: registry + dashboard) |

Below the gate, the answer to "when will there be a SaaS?" is: *when the
community makes it cheaper to fund than to self-host* — and the open core is
kept good enough that self-hosting stays easy (that is the honest price of
the open-core promise).

## Growth levers that cost $0

1. **Receipts, not narratives.** CI publishes the canary catch-rate and the
   dogfood certificate on every push — the README table regenerates itself.
2. **The spec as an ecosystem play.** A standard with language-neutral test
   vectors and a reference spec-only verifier is *implementable by
   competitors*; every independent implementation multiplies the value of
   certification (network effect we don't have to host).
3. **Content with a spine.** Publicly reported agent-coordination incidents
   show the thesis
   maps onto real incidents — turned into a public write-up it is the launch
   story: *agents already coordinate covertly; the audit channel must be the
   better medium.*
4. **The errata culture.** A standard that publicly carries its errata
   (§14.2) and accepts errata proposals as a first-class issue template earns
   the credibility standards bodies spend years on.
5. **Badge protocol.** "Audited by Veridict — certificate verifiable
   offline" badge for repos that pass a GATE audit, linking to the
   certificate: free distribution for them, free reach for us.

## Strategy deep review

The full tradeoff map is maintained by the maintainer outside the public
tree. The commitments it governs: the open core is permanent and never
gated (Apache-2.0, no crippleware); certification revenue must never
pressure watcher outcomes (guardrails below); next build decisions rank
by revenue-fit against the roadmap, not by novelty.

## G1 tracker (launch receipts)

Filled by the maintainer after each publishing step — numbers, not
narratives.

| Date | Channel | Stars (total) | Comments/replies | Signups for Issue #1 | Notes |
|---|---|---|---|---|---|
| 2026-09-13 16:13 TRT | Show HN (post 49683610) | 1 | 0 | 0 | killed by new-account spam filter 5 min after posting; `dead:true`; mod email to hn@ycombinator.com pending — revive is the blocker |
| 2026-09-13 | Reddit (r/MachineLearning) | — | — | — | modmail sent (karma/age gate + self-promo pre-approval); awaiting mod reply — post text ready (launch-ready.md §2) |
| 2026-09-13 ~21:45 TRT | dev.to (canonical article) | 1 | 0 | 0 | PUBLISHED: "Agents already found their forum. We built the better one." — https://dev.to/goun7/agents-already-found-their-forum-we-built-the-better-one-2d37 |

Gate trips at **≥500 stars or ≥3 external contributors** → unlocks paid
launch content + conference talk budget.

## Anti-corruption guardrails

- Certification revenue must never create pressure to pass watchers; the
  kit's checks are code, not judgment calls, and refusals are recorded with
  reasons.
- The open core is never crippled to sell the hosted layer: no open-core
  rate limits, no license key checks, no "enterprise-only" security fixes.
- If these guardrails ever look unsustainable, the correct move is to spin
  the certification body into an independent entity (P7), not to bend the
  core.
