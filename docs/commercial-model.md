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
| **Enterprise adoption support** | $0 | immediately on first inbound inquiry | Consulting on embedding Veridict in a company's CI: policy tuning, audit pipelines, verifier integration |
| **Crypto donations** (multi-chain: EVM + Solana + TRC-20; addresses pending from maintainer's phantom wallet — FUNDING.yml `custom` block ready to activate per chain) | $0 | ACTIVE RAIL (decision 2026-09-10, widened 2026-09-11) | Global donors pick their cheapest rail; no custody, no payout setup, no tax-setup friction. Honest note: the tax character of income does not change with the rail — declaration goes through a professional once amounts matter |
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
3. **Content with a spine.** The agent-coordination incident note
   (`docs/notes/2026-09-10-agent-coordination-incident.md`) shows the thesis
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

The full tradeoff map (roadmap critique, revenue ranking by speed×fit,
protocol terminal-state, and the two imperatives) lives in
`docs/notes/strategy-deep-review.md`. It is the reference for the next big
build decision — read it before choosing what to fund or build.

## G1 tracker (launch receipts)

Filled by the maintainer after publishing per
`docs/notes/launch-ready.md` step 4 — numbers, not narratives.

| Date | Channel | Stars (total) | Comments/replies | Signups for Issue #1 | Notes |
|---|---|---|---|---|---|
| — | Show HN | — | — | — | pending |
| — | Reddit (r/MachineLearning or r/singularity) | — | — | — | pending |
| — | dev.to (canonical article) | — | — | — | pending |

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
