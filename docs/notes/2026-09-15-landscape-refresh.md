# Landscape & position — verified 2026-09-15 (primary sources only)

Companion to design doc §10.5; this note carries the *verdict*, the table
carries the receipts. Everything below was re-grounded this date; secondary
surveys failed verification (see "AegisChain"). Evening same date: HANSARD
(2608.22512) and one calibration-cluster paper (2609.12002) re-fetched
directly from arXiv — abstracts, dates and the "record produced by the
suspects" framing match this note's characterizations verbatim.

## What is true as of today

- **The ledger primitive has converged.** Three independent 2026 papers
  (AuditWeave 2607.09682, HANSARD 2608.22512, VCT 2606.23003) arrived at
  hash-chained evidence recording for agent activity within months of us.
  Good news, honestly read: it validates the substrate; bad news: "we use
  a tamper-evident ledger" is no longer a differentiator anywhere.
- **The critique we must keep answering** is HANSARD's: records produced
  by suspects don't acquit suspects. Our answer is structural, not
  rhetorical: W1a re-executed by the verifier; third-party transparency
  anchoring (Rekor); author-family-excluded blind juries; doctrine can
  never outrank machine evidence (now a Lean theorem, I5).
- **Nobody ships the combination.** Recording (papers) OR runtime
  enforcement (microsoft/agent-governance-toolkit, 6.3k★ — real, busy,
  different direction of flow) OR content credentials (C2PA-line; gap
  papers 2604.24890/2603.02378 document its in-band limits) — the
  post-hoc, offline-verifiable, evidence-weighted CERTIFICATE as a public
  protocol is still unoccupied.
- **SLSA-for-AI-work-product: open niche.** No dedicated paper or shipped
  artifact maps VSA attestation onto AI claim audits (scanned today);
  our `export --format vsa` + `export --format spdx` look like the first
  artifacts in that seam. Position claim accordingly: "first shipped",
  never "first thought".
- **Judge science backs the design, not the hype.** Calibration cluster
  (2609.12002, 2609.12439, 2606.13221, 2607.28636) + MedAgentAudit
  (2510.10185: 98.42% self-consistency collapse) say juries are useful
  ONLY when head-counting is replaced by family-diversity + structural
  caps. That is literally §5.2. Expect reviewers to know these papers;
  cite before they ask.
- **Regulatory clock, current:** GPAI obligations + enforcement powers
  live since 2026-08-02; Art. 50 transparency applies 2026-08-02;
  Omnibus grace for machine-readable marking of legacy systems ends
  2026-12-02; 180+ CoP signatories listed 2026-08-02. Wedge: the
  machine-readable-marking + training-data-summary duties reduce to
  file-shape checks — the aiact watcher is the deterministic answer,
  and it is W1b-capped so it never overclaims legally.

## Realistic threat ranking (adversarial self-review)

1. **HANSARD authors formalizing tiered evidence** — our tier rules are
   published in the standard + Lean; a concurrent formalization would
   erode "machine-checked protocol" novelty. Counter: ship the ledger/
   anchor proofs (issue #8 remainder) before they do. → **Counter
   executed same day (a859d8b): anchor lane A0–A7 machine-checked
   (verified vs. HANSARD v1 abstract, fetched directly from arXiv
   2026-09-15: it is a reference architecture — tiers named, nothing
   kernel-checked, no executable standard, no conformance kit). The
   remaining realistic erosion is *scope*, not speed: nobody can
   un-publish our four CI lanes + 28k-oracle + vectors combo.**
2. **agent-governance-toolkit adding post-hoc certificates** — they have
   the distribution; we have the protocol. Counter: the side-by-side
   README note invites exactly the integration they'd have to build.
3. **Micro-clones (≤6★, several seen)** — not threats; adoption proof
   points. Link them in the adoption thread rather than fighting them.
4. **"AegisChain" (non-oracle lesson)** — cited across surveys, zero
   primary sources. We now state survey-skepticism in the design doc.

## Where we genuinely stand vs the marketplace bar

GitHub Marketplace "veridict audit": action surface e2e-proven on every
tag through `uses: ./` (v0.5.0: success), anchor inputs live, listing
text = action.yml. Remaining listing polish (screenshot of dossier
output, "verified by strangers" usage example) is UI-only and owner-side.
