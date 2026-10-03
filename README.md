<table><tr><td valign="middle" width="66"><img src="docs/assets/logo.svg" alt="Veridict mark" width="52" height="43"></td><td valign="middle"><h1>Veridict</h1></td></tr></table>

[![CI](https://github.com/goun7/veridict/actions/workflows/ci.yml/badge.svg)](https://github.com/goun7/veridict/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/badge/pypi-veridict--standard-blue)](https://pypi.org/project/veridict-standard/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)
[![Standard](https://img.shields.io/badge/standard-v1.0.0--draft-8A2BE2.svg)](docs/specs/2026-09-10-veridict-standard-v1.0.md)
[![Veridict self-audit](https://raw.githubusercontent.com/goun7/veridict/main/docs/assets/veridict-badge.svg)](https://github.com/goun7/veridict/releases/download/v1.0.0/dogfood_cert.json)

*The verdict that survived verification.* | **[Türkçe](README.tr.md)**

Veridict is a protocol and reference implementation for **auditing AI with AI
when humans no longer can**. An append-only, hash-chained evidence ledger
records every step of an audit: falsifiable claims, machine verifiers, a
blind heterogeneous jury, third-party watchers, and a signed certificate that
**anyone can verify offline** — no trust in the auditor required.

The founding premise: as AI output outgrows human review capacity, the human
role is not *code reviewer* but **risk owner**. Veridict is built around that
transformation — the machine owns the verdict of intelligence, the human owns
the verdict of responsibility.

## In 30 seconds

An agent says it did the work — deployed, paid, refactored, passed. "It says
so" is a **claim**. Veridict turns it into **proof**: a signed certificate
whose content hash, signature and timestamp **anyone can recompute from the
file alone** — no ledger, no network, no account, no trust in the auditor.

```bash
pip install veridict-standard

# an agent issues a signed receipt for completed work
export VERIDICT_HOME=$PWD/.veridict
veridict receipt issue --achievement "deployed api v2 to staging" \
  --actor agent-7 --evidence "gh run 8812 passed"

# the other side verifies it — independently, from the file alone
veridict verify .veridict/receipts/<cert_id>.json
# → {"valid": true, "signature_valid": true, "content_hash_valid": true, ...}

# tampering breaks it: one bit in the body breaks the signature,
# one digit in cert_id breaks the content hash; revocation is an
# append-only ledger entry, never a rewrite
```

Two document kinds, one verifier:

- **Receipts** (`veridict receipt`) — signed *proof-of-done* for one
  achievement: the smallest unit a counterparty actually needs. Exposed to
  agents over MCP (`mcp/`): `issue` / `verify` / `revoke` / `list`.
- **Audit certificates** (`veridict audit`) — a full adjudication over a
  machine-verifiable evidence ladder (tests, static analysis, a blind
  heterogeneous jury, watchers), replayable offline against the ledger.

Both are append-only, hash-chained, and fail closed: no evidence →
INCONCLUSIVE, never a clean bill.

## Why an audit ledger

- **No silent passes.** No evidence → INCONCLUSIVE, flagged — never a clean bill.
- **Tiers, not vibes.** Evidence has a fixed rank order: what a machine can
  check directly (W1a) beats what can be reproduced statistically (W1b),
  and both beat what a jury of models believes (W2/W3) — the ladder never
  lets doctrine overturn machine evidence, and W3 alone never verifies.
- **Identity is binding.** Every entry's hash binds its author; watcher manifests are signed, W1a is structurally impossible for them; a calibration ledger discounts producers whose claims were contradicted.
- **Verify, don't trust.** Certificates replay offline against the ledger. `examples/spec_verifier.py` is a verifier written **from the standard alone** (zero imports of this codebase) that reaches the same verdicts from the published test vectors.

## Quickstart

```bash
pip install veridict-standard
# PyPI name is `veridict-standard` (the bare `veridict` on PyPI is a
# DIFFERENT project — not ours). Same package from the repo, if preferred:
#   pip install -e . && pip install pytest

# first run: who am I, what can I do
veridict --version && veridict --help

# the system audits itself: ledger → claims → jury → certificate → offline verify
python scripts/dogfood.py

# verify a certificate offline (the property third parties care about)
# ledger + cert ship as release assets: gh release download --latest
veridict verify --ledger dogfood_ledger.jsonl --cert dogfood_cert.json

# or verify ANY certificate from the file alone — no ledger needed
# (the cert embeds the signer's public key and a signed timestamp)
veridict verify dogfood_cert.json

# issue a signed proof-of-done receipt for one achievement, and list them
export VERIDICT_HOME=$PWD/.veridict
veridict receipt issue --achievement "cut release v1.1" --actor agent-7
veridict receipt list

# your own repo, three commands: see "Audit your own repo" below

# regenerate the standard's conformance test vectors (deterministic)
python scripts/build_test_vectors.py

# measure GATE latency against the design budget (§6.5: p95 < 30 min)
python scripts/measure_latency.py
```

## Receipts (evidence over claims)

The self-audit badge above is regenerated by CI on every push from the
actual dogfood certificate (never hand-drawn) — and it links to that
certificate, which you can verify offline yourself: fetch the ledger and
certificate from the [latest release](https://github.com/goun7/veridict/releases)
(`gh release download` or the assets list), then run
`veridict verify --ledger dogfood_ledger.jsonl --cert dogfood_cert.json`.
A failing audit turns it amber or red — worst-verdict-wins.

| Check | Result |
|---|---|
| Test suite | 434 passed (both invocation styles, Python 3.12–3.14 in CI) |
| Self-audit | valid certificate, risk `low`, GATE not blocked |
| Offline replay | `veridict verify` rc 0 on the dogfood certificate |
| Standalone verification | receipt/cert verified from the **file alone** — content hash + signature + signed timestamp; new suites cover issue/verify/revoke/list, tamper, custody and the MCP protocol surface |
| Canary (scripted jury) | 23 catches / 3 honest misses / 0 false positives across 26 defect classes — measures a hand-authored refutation table, **not model capability**; labeled as such |
| Canary (real LLM, lower bound) | **2/25** classes caught, **0 false positives**, by local qwen2.5:3b + llama3.2:3b — the audit's end-to-end catch rate; the earlier 23/25 figure was inflated by a metric bug that counted coverage-meta-claim refusals as findings; sheets in `docs/notes/` |
| Judgment sonde (model, decoupled from the ladder) | **42/48** correct refutations of defective artifacts by the same 3B jurors (23/24 + 19/24), but **2/4 false refutations on clean code** — the model sees most of the defects; §5.3 rule 2 keeps those refutations from turning a W1a-supported verdict, and the false-refutation rate is the measured justification for that rule |
| Tamper soak | 1500 mutated ledgers, 5 seeds → 100% detected, 0 silent passes |
| Spec parity | reference verifier ≡ spec-only verifier on 8 failure modes |

CI runs the suite, the dogfood self-audit, and the offline replay on every
push — the receipts are regenerated, not narrated. The 1500-ledger tamper
soak runs nightly (the push run exercises a 150-ledger slice).

## Register a watcher in 3 commands

```bash
veridict registry init --registry r.jsonl --key-out r.key.json
veridict registry register --registry r.jsonl --manifest examples/manifests/example-security.json --key-file r.key.json
veridict registry index --registry r.jsonl --out index.json
```

Then audit with the external registry as authority:
`veridict audit ... --registry r.jsonl` — revoked watchers are refused
(§6.6). See CONTRIBUTING.md for writing your own.

## Audit your own repo in 3 commands

The fastest way to see Veridict work on *your* code: write a one-file task
manifest naming your checkout and the claims you want evidence about, run
the audit, verify the certificate offline — then link the pair from your
README. A runnable demo lives in [`examples/run_audit.py`](examples/run_audit.py).

```bash
# 1) a task manifest (see examples/ and TaskManifest in veridict/schemas.py)
cat > task.json <<'EOF'
{"task_id": "my-audit", "artifact_path": "/path/to/your/repo",
 "actor_identity": "you", "intent_lines": ["DOCTRINE: modules are idiomatic python"],
 "criticality": [], "has_existing_tests": true, "pytest_args": []}
EOF

# 2) audit → ledger + certificate
veridict audit --task task.json --mode HYBRID \
    --ledger my-ledger.jsonl --cert-out my-cert.json

# 2b) or WATCH a live audit as it writes (streaming transport, §10.3):
veridict watch --ledger my-ledger.jsonl --forever

# 3) verify offline (anyone can; no trust in the auditor required)
veridict verify --ledger my-ledger.jsonl --cert my-cert.json
```

Want the reference implementation to run the audit for you and publish the
certificate? Open an **[Audit my repo](https://github.com/goun7/veridict/issues/new?template=audit-my-repo.md)**
issue — the certificate that comes back is evidence, not endorsement (§13):
anyone can replay it offline against the published ledger, and a REFUTED
claim says exactly which evidence refuted it.

### Audit on every push (GitHub Action)

Run Veridict inside your own CI without installing anything locally — two
equivalent styles:

```yaml
# style 1 — the composite action (root action.yml; appears on the
# GitHub Marketplace as "veridict audit")
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: goun7/veridict@v1
        with:
          intent: "DOCTRINE: modules are idiomatic python"
          mode: HYBRID          # GATE / WATCH / CERTIFICATE also available
          fail-on-refuted: false # flip to true once you trust the audit

# style 2 — the reusable workflow (same engine, same inputs)
  audit-wf:
    uses: goun7/veridict/.github/workflows/veridict-audit.yml@v1
    with:
      intent: "DOCTRINE: modules are idiomatic python"
      mode: HYBRID
```

The run uploads `veridict-audit` artifacts (ledger + certificate) — download
once, verify forever: `veridict verify --ledger veridict-ledger.jsonl --cert
veridict-cert.json`. See the workflow file for all inputs — notably
`anchor: rekor` (pin the checkpoint to the public transparency log; the
verify step checks the sidecar automatically) and `actor-family` (declare
the authoring model's family and same-family jury opinions are excluded —
the self-preference guard).

By default the jury runs on scripted stubs (loudly marked in the report —
stubs never pretend to be judges). To bring a real model jury, the action
reads the same environment as the CLI — step-level `env:` flows into
composite steps:

```yaml
      - uses: goun7/veridict@v1
        env:
          VERIDICT_JURY_URL: https://api.openai.com/v1      # any OpenAI-compat
          VERIDICT_JURY_KEY: ${{ secrets.JURY_KEY }}
          VERIDICT_JURY_MODEL: gpt-4o
          VERIDICT_JURY_URL2: https://api.anthropic.com/... # a 2nd FAMILY
          VERIDICT_JURY_KEY2: ${{ secrets.JURY_KEY2 }}      # (required: juries
          VERIDICT_JURY_MODEL2: claude-sonnet-4-5           #  need ≥2 families)
        with:
          intent: "DOCTRINE: ..."
```

## Receipts for agent work (proof-of-done)

An audit certificate is the heavy instrument — evidence ladder, jury,
watchers. Most of the time a counterparty needs the light one: *did the
agent do the thing it said it did, and can I check it myself?* That is a
receipt.

```bash
export VERIDICT_HOME=$PWD/.veridict     # workspace: ledger + issuer key

# issue: achievement + grounds -> signed, self-contained receipt
veridict receipt issue --achievement "paid invoice 1042" \
  --actor agent-pay --evidence "bank confirmation tx 77f3"

# verify standalone (file alone) or fully (with the issuer's ledger)
veridict verify $PWD/.veridict/receipts/<cert_id>.json
veridict receipt verify --cert .veridict/receipts/<cert_id>.json \
  --ledger .veridict/ledger.jsonl

# revoke (append-only: the receipt file is never modified) and list
veridict receipt revoke --cert .veridict/receipts/<cert_id>.json \
  --reason "chargeback case 91"
veridict receipt list --active-only
```

`veridict verify` dispatches on `certificate_type`: a receipt proves chain
integrity, issuance and revocation over a ledger, an audit certificate adds
the claim replay — the top-level command handles both. Revoke accepts the
receipt file (`--cert`) or a bare `--cert-id`.

Every receipt carries a `content_digest` recomputable from its own fields,
an Ed25519 signature over the canonical body verified against the public key
**embedded in the receipt**, and an `issued_at` inside the signed body. The
issuer's private key stays local (mode 0600, never emitted); only its public
half ships. Revocation appends a `receipt.revoked` entry to the same
hash-chained ledger that issued it — the signature stays intact and the
disavowal stays auditable. See [`mcp/README.md`](mcp/README.md) for the
agent-facing surface and [`docs/arastirma/`](docs/arastirma/README.md) for
the academic map of the proof gap this closes.

## From certificate to settlement

A certificate proves what happened. It does not by itself authorize
payment — a settlement layer still has to decide whether *this* verified
work qualifies, and that decision has to fail closed on its own.
payment — a settlement layer still has to decide whether *this* verified
work qualifies, and that decision has to fail closed on its own.
`veridict settle` is that boundary:

```bash
# certificate already verified offline (veridict verify)
veridict settle --cert dogfood_cert.json --out claim.json   # derive
veridict settle --cert dogfood_cert.json --claim claim.json  # reconcile
```

The claim is derived only from certificate fields — accepted claims, jury
families, risk level — under a policy that is itself part of the claim's
digest, so the caller cannot swap in a more permissive policy after
seeing the verdict. Reconciliation never trusts the presented claim: it
recomputes it from the certificate, so inflating `accepted_claims` (or
flipping `valid`, or presenting a claim minted against a different
certificate) is refused. Exit code 0 means the claim holds; non-zero
means it does not — a pipeline that ignores the report and pays on any rc
has a bug, and the tool will not help it.

This is deliberately a **claim generator**, not a payment executor. It
answers "was provably-done work done", not "should money move". Keeping
those separate is what stops a dropped or replayed settlement message
from becoming a silent release.

## Interoperability

**Positioning vs runtime governance** (e.g. microsoft/agent-governance-
toolkit): those constrain agents *before/during* actions; Veridict
adjudicates *after* the fact into a certificate a counterparty verifies
without trusting vendor, auditor, or runtime. Directions of flow differ —
a deployment can run both, and the runtime's own action logs are exactly
the evidence class an audit anchors on.

Two ways a Veridict verdict reaches tooling that never heard of us:

- **External anchoring** — `veridict audit … --anchor rekor` (or in CI, the
  `anchor: rekor` action input; or `veridict anchor publish`) pins the certificate's checkpoint to the Sigstore
  Rekor public-good transparency log. The anchor proves *existence at time T*;
  authority stays with the certificate's own key. Anyone holding cert + ledger
  + anchor sidecar checks it fully offline:
  `veridict verify --ledger L --cert C --anchor A` (pinned Rekor key, no
  network, no trust in us). The v1 release's dogfood certificate is anchored
  live — see `docs/receipts-anchor-v1-dogfood.json`.
- **SLSA export** — `veridict export --format vsa` projects a certificate onto
  a SLSA v1.2 Verification Summary Attestation (in-toto Statement) so existing
  supply-chain policy engines can consume the verdict. The VSA is a lossy
  projection: it names the certificate by digest (`inputAttestations`) and
  embeds the full binding as a spec-sanctioned extension field; the
  certificate remains the authoritative object. Optional `--sign KEYFILE`
  wraps it in a DSSE envelope under the issuing key.
- **SPDX 3.0.1 export** — `veridict export --format spdx` emits an SPDX 3.0.1
  AI-profile JSON-LD document, validated in CI against the pinned official
  schema. The audited artifact rides as an `ai_AIPackage` (identity, digest,
  supplier); every audit semantic — claims, evidence, jury composition, risk,
  Rekor anchor — rides on core Annotation/Relationship/ExternalRef elements.
  Deliberate limit: the AI profile models AI *systems*, not audit verdicts,
  so no `ai_*` field is made to carry a meaning the spec does not give it
  (our risk_level never occupies ai_safetyRiskAssessment — there is a test
  locking that refusal in). The `certificationReport` externalRef binds the
  authoritative certificate by canonical digest.

## Public site

The standard and the design document are readable (and linkable) at
**https://goun7.github.io/veridict/** — deployed from `main` on every push.
The launch article — *"Agents already found their forum. We built the
better one."* — is on [dev.to](https://dev.to/goun7/agents-already-found-their-forum-we-built-the-better-one-2d37).

## Documents

- **Standard (normative draft):** [`docs/specs/2026-09-10-veridict-standard-v1.0.md`](docs/specs/2026-09-10-veridict-standard-v1.0.md) — §14.2 carries errata; errata proposals are a first-class issue template
- **Standard v1.1 delta (draft):** [`docs/specs/2026-09-12-veridict-standard-v1.1-delta.md`](docs/specs/2026-09-12-veridict-standard-v1.1-delta.md) — ratifies the WATCH transport latency sentence (D10); read on top of v1.0
- **Design document (founding paper):** [`docs/specs/2026-09-09-veridict-design.md`](docs/specs/2026-09-09-veridict-design.md)
- **Architecture:** [`ARCHITECTURE.md`](ARCHITECTURE.md) — module map to standard sections
- **Commercial model:** [`docs/commercial-model.md`](docs/commercial-model.md) — open-core model, growth levers, anti-corruption guardrails
- **Landing page prep:** [`docs/landing.md`](docs/landing.md) — 30-second pitch, feature map, tiered pricing ($29–99/mo, the core never paywalled)
- **Academic research:** [`docs/arastirma/README.md`](docs/arastirma/README.md) — the proof gap mapped to six 2025–2026 papers (real links), W3C VC v2.0 / Data Integrity alignment, and the EAS on-chain model
- **MCP server (receipts):** [`mcp/README.md`](mcp/README.md) — stdio install for Claude Desktop / Cursor / Cline; tools `issue` / `verify` / `revoke` / `list`; registry definition in `mcp/mcp.json`
- **Contributing / Governance / Security:** [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`GOVERNANCE.md`](GOVERNANCE.md) · [`SECURITY.md`](SECURITY.md)
- **Building your own verifier** (independent of this codebase, issue #1): [`docs/verifier-onboarding.md`](docs/verifier-onboarding.md) — closure kit: trusted-artifact table, byte-level traps list, one-command parity harness, proofs-as-behavioral-spec

## Status & roadmap

**Formal core (Sep 2026):** every structural layer of the core is
machine-checked in Lean (v4.34, kernel-only). The ladder
(`proofs/ladder/Ladder.lean`) proves seven invariants over evidence lists
of *arbitrary* length — fail-safe-empty, no-silent-pass, W1a-decisiveness,
doctrine-can-never-topple, escalation conditions, split visibility,
meta-budget — and a generated oracle (`TruthTable.lean`, digest-tied to the
bounded receipt) re-verifies the model against all 28,080 sampled cases on
every CI run; its first build caught a real model-vs-code divergence and
the model moved. The ledger chaining (`proofs/ledger/Chain.lean`) proves
six theorems over chains of *arbitrary* length — writer/reader agreement,
prefix-closure, payload-edit and honest-remint tamper detection (the one
collision hypothesis is *stated*, not smuggled), genesis-rooting. The
anchor sidecar (`proofs/anchor/Anchor.lean`) proves nine theorems about
certificate⇄CT cross-verification — its headline (A4): with the wrong
binding, valid ECDSA signatures cannot rescue a sidecar; structural
rejection is unconditional. ECDSA itself stays honest TCB: no structural
proof discharges a computational assumption, so it enters the model as a
disclosed opaque boolean rather than being silently "proven". Trust
placement (kernel `decide`; disclosed `native_decide` for the oracle lane
only) and the measured axiom footprints (C1 and I1/I7 axiom-free; the rest
`[propext]`/`Quot.sound`-maximal) are disclosed in the file headers and
re-printed by `proofs.yml` on every run — per house doctrine: receipts,
not narrative.

Phase 1 (core) and Phase 2 (watcher layer) are implemented with end-to-end
receipts in the dogfood run. Phase 3 (platform + standard) substrate is in
place: spec draft, conformance kit (C1–C13), marketplace index, test vectors,
spec-only verifier. The remaining exit criteria are external by nature:

1. an **independent verifier** implemented from the spec by someone else,
2. a first **external production deployment**,
3. **≥10 active watcher manifests** on the marketplace.

Roadmap decisions are tracked in the issue tracker — the post-launch
expansion plan is [Roadmap v2 (#10)](https://github.com/goun7/veridict/issues/10)
(launch-hygiene fixes first, then standard maturity, federation, and
formal verification); the commercial
model is documented in [`docs/commercial-model.md`](docs/commercial-model.md).

## Akademik Kaynaklar (2024-2026)

Veridict'in dayandığı alan — DSSE/in-toto tarzı imzalı attestation, yazılım
tedarik zinciri güvenliği, doğrulanabilir iddialar (verifiable claims) ve SLSA
build provenance — üzerine 2024-2026 yayınları. Tüm bağlantılar canlı arXiv
sayfalarıdır.

- **[1] DSSE İmzalı, Değişmez ve Yeniden Oynatılabilir Ajan Kanıtı** —
  *NovaFabric: Tamper-Evident, Replayable Evidence for Autonomous AI Agent
  Runs* — Ardebili, arXiv 2026.
  Otonom bir ajan çalışmasını, hiçbir ajan mantığını değiştirmeden, DSSE
  imzası + RFC 3161 zaman damgası + Merkle log ile mühürlü, taşınabilir ve
  yeniden oynatılabilir bir "Run Capsule" olarak kaydeder. Veridict'in
  hash-chained ledger + çevrimdışı doğrulanabilir sertifika yaklaşımının
  aynı ailesinden, doğrudan DSSE uygulaması.
  [arXiv:2609.12582](https://arxiv.org/abs/2609.12582)

- **[2] Doğrulanabilir Eğitim/Yayın İddiaları için Attestation Geçidi** —
  *Attesting LLM Pipelines: Enforcing Verifiable Training and Release Claims*
  — Tan et al., arXiv 2026.
  Üçüncü parti ağırlıklar, adapter'lar ve dependency'lerden oluşan LLM
  tedarik zincirinde "data/code lineage, build environment, security
  scanning" gibi iddiaların kriptografik olarak artifact'e bağlanmamasını
  bir boşluk olarak tanımlar ve attestation-aware bir promotion gate önerir.
  Veridict'in "iddia → imzalı, makine-doğrulanabilir kanıt" dönüşümünün
  ML pipeline genellemesi.
  [arXiv:2603.28988](https://arxiv.org/abs/2603.28988)

- **[3] CI Hatları için Kanıt Tabanlı Provenance Protokolü** —
  *An Evidence-driven Protocol for Trustworthy CI Pipelines* — Castillo et
  al., arXiv 2026.
  Deterministic Build Systems + Trusted Execution Environments kombinasyonuyla
  CI artifact'leri için kriptografik doğrulanabilir bütünlük, özgünlük ve
  attestation garantisi sunar; her tüketicinin build'i yeniden çalıştırmasının
  doğurduğu doğrulama darboğazını çözer. SLSA build provenance hedefinin
  kanıt-odaklı bir gerçeklemesi.
  [arXiv:2605.21089](https://arxiv.org/abs/2605.21089)

- **[4] SLSA/in-toto Ötesinde Otonom Tedarik Zinciri Savunması** —
  *Agentic AI for Autonomous Defense in Software Supply Chain Security:
  Beyond Provenance to Vulnerability Mitigation* — Syed et al., arXiv 2025.
  Mevcut SLSA, SBOM ve in-toto çerçevelerinin provenance ve izlenebilirlik
  sağladığını ama üretime gömülü zafiyetleri aktif olarak tespit edip
  gideremediğini belirtir; LLM tabanlı otonom savunmayla tamamlamayı önerir.
  Veridict'in kanıt katmanının (provenance) ötesine geçiş ihtiyacını
  tanımlayan referans.
  [arXiv:2512.23480](https://arxiv.org/abs/2512.23480)

- **[5] Kod Asistanları Provenance Sinyallerini Okuyor mu?** —
  *Do AI Coding Assistants Check Before They Install? A Pre-Registered
  Demand-Side Audit of Trust Signals in the Research Software Supply Chain*
  — Shan, arXiv 2026.
  SBOM, imzalı release'ler, build provenance attestations ve resmi kanal
  beyanları gibi makine-okunabilir güven sinyallerinin, paket seçip kuran
  AI kod asistanları tarafından okunup okunmadığını ölçen önceden
  kayıtlı bir deney. İmzalı kanıtın üretildiğiyle tüketildiği arasındaki
  açığı gösterir.
  [arXiv:2609.07754](https://arxiv.org/abs/2609.07754)

- **[6] LLM Ajanlarında Yürütüm Provenance'ı ve Kanıt İzleme Araştırması** —
  *From Agent Traces to Trust: A Survey of Evidence Tracing and Execution
  Provenance in LLM Agents* — Wang et al., arXiv 2026.
  Ajan izlerini (trace) salt gözlemden, süreç düzeyinde hesap verebilirliğin
  temeli olarak yürütüm provenance'ına yükseltir: her iddianın arkasındaki
  kanıt, araç çağrılarının gerekçesi ve belleğin kararlara etkisi. Veridict'in
  evidence ladder'ının akademik zeminini oluşturur.
  [arXiv:2606.04990](https://arxiv.org/abs/2606.04990)

- **[7] Skor Değil, İddia Doğrulaması** —
  *Verify Claims, Not Scores: Evidence-Based Verification of Modular Agents*
  — Alzahrani, arXiv 2026.
  Ajanı toplam bir görev skoruyla yargılamak yerine, her sonucu arkasındaki
  kanıtla birlikte kaydeden ve destekli / desteklenmiyor / çözümlenemedi /
  değerlendirilmedi olmak üzere dört verdicttan biriyle etiketleyen bir
  doğrulama denetimi önerir. Veridict'in fail-closed INCONCLUSIVE verdict
  felsefesiyle aynı özü taşır.
  [arXiv:2610.01348](https://arxiv.org/abs/2610.01348)

- **[8] Yapısal Ajan Eylemleri için Kaynaklarası Bütünlük Sertifikası** —
  *Certified Multi-Source Integrity for Structured Agent Actions* — Pandey
  et al., arXiv 2026.
  Ajanların ayrıcalıklı, geri alınamaz yapısal eylemlerini (ör. fatura ödeme)
  bozabilecek belge/araç çıktısı kirlenmesi ve prompt injection'a karşı,
  bir corruption budget altında eylemin ne zaman güvenle sertifikalanabileceğini
  tanımlar. Veridict'in imzalı makine-verifier'larıyla aynı "sertifikala,
  sonra serbest bırak" modeli.
  [arXiv:2609.34245](https://arxiv.org/abs/2609.34245)

