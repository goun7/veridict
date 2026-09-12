---
name: Audit my repo
about: Ask the Veridict reference implementation to run a GATE audit on YOUR repository and publish the certificate
labels: auditee, audit-request
---

**Repository URL** — a public repo we can clone (GitHub preferred)

**What to audit** — pick one or more claims you want evidence about, in your own words
(e.g. "no subprocess calls with shell=True", "the test suite passes on a clean
checkout", "no secrets are committed", "dependencies are licensed permissively").
Veridict audits *claims*, not vibes: each claim gets a tiered verdict
(VERIFIED / REFUTED / INCONCLUSIVE) with machine evidence (W1a/W1b) where the
claim allows it.

**Criticality** — which claim classes are release-blocking for you
(e.g. security, payments, compliance). REFUTES on a critical class escalate to
a human dossier; non-critical REFUTES are recorded, not blocking.

**Policy mode** — `GATE` (blocking: REFUTES on critical classes fail the audit),
`WATCH` (non-blocking: everything recorded, nothing blocked), or `HYBRID`
(machine evidence blocking, doctrinal advisory).

**Verification you will do afterwards** — the audit publishes a certificate +
ledger pair. Anyone can re-verify offline:

```
pip install -e git+https://github.com/goun7/veridict.git#egg=veridict-standard
veridict verify --ledger <published>.jsonl --cert <published>.json
```

(Note: `pip install veridict` on PyPI installs an UNRELATED third-party
project that happens to share the name — our distribution is
`veridict-standard`.)

**Checklist**
- [ ] The repo is publicly cloneable
- [ ] I understand the certificate reports evidence, not endorsement (§13)
- [ ] I will embed the badge/certificate link in my README if the audit passes
