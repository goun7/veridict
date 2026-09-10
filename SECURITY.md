# Security Policy

## Reporting a vulnerability

Veridict is itself a security tool — please hold it to the standard it
preaches. Report vulnerabilities **privately** via GitHub Security
Advisories ("Report a vulnerability" on the Security tab) rather than a
public issue.

Scope of highest interest (matches the standard's threat model,
`docs/specs/2026-09-10-veridict-standard-v1.0.md` §13):

- chain-integrity breaks: any way to alter, reorder, or append to a ledger
  without `verify_chain` failing
- replay/verification bypasses: any way to make `verify_certificate` accept
  an invalid certificate (including the §9.4 deliberation-exclusion scope)
- blindness violations in watcher sessions (§6.3)
- tier-ceiling escapes (a watcher producing W1a evidence, §5.3)
- fail-open paths: anywhere the system passes silently instead of
  abstaining (§4.3 rule 5 — the no-silent-pass invariant)

## Supported versions

Only the latest `main` branch is supported pre-1.0. Ledger-format breaks are
documented in `CHANGELOG.md` (semver applies to the chain format).

## Disclosure

We will acknowledge within 72 hours, publish a fix with an erratum entry in
the standard's §14.2 when the issue reflects a specification gap, and credit
reporters (opt-out honored).
