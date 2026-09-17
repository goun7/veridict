# Marketplace publishing — step-by-step (maintainer's runbook)

The `action.yml` at the repo root is already Marketplace-compliant
(verified 2026-09-17: name, description 104/125 chars, branding
icon+color, `runs.using: composite`, every input documents itself).
Publishing is a browser action on GitHub — no code changes are needed.

## Preconditions (all met)

- [x] `action.yml` at repo root, `using: composite`
- [x] `v1` tag moved to the latest commit (`e3f0d2d`, 2026-09-17)
- [x] CI green on that commit
- [x] All Marketplace-required metadata present

## Steps (5 minutes, browser only)

1. Open https://github.com/goun7/veridict
2. Click **Actions** → the left sidebar lists workflows, but the
   Marketplace link is on the repo page itself: click the repo's
   **"Publish this action to the GitHub Marketplace"** prompt that
   appears on the action's page, OR go directly to
   https://github.com/marketplace/actions/new and select the repo.
3. The form pre-fills from `action.yml`. Review:
   - **Name**: `Veridict audit`
   - **Description**: from `action.yml` (editable here only as an
     override — prefer editing `action.yml` instead, then re-publish)
   - **Categories**: pick `Security`, `Utilities`, `DevOps`
   - **Branding**: icon `check-circle`, color `green` (from action.yml)
4. Accept the **GitHub Marketplace Developer Agreement**.
5. Click **Publish**.

The listing appears at
https://github.com/marketplace/actions/veridict-audit and the README's
`@v1` examples become one-click copy-paste that works.

## Versioning after publish

- Patch releases: push commits, then force-move the `v1` tag and it
  propagates to everyone using `@v1` (already done once for `e3f0d2d`).
- Breaking changes: cut a `v2` tag and publish it as a separate
  listing entry; never force-move a major tag in a breaking way.

## Rollback

If a published version is bad: move `v1` back to the last good commit
and force-push the tag (`git tag -f v1 <sha> && git push -f origin
refs/tags/v1`). Existing Marketplace listings read the tag, so the fix
is immediate.
