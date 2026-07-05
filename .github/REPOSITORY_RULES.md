# GitHub branch and merge rules (for maintainers)

Branch protection and **rulesets** are configured in the GitHub **web UI** (or the `gh` CLI / REST API), not by a rules file in this repo. Use this as a **checklist** when tightening `main`.

## Recommended: Rulesets (Settings → Rules → Rulesets)

Create a ruleset targeting **`main`** (or `include default branch`).

| Rule | Suggested |
|------|------------|
| **Require a pull request before merging** | On |
| **Required approvals** | 1 (2 if you have multiple maintainers) |
| **Dismiss stale pull request approvals** | On |
| **Require status checks to pass** | On  -  add the job that runs your Python + npm CI (see `.github/workflows/ci.yml` job name: `Python (validate + pytest)` and `TypeScript (npm test)` or whatever appears in the PR checks) |
| **Require branches to be up to date** | On (optional; stricter) |
| **Block force pushes** | On |
| **Require code scanning results** | On if Code Scanning is enabled |
| **Require review from Code Owners** | Optional  -  requires `.github/CODEOWNERS` and that listed accounts can review |

**Solo maintainers:** you can add yourself to a **bypass list** in the ruleset so urgent fixes can still merge while keeping the rules for everyone else, or start without “required approvals” and add them when the team grows.

## Classic: Branch protection (Settings → Branches)

If you prefer the older UI: add a rule for `main`, then enable “Require a pull request before merging”, “Require status checks to pass”, and “Include administrators” only if you want rules to apply to admins too.

## After adding `CODEOWNERS`

The file [CODEOWNERS](CODEOWNERS) requests reviews from `@vaquarkhan` by default. Update paths and usernames/teams to match this organization. It takes effect for **new** PRs; merge rules still depend on the ruleset / branch protection toggles above.

## Automation in this repository

- **CI:** `.github/workflows/ci.yml` (Python + optional npm in workspaces)
- **Dependabot:** `.github/dependabot.yml` (if present) for dependency update PRs
- **PR template:** [PULL_REQUEST_TEMPLATE.md](PULL_REQUEST_TEMPLATE.md)
