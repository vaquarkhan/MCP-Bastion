# Publish Docs as GitHub Pages

This repository can publish documentation directly from the `docs/` folder.

## Option 1 (fastest): GitHub Pages from `main` + `/docs`

1. Push your branch to GitHub.
2. Open repository **Settings**.
3. Go to **Pages**.
4. Under **Build and deployment**:
   - **Source**: `Deploy from a branch`
   - **Branch**: `main`
   - **Folder**: `/docs`
5. Save.

After a few minutes, your site is available at:

- `https://<org-or-user>.github.io/<repo>/`

`docs/index.md` becomes the landing page.

## Option 2: Custom domain

1. Add DNS record (CNAME) pointing to GitHub Pages target.
2. In **Settings > Pages**, set **Custom domain**.
3. Enable **Enforce HTTPS**.

## Suggested docs navigation structure

- `docs/QUICK_START.md` (minimal code + CI)
- `docs/DISCOVERY.md` (registry checklist)
- `docs/ROADMAP.md` (high-level directions)
- `docs/index.md` (home)
- `docs/DETAILED_TUTORIAL.md` (full walkthrough)
- `docs/PILLARS.md` (pillar definitions and `bastion.yaml` mapping)
- `docs/SUPPLY_CHAIN.md` (CI, releases, npm provenance, PyPI OIDC)
- `docs/INTEGRATION_MODELS.md` (middleware vs URL-swap adoption; stack bridges)
- `docs/POLICY_AS_CODE.md` (configuration)
- `docs/CLI.md` (commands)
- `docs/LLM_INTEGRATION.md` (provider integration)
- `docs/SECURITY.md` and `docs/METRICS.md` (operations)

## Maintenance workflow

1. Update docs in feature branch.
2. Run tests (`pytest`) and verify commands in examples.
3. Open PR and review docs links.
4. Merge to `main`; Pages auto-publishes changes from `docs`.
