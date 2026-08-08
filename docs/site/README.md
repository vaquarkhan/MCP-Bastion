# GitHub Pages site (`docs/site/`)

Static marketing + docs site deployed to https://vaquarkhan.github.io/MCP-Bastion/

| Path | Content |
|------|---------|
| `/` | Landing (`index.html`) — v4.0.0 |
| `/integrations.html` | 26 packages + PePy download dashboard |
| `/guide/` | Generated handbook from `docs/*.md` |
| `/guide/handbook.html` | Visual documentation handbook |

Rebuild guide HTML: `python scripts/build_docs_site.py`

## Deploy

Pushes to `main` that touch `docs/site/**` run [.github/workflows/pages.yml](../../.github/workflows/pages.yml).

**Required repo setting:** Settings → Pages → Build and deployment → **Source: GitHub Actions** (not “Deploy from branch”). Using legacy branch deploy alongside this workflow causes `Deployment failed, try again later`.

Manual redeploy: Actions → “Deploy to GitHub Pages” → Run workflow.
