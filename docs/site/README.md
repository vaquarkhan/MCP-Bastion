# GitHub Pages site (`docs/site/`)

Static marketing site deployed to https://vaquarkhan.github.io/MCP-Bastion/

## Deploy

Pushes to `main` that touch `docs/site/**` run [.github/workflows/pages.yml](../../.github/workflows/pages.yml).

**Required repo setting:** Settings → Pages → Build and deployment → **Source: GitHub Actions** (not “Deploy from branch”). Using legacy branch deploy alongside this workflow causes `Deployment failed, try again later`.

Manual redeploy: Actions → “Deploy to GitHub Pages” → Run workflow.
