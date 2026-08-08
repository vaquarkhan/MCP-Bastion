# Publish Docs as GitHub Pages

The public site is built from **`docs/site/`** and deployed by [`.github/workflows/pages.yml`](../.github/workflows/pages.yml).

**Live URL:** https://vaquarkhan.github.io/MCP-Bastion/

| Path | Content |
|------|---------|
| `/` | Marketing landing (`docs/site/index.html`) — **4.0.0**, 26 integrations |
| `/guide/` | Professional documentation handbook (generated HTML) |
| `/guide/handbook.html` | Visual system handbook (attack GIFs, dashboard, feature map) |
| `/guide/bible.html` | Redirect → `handbook.html` (legacy URL) |
| `/integrations.html` | Integration matrix + live PePy download totals |

## Documentation guide (handbook)

Markdown under `docs/` is the source of truth. A curated set is rendered into `docs/site/guide/` with left-nav IA (Apache Spark / AWS-style handbook).

```bash
pip install markdown
python scripts/build_docs_site.py
```

Then open `docs/site/guide/index.html` locally, or after merge wait for Pages.

**Primary handbook:** [USER_GUIDE.md](USER_GUIDE.md) → https://vaquarkhan.github.io/MCP-Bastion/guide/user-guide.html

CI regenerates `guide/*.html` on every Pages deploy when markdown, the builder, or `docs/site/**` changes.

## Enable Pages (one-time)

1. Repository **Settings → Pages**.
2. **Source**: GitHub Actions (not “Deploy from a branch”).
3. Ensure the `Deploy to GitHub Pages` workflow has permission to write Pages.

## Custom domain (optional)

1. Add DNS (CNAME) to the GitHub Pages target.
2. **Settings → Pages → Custom domain**.
3. Enable **Enforce HTTPS**.

## Maintenance workflow

1. Edit markdown in `docs/` (or marketing HTML in `docs/site/`).
2. Run `python scripts/build_docs_site.py` locally to preview.
3. Open a PR; merge to `main`.
4. Pages workflow builds the guide and publishes.
