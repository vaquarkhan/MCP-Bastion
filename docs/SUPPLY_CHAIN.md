# Supply chain, releases, and provenance

This page is for **operators and security reviewers**: how MCP-Bastion **builds and publishes** artifacts today, and how to describe that accurately in questionnaires and release notes. Verifiable facts (GitHub Actions, npm provenance, PyPI Trusted Publishing) usually read stronger than generic “enterprise-grade supply chain” labels.

## What GitHub Actions does today

Workflows live under [`.github/workflows/`](../.github/workflows/). Highlights:

### `ci.yml` (pull requests and `main`)

- **Python:** `pip install -e ".[dev,policy,dashboard]"`, then `mcp-bastion validate --config bastion.yaml.example`, then **`pytest --cov=mcp_bastion --cov-fail-under=99`** (see `[tool.coverage.*]` in `pyproject.toml`).
- **TypeScript:** `npm ci` and **`npm test`** (workspace packages).

### `publish-mcp.yml` (main package: PyPI + npm + MCP Registry)

- **Checkout** of the ref that triggered the run (`actions/checkout@v4`).
- **TypeScript (monorepo):** `npm ci`, `npm run build`, `npm run test` (workspace tests).
- **npm release (on version tags):** `npm publish --workspace=@mcp-bastion/core --provenance` — see [npm provenance](https://docs.npmjs.com/generating-provenance-statements) (binds the published package to this workflow run via OIDC).
- **Python:** `uv build` to produce wheels/sdists; **PyPI** publish uses **`pypa/gh-action-pypi-publish`** with **`id-token: write`** for [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC; no long-lived PyPI password in the workflow).
- **MCP Registry (on tags):** publisher CLI with `github-oidc` login, as configured in that job.

### `publish-integrations.yml` (integration packages)

- Per-package **`uv build`** and PyPI publish via the same **OIDC** pattern (`id-token: write`).

### `update-downloads.yml`

- Scheduled README badge refresh for download stats.

## Release and provenance summary

- **Merge gate:** every PR to **`main`** runs validation, **pytest with ≥99% coverage** on `src/mcp_bastion`, and npm workspace tests before merge.
- **Publish:** tagged releases build on GitHub Actions with **npm provenance** and **PyPI Trusted Publishing** (OIDC).
- **Artifacts:** Python wheels/sdists and npm package are produced from the same automated pipelines linked above.

## Operating guidance

1. **Keep this file in sync** with `.github/workflows/*.yml` whenever CI or publish jobs change.
2. **Provenance** — cite **npm provenance** for `@mcp-bastion/core` and **PyPI Trusted Publishing** for Python wheels when answering security questionnaires.
3. **One-line summary** — “Python and npm releases build in GitHub Actions; npm uses provenance; PyPI uses OIDC trusted publishing.”

## Related reading

- [SECURITY.md](SECURITY.md) — product security behavior and dependency notes  
- [PILLARS.md](PILLARS.md) — policy controls, `bastion.yaml`, and dashboard health rows  
