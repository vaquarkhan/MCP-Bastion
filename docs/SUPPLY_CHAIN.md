# Supply chain, releases, and provenance

This page is for **operators and security reviewers**: how MCP-Bastion **builds and publishes** artifacts today, and how to describe that accurately in questionnaires and release notes. Verifiable facts (GitHub Actions, npm provenance, PyPI Trusted Publishing) usually read stronger than generic “enterprise-grade supply chain” labels.

## What GitHub Actions does today

Workflows live under [`.github/workflows/`](../.github/workflows/). Highlights:

### `ci.yml` (pull requests and `main`)

- **Python:** `pip install -e ".[dev,policy,dashboard]"`, then `mcp-bastion validate --config bastion.yaml.example`, then **`python -m pytest --cov=mcp_bastion --cov-fail-under=92`** (see `[tool.coverage.*]` in `pyproject.toml`).
- **TypeScript:** `npm ci` and **`npm test`** (workspace packages).

### `publish-mcp.yml` (main package: PyPI + npm + MCP Registry)

- **Checkout** of the ref that triggered the run (`actions/checkout@v4`).
- **TypeScript (monorepo):** `npm ci`, `npm run build`, `npm run test` (workspace tests).
- **npm release (on version tags):** Prefer OIDC Trusted Publishing with `--provenance`. If `@mcp-bastion/core` does not exist yet, a one-time **`NPM_TOKEN`** bootstrap is required - see [PUBLISHING_NPM_AND_REGISTRY.md](PUBLISHING_NPM_AND_REGISTRY.md).
- **Python:** `uv build` to produce wheels/sdists; **PyPI** publish uses **`pypa/gh-action-pypi-publish`** with **`id-token: write`** for [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC; no long-lived PyPI password in the workflow).
- **MCP Registry (on tags):** `mcp-publisher` **v1.7.9+** with `github-oidc` login (correct OIDC audience for production registry).

### `publish-integrations.yml` (integration packages)

- Per-package **`uv build`** and PyPI publish via the same **OIDC** pattern (`id-token: write`).
- Trigger: push tag **`integration-v*`** (see workflow conditions) or **Actions → “Publish Integration Packages” → Run workflow** and choose a **single** package (recommended) or `all` (matrix runs all jobs in parallel).

## PyPI publish order (do not skip)

Integration packages in `integrations/*/pyproject.toml` depend on **`mcp-bastion-python>=...`**. If you publish an integration **before** that version of the core package exists on PyPI, **installs can fail** (`ResolutionImpossible` / “No matching distribution”).

**Recommended order:**

1. **Merge** your release branch to the branch you tag from (usually `main`) so `pyproject.toml` at the repo root matches the version you are shipping (e.g. `2.0.0`).
2. **Tag the monorepo** with **`v2.0.0`** (same version as [pyproject.toml](../pyproject.toml) `version`) and **push the tag**  -  this runs [`.github/workflows/publish-mcp.yml`](../.github/workflows/publish-mcp.yml) and publishes **`mcp-bastion-python`** (and npm `@mcp-bastion/core` when the job succeeds, plus MCP registry steps if configured).
3. **Wait** until [PyPI](https://pypi.org/project/mcp-bastion-python/#history) shows the new **`mcp-bastion-python`** release (and fix any failed workflow before continuing).
4. **Publish each integration on PyPI one at a time**  -  use **Run workflow** on **`publish-integrations.yml`**, set **package** to e.g. `mcp-bastion-openai`, then repeat for `mcp-bastion-langchain`, `mcp-bastion-fastmcp`, etc. Avoid choosing **`all`** for the first time after a core bump if you want easier failure triage; the matrix is **parallel** and does not depend on each other, but a missing core wheel still breaks every integration’s install.
5. If you need a new **integration** package version, bump `version` in that integration’s `pyproject.toml`, merge, then run the integration workflow (or use an `integration-v*` tag if your process uses it).

**Local one-off (if you do not use Actions):** from repo root, `uv build` then upload only under `src/` for the main package; for integrations, `cd integrations/<name>` and `uv build` / `twine upload`  -  still **after** the matching `mcp-bastion-python` is on PyPI.

## Release and provenance summary

- **Merge gate:** every PR to **`main`** runs validation, **pytest with ≥92% coverage** on `src/mcp_bastion`, and npm workspace tests before merge.
- **Publish:** tagged releases build on GitHub Actions with **npm provenance** and **PyPI Trusted Publishing** (OIDC).
- **Artifacts:** Python wheels/sdists and npm package are produced from the same automated pipelines linked above.

## Operating guidance

1. **Keep this file in sync** with `.github/workflows/*.yml` whenever CI or publish jobs change.
2. **Provenance** - cite **npm provenance** for `@mcp-bastion/core` and **PyPI Trusted Publishing** for Python wheels when answering security questionnaires.
3. **One-line summary** - "Python and npm releases build in GitHub Actions; npm uses provenance; PyPI uses OIDC trusted publishing; CycloneDX SBOMs upload as release-workflow artifacts."

## Software Bill of Materials (CycloneDX)

For **CRA / OpenSSF** supply-chain transparency, release workflows generate CycloneDX **1.5** JSON without adding runtime dependencies:

| Workflow | Outputs | Notes |
|----------|---------|--------|
| `publish-mcp.yml` | `bom.json`, `bom-npm.json` | After `uv build`; `continue-on-error` (fail-safe) |
| `publish-docker.yml` | `bom.json` | Before image push; fail-safe |

Local generation:

```bash
python scripts/generate_sbom.py --output bom.json
python scripts/generate_sbom.py --npm packages/core/package.json --output bom-npm.json
```

Docs: [CRA_COMPLIANCE.md](CRA_COMPLIANCE.md) · tutorial [CRA_SBOM_TUTORIAL.md](CRA_SBOM_TUTORIAL.md) · diagram `images/mcp-bastion-cra-sbom.svg`.

## Sigstore-signed container images

`publish-docker.yml` uses **keyless Cosign** (GitHub OIDC → Sigstore) after pushing GHCR images:

```bash
# Verify a release tag image (example)
cosign verify \
  --certificate-identity-regexp 'https://github.com/vaquarkhan/MCP-Bastion/.github/workflows/publish-docker.yml@.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/vaquarkhan/mcp-bastion-proxy:v5.0.0
```

PyPI/npm continue to use **Trusted Publishing / npm provenance** (OIDC). Session `mcp-bastion attest export` is **runtime governance evidence**, not release SLSA.

## Related reading

- [THREAT_MODEL.md](THREAT_MODEL.md) - public threat model  
- [BASTION_AND_TEST_HARNESS.md](BASTION_AND_TEST_HARNESS.md) - CI pairing with MCP Test Harness  
- [SECURITY.md](SECURITY.md) - product security behavior and dependency notes  
- [../SECURITY.md](../SECURITY.md) - vulnerability disclosure + CRA Article 14  
- [PILLARS.md](PILLARS.md) - policy controls, `bastion.yaml`, and dashboard health rows  
