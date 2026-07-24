# Tutorial: CycloneDX SBOM for CRA / OpenSSF

Generate and consume MCP-Bastion Software Bills of Materials without changing runtime middleware behavior.

## Prerequisites

- Python 3.10+ (stdlib only; no extra packages required for the generator)
- Repo checkout at the version you care about (tag `v3.3.0`, `main`, etc.)

## Step 1 - Generate the Python SBOM

From the repository root:

```bash
python scripts/generate_sbom.py --pyproject pyproject.toml --output bom.json
```

Expected console line:

```text
Wrote CycloneDX SBOM: .../bom.json
```

Open `bom.json` and confirm:

- `bomFormat` is `CycloneDX`
- `specVersion` is `1.5`
- `metadata.component.name` is `mcp-bastion-python`
- `components` lists declared runtime dependencies from `pyproject.toml`

## Step 2 - Generate the npm SBOM (optional)

```bash
python scripts/generate_sbom.py --npm packages/core/package.json --output bom-npm.json
```

Use this when answering questionnaires that ask for the TypeScript package graph (`@mcp-bastion/core`).

## Step 3 - Validate shape in CI / tests

The unit suite covers the generator:

```bash
python -m pytest tests/test_generate_sbom.py -q
```

## Step 4 - Find release artifacts

On tagged releases, GitHub Actions uploads SBOM artifacts from:

- **Build, Test, and Publish MCP-Bastion** (`publish-mcp.yml`) - `bom.json` + `bom-npm.json`
- **Publish Docker (GHCR)** (`publish-docker.yml`) - `bom.json`

Download from the workflow run **Artifacts** panel. SBOM steps are **fail-safe** (`continue-on-error`): a generator failure never blocks PyPI or GHCR publish.

## Step 5 - Point auditors at disclosure + SBOM

1. Vulnerability process: [SECURITY.md](../SECURITY.md) (includes CRA Article 14 section)
2. Supply-chain map: [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)
3. Architecture posture: [CRA_COMPLIANCE.md](CRA_COMPLIANCE.md)

Downstream manufacturers can attach these SBOMs to their own Technical Documentation packages; Bastion does not claim CE marking for third-party PDEs.

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `generate_sbom failed: ...` | Ensure `pyproject.toml` / `package.json` path exists and is UTF-8 |
| Empty `components` | Check `[project].dependencies` (or `dependencies` in package.json) |
| Want deterministic serial | Pass `--serial urn:uuid:...` (used by tests) |

## Related

- [CRA_COMPLIANCE.md](CRA_COMPLIANCE.md)
- [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)
- [CLI.md](CLI.md) (`attest export` for session evidence)
