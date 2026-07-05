# Developer guide

Everything you need to develop, test, extend, and release MCP-Bastion locally.

## Repository layout

```
MCP-Bastion/
├── src/mcp_bastion/          # Core Python package (PyPI: mcp-bastion-python)
│   ├── middleware.py         # MCPBastionMiddleware pipeline
│   ├── config.py             # BastionConfig, load_config()
│   ├── cli.py                # mcp-bastion CLI entry
│   ├── pillars/              # Individual security controls (rbac, pii, …)
│   └── proxy_server.py       # serve --proxy boundary mode
├── integrations/             # 17 framework/provider packages (mcp-bastion-*)
├── packages/core/            # TypeScript @mcp-bastion/core (npm)
├── dashboard/                # FastAPI metrics UI
├── docs/                     # Documentation hub (GitHub Pages)
├── examples/                 # Runnable samples and CI snippets
├── tests/                    # pytest suite (≥92% coverage gate)
└── bastion.yaml.example      # Reference policy file
```

## Local setup

### Prerequisites

- Python 3.10+
- Node.js 22+ (for npm workspace and dashboard)
- Optional: Redis (for `state_backend` integration tests)

### Install for development

```bash
git clone https://github.com/vaquarkhan/MCP-Bastion.git
cd MCP-Bastion
pip install -e ".[dev,policy,dashboard,redis]"
npm ci
```

Verify:

```bash
mcp-bastion --version
mcp-bastion validate --config bastion.yaml.example
mcp-bastion doctor
```

### Run tests

```bash
# Full suite with coverage gate (matches CI)
pytest --cov=mcp_bastion --cov-fail-under=92

# TypeScript
npm test

# Single module
pytest tests/test_rbac.py -v
```

### Run locally

```bash
# Example MCP server with middleware
python examples/llm_server.py --http 8080

# With your bastion.yaml
mcp-bastion serve --config bastion.yaml --http 8080

# Proxy boundary mode (forwards to upstream MCP)
mcp-bastion serve --config bastion.yaml --proxy http://127.0.0.1:9000/mcp --http 8080

# Dashboard
python dashboard/app.py
```

## Working with policy

1. Copy `bastion.yaml.example` to `bastion.yaml`
2. Enable pillars incrementally ([FEATURES.md](FEATURES.md))
3. Validate: `mcp-bastion validate --config bastion.yaml`
4. Dry-run blocks: enable `shadow_mode=True` programmatically or use `policy_simulator`

Policy flows: **`bastion.yaml` → `load_config()` → `BastionConfig` → `build_middleware_from_config()`**.

## Extending a pillar

1. Add logic under `src/mcp_bastion/pillars/your_feature.py`
2. Wire config field in `config.py` / `BastionConfig`
3. Call from `middleware.py` in `_handle_call_tool` (or shared MCP surface handler)
4. Add JSON-RPC error in `errors.py` if you deny requests
5. Add tests in `tests/test_your_feature.py`
6. Document in [FEATURES.md](FEATURES.md) and [POLICY_AS_CODE.md](POLICY_AS_CODE.md)

Match existing patterns: small classes, `logger.warning` on deny, raise typed errors from `errors.py`.

## Integration packages

Each integration under `integrations/mcp-bastion-<name>/` is a separate PyPI package depending on `mcp-bastion-python`.

```bash
cd integrations/mcp-bastion-langchain
uv build
pip install -e .
```

All 17 integrations publish via the **Publish Integration Packages** workflow (tag `integration-v*` or manual dispatch).

## Docker (local)

```bash
docker build -t mcp-bastion/proxy .
docker build -f Dockerfile.dashboard -t mcp-bastion/dashboard .
docker-compose up -d
```

Prebuilt images: `ghcr.io/vaquarkhan/mcp-bastion-proxy` and `mcp-bastion-dashboard`. See [DOCKER.md](../DOCKER.md).

## Contributing checklist

Before opening a PR ([CONTRIBUTING.md](../CONTRIBUTING.md)):

1. `pytest --cov=mcp_bastion --cov-fail-under=92`
2. `npm test`
3. `mcp-bastion validate --config bastion.yaml.example` (if config loading changed)
4. One concern per PR; link related docs

## Release (maintainers)

### Version locations

| Artifact | File |
|----------|------|
| Core PyPI | `pyproject.toml` (`mcp-bastion-python`) |
| 17 integrations | `integrations/mcp-bastion-*/pyproject.toml` |
| npm | `packages/core/package.json` |
| Docker | `Dockerfile`, `Dockerfile.dashboard` (`BASTION_VERSION` ARG) |
| Docs badges | `README.md`, `docs/README.md`, `CHANGELOG.md` |

### Release steps

1. Merge to `main` with CI green
2. Bump all versions consistently (e.g. `2.0.1`)
3. Update `CHANGELOG.md`
4. Tag and push:

```bash
git tag v2.0.1
git push origin v2.0.1
```

This triggers:
- **`.github/workflows/publish-mcp.yml`** - core PyPI, npm, MCP Registry
- **`.github/workflows/publish-docker.yml`** - GHCR proxy + dashboard images

5. Publish all 17 integration packages:

```bash
git tag integration-v2.0.1
git push origin integration-v2.0.1
```

Or: GitHub Actions → **Publish Integration Packages** → `all`.

6. Verify PyPI, GHCR, and [GitHub Releases](https://github.com/vaquarkhan/MCP-Bastion/releases)

### Post-release

- Regenerate benchmark report if pillar behavior changed: `python scripts/generate_benchmark_report.py`
- Update GitHub Pages if docs changed: merge to `main` (workflow deploys `docs/site/`)

## Documentation map

| Audience | Start here |
|----------|------------|
| New user | [QUICK_START.md](QUICK_START.md) |
| Policy author | [FEATURES.md](FEATURES.md) → [RBAC.md](RBAC.md) → [POLICY_AS_CODE.md](POLICY_AS_CODE.md) |
| Production ops | [SECURITY_OBSERVABILITY.md](SECURITY_OBSERVABILITY.md) → [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md) |
| Contributor | This guide → [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Maintainer | This guide (Release section) → [CHANGELOG.md](../CHANGELOG.md) |

## Get help

- [SUPPORT.md](../SUPPORT.md) - issues and docs links
- [FUNDING.md](../FUNDING.md) - sponsorship and commercial licensing
- [SECURITY.md](../SECURITY.md) - vulnerability reporting
