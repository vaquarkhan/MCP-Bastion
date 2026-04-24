# MCP-Bastion CLI

Developer CLI for validating config, running the server, the dashboard, and operational tools.

| Command | Purpose |
|---------|---------|
| `validate` | Check `bastion.yaml` / policy |
| `serve` | Run the example MCP server with config |
| `dashboard` | Metrics UI + `/api/metrics` |
| `redteam` | Run integrated OWASP / MCP Top 10 style harness |
| `doctor` | Preflight + supply-chain style checks |

## Install

```bash
pip install mcp-bastion-python
```

Then run `mcp-bastion` (or `python -m mcp_bastion.cli` from repo).

## Commands

### validate

Validate `bastion.yaml` (or `--config PATH`):

```bash
mcp-bastion validate
mcp-bastion validate --config /path/to/bastion.yaml
```

Validate `bastion.yaml` (or `--config PATH`). Logs loaded settings and exits 0 if valid.

### serve

Run the MCP server with config. Uses `examples/llm_server.py` when run from repo:

```bash
mcp-bastion serve
mcp-bastion serve --http 8080 --host 0.0.0.0
mcp-bastion serve --config bastion.yaml --http 9000
```

### dashboard

Run the metrics dashboard:

```bash
mcp-bastion dashboard
mcp-bastion dashboard --port 7000
```

Requires: `pip install fastapi uvicorn` (or `pip install mcp-bastion-python[dashboard]`).

### redteam

Run the **integrated red-team** harness (OWASP + MCP Top 10 style cases) against your effective policy. Uses `load_config` / `build_middleware_from_config` the same as production.

```bash
mcp-bastion redteam
mcp-bastion redteam --config bastion.yaml
# Optional JSON report path:
mcp-bastion redteam --output report.json
```

See [REDTEAM.md](REDTEAM.md) for interpreting the score.

### doctor

**Preflight** checks: config validation, optional paths, and supply-chain style hints (MCP04-related).

```bash
mcp-bastion doctor
mcp-bastion doctor --config bastion.yaml
```

## Environment

- `BASTION_CONFIG` – path to config file (default `bastion.yaml`)
- `PYTHONPATH` – CLI adds repo `src` when run from repo root
