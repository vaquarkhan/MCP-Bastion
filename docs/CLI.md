# MCP-Bastion CLI

Developer CLI for validating config, running the server, and the dashboard.

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

## Environment

- `BASTION_CONFIG` – path to config file (default `bastion.yaml`)
- `PYTHONPATH` – CLI adds repo `src` when run from repo root
