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

The dashboard UI includes tenant filtering (stored in the browser), FinOps charts (provider/model), tamper-evident audit chain summary, and forensics drill-down.

### redteam

Run the integrated red-team suite against your loaded `bastion.yaml` and emit a JSON report (OWASP LLM Top 10-style tags):

```bash
mcp-bastion redteam --config bastion.yaml
mcp-bastion redteam -c bastion.yaml -o redteam-report.json
```

Exit code `0` when the command completes; inspect `score_blocked_pct` and per-case rows in the report.

## Environment

- `BASTION_CONFIG`: path to config file (default `bastion.yaml`)
- `PYTHONPATH`: CLI adds repo `src` when run from repo root
