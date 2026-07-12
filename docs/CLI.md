# MCP-Bastion CLI

Developer CLI for validating config, running the server, the dashboard, and operational tools.

| Command | Purpose |
|---------|---------|
| **`scan`** | Static scan of MCP tool definitions (pre-deploy poisoning / drift / schema) + optional `--skills` |
| **`audit`** | Local MCP risk audit (client configs, over-broad tools, credential smells) |
| **`osv-refresh`** | Download local OSV vulnerability dump (opt-in) |
| **`osv-scan`** | Offline-first dependency CVE lookup (optional `--online`) |
| `validate` | Check `bastion.yaml` / policy |
| `serve` | Run the example MCP server with config |
| `dashboard` | Metrics UI + `/api/metrics` |
| `redteam` | Run integrated OWASP / MCP Top 10 style harness |
| `doctor` | Preflight + supply-chain style checks |
| `attest export` | Export signed governance attestation for a session |
| `report` | Generate compliance evidence report from audit JSONL |
| `tail` | Tail append-only audit JSONL |

## Install

```bash
pip install mcp-bastion-python
```

Then run `mcp-bastion` (or `python -m mcp_bastion.cli` from repo).

### scan

Static scan of MCP **tool definitions** before deploy. Client-side only — reuses Bastion `content_filter`, injection heuristics, and `tool_metadata_fingerprint`. No ML download, no cloud.

```bash
# Scan a tools/list export or hand-authored catalog
mcp-bastion scan examples/fixtures/tools-poisoned.json

# Baseline drift detection (pair with fingerprint)
mcp-bastion fingerprint tools.json -o baseline.json
mcp-bastion scan tools.json --baseline baseline.json

# CI-friendly JSON + non-failing report
mcp-bastion scan tools.json --format json -o report.json --fail-on none

# Skill files (opt-in; SKILL.md / *.skill.md under a directory)
mcp-bastion scan --skills ./skills/
```

Checks: prompt-injection patterns in descriptions/schemas, credential-like material, code-exec patterns, homoglyph tool-name pairs, hidden Unicode, optional fingerprint drift, and **structural inputSchema preconditions** (unbounded strings, free-form objects, unconstrained numerics). Schema checks are on by default within `scan`; disable with `--no-schema-checks`. Letter grade **A-F** in output. Exit **1** when findings meet `--fail-on` (default `high`).

Sample fixtures: `examples/fixtures/tools-clean.json`, `tools-poisoned.json`.

### osv-refresh / osv-scan

Offline-first dependency CVE lookup via a local OSV dump. Network is opt-in only.

```bash
# User-run refresh (downloads ecosystem zip into .osv/)
mcp-bastion osv-refresh --ecosystem PyPI --dir .osv

# Scan requirements-style pins (local DB only by default)
mcp-bastion osv-scan requirements-lock.txt
mcp-bastion osv-scan -p demo-pkg==1.0.0 --dir .osv

# Opt-in online querybatch (fail-open; package name+version only)
mcp-bastion osv-scan -p demo-pkg==1.0.0 --online --timeout-ms 3000
```

### audit

Local **MCP surface** risk audit - maps what client configs grant before you enforce policy. Client-side only: discovers MCP client JSON configs, over-broad tool grants (`*`), standing credential smells in `env` / headers, and filesystem-server hints. No network, no vault, no login server.

```bash
# Scan cwd (and common user MCP config locations)
mcp-bastion audit

# Project root + explicit config path
mcp-bastion audit --root . --config .cursor/mcp.json

# CI-friendly JSON (always exit 0)
mcp-bastion audit --format json -o risk-audit.json --fail-on none
```

Letter grade **A-F**. Exit **1** when findings meet `--fail-on` (default `high`). Pair with `examples/bastion-filesystem-guards.yaml` when agents can reach local files.

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

# Boundary mode: same bastion.yaml, forward to upstream MCP (loopback only)
mcp-bastion serve --proxy http://127.0.0.1:9000/mcp --http 8080 --config bastion.yaml
```

### dashboard

Run the metrics dashboard:

```bash
mcp-bastion dashboard
mcp-bastion dashboard --port 7000
mcp-bastion dashboard --port 7000 --demo
```

Requires: `pip install fastapi uvicorn` (or `pip install mcp-bastion-python[dashboard]`).

**`--demo`** seeds sample metrics + posture findings so the UI is populated without live traffic. Posture / prevalidate panels also read `.bastion/scan/*.json` when present. See [dashboard/README.md](../dashboard/README.md).

### redteam

Run the **integrated red-team** harness (OWASP + MCP Top 10 style cases) against your effective policy. Uses `load_config` / `build_middleware_from_config` the same as production.

```bash
mcp-bastion redteam
mcp-bastion redteam --config bastion.yaml
# Optional JSON report path:
mcp-bastion redteam --output report.json
```

See [REDTEAM.md](REDTEAM.md) for interpreting the score.

### attest export

Export a **governance attestation** JSON bundle for an agent session (policy hash, pillars fired, blocked/allowed events, audit chain head):

```bash
mcp-bastion attest export --session SESSION_ID
mcp-bastion attest export --session SESSION_ID --config bastion.yaml --sign
mcp-bastion attest export --session SESSION_ID -o attestation.json
```

Signing uses `BASTION_MANIFEST_SIGNING_KEY` (same key as `manifest --sign`).

### tail

Tail the append-only audit JSONL sink:

```bash
mcp-bastion tail --path .bastion/audit.jsonl
mcp-bastion tail --config bastion.yaml -n 50
```

### report

Generate a **compliance evidence** markdown report from audit JSONL. Maps pillar activity to framework controls (evidence only, not certification).

```bash
mcp-bastion report --framework soc2 --audit .bastion/audit.jsonl
mcp-bastion report --framework iso27001 --audit audit.jsonl -o report.md
mcp-bastion report --framework gdpr --audit audit.jsonl --from 2026-01-01 --to 2026-12-31
```

Framework keys: `soc2`, `iso27001`, `gdpr`, `nist_ai_rmf`. See [ENTERPRISE_RUNTIME_CONTROLS.md](ENTERPRISE_RUNTIME_CONTROLS.md).

### doctor

**Preflight** checks: config validation, optional paths, and supply-chain style hints (MCP04-related).

```bash
mcp-bastion doctor
mcp-bastion doctor --config bastion.yaml
```

## Environment

- `BASTION_CONFIG` – path to config file (default `bastion.yaml`)
- `PYTHONPATH` – CLI adds repo `src` when run from repo root
