# MCP-Bastion Dashboard

Real-time **command-center** UI and JSON APIs for MCP-Bastion: security KPIs, FinOps attribution, tamper-evident audit chain, multi-tenant drill-down, forensics, and policy shadow simulation.

## Run

```bash
cd MCP-Bastion
pip install fastapi uvicorn mcp-bastion-python
python dashboard/app.py
```

From a development checkout you can instead use `PYTHONPATH=src` and omit the wheel if `mcp_bastion` is importable from `./src`.

Open [http://localhost:7000/](http://localhost:7000/)

**Product hero image:** the UI references `/images/mcp-bastian.png`. The FastAPI app mounts the repository `images/` directory at `/images` when that folder exists (clone includes `images/mcp-bastian.png`).

**If you see `{"detail":"Not Found"}`** on some URL, that response is from *a* FastAPI app, but not our route (wrong path, wrong port, or another process). Try [http://localhost:7000/api/health](http://localhost:7000/api/health) first: it must include `"service":"mcp-bastion-dashboard"` and `"ui_revision"`. Short diagnostic: [http://localhost:7000/meta](http://localhost:7000/meta).

**If the UI looks outdated:** stop the server, `cd` to the **repository root** (the folder that contains `dashboard/` and `images/`), then run `mcp-bastion dashboard` or `PYTHONPATH=src python dashboard/app.py`. Check `/meta`: `ui_revision` should be `v5-command-center-tenant-finops-audit`.

## UI highlights (v5+)

- Hero strip with product art and short product tagline
- **Tenant toolbar:** filter metrics and blocked forensics; preference stored in `localStorage` (`mcp-bastion-tenant`)
- **Audit chain** card: live `head_hash` / `chain_length` from in-memory chain
- **FinOps:** top providers table plus **Cost by LLM provider** and **Cost by model** bar charts (`cost_attribution`)
- **Tenant chips:** quick jump filter from `tenants` aggregate map
- Existing: pillar health, latency percentiles, cost burn, traffic sparkline, blocked reasons, tool drill-down, **live forensics** (trace and replay JSON), auto-tune anomalies, alerts

## HTTP endpoints

| Method | URL | Description |
|--------|-----|-------------|
| GET | `/` | Single-page dashboard (Chart.js, dark/light theme) |
| GET | `/api/metrics` | Full metrics JSON (`tenants`, `cost_attribution`, `audit_chain`, `auto_tune`, `forensic_recent_blocked`, …) |
| GET | `/api/metrics?tenant_id=acme` | Same payload plus `tenant_view` for that tenant |
| GET | `/api/forensics` | Blocked (default) or all events; supports `tenant_id`, `limit`, `blocked_only` |
| GET | `/api/forensics/{event_id}` | Full forensic row (includes hash-chain fields when audit export ran) |
| GET | `/api/forensics/{event_id}/replay` | Replay payload for debugging |
| POST | `/api/audit/verify` | Body `{ "events": [ ... ] }` → `{ "valid": bool, "errors": [...] }` |
| POST | `/api/policy/simulate` | Shadow-run candidate `bastion.yaml` overrides against recent forensics |
| GET | `/api/health` | `{ "status":"ok", ... build info }` |
| GET | `/api/dashboard-meta` | Same as health meta |
| GET | `/meta` | Short alias for meta JSON |
| GET | `/metrics` | Prometheus text exposition |

## Wire metrics from your server

Use `AuditLogMiddleware` with an export callback that updates the metrics store:

```python
from mcp_bastion import AuditLogMiddleware, compose_middleware
from mcp_bastion.pillars import make_audit_export_callback, MetricsStore, SlackAlertSink

sinks = []
if os.environ.get("SLACK_WEBHOOK_URL"):
    sinks.append(SlackAlertSink(os.environ["SLACK_WEBHOOK_URL"]))

audit = AuditLogMiddleware(export_callback=make_audit_export_callback(
    alert_sinks=sinks,
    alert_on={"injection", "rate_limit", "cost"},
))
middleware = compose_middleware(audit, bastion, ...)
```

Run the dashboard in another process to see live metrics.
