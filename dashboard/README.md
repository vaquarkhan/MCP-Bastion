# MCP-Bastion Dashboard

Real-time dashboard and metrics API for MCP-Bastion.

## Run

```bash
cd MCP-Bastion
pip install fastapi uvicorn
# With demo metrics (charts non-zero without an MCP server feeding the store):
MCP_BASTION_DEMO=1 PYTHONPATH=src python dashboard/app.py
# Windows PowerShell:
#   $env:MCP_BASTION_DEMO="1"; $env:PYTHONPATH="src"; python dashboard/app.py
# or CLI:
mcp-bastion dashboard --demo
# Plain dashboard (zeros until your MCP process records metrics):
PYTHONPATH=src python dashboard/app.py
mcp-bastion dashboard
# while editing dashboard/app.py, auto-reload:
mcp-bastion dashboard --reload --demo
# same as: set MCP_BASTION_DASHBOARD_RELOAD=1
```

Richer scripted demo (same seed + optional live background traffic): `PYTHONPATH=src python examples/dashboard_demo.py`

Open [http://localhost:7000/](http://localhost:7000/) — the UI shows a **KPI summary strip** (totals, block %, top threat, active users) and loading guidance while metrics connect; **PII** charts use **severity-style** colors for entity types, and long **block reasons** are readable via tooltips / expand-in-place where applicable.

**If you see `{"detail":"Not Found"}`** on some URL, that response is from *a* FastAPI app, but not our route — wrong path, wrong port, or another process. Try [http://localhost:7000/api/health](http://localhost:7000/api/health) first: it must include `"service":"mcp-bastion-dashboard"` and `"ui_revision"`. Short diagnostic: [http://localhost:7000/meta](http://localhost:7000/meta).

**If the UI looks unchanged after editing `dashboard/app.py`:** the server only loads HTML at startup. Stop the process and start again, **or** run `mcp-bastion dashboard --reload` so `dashboard/` is watched. Always run from the **repository root** (the folder that contains `dashboard/`). Check `/meta` — `dashboard_app_py` must point at this repo’s `dashboard/app.py`, and `ui_revision` should match the current code (for example `v9-demo-seed-theme`).

**If charts show all zeros:** the in-memory store is empty until middleware records traffic. Use **`mcp-bastion dashboard --demo`** or **`MCP_BASTION_DEMO=1`** to load the same rich seed as `examples/dashboard_demo.py`, or run the full `examples/dashboard_demo.py` process.

## Endpoints

| URL | What it returns |
|-----|-----------------|
| GET / | Visual dashboard with charts |
| GET /api/metrics | JSON: `requests_total`, `blocked_total`, `blocked_pct`, `blocked_by_reason`, `top_tools`, `cost_by_user`, `alerts`, plus `time_series` (rolling allowed/blocked per bucket), `time_series_bucket_seconds`, `time_series_window_seconds` |
| GET /api/health | `{"status":"ok","service":"mcp-bastion-dashboard","ui_revision":...}` |
| GET /api/dashboard-meta | Same build info as health |
| GET /meta | Same JSON (short URL) |
| GET /metrics | Prometheus text format (Grafana/Datadog) |

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
