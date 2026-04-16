# MCP-Bastion Dashboard

Real-time dashboard and metrics API for MCP-Bastion.

## Run

```bash
cd MCP-Bastion
pip install fastapi uvicorn
PYTHONPATH=src python dashboard/app.py
```

Open [http://localhost:7000/](http://localhost:7000/)

**If you see `{"detail":"Not Found"}`** on some URL, that response is from *a* FastAPI app, but not our route — wrong path, wrong port, or another process. Try [http://localhost:7000/api/health](http://localhost:7000/api/health) first: it must include `"service":"mcp-bastion-dashboard"` and `"ui_revision"`. Short diagnostic: [http://localhost:7000/meta](http://localhost:7000/meta).

**If the UI looks like an old version** (plain bars, title “MCP-Bastion Dashboard” in one line): stop the server, `cd` to the **repository root** (the folder that contains `dashboard/`), then run `mcp-bastion dashboard` or `PYTHONPATH=src python dashboard/app.py`. Check `/api/health` or `/meta` — `ui_revision` should be `v2-chartjs-dmsans` and `dashboard_app_py` should point at this repo’s `dashboard/app.py`.

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
