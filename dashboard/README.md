# MCP-Bastion Dashboard

Real-time dashboard and metrics API for MCP-Bastion.

## Run

```bash
cd MCP-Bastion
pip install fastapi uvicorn
PYTHONPATH=src python dashboard/app.py
```

Open http://localhost:7000/

## Endpoints

| Endpoint | Description |
|----------|-------------|
| GET / | Dashboard UI |
| GET /api/metrics | JSON metrics |
| GET /metrics | Prometheus format (Grafana/Datadog) |
| GET /api/health | Health check |

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
