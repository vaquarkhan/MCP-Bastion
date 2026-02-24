"""
MCP-Bastion real-time dashboard and metrics API.

Run: PYTHONPATH=src python dashboard/app.py
Serves: http://localhost:7000/ (dashboard), http://localhost:7000/api/metrics (JSON)
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

logger = logging.getLogger("mcp_bastion.dashboard")

# Add src so mcp_bastion is importable
root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "src"))

try:
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
except ImportError:
    logger.error("Install: pip install fastapi uvicorn")
    sys.exit(1)

from mcp_bastion.pillars.metrics import MetricsStore

app = FastAPI(title="MCP-Bastion Dashboard")


@app.get("/api/metrics")
def get_metrics():
    try:
        return JSONResponse(MetricsStore.get().get_metrics())
    except Exception as e:
        logger.exception("Failed to get metrics: %s", e)
        return JSONResponse(
            {"error": "metrics_unavailable", "message": str(e)},
            status_code=500,
        )


@app.get("/api/health")
def health():
    try:
        return {"status": "ok"}
    except Exception as e:
        logger.exception("Health check failed: %s", e)
        return JSONResponse(
            {"status": "error", "message": str(e)},
            status_code=503,
        )


@app.get("/metrics")
def prometheus_metrics():
    """Prometheus-style metrics for Grafana/Datadog scraping."""
    try:
        m = MetricsStore.get().get_metrics()
    except Exception as e:
        logger.exception("Failed to get metrics for Prometheus: %s", e)
        return PlainTextResponse("# metrics unavailable\n", status_code=503)
    lines = [
        "# HELP mcp_bastion_requests_total Total requests",
        "# TYPE mcp_bastion_requests_total counter",
        f"mcp_bastion_requests_total {m.get('requests_total', 0)}",
        "# HELP mcp_bastion_blocked_total Blocked requests",
        "# TYPE mcp_bastion_blocked_total counter",
        f"mcp_bastion_blocked_total {m.get('blocked_total', 0)}",
        "# HELP mcp_bastion_pii_redacted_total PII redaction count",
        "# TYPE mcp_bastion_pii_redacted_total counter",
        f"mcp_bastion_pii_redacted_total {m.get('pii_redacted_total', 0)}",
        "# HELP mcp_bastion_cost_total Cost sum",
        "# TYPE mcp_bastion_cost_total gauge",
        f"mcp_bastion_cost_total {m.get('cost_total', 0)}",
    ]
    return PlainTextResponse("\n".join(lines) + "\n")


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MCP-Bastion Dashboard</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 16px; background: #0f172a; color: #e2e8f0; }
    h1 { font-size: 1.25rem; margin: 0 0 16px 0; display: flex; align-items: center; gap: 8px; }
    .badge { background: #ef4444; color: white; padding: 2px 8px; border-radius: 999px; font-size: 0.75rem; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: #1e293b; border-radius: 8px; padding: 16px; }
    .card h2 { font-size: 0.75rem; text-transform: uppercase; color: #94a3b8; margin: 0 0 8px 0; }
    .card .value { font-size: 1.5rem; font-weight: 700; }
    .row { display: flex; justify-content: space-between; margin: 4px 0; }
    .bar { height: 8px; background: #334155; border-radius: 4px; overflow: hidden; margin-top: 4px; }
    .bar fill { display: block; height: 100%; background: #3b82f6; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 8px; border-bottom: 1px solid #334155; }
    th { color: #94a3b8; font-size: 0.75rem; }
    .alerts { max-height: 200px; overflow-y: auto; }
    .alert { font-size: 0.8rem; padding: 6px; border-left: 3px solid #f59e0b; margin-bottom: 4px; background: #334155; }
  </style>
</head>
<body>
  <h1>MCP-Bastion Dashboard <span class="badge" id="alertCount">0 Alerts</span></h1>
  <div class="grid" id="summary"></div>
  <div class="grid" style="grid-template-columns: 1fr 1fr 1fr;">
    <div class="card">
      <h2>Blocked by reason</h2>
      <div id="blockedReasons"></div>
    </div>
    <div class="card">
      <h2>Top tools</h2>
      <div id="topTools"></div>
    </div>
    <div class="card">
      <h2>Cost by user</h2>
      <div id="costByUser"></div>
    </div>
  </div>
  <div class="card">
    <h2>Recent alerts</h2>
    <div class="alerts" id="alerts"></div>
  </div>
  <script>
    async function fetchMetrics() {
      const r = await fetch('/api/metrics');
      return r.json();
    }
    function render(d) {
      document.getElementById('alertCount').textContent = (d.alerts && d.alerts.length) + ' Alerts';
      const s = document.getElementById('summary');
      s.innerHTML = `
        <div class="card"><h2>Requests</h2><div class="value">${d.requests_total ?? 0}</div></div>
        <div class="card"><h2>Blocked</h2><div class="value">${d.blocked_total ?? 0} (${d.blocked_pct ?? 0}%)</div></div>
        <div class="card"><h2>PII redacted</h2><div class="value">${d.pii_redacted_total ?? 0}</div></div>
        <div class="card"><h2>Cost</h2><div class="value">$${(d.cost_total ?? 0).toFixed(2)}</div></div>
      `;
      const maxReason = Math.max(...Object.values(d.blocked_by_reason || {}), 1);
      document.getElementById('blockedReasons').innerHTML = Object.entries(d.blocked_by_reason || {}).map(([k, v]) =>
        `<div class="row"><span>${k}</span><span>${v}</span></div><div class="bar"><div style="width:${100*v/maxReason}%;height:100%;background:#3b82f6;"></div></div>`
      ).join('');
      const maxTool = Math.max(...Object.values(d.top_tools || {}), 1);
      document.getElementById('topTools').innerHTML = Object.entries(d.top_tools || {}).slice(0, 5).map(([k, v]) =>
        `<div class="row"><span>${k}</span><span>${v}</span></div><div class="bar"><div style="width:${100*v/maxTool}%;height:100%;background:#10b981;"></div></div>`
      ).join('') || '<div class="row">No data</div>';
      document.getElementById('costByUser').innerHTML = Object.entries(d.cost_by_user || {}).slice(0, 5).map(([k, v]) =>
        `<div class="row"><span>${k}</span><span>$${v.toFixed(2)}</span></div>`
      ).join('') || '<div class="row">No data</div>';
      document.getElementById('alerts').innerHTML = (d.alerts || []).slice(-8).reverse().map(a =>
        `<div class="alert">${a.kind}: ${a.message}</div>`
      ).join('') || '<div>No alerts</div>';
    }
    (async function poll() {
      try { render(await fetchMetrics()); } catch (e) { console.error(e); }
      setTimeout(poll, 2000);
    })();
  </script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(DASHBOARD_HTML)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7000)
