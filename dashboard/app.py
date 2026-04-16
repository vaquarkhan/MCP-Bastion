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
    from fastapi.staticfiles import StaticFiles
except ImportError:
    logger.error("Install: pip install fastapi uvicorn")
    sys.exit(1)

from mcp_bastion.pillars.metrics import MetricsStore

app = FastAPI(title="MCP-Bastion Dashboard")

_static_dir = Path(__file__).resolve().parent / "static"
if _static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")


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


def _dashboard_build_info() -> dict:
    here = Path(__file__).resolve()
    return {
        "service": "mcp-bastion-dashboard",
        "dashboard_app_py": str(here),
        "ui_revision": "v4-pillar-health-tool-drilldown",
        "hint": "If this is missing, you are not hitting dashboard/app.py — check port and process.",
    }


@app.get("/api/health")
def health():
    try:
        return {"status": "ok", **_dashboard_build_info()}
    except Exception as e:
        logger.exception("Health check failed: %s", e)
        return JSONResponse(
            {"status": "error", "message": str(e)},
            status_code=503,
        )


@app.get("/api/dashboard-meta")
def dashboard_meta():
    """Which dashboard code is running (use this if the UI looks outdated)."""
    return _dashboard_build_info()


@app.get("/meta")
def meta_short():
    """Short URL — same payload as /api/dashboard-meta (easier to type)."""
    return _dashboard_build_info()


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
  <meta name="color-scheme" content="dark light">
  <title>MCP-Bastion Dashboard</title>
  <script>
    (function () {
      var t = localStorage.getItem("mcp-bastion-theme");
      document.documentElement.setAttribute("data-theme", t === "light" ? "light" : "dark");
    })();
  </script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,600;0,9..40,700;1,9..40,400&display=swap" rel="stylesheet">
  <!-- Local Chart.js (same-origin); CDN fallback if /static missing -->
  <script src="/static/chart.umd.min.js" onerror="this.onerror=null;this.src='https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js'"></script>
  <style>
    :root {
      --bg0: #0c1222;
      --bg1: #111827;
      --card: rgba(30, 41, 59, 0.72);
      --card-border: rgba(148, 163, 184, 0.12);
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --ok: #34d399;
      --bad: #fb7185;
      --warn: #fbbf24;
    }
    * { box-sizing: border-box; }
    body {
      font-family: "DM Sans", system-ui, sans-serif;
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background:
        radial-gradient(ellipse 120% 80% at 50% -30%, rgba(56, 189, 248, 0.12), transparent 50%),
        radial-gradient(ellipse 80% 50% at 100% 50%, rgba(167, 139, 250, 0.06), transparent),
        linear-gradient(165deg, var(--bg0) 0%, #0f172a 40%, var(--bg1) 100%);
      padding: 20px 24px 40px;
    }
    .header {
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      justify-content: space-between;
      gap: 12px;
      margin-bottom: 24px;
    }
    .header h1 {
      font-size: 1.5rem;
      font-weight: 700;
      margin: 0;
      letter-spacing: -0.02em;
      background: linear-gradient(135deg, #f8fafc 0%, #94a3b8 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .header p { margin: 4px 0 0; font-size: 0.85rem; color: var(--muted); }
    .badge {
      background: linear-gradient(135deg, #f43f5e, #ec4899);
      color: white;
      padding: 6px 14px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      box-shadow: 0 4px 14px rgba(244, 63, 94, 0.35);
    }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 14px;
      margin-bottom: 20px;
    }
    .kpi {
      position: relative;
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 18px 18px 16px;
      overflow: hidden;
      backdrop-filter: blur(12px);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.25);
    }
    .kpi::before {
      content: "";
      position: absolute;
      left: 0; top: 0; bottom: 0;
      width: 4px;
      border-radius: 14px 0 0 14px;
    }
    .kpi.req::before { background: linear-gradient(180deg, #38bdf8, #2563eb); }
    .kpi.block::before { background: linear-gradient(180deg, #fb7185, #e11d48); }
    .kpi.pii::before { background: linear-gradient(180deg, #2dd4bf, #0d9488); }
    .kpi.cost::before { background: linear-gradient(180deg, #fbbf24, #d97706); }
    .kpi h2 {
      font-size: 0.7rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin: 0 0 6px 0;
      font-weight: 600;
    }
    .kpi .value {
      font-size: 1.65rem;
      font-weight: 700;
      letter-spacing: -0.03em;
      font-variant-numeric: tabular-nums;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 18px;
      margin-bottom: 18px;
      backdrop-filter: blur(12px);
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.2);
    }
    .card h2 {
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--muted);
      margin: 0 0 14px 0;
      font-weight: 600;
    }
    .chart-wrap { position: relative; height: 240px; width: 100%; }
    .chart-wrap.sm { height: 200px; }
    .charts-row {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 18px;
      margin-bottom: 18px;
    }
    @media (max-width: 1100px) { .charts-row { grid-template-columns: 1fr; } }
    .alerts {
      max-height: 220px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .alert {
      font-size: 0.8rem;
      padding: 10px 12px;
      border-radius: 10px;
      border-left: 4px solid var(--warn);
      background: rgba(51, 65, 85, 0.6);
      color: #e2e8f0;
    }
    .alert.critical { border-left-color: #f43f5e; }
    .dash-footer {
      text-align: center;
      margin-top: 28px;
      padding: 12px;
      font-size: 0.75rem;
      color: var(--muted);
      border-top: 1px solid var(--card-border);
    }
    .dash-footer strong { color: #38bdf8; }
    html[data-theme="light"] {
      --bg0: #f1f5f9;
      --bg1: #e2e8f0;
      --card: rgba(255, 255, 255, 0.94);
      --card-border: rgba(100, 116, 139, 0.22);
      --text: #0f172a;
      --muted: #64748b;
    }
    html[data-theme="light"] body {
      background:
        radial-gradient(ellipse 120% 80% at 50% -25%, rgba(56, 189, 248, 0.1), transparent 48%),
        radial-gradient(ellipse 70% 50% at 100% 30%, rgba(167, 139, 250, 0.06), transparent),
        linear-gradient(165deg, #f8fafc 0%, #e2e8f0 100%);
    }
    html[data-theme="light"] .header h1 {
      background: linear-gradient(135deg, #0f172a 0%, #475569 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    html[data-theme="light"] .kpi {
      box-shadow: 0 4px 24px rgba(15, 23, 42, 0.06);
    }
    html[data-theme="light"] .card {
      box-shadow: 0 4px 24px rgba(15, 23, 42, 0.06);
    }
    html[data-theme="light"] .alert {
      background: rgba(241, 245, 249, 0.95);
      color: var(--text);
      border: 1px solid var(--card-border);
      border-left-width: 4px;
    }
    html[data-theme="light"] .dash-footer strong { color: #0284c7; }
    .header-right {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
    }
    .theme-toggle {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--card);
      border: 1px solid var(--card-border);
      color: var(--text);
      border-radius: 10px;
      padding: 8px 14px;
      cursor: pointer;
      font-family: inherit;
      font-size: 0.85rem;
      font-weight: 600;
      box-shadow: 0 2px 12px rgba(0, 0, 0, 0.12);
    }
    .theme-toggle:hover {
      border-color: var(--accent);
      color: var(--accent);
    }
    html[data-theme="light"] .theme-toggle:hover {
      color: #0284c7;
      border-color: #38bdf8;
    }
    .latency-row {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
      font-variant-numeric: tabular-nums;
    }
    .latency-row .lab { display: block; font-size: 0.65rem; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }
    .latency-row .num { font-size: 1.25rem; font-weight: 700; }
    .burn-text { font-size: 0.95rem; line-height: 1.6; color: var(--text); }
    .burn-text .muted { color: var(--muted); font-size: 0.8rem; }
    span.muted { color: var(--muted); font-size: 0.85rem; }
    p.muted { color: var(--muted); }
    .pillar-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 10px;
      margin-bottom: 18px;
    }
    .pillar {
      border: 1px solid var(--card-border);
      background: rgba(15, 23, 42, 0.24);
      border-radius: 10px;
      padding: 10px 12px;
    }
    html[data-theme="light"] .pillar {
      background: rgba(241, 245, 249, 0.82);
    }
    .pillar .name {
      font-size: 0.75rem;
      font-weight: 700;
      margin-bottom: 6px;
      letter-spacing: 0.01em;
    }
    .pill {
      display: inline-block;
      border-radius: 999px;
      font-size: 0.62rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      font-weight: 700;
      padding: 3px 8px;
      margin-bottom: 6px;
    }
    .pill.healthy { background: rgba(52, 211, 153, 0.2); color: #86efac; border: 1px solid rgba(52, 211, 153, 0.35); }
    .pill.active { background: rgba(251, 191, 36, 0.2); color: #fde68a; border: 1px solid rgba(251, 191, 36, 0.35); }
    .pill.idle { background: rgba(148, 163, 184, 0.2); color: #cbd5e1; border: 1px solid rgba(148, 163, 184, 0.35); }
    html[data-theme="light"] .pill.healthy { color: #065f46; }
    html[data-theme="light"] .pill.active { color: #92400e; }
    html[data-theme="light"] .pill.idle { color: #334155; }
    .pillar .detail {
      font-size: 0.73rem;
      color: var(--muted);
      line-height: 1.35;
    }
    .tool-table-wrap {
      overflow-x: auto;
      margin-top: 6px;
    }
    table.tool-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.8rem;
      font-variant-numeric: tabular-nums;
    }
    .tool-table th, .tool-table td {
      text-align: left;
      padding: 8px 10px;
      border-bottom: 1px solid var(--card-border);
      white-space: nowrap;
    }
    .tool-table th {
      color: var(--muted);
      font-size: 0.67rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    .tool-table td:last-child {
      max-width: 260px;
      overflow: hidden;
      text-overflow: ellipsis;
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1>MCP-Bastion</h1>
      <p>Live security &amp; FinOps · refreshes every 2s</p>
    </div>
    <div class="header-right">
      <button type="button" class="theme-toggle" id="themeToggle" aria-label="Toggle color theme">Light</button>
      <span class="badge" id="alertCount">0 Alerts</span>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi req"><h2>Requests</h2><div class="value" id="kpiReq">0</div></div>
    <div class="kpi block"><h2>Blocked</h2><div class="value" id="kpiBlocked">0</div></div>
    <div class="kpi pii"><h2>PII redacted</h2><div class="value" id="kpiPii">0</div></div>
    <div class="kpi cost"><h2>Cost</h2><div class="value" id="kpiCost">$0.00</div></div>
  </div>

  <div class="card">
    <h2>Pillar health</h2>
    <div id="pillarHealth" class="pillar-grid"></div>
  </div>

  <div class="charts-row" style="grid-template-columns: 1fr 1fr; margin-bottom: 18px;">
    <div class="card" style="margin-bottom:0;">
      <h2>Latency (middleware)</h2>
      <div class="latency-row" id="latencyStats">
        <div><span class="lab">P50</span><span class="num" id="latP50">0</span> <span class="muted">ms</span></div>
        <div><span class="lab">P95</span><span class="num" id="latP95">0</span> <span class="muted">ms</span></div>
        <div><span class="lab">P99</span><span class="num" id="latP99">0</span> <span class="muted">ms</span></div>
      </div>
      <p class="muted" style="margin:10px 0 0;font-size:0.75rem;" id="latSamples">0 samples</p>
    </div>
    <div class="card" style="margin-bottom:0;">
      <h2>Cost burn</h2>
      <div id="costBurn" class="burn-text">$0.00 / hr projected · $0.00 / day</div>
      <p class="muted" style="margin:8px 0 0;font-size:0.75rem;" id="burnWindow">Window elapsed: 0s</p>
    </div>
  </div>

  <div class="card">
    <h2>Traffic · last <span id="tsWindow">10 min</span> · <span id="tsBucket">30s</span> buckets</h2>
    <div class="chart-wrap"><canvas id="chartTraffic"></canvas></div>
  </div>

  <div class="charts-row">
    <div class="card" style="margin-bottom:0;">
      <h2>Blocked by reason</h2>
      <div class="chart-wrap sm"><canvas id="chartReasons"></canvas></div>
    </div>
    <div class="card" style="margin-bottom:0;">
      <h2>Top tools</h2>
      <div class="chart-wrap sm"><canvas id="chartTools"></canvas></div>
    </div>
    <div class="card" style="margin-bottom:0;">
      <h2>Cost by user</h2>
      <div class="chart-wrap sm"><canvas id="chartCost"></canvas></div>
    </div>
  </div>

  <div class="card">
    <h2>PII by entity type</h2>
    <div class="chart-wrap sm"><canvas id="chartPiiEntity"></canvas></div>
  </div>

  <div class="card">
    <h2>Tool drill-down</h2>
    <div class="tool-table-wrap">
      <table class="tool-table" id="toolTable">
        <thead>
          <tr>
            <th>Tool</th>
            <th>Total</th>
            <th>Allowed</th>
            <th>Blocked</th>
            <th>Blocked %</th>
            <th>P95 ms</th>
            <th>Avg ms</th>
            <th>Reasons</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h2>Recent alerts</h2>
    <div class="alerts" id="alerts"></div>
  </div>

  <script>
    const PALETTE = ['#38bdf8', '#a78bfa', '#34d399', '#fb7185', '#fbbf24', '#2dd4bf', '#f472b6', '#94a3b8'];
    const charts = {};
    let initialized = false;

    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(148, 163, 184, 0.15)';
    Chart.defaults.font.family = '"DM Sans", system-ui, sans-serif';

    function updateThemeButton() {
      var dark = document.documentElement.getAttribute('data-theme') !== 'light';
      var btn = document.getElementById('themeToggle');
      if (!btn) return;
      btn.textContent = dark ? 'Light' : 'Dark';
      btn.setAttribute('aria-pressed', dark ? 'true' : 'false');
      btn.title = dark ? 'Switch to light mode' : 'Switch to dark mode';
    }
    function chartThemeColors() {
      var light = document.documentElement.getAttribute('data-theme') === 'light';
      return {
        tick: light ? '#475569' : '#94a3b8',
        grid: light ? 'rgba(71, 85, 105, 0.14)' : 'rgba(148, 163, 184, 0.08)',
        tooltipBg: light ? 'rgba(255, 255, 255, 0.96)' : 'rgba(15, 23, 42, 0.92)',
        titleColor: light ? '#0f172a' : '#f1f5f9',
        bodyColor: light ? '#334155' : '#cbd5e1',
        border: light ? 'rgba(100, 116, 139, 0.3)' : 'rgba(148, 163, 184, 0.2)'
      };
    }
    function applyChartTheme() {
      if (typeof Chart === 'undefined' || !charts.traffic) return;
      var th = chartThemeColors();
      Chart.defaults.color = th.tick;
      Chart.defaults.borderColor = th.grid;
      function patchTooltip(plug) {
        if (!plug) return;
        if (!plug.tooltip) plug.tooltip = {};
        var tip = plug.tooltip;
        tip.backgroundColor = th.tooltipBg;
        tip.titleColor = th.titleColor;
        tip.bodyColor = th.bodyColor;
        tip.borderColor = th.border;
      }
      function patchScales(scales) {
        if (!scales) return;
        ['x', 'y'].forEach(function (axis) {
          if (scales[axis] && scales[axis].grid) scales[axis].grid.color = th.grid;
          if (scales[axis] && scales[axis].ticks) scales[axis].ticks.color = th.tick;
        });
      }
      patchScales(charts.traffic.options.scales);
      patchTooltip(charts.traffic.options.plugins);
      charts.traffic.update('none');
      if (charts.reasons.options.plugins && charts.reasons.options.plugins.legend && charts.reasons.options.plugins.legend.labels) {
        charts.reasons.options.plugins.legend.labels.color = th.tick;
      }
      patchTooltip(charts.reasons.options.plugins);
      charts.reasons.update('none');
      patchScales(charts.tools.options.scales);
      patchTooltip(charts.tools.options.plugins);
      charts.tools.update('none');
      patchScales(charts.cost.options.scales);
      patchTooltip(charts.cost.options.plugins);
      charts.cost.update('none');
      if (charts.piiEntity) {
        patchScales(charts.piiEntity.options.scales);
        patchTooltip(charts.piiEntity.options.plugins);
        charts.piiEntity.update('none');
      }
    }
    document.addEventListener('DOMContentLoaded', function () {
      updateThemeButton();
      var btn = document.getElementById('themeToggle');
      if (btn) {
        btn.addEventListener('click', function () {
          var cur = document.documentElement.getAttribute('data-theme');
          var next = cur === 'light' ? 'dark' : 'light';
          document.documentElement.setAttribute('data-theme', next);
          localStorage.setItem('mcp-bastion-theme', next);
          updateThemeButton();
          applyChartTheme();
        });
      }
    });

    function shortLabel(iso) {
      try {
        const d = new Date(iso);
        return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      } catch (e) { return ''; }
    }

    function createCharts() {
      const trafficCtx = document.getElementById('chartTraffic').getContext('2d');
      charts.traffic = new Chart(trafficCtx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'Allowed',
              data: [],
              borderColor: '#34d399',
              backgroundColor: 'rgba(52, 211, 153, 0.12)',
              fill: true,
              tension: 0.38,
              borderWidth: 2.5,
              pointRadius: 0,
              pointHoverRadius: 4
            },
            {
              label: 'Blocked',
              data: [],
              borderColor: '#fb7185',
              backgroundColor: 'rgba(251, 113, 133, 0.1)',
              fill: true,
              tension: 0.38,
              borderWidth: 2.5,
              pointRadius: 0,
              pointHoverRadius: 4
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 450, easing: 'easeOutQuart' },
          interaction: { mode: 'index', intersect: false },
          scales: {
            x: {
              grid: { color: 'rgba(148, 163, 184, 0.08)' },
              ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 10, font: { size: 10 } }
            },
            y: {
              beginAtZero: true,
              grid: { color: 'rgba(148, 163, 184, 0.08)' },
              ticks: { font: { size: 10 }, precision: 0 }
            }
          },
          plugins: {
            legend: { position: 'top', labels: { usePointStyle: true, padding: 20 } },
            tooltip: {
              backgroundColor: 'rgba(15, 23, 42, 0.92)',
              titleColor: '#f1f5f9',
              bodyColor: '#cbd5e1',
              borderColor: 'rgba(148, 163, 184, 0.2)',
              borderWidth: 1,
              padding: 12,
              cornerRadius: 10
            }
          }
        }
      });

      charts.reasons = new Chart(document.getElementById('chartReasons'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE, borderWidth: 0, hoverOffset: 8 }] },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '62%',
          plugins: {
            legend: { position: 'right', labels: { boxWidth: 10, font: { size: 10 } } },
            tooltip: {
              backgroundColor: 'rgba(15, 23, 42, 0.92)',
              borderColor: 'rgba(148, 163, 184, 0.2)',
              borderWidth: 1
            }
          }
        }
      });

      const gradBlue = (ctx) => {
        const c = ctx.chart.ctx;
        const g = c.createLinearGradient(0, 0, 0, 200);
        g.addColorStop(0, 'rgba(56, 189, 248, 0.9)');
        g.addColorStop(1, 'rgba(37, 99, 235, 0.45)');
        return g;
      };
      charts.tools = new Chart(document.getElementById('chartTools'), {
        type: 'bar',
        data: {
          labels: [],
          datasets: [{
            label: 'Calls',
            data: [],
            backgroundColor: gradBlue,
            borderRadius: 8,
            borderSkipped: false
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 450, easing: 'easeOutQuart' },
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: 'rgba(148, 163, 184, 0.08)' },
              ticks: { font: { size: 10 }, precision: 0 }
            },
            y: { grid: { display: false }, ticks: { font: { size: 11 } } }
          }
        }
      });

      const gradGold = (ctx) => {
        const c = ctx.chart.ctx;
        const g = c.createLinearGradient(220, 0, 0, 0);
        g.addColorStop(0, 'rgba(251, 191, 36, 0.95)');
        g.addColorStop(1, 'rgba(217, 119, 6, 0.4)');
        return g;
      };
      charts.cost = new Chart(document.getElementById('chartCost'), {
        type: 'bar',
        data: {
          labels: [],
          datasets: [{
            label: 'USD',
            data: [],
            backgroundColor: gradGold,
            borderRadius: 8,
            borderSkipped: false
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 450, easing: 'easeOutQuart' },
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: 'rgba(148, 163, 184, 0.08)' },
              ticks: {
                callback: (v) => '$' + Number(v).toFixed(2),
                font: { size: 10 }
              }
            },
            y: { grid: { display: false }, ticks: { font: { size: 11 } } }
          }
        }
      });

      const gradPii = (ctx) => {
        const c = ctx.chart.ctx;
        const g = c.createLinearGradient(0, 0, 0, 160);
        g.addColorStop(0, 'rgba(167, 139, 250, 0.88)');
        g.addColorStop(1, 'rgba(99, 102, 241, 0.42)');
        return g;
      };
      charts.piiEntity = new Chart(document.getElementById('chartPiiEntity'), {
        type: 'bar',
        data: {
          labels: [],
          datasets: [{
            label: 'Detections',
            data: [],
            backgroundColor: gradPii,
            borderRadius: 8,
            borderSkipped: false
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          animation: { duration: 450, easing: 'easeOutQuart' },
          indexAxis: 'y',
          plugins: { legend: { display: false } },
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: 'rgba(148, 163, 184, 0.08)' },
              ticks: { font: { size: 10 }, precision: 0 }
            },
            y: { grid: { display: false }, ticks: { font: { size: 10 } } }
          }
        }
      });
      applyChartTheme();
    }

    function updateTraffic(ts) {
      const series = ts || [];
      const labels = series.map((b) => shortLabel(b.bucket_start));
      const allowed = series.map((b) => b.allowed || 0);
      const blocked = series.map((b) => b.blocked || 0);
      charts.traffic.data.labels = labels;
      charts.traffic.data.datasets[0].data = allowed;
      charts.traffic.data.datasets[1].data = blocked;
      charts.traffic.update('none');
    }

    function updateReasons(obj) {
      const entries = Object.entries(obj || {});
      if (!entries.length) {
        charts.reasons.data.labels = ['No blocks yet'];
        charts.reasons.data.datasets[0].data = [1];
        charts.reasons.data.datasets[0].backgroundColor = ['rgba(148, 163, 184, 0.25)'];
      } else {
        charts.reasons.data.labels = entries.map((e) => e[0]);
        charts.reasons.data.datasets[0].data = entries.map((e) => e[1]);
        charts.reasons.data.datasets[0].backgroundColor = entries.map((_, i) => PALETTE[i % PALETTE.length]);
      }
      charts.reasons.update('none');
    }

    function updateTools(obj) {
      const entries = Object.entries(obj || {}).slice(0, 8);
      if (!entries.length) {
        charts.tools.data.labels = ['—'];
        charts.tools.data.datasets[0].data = [0];
      } else {
        charts.tools.data.labels = entries.map((e) => e[0]);
        charts.tools.data.datasets[0].data = entries.map((e) => e[1]);
      }
      charts.tools.update('none');
    }

    function updateCost(obj) {
      const entries = Object.entries(obj || {}).slice(0, 8);
      if (!entries.length) {
        charts.cost.data.labels = ['—'];
        charts.cost.data.datasets[0].data = [0];
      } else {
        charts.cost.data.labels = entries.map((e) => e[0]);
        charts.cost.data.datasets[0].data = entries.map((e) => e[1]);
      }
      charts.cost.update('none');
    }

    function updatePiiEntity(obj) {
      const entries = Object.entries(obj || {}).slice(0, 12);
      if (!entries.length) {
        charts.piiEntity.data.labels = ['(none yet)'];
        charts.piiEntity.data.datasets[0].data = [0];
      } else {
        charts.piiEntity.data.labels = entries.map((e) => e[0]);
        charts.piiEntity.data.datasets[0].data = entries.map((e) => e[1]);
      }
      charts.piiEntity.update('none');
    }

    function updatePillarHealth(items) {
      const node = document.getElementById('pillarHealth');
      const data = (items || []);
      if (!data.length) {
        node.innerHTML = '<div class="pillar"><div class="name">No data</div><div class="detail">No telemetry yet.</div></div>';
        return;
      }
      node.innerHTML = data.map(function (p) {
        var st = (p.status || 'idle').toLowerCase();
        var label = st === 'active' ? 'Active' : (st === 'healthy' ? 'Healthy' : 'Idle');
        return '<div class="pillar">'
          + '<div class="name">' + (p.name || 'Unknown') + '</div>'
          + '<span class="pill ' + st + '">' + label + '</span>'
          + '<div class="detail">' + (p.detail || '') + '</div>'
          + '</div>';
      }).join('');
    }

    function updateToolTable(stats) {
      const body = document.querySelector('#toolTable tbody');
      const entries = Object.entries(stats || {})
        .sort((a, b) => (b[1].total || 0) - (a[1].total || 0))
        .slice(0, 12);
      if (!entries.length) {
        body.innerHTML = '<tr><td colspan="8" class="muted">No tool activity yet.</td></tr>';
        return;
      }
      body.innerHTML = entries.map(function (entry) {
        var tool = entry[0];
        var s = entry[1] || {};
        var reasons = Object.entries(s.blocked_reasons || {}).map(function (r) {
          return r[0] + ' (' + r[1] + ')';
        }).join(', ');
        return '<tr>'
          + '<td>' + tool + '</td>'
          + '<td>' + (s.total || 0) + '</td>'
          + '<td>' + (s.allowed || 0) + '</td>'
          + '<td>' + (s.blocked || 0) + '</td>'
          + '<td>' + Number(s.blocked_pct || 0).toFixed(2) + '%</td>'
          + '<td>' + Number(s.latency_ms_p95 || 0).toFixed(2) + '</td>'
          + '<td>' + Number(s.latency_ms_avg || 0).toFixed(2) + '</td>'
          + '<td>' + (reasons || '—') + '</td>'
          + '</tr>';
      }).join('');
    }

    async function fetchMetrics() {
      const r = await fetch('/api/metrics');
      return r.json();
    }

    function render(d) {
      const n = (d.alerts && d.alerts.length) || 0;
      document.getElementById('alertCount').textContent = n + ' Alerts';

      document.getElementById('kpiReq').textContent = d.requests_total ?? 0;
      document.getElementById('kpiBlocked').textContent =
        (d.blocked_total ?? 0) + ' (' + (d.blocked_pct ?? 0) + '%)';
      document.getElementById('kpiPii').textContent = d.pii_redacted_total ?? 0;
      document.getElementById('kpiCost').textContent =
        '$' + Number(d.cost_total ?? 0).toFixed(2);

      var lm = d.latency_ms || {};
      document.getElementById('latP50').textContent = (lm.p50 != null) ? lm.p50 : '0';
      document.getElementById('latP95').textContent = (lm.p95 != null) ? lm.p95 : '0';
      document.getElementById('latP99').textContent = (lm.p99 != null) ? lm.p99 : '0';
      document.getElementById('latSamples').textContent = (lm.samples || 0) + ' samples';

      var br = d.cost_burn || {};
      var ph = (br.per_hour_usd != null) ? Number(br.per_hour_usd).toFixed(4) : '0.0000';
      var pd = (br.projected_daily_usd != null) ? Number(br.projected_daily_usd).toFixed(2) : '0.00';
      document.getElementById('costBurn').textContent =
        '$' + ph + ' / hr projected · $' + pd + ' / day projected';
      document.getElementById('burnWindow').textContent =
        'Window elapsed: ' + (br.window_elapsed_seconds || 0) + ' s';

      const winSec = d.time_series_window_seconds || 600;
      document.getElementById('tsWindow').textContent = Math.round(winSec / 60) + ' min';
      document.getElementById('tsBucket').textContent = (d.time_series_bucket_seconds || 30) + 's';

      document.getElementById('alerts').innerHTML =
        (d.alerts || []).slice(-8).reverse().map((a) => {
          const sev = (a.severity === 'critical') ? 'critical' : '';
          return '<div class="alert ' + sev + '">' + a.kind + ': ' + (a.message || '') + '</div>';
        }).join('') || '<div class="alert" style="border-left-color:#64748b;">No alerts</div>';

      if (!initialized) {
        initialized = true;
        createCharts();
      }
      updateTraffic(d.time_series);
      updateReasons(d.blocked_by_reason);
      updateTools(d.top_tools);
      updateCost(d.cost_by_user);
      updatePiiEntity(d.pii_by_entity);
      updatePillarHealth(d.pillar_health);
      updateToolTable(d.tool_stats);
    }

    (async function poll() {
      try { render(await fetchMetrics()); } catch (e) { console.error(e); }
      setTimeout(poll, 2000);
    })();
  </script>
  <p class="dash-footer"><strong>MCP-Bastion dashboard</strong> · Chart.js · Theme preference stored in this browser only</p>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return HTMLResponse(
        DASHBOARD_HTML,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=7000)
