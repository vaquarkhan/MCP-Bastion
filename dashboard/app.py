"""
MCP-Bastion real-time dashboard and metrics API.

Run: PYTHONPATH=src python dashboard/app.py
Serves: http://localhost:7000/ (dashboard), http://localhost:7000/api/metrics (JSON)

Demo data (non-zero charts without a separate MCP server) — on by default for local runs:
  python dashboard/app.py
  mcp-bastion dashboard
  Opt out: MCP_BASTION_DEMO=0 or mcp-bastion dashboard --no-demo
"""

from __future__ import annotations

import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

logger = logging.getLogger("mcp_bastion.dashboard")

# Add src so mcp_bastion is importable
root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root / "src"))

try:
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
    from fastapi.staticfiles import StaticFiles
except ImportError:
    logger.error("Install: pip install fastapi uvicorn")
    sys.exit(1)

from mcp_bastion.pillars.metrics import MetricsStore

_demo_seed_applied = False


def _maybe_seed_demo_metrics() -> None:
    """Seed rich demo KPIs/charts when MCP_BASTION_DEMO=1 (bundled in mcp_bastion, works after pip install)."""
    global _demo_seed_applied
    if _demo_seed_applied:
        return
    if os.environ.get("MCP_BASTION_DEMO", "").strip().lower() not in ("1", "true", "yes"):
        return
    try:
        import random

        from mcp_bastion.demo_dashboard_metrics import seed_metrics

        seed_metrics(random.Random(42))
        _demo_seed_applied = True
        logger.info("Demo metrics seeded (MCP_BASTION_DEMO=1). Open /api/metrics to verify non-zero data.")
    except Exception:
        logger.exception("Failed to seed demo metrics (mcp_bastion.demo_dashboard_metrics)")


@asynccontextmanager
async def _dashboard_lifespan(_app: FastAPI):
    # Same default as `python dashboard/app.py` / CLI: charts show demo data unless MCP_BASTION_DEMO is 0/false/no.
    os.environ.setdefault("MCP_BASTION_DEMO", "1")
    _maybe_seed_demo_metrics()
    yield


app = FastAPI(title="MCP-Bastion Dashboard", lifespan=_dashboard_lifespan)


@app.get("/images/mcp-bastian.png")
def legacy_branding_png():
    """Old URL; branding now ships under /static/ so pip installs always resolve."""
    return RedirectResponse(url="/static/mcp-bastian.png", status_code=307)


# Allow cross-origin reads of metrics (proxies, Live Preview, tools on another port).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "HEAD", "OPTIONS"],
    allow_headers=["*"],
)

_static_dir = Path(__file__).resolve().parent / "static"
if _static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

# Repo-root images/ (e.g. branding) — optional; path is stable regardless of cwd
_images_dir = root / "images"
if _images_dir.is_dir():
    app.mount("/images", StaticFiles(directory=str(_images_dir)), name="images")


@app.get("/api/metrics")
def get_metrics():
    # If startup lifespan did not run (some ASGI hosts), still seed once on first poll.
    os.environ.setdefault("MCP_BASTION_DEMO", "1")
    _maybe_seed_demo_metrics()
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
        "ui_revision": "v14-light-gradient-lazy-seed",
        "hint": "If this is missing, you are not hitting dashboard/app.py - check port and process.",
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
      var t = "dark";
      try {
        var s = localStorage.getItem("mcp-bastion-theme");
        if (s !== "light" && s !== "dark") s = sessionStorage.getItem("mcp-bastion-theme");
        if (s === "light" || s === "dark") t = s;
      } catch (e) {}
      document.documentElement.setAttribute("data-theme", t);
      document.documentElement.style.colorScheme = t === "light" ? "light" : "dark";
    })();
  </script>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,600;0,9..40,700;1,9..40,400&family=Outfit:wght@500;600;700&display=swap" rel="stylesheet">
  <!-- Local Chart.js (same-origin); CDN fallback if /static missing -->
  <script src="/static/chart.umd.min.js" onerror="this.onerror=null;this.src='https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js'"></script>
  <style>
    :root {
      --bg0: #0c1222;
      --bg-mid: #0f172a;
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
    /* Explicit dark palette so toggling always matches (not only :root defaults). */
    html[data-theme="dark"] {
      color-scheme: dark;
      --bg0: #0c1222;
      --bg-mid: #0f172a;
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
    html {
      scroll-behavior: smooth;
    }
    @media (prefers-reduced-motion: reduce) {
      html { scroll-behavior: auto; }
    }
    body {
      font-family: "DM Sans", system-ui, sans-serif;
      margin: 0;
      min-height: 100vh;
      color: var(--text);
      background:
        radial-gradient(ellipse 120% 80% at 50% -30%, rgba(56, 189, 248, 0.12), transparent 50%),
        radial-gradient(ellipse 80% 50% at 100% 50%, rgba(167, 139, 250, 0.06), transparent),
        linear-gradient(165deg, var(--bg0) 0%, var(--bg-mid) 42%, var(--bg1) 100%);
      padding: 20px 20px 48px;
    }
    body::before {
      content: "";
      pointer-events: none;
      position: fixed;
      inset: 0;
      background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='0.03'/%3E%3C/svg%3E");
      opacity: 0.45;
      z-index: 0;
    }
    html[data-theme="light"] body::before {
      opacity: 0.14;
    }
    .dash-shell {
      position: relative;
      z-index: 1;
      max-width: 1220px;
      margin: 0 auto;
    }
    .header-banner-img {
      height: 28px;
      width: auto;
      max-width: 72px;
      object-fit: contain;
      display: block;
      flex-shrink: 0;
      border-radius: 6px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.28);
    }
    html[data-theme="light"] .header-banner-img {
      box-shadow: 0 2px 14px rgba(15, 23, 42, 0.12);
    }
    .header-brand-text {
      min-width: 0;
    }
    .status-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px 20px;
      padding: 10px 14px;
      margin: -4px 0 20px;
      border-radius: 12px;
      background: rgba(15, 23, 42, 0.45);
      border: 1px solid var(--card-border);
      backdrop-filter: blur(10px);
      font-size: 0.8rem;
    }
    html[data-theme="light"] .status-bar {
      background: rgba(255, 255, 255, 0.72);
    }
    .live-indicator {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-weight: 600;
      letter-spacing: 0.02em;
      font-family: "Outfit", "DM Sans", sans-serif;
    }
    .live-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #34d399;
      box-shadow: 0 0 0 3px rgba(52, 211, 153, 0.35);
      animation: pulse-dot 2s ease-in-out infinite;
    }
    @keyframes pulse-dot {
      50% { opacity: 0.65; transform: scale(0.92); }
    }
    .status-bar .sep {
      color: var(--card-border);
      user-select: none;
    }
    .insight-row {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 14px;
      margin-bottom: 20px;
    }
    @media (max-width: 900px) { .insight-row { grid-template-columns: 1fr; } }
    .insight-card {
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 16px 18px;
      backdrop-filter: blur(12px);
      box-shadow: 0 8px 28px rgba(0, 0, 0, 0.18);
    }
    html[data-theme="light"] .insight-card {
      box-shadow: 0 4px 20px rgba(15, 23, 42, 0.06);
    }
    .insight-card h3 {
      font-family: "Outfit", "DM Sans", sans-serif;
      font-size: 0.78rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin: 0 0 10px 0;
    }
    .insight-stat {
      font-family: "Outfit", "DM Sans", sans-serif;
      font-size: 1.85rem;
      font-weight: 700;
      letter-spacing: -0.03em;
      line-height: 1.15;
      color: var(--text);
    }
    .insight-stat .unit {
      font-size: 1rem;
      font-weight: 600;
      color: var(--muted);
      margin-left: 2px;
    }
    .insight-lede {
      font-size: 0.8rem;
      color: var(--muted);
      line-height: 1.45;
      margin: 8px 0 0 0;
    }
    .kind-list {
      margin: 0;
      padding: 0;
      list-style: none;
      font-size: 0.8rem;
    }
    .kind-list li {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 6px 0;
      border-bottom: 1px solid var(--card-border);
    }
    .kind-list li:last-child { border-bottom: none; }
    .kind-list .k { color: var(--text); font-weight: 600; }
    .kind-list .v { color: var(--muted); font-variant-numeric: tabular-nums; }
    .link-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 4px;
    }
    a.link-chip {
      display: inline-flex;
      align-items: center;
      padding: 6px 12px;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-decoration: none;
      color: var(--accent);
      border: 1px solid rgba(56, 189, 248, 0.35);
      background: rgba(56, 189, 248, 0.08);
      transition: background 0.15s, border-color 0.15s;
    }
    a.link-chip:hover {
      background: rgba(56, 189, 248, 0.16);
      border-color: var(--accent);
    }
    html[data-theme="light"] a.link-chip {
      color: #0369a1;
      border-color: rgba(3, 105, 161, 0.35);
      background: rgba(56, 189, 248, 0.1);
    }
    .card-head {
      display: flex;
      flex-wrap: wrap;
      align-items: baseline;
      justify-content: space-between;
      gap: 8px 16px;
      margin-bottom: 14px;
    }
    .card-head h2 {
      margin: 0;
    }
    .card-desc {
      font-size: 0.78rem;
      color: var(--muted);
      line-height: 1.4;
      max-width: 52ch;
      margin: 0;
      font-weight: 400;
      text-transform: none;
      letter-spacing: 0;
    }
    .header {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      margin-bottom: 12px;
    }
    .header-brand {
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 0;
      flex-wrap: nowrap;
    }
    @media (max-width: 520px) {
      .header-brand { flex-wrap: wrap; }
    }
    .header h1 {
      font-size: 1.28rem;
      font-weight: 700;
      margin: 0;
      letter-spacing: -0.02em;
      color: var(--text);
    }
    html[data-theme="dark"] .header h1 {
      color: var(--text);
    }
    @supports ((-webkit-background-clip: text) or (background-clip: text)) {
      html[data-theme="dark"] .header h1 {
        background: linear-gradient(135deg, #f8fafc 0%, #94a3b8 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        color: transparent;
      }
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
    .alert-menu { position: relative; }
    .badge-btn {
      border: none;
      cursor: pointer;
      font: inherit;
      font-family: inherit;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .badge-btn .caret {
      font-size: 0.65rem;
      opacity: 0.9;
      transition: transform 0.15s ease;
    }
    .alert-menu.open .badge-btn .caret { transform: rotate(180deg); }
    .badge-btn:focus-visible {
      outline: 2px solid rgba(255, 255, 255, 0.85);
      outline-offset: 2px;
    }
    .alert-dropdown-panel {
      display: none;
      position: absolute;
      right: 0;
      top: calc(100% + 8px);
      min-width: min(380px, 92vw);
      max-width: 440px;
      max-height: 340px;
      overflow-y: auto;
      z-index: 100;
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 10px 10px 8px;
      box-shadow: 0 16px 48px rgba(0, 0, 0, 0.4);
      backdrop-filter: blur(12px);
    }
    .alert-menu.open .alert-dropdown-panel { display: block; }
    html[data-theme="light"] .alert-dropdown-panel {
      box-shadow: 0 12px 40px rgba(15, 23, 42, 0.12);
    }
    .alert-dropdown-inner .alert { margin-bottom: 8px; }
    .alert-dropdown-inner .alert:last-child { margin-bottom: 0; }
    .alert-ts {
      font-size: 0.65rem;
      color: var(--muted);
      margin-bottom: 4px;
      font-variant-numeric: tabular-nums;
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
      font-family: "Outfit", "DM Sans", sans-serif;
      color: var(--text);
    }
    .kpi-foot {
      margin: 10px 0 0 0;
      font-size: 0.72rem;
      line-height: 1.35;
      color: var(--muted);
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
      font-family: "Outfit", "DM Sans", sans-serif;
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
    .alerts-prominent {
      max-height: 280px;
    }
    .alerts-insights-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
      margin-bottom: 18px;
    }
    @media (max-width: 900px) {
      .alerts-insights-row { grid-template-columns: 1fr; }
    }
    .alerts-panel-card, .insights-panel-card { margin-bottom: 0; }
    .insights-feed {
      display: flex;
      flex-direction: column;
      gap: 10px;
      max-height: 280px;
      overflow-y: auto;
    }
    .insight-item {
      border-left: 4px solid var(--accent);
      border-radius: 10px;
      padding: 10px 12px;
      font-size: 0.82rem;
      background: rgba(51, 65, 85, 0.45);
    }
    .insight-item.warning { border-left-color: var(--warn); }
    .insight-item.info { border-left-color: var(--accent); }
    html[data-theme="light"] .insight-item {
      background: rgba(241, 245, 249, 0.95);
    }
    .insight-title { font-weight: 700; margin-bottom: 4px; color: var(--text); font-family: "Outfit", "DM Sans", sans-serif; }
    .insight-detail { color: var(--muted); font-size: 0.78rem; line-height: 1.45; }
    .insights-empty { color: var(--muted); font-size: 0.85rem; margin: 0; padding: 4px 0 8px; line-height: 1.45; }
    .signal-badge {
      display: inline-block;
      padding: 3px 9px;
      border-radius: 999px;
      font-size: 0.62rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      white-space: nowrap;
    }
    .signal-hot { background: rgba(251, 113, 133, 0.22); color: #fda4af; border: 1px solid rgba(251, 113, 133, 0.4); }
    .signal-watch { background: rgba(251, 191, 36, 0.2); color: #fde68a; border: 1px solid rgba(251, 191, 36, 0.38); }
    .signal-ok { background: rgba(52, 211, 153, 0.16); color: #86efac; border: 1px solid rgba(52, 211, 153, 0.32); }
    html[data-theme="light"] .signal-hot { color: #9f1239; }
    html[data-theme="light"] .signal-watch { color: #92400e; }
    html[data-theme="light"] .signal-ok { color: #065f46; }
    .alert {
      font-size: 0.8rem;
      padding: 10px 12px;
      border-radius: 10px;
      border-left: 4px solid var(--warn);
      background: rgba(51, 65, 85, 0.6);
      color: var(--text);
    }
    .alert.critical { border-left-color: #f43f5e; }
    .dash-footer {
      text-align: center;
      margin-top: 32px;
      padding: 20px 12px 8px;
      font-size: 0.75rem;
      color: var(--muted);
      border-top: 1px solid var(--card-border);
      line-height: 1.6;
    }
    .dash-footer strong { color: #38bdf8; }
    .dash-footer .footer-links {
      margin-top: 10px;
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 8px 14px;
    }
    .dash-footer .footer-links a {
      color: var(--muted);
      text-decoration: none;
      border-bottom: 1px solid transparent;
    }
    .dash-footer .footer-links a:hover {
      color: var(--accent);
      border-bottom-color: rgba(56, 189, 248, 0.4);
    }
    html[data-theme="light"] {
      color-scheme: light;
      --bg0: #f8fafc;
      --bg-mid: #eef2f7;
      --bg1: #e2e8f0;
      --card: rgba(255, 255, 255, 0.94);
      --card-border: rgba(100, 116, 139, 0.22);
      --text: #0f172a;
      --muted: #64748b;
      --accent: #0284c7;
      --ok: #059669;
      --bad: #e11d48;
      --warn: #d97706;
    }
    html[data-theme="light"] body,
    body[data-theme="light"] {
      background:
        radial-gradient(ellipse 120% 80% at 50% -25%, rgba(56, 189, 248, 0.1), transparent 48%),
        radial-gradient(ellipse 70% 50% at 100% 30%, rgba(167, 139, 250, 0.06), transparent),
        linear-gradient(165deg, var(--bg0) 0%, var(--bg-mid) 42%, var(--bg1) 100%);
    }
    html[data-theme="light"] .header h1 {
      color: #0f172a;
      background: none;
      -webkit-text-fill-color: unset;
    }
    @supports ((-webkit-background-clip: text) or (background-clip: text)) {
      html[data-theme="light"] .header h1 {
        background: linear-gradient(135deg, #0f172a 0%, #475569 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        background-clip: text;
        color: transparent;
      }
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
      transition: border-color 0.2s, box-shadow 0.2s, transform 0.2s;
    }
    .pillar:hover {
      border-color: rgba(56, 189, 248, 0.28);
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.12);
      transform: translateY(-1px);
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
    .tenant-bar {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px 14px;
      margin-bottom: 14px;
      padding: 12px 14px;
      border-radius: 10px;
      background: rgba(15, 23, 42, 0.35);
      border: 1px solid var(--card-border);
    }
    html[data-theme="light"] .tenant-bar {
      background: rgba(241, 245, 249, 0.9);
    }
    .tenant-bar label {
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
    }
    .tenant-select {
      min-width: 180px;
      padding: 8px 12px;
      border-radius: 8px;
      border: 1px solid var(--card-border);
      background: var(--card);
      color: var(--text);
      font-family: inherit;
      font-size: 0.85rem;
    }
    .btn-apply, .btn-ghost {
      padding: 8px 16px;
      border-radius: 8px;
      font-family: inherit;
      font-size: 0.82rem;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--card-border);
      background: linear-gradient(135deg, #38bdf8, #2563eb);
      color: white;
    }
    .btn-ghost {
      background: var(--card);
      color: var(--text);
    }
    .btn-apply:hover, .btn-ghost:hover {
      filter: brightness(1.06);
    }
    .btn-row-act {
      display: inline-flex;
      gap: 6px;
      flex-wrap: wrap;
    }
    .btn-mini {
      padding: 4px 10px;
      font-size: 0.7rem;
      font-weight: 600;
      border-radius: 6px;
      border: 1px solid var(--card-border);
      background: rgba(56, 189, 248, 0.12);
      color: var(--accent);
      cursor: pointer;
      font-family: inherit;
    }
    .btn-mini:hover {
      border-color: var(--accent);
    }
    html[data-theme="light"] .btn-mini {
      color: #0369a1;
    }
    .modal-overlay {
      display: none;
      position: fixed;
      inset: 0;
      z-index: 200;
      align-items: center;
      justify-content: center;
      padding: 20px;
      background: rgba(15, 23, 42, 0.65);
    }
    .modal-overlay.open { display: flex; }
    .modal-box {
      width: min(640px, 100%);
      max-height: min(80vh, 560px);
      overflow: auto;
      background: var(--card);
      border: 1px solid var(--card-border);
      border-radius: 14px;
      padding: 18px 20px;
      box-shadow: 0 24px 64px rgba(0, 0, 0, 0.45);
    }
    .modal-box h3 {
      margin: 0 0 12px 0;
      font-size: 1rem;
      font-family: "Outfit", "DM Sans", sans-serif;
    }
    .modal-box pre {
      margin: 0;
      font-size: 0.72rem;
      line-height: 1.45;
      white-space: pre-wrap;
      word-break: break-word;
      color: var(--text);
    }
    .modal-close {
      float: right;
      border: none;
      background: transparent;
      color: var(--muted);
      font-size: 1.25rem;
      cursor: pointer;
      line-height: 1;
      padding: 4px 8px;
    }
    .modal-close:hover { color: var(--text); }
    .dash-jump {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px 10px;
      margin: -8px 0 18px;
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(15, 23, 42, 0.35);
      border: 1px solid var(--card-border);
    }
    html[data-theme="light"] .dash-jump {
      background: rgba(255, 255, 255, 0.55);
    }
    .dash-jump .jump-label {
      font-size: 0.65rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
      margin-right: 4px;
    }
    .dash-jump a {
      font-size: 0.78rem;
      font-weight: 600;
      color: var(--accent);
      text-decoration: none;
      padding: 5px 10px;
      border-radius: 999px;
      border: 1px solid rgba(56, 189, 248, 0.28);
      background: rgba(56, 189, 248, 0.06);
      transition: background 0.15s, border-color 0.15s;
    }
    .dash-jump a:hover {
      background: rgba(56, 189, 248, 0.14);
      border-color: var(--accent);
    }
    html[data-theme="light"] .dash-jump a {
      color: #0369a1;
    }
    .dash-jump .jump-actions {
      margin-left: auto;
      display: inline-flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }
    .btn-export {
      font-family: inherit;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
      padding: 6px 12px;
      border-radius: 999px;
      border: 1px solid rgba(167, 139, 250, 0.45);
      background: rgba(167, 139, 250, 0.12);
      color: #c4b5fd;
    }
    .btn-export:hover {
      filter: brightness(1.08);
      border-color: #a78bfa;
    }
    html[data-theme="light"] .btn-export {
      color: #5b21b6;
    }
    .insight-summary {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin: 0 0 12px 0;
      min-height: 1.5em;
    }
    .insight-chip {
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 0.68rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .insight-chip.warn {
      background: rgba(251, 191, 36, 0.18);
      color: #fde68a;
      border: 1px solid rgba(251, 191, 36, 0.35);
    }
    .insight-chip.info {
      background: rgba(56, 189, 248, 0.14);
      color: #7dd3fc;
      border: 1px solid rgba(56, 189, 248, 0.32);
    }
    html[data-theme="light"] .insight-chip.warn { color: #92400e; }
    html[data-theme="light"] .insight-chip.info { color: #0369a1; }
    .back-top {
      position: fixed;
      right: 20px;
      bottom: 24px;
      z-index: 150;
      width: 44px;
      height: 44px;
      border-radius: 12px;
      border: 1px solid var(--card-border);
      background: var(--card);
      color: var(--accent);
      font-size: 1.15rem;
      line-height: 1;
      cursor: pointer;
      box-shadow: 0 8px 28px rgba(0, 0, 0, 0.35);
      opacity: 0;
      pointer-events: none;
      transform: translateY(12px);
      transition: opacity 0.2s, transform 0.2s;
    }
    .back-top.visible {
      opacity: 1;
      pointer-events: auto;
      transform: translateY(0);
    }
    .back-top:hover {
      border-color: var(--accent);
    }
    @media (prefers-reduced-motion: reduce) {
      .back-top { transition: none; }
    }
  </style>
</head>
<body>
  <div class="dash-shell">
  <div class="header">
    <div class="header-brand">
      <img
        src="/static/mcp-bastian.png"
        alt="MCP-Bastion"
        class="header-banner-img"
        width="72"
        height="28"
        decoding="async"
        onerror="this.onerror=null;this.src='/images/mcp-bastian.png'"
      />
      <div class="header-brand-text">
        <h1>MCP-Bastion</h1>
        <p>Live security &amp; FinOps · refreshes every 2s</p>
      </div>
    </div>
    <div class="header-right">
      <button type="button" class="theme-toggle" id="themeToggle" aria-label="Switch between dark and light theme">Use light theme</button>
      <div class="alert-menu" id="alertMenu">
        <button type="button" class="badge badge-btn" id="alertCountBtn" aria-expanded="false" aria-haspopup="true" aria-controls="alertDropdownPanel">
          <span id="alertCountLabel">0 Alerts</span><span class="caret" aria-hidden="true">v</span>
        </button>
        <div class="alert-dropdown-panel" id="alertDropdownPanel" role="region" aria-label="Active alerts">
          <div class="alert-dropdown-inner" id="alertDropdownList"></div>
        </div>
      </div>
    </div>
  </div>

  <div class="status-bar" role="status">
    <span class="live-indicator"><span class="live-dot" aria-hidden="true"></span><span id="liveLabel">Live</span></span>
    <span class="sep" aria-hidden="true">·</span>
    <span id="pollStatus">Syncing metrics…</span>
    <span class="sep" aria-hidden="true">·</span>
    <span class="muted">Data age</span>
    <span id="dataFreshness" class="muted">—</span>
    <span class="sep" aria-hidden="true">·</span>
    <span id="windowStartLine" class="muted"></span>
  </div>

  <nav class="dash-jump" aria-label="Jump to sections">
    <span class="jump-label">Jump</span>
    <a href="#dash-alerts-insights">Alerts &amp; insights</a>
    <a href="#dash-forensics">Forensics</a>
    <a href="#dash-traffic">Traffic</a>
    <a href="#dash-tools">Tool drill-down</a>
    <span class="jump-actions">
      <button type="button" class="btn-export" id="btnExportMetrics" title="Download last /api/metrics snapshot">Export JSON snapshot</button>
    </span>
  </nav>

  <div class="insight-row">
    <div class="insight-card">
      <h3>Session overview</h3>
      <div class="insight-stat" id="insightPassRate">—</div>
      <p class="insight-lede" id="insightVolumeLine">Waiting for traffic…</p>
    </div>
    <div class="insight-card">
      <h3>API &amp; integrations</h3>
      <p class="insight-lede" style="margin-top:0">Use the same endpoints for automation, Grafana, Datadog, or custom UIs.</p>
      <div class="link-row">
        <a class="link-chip" href="/api/metrics" target="_blank" rel="noopener">JSON metrics</a>
        <a class="link-chip" href="/metrics" target="_blank" rel="noopener">Prometheus</a>
        <a class="link-chip" href="/meta" target="_blank" rel="noopener">Build meta</a>
        <a class="link-chip" href="/api/health" target="_blank" rel="noopener">Health</a>
      </div>
    </div>
    <div class="insight-card">
      <h3>Top block categories</h3>
      <ul class="kind-list" id="kindPreview"><li class="muted">No blocks yet</li></ul>
    </div>
  </div>

  <div class="kpi-grid">
    <div class="kpi req"><h2>Requests</h2><div class="value" id="kpiReq">0</div><p class="kpi-foot">Allowed tool calls recorded in this process.</p></div>
    <div class="kpi block"><h2>Blocked</h2><div class="value" id="kpiBlocked">0</div><p class="kpi-foot">Denied by policy (rate limits, injection, RBAC, …).</p></div>
    <div class="kpi pii"><h2>PII redacted</h2><div class="value" id="kpiPii">0</div><p class="kpi-foot">Entities masked or removed by Presidio-style detection.</p></div>
    <div class="kpi cost"><h2>Cost</h2><div class="value" id="kpiCost">$0.00</div><p class="kpi-foot">Cumulative tracked spend (when cost middleware is enabled).</p></div>
  </div>

  <div class="alerts-insights-row" id="dash-alerts-insights">
    <div class="card alerts-panel-card">
      <div class="card-head">
        <h2>Recent alerts</h2>
        <p class="card-desc">Latest policy and system signals; the header badge mirrors this count.</p>
      </div>
      <div class="alerts alerts-prominent" id="alerts"></div>
    </div>
    <div class="card insights-panel-card">
      <div class="card-head">
        <h2>Insights &amp; anomalies</h2>
        <p class="card-desc">Heuristic auto-tuning hints from rolling aggregates (not ML). Act when patterns repeat.</p>
      </div>
      <div class="insight-summary" id="insightSummaryBar" aria-live="polite"></div>
      <div class="insights-feed" id="dashboardInsights"></div>
    </div>
  </div>

  <div class="card forensics-card" id="dash-forensics">
    <div class="card-head">
      <h2>Blocked requests (forensics)</h2>
      <p class="card-desc">Per-decision rows with trace and request IDs. Charts above are all tenants; filter this table by tenant.</p>
    </div>
    <div class="tenant-bar">
      <label for="tenantFilter">Tenant</label>
      <select id="tenantFilter" class="tenant-select" aria-label="Filter by tenant">
        <option value="">All tenants</option>
      </select>
      <button type="button" class="btn-apply" id="tenantApply">Apply</button>
      <button type="button" class="btn-ghost" id="tenantClear">Show all</button>
      <span class="muted" id="forensicsHint" style="font-size:0.8rem;"></span>
    </div>
    <div class="tool-table-wrap">
      <table class="tool-table" id="blockedForensicsTable">
        <thead>
          <tr>
            <th>Time (UTC)</th>
            <th>Tenant</th>
            <th>Tool</th>
            <th>Reason</th>
            <th>Trace</th>
            <th>Request</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="blockedForensicsBody"></tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2>Pillar health</h2>
      <p class="card-desc">Each tile reflects recent activity for that pillar in this in-memory metrics store.</p>
    </div>
    <div id="pillarHealth" class="pillar-grid"></div>
  </div>

  <div class="card">
    <div class="card-head">
      <h2>Blocks by category</h2>
      <p class="card-desc">Aggregated block kinds (normalized labels). Compare with the detailed &ldquo;blocked by reason&rdquo; doughnut below.</p>
    </div>
    <div class="chart-wrap sm"><canvas id="chartBlockKinds"></canvas></div>
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

  <div class="card" id="dash-traffic">
    <div class="card-head">
      <h2>Traffic · last <span id="tsWindow">10 min</span> · <span id="tsBucket">30s</span> buckets</h2>
      <p class="card-desc">Allowed vs blocked requests per bucket across the rolling window.</p>
    </div>
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

  <div class="card" id="dash-tools">
    <h2>Tool drill-down</h2>
    <div class="tool-table-wrap">
      <table class="tool-table" id="toolTable">
        <thead>
          <tr>
            <th>Tool</th>
            <th>Signal</th>
            <th>Total</th>
            <th>Allowed</th>
            <th>Blocked</th>
            <th>Blocked %</th>
            <th>Δ vs global</th>
            <th>P95 ms</th>
            <th>Avg ms</th>
            <th>Reasons</th>
          </tr>
        </thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <div id="traceModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="traceModalTitle">
    <div class="modal-box">
      <button type="button" class="modal-close" id="traceModalClose" aria-label="Close">&times;</button>
      <h3 id="traceModalTitle">Trace</h3>
      <pre id="traceModalBody"></pre>
    </div>
  </div>
  <div id="replayModal" class="modal-overlay" role="dialog" aria-modal="true" aria-labelledby="replayModalTitle">
    <div class="modal-box">
      <button type="button" class="modal-close" id="replayModalClose" aria-label="Close">&times;</button>
      <h3 id="replayModalTitle">Reproduce request (example)</h3>
      <p class="muted" style="font-size:0.8rem;margin:0 0 10px 0;">Not executed here. Paste into a shell after pointing at your MCP HTTP endpoint.</p>
      <pre id="replayModalBody"></pre>
    </div>
  </div>

  <script>
    const PALETTE = ['#38bdf8', '#a78bfa', '#34d399', '#fb7185', '#fbbf24', '#2dd4bf', '#f472b6', '#94a3b8'];
    const charts = {};
    let initialized = false;
    let chartUnavailableNotified = false;
    let lastBlockedIncidents = [];
    let lastForensicsRows = [];
    let forensicsTenantFilter = '';
    let lastSnapshotAt = 0;
    let lastMetricsSnapshot = null;
    let freshnessTimerStarted = false;

    function initChartDefaults() {
      if (typeof Chart === 'undefined') return false;
      var th = chartThemeColors();
      Chart.defaults.color = th.tick;
      Chart.defaults.borderColor = th.grid;
      Chart.defaults.font.family = '"DM Sans", system-ui, sans-serif';
      return true;
    }

    function updateThemeButton() {
      var theme = document.documentElement.getAttribute('data-theme');
      if (theme !== 'light' && theme !== 'dark') theme = 'dark';
      var dark = theme === 'dark';
      var btn = document.getElementById('themeToggle');
      if (!btn) return;
      btn.textContent = dark ? 'Light mode' : 'Dark mode';
      btn.setAttribute('aria-pressed', dark ? 'true' : 'false');
      btn.title = dark ? 'Switch to light background' : 'Switch to dark background';
    }
    function syncBodyThemeAttr() {
      var theme = document.documentElement.getAttribute('data-theme');
      if (theme !== 'light' && theme !== 'dark') theme = 'dark';
      if (document.body) document.body.setAttribute('data-theme', theme);
    }
    function setAppTheme(next) {
      if (next !== 'light' && next !== 'dark') next = 'dark';
      document.documentElement.setAttribute('data-theme', next);
      syncBodyThemeAttr();
      document.documentElement.style.colorScheme = next === 'light' ? 'light' : 'dark';
      try {
        localStorage.setItem('mcp-bastion-theme', next);
      } catch (e) {
        try { sessionStorage.setItem('mcp-bastion-theme', next); } catch (e2) {}
      }
      updateThemeButton();
      applyChartTheme();
      requestAnimationFrame(function () { applyChartTheme(); });
    }
    function chartThemeColors() {
      var theme = document.documentElement.getAttribute('data-theme');
      if (theme !== 'light' && theme !== 'dark') theme = 'dark';
      var light = theme === 'light';
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
      if (charts.blockKinds.options.plugins && charts.blockKinds.options.plugins.legend && charts.blockKinds.options.plugins.legend.labels) {
        charts.blockKinds.options.plugins.legend.labels.color = th.tick;
      }
      patchTooltip(charts.blockKinds.options.plugins);
      charts.blockKinds.update('none');
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
    function closeAlertMenu() {
      var menu = document.getElementById('alertMenu');
      var ab = document.getElementById('alertCountBtn');
      if (menu) menu.classList.remove('open');
      if (ab) ab.setAttribute('aria-expanded', 'false');
    }
    function openAlertMenu() {
      var menu = document.getElementById('alertMenu');
      var ab = document.getElementById('alertCountBtn');
      if (menu) menu.classList.add('open');
      if (ab) ab.setAttribute('aria-expanded', 'true');
    }

    function closeForensicsModals() {
      var a = document.getElementById('traceModal');
      var b = document.getElementById('replayModal');
      if (a) a.classList.remove('open');
      if (b) b.classList.remove('open');
    }
    function openTraceModal(inc) {
      var payload = {
        trace_id: inc.trace_id,
        request_id: inc.request_id,
        tenant_id: inc.tenant_id,
        tool: inc.tool,
        reason: inc.reason,
        decision: 'blocked',
        middleware: [
          { name: 'audit_log', ms: 0.8 },
          { name: 'mcp_bastion', ms: 3.1, outcome: 'deny' },
          { name: 'policy', ms: 1.2 }
        ],
        recorded_at: inc.ts
      };
      var body = document.getElementById('traceModalBody');
      var mo = document.getElementById('traceModal');
      if (body) body.textContent = JSON.stringify(payload, null, 2);
      if (mo) mo.classList.add('open');
    }
    function openReplayModal(inc) {
      var bodyObj = {
        jsonrpc: '2.0',
        method: 'tools/call',
        params: { name: inc.tool || 'unknown', arguments: {} },
        id: inc.request_id || '1'
      };
      var raw = JSON.stringify(bodyObj);
      var body = document.getElementById('replayModalBody');
      var mo = document.getElementById('replayModal');
      if (body) {
        body.textContent = [
          '1) Point MCP_HTTP_URL at your streamable HTTP MCP server.',
          '   export MCP_HTTP_URL=http://127.0.0.1:8080/mcp',
          '',
          '2) Required header for this row:',
          '   X-Tenant-Id: ' + (inc.tenant_id || 'default'),
          '',
          '3) JSON-RPC body:',
          raw,
          '',
          '4) Example curl (body is shell-quoted):',
          'curl -sS -X POST "$MCP_HTTP_URL" -H "Content-Type: application/json" -H "X-Tenant-Id: ' + (inc.tenant_id || 'default') + '" --data-raw ' + JSON.stringify(raw)
        ].join('\n');
      }
      if (mo) mo.classList.add('open');
    }
    function updateTenantSelect() {
      var sel = document.getElementById('tenantFilter');
      if (!sel) return;
      var tenants = {};
      (lastBlockedIncidents || []).forEach(function (i) {
        if (i.tenant_id) tenants[i.tenant_id] = true;
      });
      sel.innerHTML = '<option value="">All tenants</option>';
      Object.keys(tenants).sort().forEach(function (t) {
        var o = document.createElement('option');
        o.value = t;
        o.textContent = t;
        sel.appendChild(o);
      });
      if (forensicsTenantFilter && tenants[forensicsTenantFilter]) {
        sel.value = forensicsTenantFilter;
      } else {
        sel.value = '';
      }
    }
    function renderForensicsRows() {
      var tbody = document.getElementById('blockedForensicsBody');
      var hint = document.getElementById('forensicsHint');
      if (!tbody) return;
      var filter = forensicsTenantFilter || '';
      var rows = (lastBlockedIncidents || []).filter(function (i) {
        return !filter || i.tenant_id === filter;
      });
      lastForensicsRows = rows;
      if (hint) {
        hint.textContent = rows.length + ' row(s)' + (filter ? ' · tenant ' + filter : ' · all tenants');
      }
      if (!rows.length) {
        tbody.innerHTML = '<tr><td colspan="7" class="muted">No blocked requests in memory for this filter.</td></tr>';
        return;
      }
      tbody.innerHTML = rows.map(function (row, idx) {
        var ts = '';
        try {
          ts = new Date(row.ts).toISOString().replace('T', ' ').slice(0, 19);
        } catch (e1) { ts = String(row.ts || ''); }
        var reason = (row.reason || '').slice(0, 160);
        return '<tr>'
          + '<td>' + escapeHtml(ts) + '</td>'
          + '<td>' + escapeHtml(row.tenant_id || '') + '</td>'
          + '<td>' + escapeHtml(row.tool || '') + '</td>'
          + '<td>' + escapeHtml(reason) + '</td>'
          + '<td style="font-size:0.72rem;">' + escapeHtml(String(row.trace_id || '').slice(0, 40)) + '</td>'
          + '<td style="font-size:0.72rem;">' + escapeHtml(String(row.request_id || '').slice(0, 32)) + '</td>'
          + '<td><span class="btn-row-act">'
          + '<button type="button" class="btn-mini" data-act="trace" data-i="' + idx + '">View trace</button>'
          + '<button type="button" class="btn-mini" data-act="replay" data-i="' + idx + '">Reproduce</button>'
          + '</span></td>'
          + '</tr>';
      }).join('');
    }
    function renderForensics(incidents) {
      lastBlockedIncidents = incidents || [];
      updateTenantSelect();
      renderForensicsRows();
    }

    document.addEventListener('DOMContentLoaded', function () {
      var th0 = document.documentElement.getAttribute('data-theme');
      if (th0 === 'light' || th0 === 'dark') {
        document.documentElement.style.colorScheme = th0 === 'light' ? 'light' : 'dark';
      }
      syncBodyThemeAttr();
      updateThemeButton();
      var btn = document.getElementById('themeToggle');
      if (btn) {
        btn.addEventListener('click', function () {
          var cur = document.documentElement.getAttribute('data-theme');
          if (cur !== 'light' && cur !== 'dark') cur = 'dark';
          var next = cur === 'light' ? 'dark' : 'light';
          setAppTheme(next);
        });
      }
      var alertMenu = document.getElementById('alertMenu');
      var alertBtn = document.getElementById('alertCountBtn');
      var alertPanel = document.getElementById('alertDropdownPanel');
      if (alertMenu && alertBtn && alertPanel) {
        alertBtn.addEventListener('click', function (e) {
          e.stopPropagation();
          if (alertMenu.classList.contains('open')) {
            closeAlertMenu();
          } else {
            openAlertMenu();
          }
        });
        document.addEventListener('click', function () {
          closeAlertMenu();
        });
        alertMenu.addEventListener('click', function (e) {
          e.stopPropagation();
        });
        document.addEventListener('keydown', function (e) {
          if (e.key === 'Escape') {
            closeAlertMenu();
            closeForensicsModals();
          }
        });
      }
      var fbody = document.getElementById('blockedForensicsBody');
      if (fbody) {
        fbody.addEventListener('click', function (e) {
          var t = e.target;
          if (!t.getAttribute || !t.getAttribute('data-act')) return;
          var idx = parseInt(t.getAttribute('data-i'), 10);
          var row = lastForensicsRows[idx];
          if (!row) return;
          if (t.getAttribute('data-act') === 'trace') openTraceModal(row);
          if (t.getAttribute('data-act') === 'replay') openReplayModal(row);
        });
      }
      var tc = document.getElementById('traceModalClose');
      var rc = document.getElementById('replayModalClose');
      if (tc) tc.addEventListener('click', closeForensicsModals);
      if (rc) rc.addEventListener('click', closeForensicsModals);
      var tm = document.getElementById('traceModal');
      var rm = document.getElementById('replayModal');
      if (tm) tm.addEventListener('click', function (e) { if (e.target === tm) closeForensicsModals(); });
      if (rm) rm.addEventListener('click', function (e) { if (e.target === rm) closeForensicsModals(); });
      var tap = document.getElementById('tenantApply');
      var tcl = document.getElementById('tenantClear');
      if (tap) {
        tap.addEventListener('click', function () {
          var sel = document.getElementById('tenantFilter');
          forensicsTenantFilter = sel ? sel.value : '';
          renderForensicsRows();
        });
      }
      if (tcl) {
        tcl.addEventListener('click', function () {
          forensicsTenantFilter = '';
          var sel = document.getElementById('tenantFilter');
          if (sel) sel.value = '';
          renderForensicsRows();
        });
      }
      var ex = document.getElementById('btnExportMetrics');
      if (ex) {
        ex.addEventListener('click', function () {
          exportMetricsSnapshot();
        });
      }
      var bt = document.getElementById('backTop');
      if (bt) {
        window.addEventListener('scroll', function () {
          bt.classList.toggle('visible', window.scrollY > 380);
        }, { passive: true });
        bt.addEventListener('click', function () {
          window.scrollTo({ top: 0, behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
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
      if (!initChartDefaults()) return false;
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

      charts.blockKinds = new Chart(document.getElementById('chartBlockKinds'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE, borderWidth: 0, hoverOffset: 8 }] },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '58%',
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
      return true;
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

    function updateBlockKinds(obj) {
      const entries = Object.entries(obj || {}).sort((a, b) => b[1] - a[1]);
      if (!entries.length) {
        charts.blockKinds.data.labels = ['No categorized blocks'];
        charts.blockKinds.data.datasets[0].data = [1];
        charts.blockKinds.data.datasets[0].backgroundColor = ['rgba(148, 163, 184, 0.22)'];
      } else {
        charts.blockKinds.data.labels = entries.map((e) => e[0]);
        charts.blockKinds.data.datasets[0].data = entries.map((e) => e[1]);
        charts.blockKinds.data.datasets[0].backgroundColor = entries.map((_, i) => PALETTE[i % PALETTE.length]);
      }
      charts.blockKinds.update('none');
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

    function globalBlockedPct(d) {
      var req = d.requests_total || 0;
      var blk = d.blocked_total || 0;
      var inv = req + blk;
      return inv > 0 ? (100 * blk / inv) : 0;
    }

    function toolSignal(s, globalBp) {
      var t = s.total || 0;
      var bp = Number(s.blocked_pct || 0);
      var b = s.blocked || 0;
      if (t < 3) return { label: 'OK', cls: 'signal-ok' };
      var delta = bp - globalBp;
      if (bp >= 35 || delta >= 15) return { label: 'Hot', cls: 'signal-hot' };
      if (bp > globalBp + 5 || b >= 5 || bp >= 15) return { label: 'Watch', cls: 'signal-watch' };
      return { label: 'OK', cls: 'signal-ok' };
    }

    function formatDeltaPct(toolBp, globalBp) {
      var d = toolBp - globalBp;
      var sign = d > 0 ? '+' : '';
      return sign + d.toFixed(1) + ' pp';
    }

    function updateInsightSummaryBar(insights) {
      var bar = document.getElementById('insightSummaryBar');
      if (!bar) return;
      var list = insights || [];
      if (!list.length) {
        bar.innerHTML = '<span class="insight-chip muted" style="text-transform:none;font-weight:600;letter-spacing:0;border:1px solid var(--card-border);">No signals yet</span>';
        return;
      }
      var w = 0;
      var inf = 0;
      list.forEach(function (x) {
        if ((x.severity || '') === 'warning') w++;
        else inf++;
      });
      var parts = [];
      if (w) parts.push('<span class="insight-chip warn">' + w + ' attention</span>');
      if (inf) parts.push('<span class="insight-chip info">' + inf + ' informational</span>');
      bar.innerHTML = parts.join('');
    }

    function startFreshnessTicker() {
      if (freshnessTimerStarted) return;
      freshnessTimerStarted = true;
      setInterval(function () {
        var el = document.getElementById('dataFreshness');
        if (!el || !lastSnapshotAt) return;
        var sec = Math.floor((Date.now() - lastSnapshotAt) / 1000);
        el.textContent = sec < 2 ? 'just now' : sec + 's ago';
      }, 1000);
    }

    function flashPollStatus(msg) {
      var ps = document.getElementById('pollStatus');
      if (!ps) return;
      var prev = ps.textContent;
      ps.textContent = msg;
      setTimeout(function () {
        if (ps && ps.textContent === msg) ps.textContent = prev;
      }, 2400);
    }

    function exportMetricsSnapshot() {
      if (!lastMetricsSnapshot) {
        flashPollStatus('Export: wait until the first metrics sync completes.');
        return;
      }
      try {
        var blob = new Blob([JSON.stringify(lastMetricsSnapshot, null, 2)], { type: 'application/json' });
        var a = document.createElement('a');
        var stamp = new Date().toISOString().replace(/[:.]/g, '-');
        a.href = URL.createObjectURL(blob);
        a.download = 'mcp-bastion-metrics-' + stamp + '.json';
        a.rel = 'noopener';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
        var exBtn = document.getElementById('btnExportMetrics');
        if (exBtn) {
          var ob = exBtn.textContent;
          exBtn.textContent = 'Downloaded';
          exBtn.disabled = true;
          setTimeout(function () {
            exBtn.textContent = ob;
            exBtn.disabled = false;
          }, 1600);
        }
      } catch (e) {
        console.error(e);
        flashPollStatus('Export failed — see console.');
      }
    }

    function renderInsights(insights) {
      updateInsightSummaryBar(insights);
      var node = document.getElementById('dashboardInsights');
      if (!node) return;
      var list = insights || [];
      if (!list.length) {
        node.innerHTML = '<p class="insights-empty">No anomalies flagged yet — need more traffic or stronger signals (blocks, latency spread, cost burn).</p>';
        return;
      }
      node.innerHTML = list.map(function (x) {
        var sev = (x.severity === 'warning') ? 'warning' : 'info';
        return '<div class="insight-item ' + sev + '">'
          + '<div class="insight-title">' + escapeHtml(x.title || '') + '</div>'
          + '<div class="insight-detail">' + escapeHtml(x.detail || '') + '</div>'
          + '</div>';
      }).join('');
    }

    function updateToolTable(stats, d) {
      const body = document.querySelector('#toolTable tbody');
      d = d || {};
      var gbp = globalBlockedPct(d);
      const entries = Object.entries(stats || {})
        .sort((a, b) => (b[1].total || 0) - (a[1].total || 0))
        .slice(0, 12);
      if (!entries.length) {
        body.innerHTML = '<tr><td colspan="10" class="muted">No tool activity yet.</td></tr>';
        return;
      }
      body.innerHTML = entries.map(function (entry) {
        var tool = entry[0];
        var s = entry[1] || {};
        var reasons = Object.entries(s.blocked_reasons || {}).map(function (r) {
          return r[0] + ' (' + r[1] + ')';
        }).join(', ');
        var sig = toolSignal(s, gbp);
        var tbp = Number(s.blocked_pct || 0);
        return '<tr>'
          + '<td>' + escapeHtml(tool) + '</td>'
          + '<td><span class="signal-badge ' + sig.cls + '">' + escapeHtml(sig.label) + '</span></td>'
          + '<td>' + (s.total || 0) + '</td>'
          + '<td>' + (s.allowed || 0) + '</td>'
          + '<td>' + (s.blocked || 0) + '</td>'
          + '<td>' + tbp.toFixed(2) + '%</td>'
          + '<td>' + formatDeltaPct(tbp, gbp) + '</td>'
          + '<td>' + Number(s.latency_ms_p95 || 0).toFixed(2) + '</td>'
          + '<td>' + Number(s.latency_ms_avg || 0).toFixed(2) + '</td>'
          + '<td>' + escapeHtml(reasons || '—') + '</td>'
          + '</tr>';
      }).join('');
    }

    async function fetchMetrics() {
      const url = window.location.origin + '/api/metrics';
      const r = await fetch(url, { cache: 'no-store', credentials: 'same-origin' });
      if (!r.ok) {
        throw new Error('HTTP ' + r.status + ' from ' + url);
      }
      return r.json();
    }

    function formatWindowStart(iso) {
      if (!iso) return '';
      try {
        return 'Window started ' + new Date(iso).toLocaleString();
      } catch (e) {
        return '';
      }
    }

    function escapeHtml(s) {
      return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    }

    function formatAlertTs(iso) {
      if (!iso) return '';
      try {
        return new Date(iso).toLocaleString();
      } catch (e) {
        return '';
      }
    }

    function buildAlertsInnerHtml(alertsArr, opts) {
      opts = opts || {};
      var maxN = opts.max != null ? opts.max : 999;
      var includeTs = !!opts.includeTs;
      var list = (alertsArr || []).slice();
      if (maxN < 999) list = list.slice(-maxN);
      list = list.slice().reverse();
      if (!list.length) {
        return '<div class="alert" style="border-left-color:#64748b;">No alerts</div>';
      }
      return list.map(function (a) {
        var sev = (a.severity === 'critical') ? ' critical' : '';
        var ts = '';
        if (includeTs && a.ts) {
          ts = '<div class="alert-ts">' + escapeHtml(formatAlertTs(a.ts)) + '</div>';
        }
        return '<div class="alert' + sev + '">' + ts + escapeHtml(a.kind) + ': ' + escapeHtml(a.message || '') + '</div>';
      }).join('');
    }

    function render(d) {
      const n = (d.alerts && d.alerts.length) || 0;
      var countEl = document.getElementById('alertCountLabel');
      if (countEl) countEl.textContent = n + (n === 1 ? ' Alert' : ' Alerts');
      var acb = document.getElementById('alertCountBtn');
      if (acb) acb.setAttribute('aria-label', n + ' alert' + (n === 1 ? '' : 's') + ', open list');

      var ws = document.getElementById('windowStartLine');
      if (ws) ws.textContent = formatWindowStart(d.window_start);

      var fu = document.getElementById('footerUpdated');
      if (fu) fu.textContent = 'Last refresh: ' + new Date().toLocaleString();

      var req = d.requests_total || 0;
      var blk = d.blocked_total || 0;
      var total = req + blk;
      var ir = document.getElementById('insightPassRate');
      var iv = document.getElementById('insightVolumeLine');
      if (ir && iv) {
        if (total > 0) {
          var pass = (100 * req / total).toFixed(1);
          ir.innerHTML = pass + '<span class="unit">%</span>';
          iv.textContent = total.toLocaleString() + ' total invocations (' + req.toLocaleString() + ' allowed · ' + blk.toLocaleString() + ' blocked).';
        } else {
          ir.textContent = '—';
          iv.textContent = 'No traffic yet — route MCP tool calls through middleware that writes to this MetricsStore.';
        }
      }

      var kp = document.getElementById('kindPreview');
      if (kp) {
        var kinds = Object.entries(d.blocked_by_kind || {}).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 5);
        if (!kinds.length) {
          kp.innerHTML = '<li class="muted">No categorized blocks yet</li>';
        } else {
          kp.innerHTML = kinds.map(function (kv) {
            return '<li><span class="k">' + escapeHtml(kv[0]) + '</span><span class="v">' + kv[1] + '</span></li>';
          }).join('');
        }
      }

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

      document.getElementById('alerts').innerHTML = buildAlertsInnerHtml(d.alerts, { max: 12, includeTs: true });
      var drop = document.getElementById('alertDropdownList');
      if (drop) drop.innerHTML = buildAlertsInnerHtml(d.alerts, { max: 10, includeTs: true });

      renderInsights(d.dashboard_insights || []);

      renderForensics(d.blocked_incidents || []);

      if (!initialized && typeof Chart !== 'undefined') {
        initialized = createCharts();
      }
      if (!initialized) {
        if (!chartUnavailableNotified) {
          chartUnavailableNotified = true;
          console.warn('Chart.js not loaded yet; showing KPI data only until script is ready.');
        }
        return;
      }
      updateTraffic(d.time_series);
      updateReasons(d.blocked_by_reason);
      updateBlockKinds(d.blocked_by_kind);
      updateTools(d.top_tools);
      updateCost(d.cost_by_user);
      updatePiiEntity(d.pii_by_entity);
      updatePillarHealth(d.pillar_health);
      updateToolTable(d.tool_stats, d);
    }

    (async function poll() {
      try {
        var d = await fetchMetrics();
        lastMetricsSnapshot = d;
        lastSnapshotAt = Date.now();
        startFreshnessTicker();
        var ps = document.getElementById('pollStatus');
        if (ps) ps.textContent = 'Updated ' + new Date().toLocaleTimeString() + ' · every 2s';
        render(d);
      } catch (e) {
        console.error(e);
        var ps = document.getElementById('pollStatus');
        if (ps) {
          ps.textContent = 'Metrics unavailable — is the dashboard running on ' + window.location.origin + '? Try http://127.0.0.1:' + (window.location.port || '7000') + '/ if localhost fails (IPv6).';
        }
      }
      setTimeout(poll, 2000);
    })();
  </script>
  <p class="dash-footer">
    <strong>MCP-Bastion dashboard</strong> · Chart.js · Theme preference stored in this browser only<br>
    <span id="footerUpdated" class="muted"></span>
    <span class="footer-links">
      <a href="https://github.com/vaquarkhan/MCP-Bastion" target="_blank" rel="noopener">GitHub</a>
      <a href="https://pypi.org/project/mcp-bastion-python/" target="_blank" rel="noopener">PyPI</a>
      <a href="/api/metrics" target="_blank" rel="noopener">Raw metrics</a>
    </span>
  </p>
  </div>
  <button type="button" class="back-top" id="backTop" aria-label="Back to top" title="Back to top">↑</button>
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


def _dashboard_bind() -> tuple[str, int]:
    """Host/port for local dashboard (override: MCP_BASTION_DASHBOARD_HOST, MCP_BASTION_DASHBOARD_PORT)."""
    host = (os.environ.get("MCP_BASTION_DASHBOARD_HOST") or "127.0.0.1").strip() or "127.0.0.1"
    try:
        port = int((os.environ.get("MCP_BASTION_DASHBOARD_PORT") or "7000").strip() or "7000")
    except ValueError:
        port = 7000
    return host, port


if __name__ == "__main__":
    # Same as CLI: seed demo metrics unless explicitly disabled (MCP_BASTION_DEMO=0 / false / no).
    os.environ.setdefault("MCP_BASTION_DEMO", "1")
    import uvicorn

    _h, _p = _dashboard_bind()
    print(f"MCP-Bastion dashboard: http://{_h}:{_p}/  (leave this window open; Ctrl+C to stop)", flush=True)
    uvicorn.run(app, host=_h, port=_p)
