# MCP-Bastion Dashboard

Optional **local** security + FinOps UI for MCP-Bastion. Additive panels on top of the classic runtime charts: **pre-deploy posture**, **OWASP heatmaps**, **attack matrix**, **dated compliance reports**, **token savings**, and forensics with pillar provenance.

Zero-infra guardrail: read-only over local artifacts + in-process metrics. No login, no DB, no cloud. See [docs/ZERO_INFRA_STRATEGY.md](../docs/ZERO_INFRA_STRATEGY.md).

## Screenshots / tour

<p align="center">
  <img src="../images/mcp-bastion-dashboard-tour.gif" alt="Dashboard feature tour GIF" width="900" />
</p>
<p align="center">
  <img src="../images/mcp-bastion-dashboard.png" alt="Dashboard collage" width="900" />
</p>

Regenerate captures (dashboard must be running with demo data):

```bash
mcp-bastion dashboard --demo
# other terminal:
python scripts/capture_dashboard_demo.py
```

Slides land in `images/dashboard-demo/slides/` and publish to `images/mcp-bastion-dashboard*.png|gif`.

Tour GIF defaults to **~5 seconds per slide** (readable on GitHub). Rebuild without re-capturing:

```bash
python scripts/capture_dashboard_demo.py --gif-only
python scripts/capture_dashboard_demo.py --gif-only --duration-ms 6000
```

## What is on the board

| Section | Purpose |
|---------|---------|
| **Date filters** | Scope forensics, trends, attack matrix, and report downloads |
| **Security posture** | A-F grades from `mcp-bastion scan` / `scan --skills` / `osv-scan` / `audit` JSON |
| **OWASP / ASI / MCP / LLM** | Coverage heatmaps (tabs); click a cell for sample findings |
| **Live attack matrix** | Categories under pressure + intensity + OWASP tags + sample/trace |
| **Compliance evidence** | Policy/attestation hashes; SOC2/GDPR/ISO/NIST/ASI report or zip bundle |
| **Runtime governance** | Agent IAM, server verification, transport, stdio, fingerprint |
| **KPIs + charts** | Requests, blocks, PII, cost, traffic, reasons, tools, latency |
| **Cost burn & reduction** | Actual vs would-have-been spend/tokens; FinOps savings + block avoidance graphs; blocked-issue table |
| **Forensics** | Why (pillar/rule), Details modal with trace, reproduce helpers |
| **Alerts / insights** | Recent alerts (SSE push) + heuristic anomalies |
| **Observe banner** | When `mode: observe`, shows would-have-blocked counts |

## Run

```bash
cd MCP-Bastion
pip install fastapi uvicorn
# With demo metrics (charts non-zero without a separate MCP server):
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

Open [http://localhost:7000/](http://localhost:7000/) - the UI shows a **KPI summary strip** (totals, block %, top threat, active users) and loading guidance while metrics connect; **PII** charts use **severity-style** colors for entity types, and long **block reasons** are readable via tooltips / expand-in-place where applicable.

**If you see `{"detail":"Not Found"}`** on some URL, that response is from *a* FastAPI app, but not our route - wrong path, wrong port, or another process. Try [http://localhost:7000/api/health](http://localhost:7000/api/health) first: it must include `"service":"mcp-bastion-dashboard"` and `"ui_revision"`. Short diagnostic: [http://localhost:7000/meta](http://localhost:7000/meta).

**If the UI looks unchanged after editing `dashboard/app.py`:** the server only loads HTML at startup. Stop the process and start again, **or** run `mcp-bastion dashboard --reload` so `dashboard/` is watched. Always run from the **repository root** (the folder that contains `dashboard/`). Check `/meta` - `dashboard_app_py` must point at this repo's `dashboard/app.py`, and `ui_revision` should match the current code.

**If charts show all zeros:** the in-memory store is empty until middleware records traffic. Use **`mcp-bastion dashboard --demo`** or **`MCP_BASTION_DEMO=1`** to load the same rich seed as `examples/dashboard_demo.py`, or run the full `examples/dashboard_demo.py` process.

## Endpoints

| URL | What it returns |
|-----|-----------------|
| GET / | Visual dashboard with charts |
| GET /api/metrics | JSON: runtime KPIs plus `cost_reduction` (`tokens_saved`, `estimated_usd_saved`, `by_source`), `time_series`, `blocked_incidents`, … |
| GET /api/posture | Pre-deploy grades (catalog / skills / OSV / risk audit) from `.bastion/scan/*.json` (override with `MCP_BASTION_SCAN_DIR`) |
| GET /api/prevalidate | Sonar-style issue list + grades from the same local scan JSON (not SonarQube) |
| GET /api/issue-guide?check=weak_schema | PMD-style rule card: why / how to fix / OWASP refs / bastion knobs |
| GET /api/issue-guide?id=ASI02 | Same for an OWASP ASI / MCP / LLM id |
| GET /api/taxonomy?framework=asi\|mcp\|llm | OWASP ASI / MCP / LLM Top 10 heatmap |
| GET /api/attack-matrix?date_from=&date_to= | Live attack category matrix (blocks + finding pressure) |
| GET /api/compliance | Last attestation + policy hash (local files under `.bastion/attestations/`, override `MCP_BASTION_ATTEST_DIR`) |
| GET /api/compliance/report?framework=soc2\|gdpr\|iso27001\|nist_ai_rmf\|asi&date_from=&date_to= | Download markdown evidence report (not a certificate) |
| GET /api/compliance/bundle?framework=…&date_from=&date_to= | Zip: report + attestation + `bastion.yaml` |
| GET /api/observe | Observe-mode banner: `mode`, `would_have_blocked` |
| GET /api/agents | Denied-by-agent counts + Agent IAM scope map |
| GET /api/trends | Block-rate sparkline series from local audit JSONL |
| GET /api/onboarding | First-run checklist when the board is empty |
| GET /api/alerts/stream | SSE push for recent alerts (canary / auto-repave / observe) |
| GET /api/health | `{"status":"ok","service":"mcp-bastion-dashboard","ui_revision":...}` |
| GET /api/dashboard-meta | Same build info as health |
| GET /meta | Same JSON (short URL) |
| GET /metrics | Prometheus text format (Grafana/Datadog) |

## Pre-deploy panels (local artifacts only)

The dashboard stays a **read-only view over files the CLI already writes**. No login, no DB, no cloud.

1. **Security posture** — write scan JSON, then refresh:
   ```bash
   mkdir -p .bastion/scan
   mcp-bastion scan tools.json --format json -o .bastion/scan/catalog.json
   mcp-bastion scan --skills ./skills --format json -o .bastion/scan/skills.json
   mcp-bastion osv-scan --format json -o .bastion/scan/osv.json
   mcp-bastion audit --format json -o .bastion/scan/risk-audit.json
   ```
2. **OWASP heatmaps** — `taxonomy.py` + enabled pillars from `bastion.yaml` + recent metrics (`asi` / `mcp` / `llm` tabs).
3. **Issue guides** — every finding/detail opens a PMD-style card (why it matters, how to fix, bastion.yaml knobs, OWASP reference links). Bundled in `issue_guides.py` — offline; links are optional browser opens.
4. **Static prevalidation** — `/api/prevalidate` surfaces the same scan suite as a Sonar-like issue list on the dashboard (local JSON only; not a SonarQube install).
5. **Compliance evidence** — drop attestation JSON under `.bastion/attestations/` (from `mcp-bastion attest export -o …`) and use the Generate / Download buttons (date-filtered).
6. **Observe mode** — set `mode: observe` in `bastion.yaml`; the banner shows would-have-blocked counts from the in-process metrics store.

See [docs/ZERO_INFRA_STRATEGY.md](../docs/ZERO_INFRA_STRATEGY.md).

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
