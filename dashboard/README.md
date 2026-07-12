# MCP-Bastion Dashboard

Optional **local** security + FinOps UI for MCP-Bastion. Additive panels on top of the classic runtime charts.

**Highlights (3.1.1):** pre-deploy posture + Sonar-style prevalidation, **PMD-style how-to-fix** issue guides, OWASP heatmaps, attack matrix, **RBAC + governance tiles**, posture drift from audit JSONL, **token reduction & cost savings** (actual vs would-have-been), forensics with pillar provenance.

Zero-infra: read-only over local artifacts + in-process metrics. No login, no DB, no cloud. See [docs/ZERO_INFRA_STRATEGY.md](../docs/ZERO_INFRA_STRATEGY.md).

## Screenshots / tour

<p align="center">
  <img src="../images/mcp-bastion-dashboard-tour.gif" alt="Dashboard feature tour GIF — posture, how-to-fix, FinOps, RBAC" width="900" />
</p>
<p align="center">
  <img src="../images/mcp-bastion-dashboard.png" alt="Dashboard collage" width="900" />
</p>

### Tour slides (in the GIF)

| # | Slide | What you see |
|---|-------|----------------|
| 01 | Overview | KPIs, posture grades, jump links |
| 02 | Posture + prevalidation | A–F grades + Sonar-style issue list |
| 03 | **How to fix** | PMD-style guide: why / fix steps / Bastion knobs / OWASP |
| 04 | OWASP heatmaps | ASI / MCP / LLM tabs |
| 05 | Attack matrix | Live pressure by category |
| 06 | Compliance | Evidence reports + bundle |
| 07 | **RBAC + governance** | RBAC, prompt guard, rate/cost, PII, Agent IAM, …
| 08 | Forensics | Why blocked + Details / reproduce |
| 09 | Agents | Confused-deputy denials + scope map |
| 10 | Posture drift | Audit JSONL allow/block + drift Δ |
| 11 | **Token & cost savings** | Actual vs would-have-been + charts |
| 12 | Traffic | Time series + block reasons (incl. RBAC) |

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
| **Security posture** | A–F grades from `mcp-bastion scan` / `scan --skills` / `osv-scan` / `audit` JSON |
| **Static prevalidation** | Sonar-style issue list (`/api/prevalidate`) — not SonarQube |
| **Issue guides** | PMD-style why / how to fix / Bastion knobs / OWASP refs (`/api/issue-guide`) |
| **OWASP / ASI / MCP / LLM** | Coverage heatmaps (tabs); click a cell for sample findings |
| **Live attack matrix** | Categories under pressure + intensity + OWASP tags + sample/trace |
| **Compliance evidence** | Policy/attestation hashes; SOC2/GDPR/ISO/NIST/ASI report or zip bundle |
| **Runtime governance & policy** | **RBAC**, prompt guard, rate limit, cost, PII, schema, content filter, Agent IAM, server verification, transport |
| **KPIs + charts** | Requests, blocks, PII, cost, traffic, reasons, tools, latency |
| **Cost burn & reduction** | Actual vs would-have-been spend/tokens; FinOps savings + **tokens avoided by blocks**; graphs + blocked-issue table |
| **Posture drift** | Daily allow/block from audit JSONL, drift Δ, top drivers, recent blocks |
| **Forensics** | Why (pillar/rule), Details modal with guide + trace, reproduce helpers |
| **Agents** | Denied-by-agent + Agent IAM scope map |
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
```

Richer scripted demo: `PYTHONPATH=src python examples/dashboard_demo.py`

Open [http://localhost:7000/](http://localhost:7000/).

**If you see `{"detail":"Not Found"}`:** check [http://localhost:7000/api/health](http://localhost:7000/api/health) — must include `"service":"mcp-bastion-dashboard"` and `"ui_revision"`.

**If the UI looks unchanged:** restart the dashboard (or `--reload`) and hard-refresh the browser. Check `/meta` for `ui_revision`.

**If charts show all zeros:** use `mcp-bastion dashboard --demo` or wire middleware to `MetricsStore`.

## Endpoints

| URL | What it returns |
|-----|-----------------|
| GET / | Visual dashboard with charts |
| GET /api/metrics | Runtime KPIs + `cost_reduction` (used/saved/avoided + would-have cost) + forensics |
| GET /api/posture | Pre-deploy grades from `.bastion/scan/*.json` |
| GET /api/prevalidate | Sonar-style issue list + grades |
| GET /api/issue-guide?check=weak_schema | PMD-style rule card (or `?id=ASI02`) |
| GET /api/taxonomy?framework=asi\|mcp\|llm | OWASP heatmaps |
| GET /api/attack-matrix | Live attack categories |
| GET /api/compliance | Attestation + policy hash |
| GET /api/compliance/report | Evidence markdown download |
| GET /api/compliance/bundle | Zip evidence bundle |
| GET /api/observe | Observe-mode banner data |
| GET /api/agents | Denied-by-agent + Agent IAM scope |
| GET /api/governance | RBAC + core pillars + zero-trust feature flags |
| GET /api/trends | Posture drift from audit JSONL |
| GET /api/onboarding | First-run checklist |
| GET /api/alerts/stream | SSE alerts |
| GET /api/health | `ui_revision` + service id |
| GET /metrics | Prometheus text |

## Pre-deploy panels (local artifacts only)

1. **Security posture / prevalidate** — write scan JSON, then refresh:
   ```bash
   mkdir -p .bastion/scan
   mcp-bastion scan tools.json --format json -o .bastion/scan/catalog.json
   mcp-bastion scan --skills ./skills --format json -o .bastion/scan/skills.json
   mcp-bastion osv-scan --format json -o .bastion/scan/osv.json
   mcp-bastion audit --format json -o .bastion/scan/risk-audit.json
   ```
2. **Issue guides** — click **Why / how to fix** on any finding (bundled in `issue_guides.py`).
3. **OWASP heatmaps** — taxonomy + enabled pillars from `bastion.yaml`.
4. **FinOps** — output budget / discovery filter / cache savings + estimated tokens avoided when Bastion blocks a call.
5. **Posture drift** — enable `audit.jsonl_path` (or `MCP_BASTION_AUDIT_PATH`) for daily allow/block trends.
6. **Compliance** — `mcp-bastion attest export -o .bastion/attestations/…`
7. **Observe mode** — `mode: observe` in `bastion.yaml`.

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
