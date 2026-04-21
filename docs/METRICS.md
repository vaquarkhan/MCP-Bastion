# Performance Overhead & Effectiveness Metrics

MCP-Bastion is designed for low latency and measurable security effectiveness. This document describes how to interpret and collect these metrics.

---

## Performance Overhead

### Proxy overhead (without ML)

When **prompt injection** and **PII redaction** are disabled (rate limiting only), the middleware adds a small amount of latency per request. The validation checklist measures this:

- **Target:** Under **5 ms** added per tool call (excluding ML inference).
- **How it’s measured:** `scripts/validate_checklist.py` runs 100 requests without Bastion (baseline) and 100 with Bastion (rate limit only), then computes the difference.

```bash
PYTHONPATH=src python scripts/validate_checklist.py
# Look for: "Proxy overhead < 5ms (excl. ML)" and "Overhead: X.XXms"
```

- **Typical result:** On a modern machine, overhead is well under 5 ms (often &lt; 1 ms for the rate-limit-only path).

### When ML is enabled

- **PromptGuard (injection):** Adds latency proportional to model inference (e.g. tens to a few hundred ms per call depending on hardware). Run locally (CPU or GPU) so data does not leave your network.
- **PII redaction (Presidio):** Adds latency per response (e.g. tens of ms depending on text length and entities). Tune by limiting entities or response size if needed.

Use the **dashboard** and **Prometheus** metrics (see below) to observe request volume and latency in production.

---

## Effectiveness Metrics

These metrics show how well MCP-Bastion is blocking threats and protecting data.

### From the dashboard

Run `mcp-bastion dashboard --port 7000` and open http://localhost:7000/. You get:

| Metric | Meaning |
|--------|--------|
| **Requests** | Total tool (and optionally resource) requests seen. |
| **Blocked** | Number of requests blocked (injection, rate limit, RBAC, content filter, etc.). |
| **Blocked %** | Percentage of requests blocked; useful for tuning thresholds and understanding abuse. |
| **PII redacted** | Number of responses where PII was redacted (count of redaction events). |
| **Cost** | Sum of cost recorded via cost tracker (e.g. per-session or per-tenant). |
| **Blocked by reason** | Breakdown of why requests were blocked (injection, rate_limit, rbac, content_filter, cost_budget, schema, etc.). |
| **Top tools** | Most frequently used tools; helps identify high-value or high-risk tools. |
| **Cost by user** | Cost per user/session when cost tracker is used with a user identifier. |
| **Recent alerts** | Last N alerts (injection, rate_limit, cost, rbac, etc.) for quick triage. |
| **Cost attribution** | `cost_attribution.by_provider`, `by_model`, `by_tool`, `by_dataset` for FinOps drill-down. |
| **Tenants** | `tenants` map: per-tenant `requests_total`, `blocked_total`, `cost_total` when multi-tenant traffic is tagged. |
| **Audit chain** | `audit_chain` includes `head_hash`, `chain_length`, recent links for tamper-evidence visibility. |
| **Auto-tune** | `auto_tune.recent_anomalies` surfaces latency spikes, call-rate spikes, and behavior drift. |

### From the API

- **JSON metrics:** `GET http://localhost:7000/api/metrics` returns the same data as the dashboard in JSON (e.g. for custom dashboards or automation).
- **Tenant-scoped metrics:** `GET http://localhost:7000/api/metrics?tenant_id=acme` adds a `tenant_view` object for that tenant while preserving global aggregates.
- **Forensics with tenant:** `GET http://localhost:7000/api/forensics?blocked_only=true&limit=20&tenant_id=acme`
- **Audit verify:** `POST http://localhost:7000/api/audit/verify` with JSON body `{ "events": [ ... exported forensic rows ... ] }` returns chain validity.
- **Prometheus:** `GET http://localhost:7000/metrics` exposes Prometheus format so you can scrape with Grafana/Datadog and set alerts (e.g. on `blocked_total` or `blocked_pct`).

### From OpenTelemetry

If OTLP is configured (explicitly or via auto-detection; see [OTEL.md](OTEL.md)), each tool call is recorded as a span with attributes such as `mcp.tool`, `mcp.action`, `mcp.latency_ms`, and `mcp.error` when blocked. Use that to measure latency and blocked rate per tool in your observability stack.

---

## Interpreting Effectiveness

- **Blocked %:** A non-zero blocked rate is expected (malicious or abusive traffic). Very high blocked % might indicate overly strict rules (e.g. prompt threshold) or a real attack surge; use “blocked by reason” to tune.
- **PII redacted:** Confirms that PII detection is active; combine with logging to ensure no raw PII is logged.
- **Cost and cost by user:** Helps enforce budgets and detect runaway sessions or expensive tenants.

Use the dashboard and alerts (Slack, webhook) to react to spikes in blocked count or cost. See [dashboard/README.md](../dashboard/README.md) and [SETUP_GUIDE.md](../SETUP_GUIDE.md) for wiring the dashboard and audit callbacks.
