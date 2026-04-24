# Security pillars and `bastion.yaml` mapping

This page is the **authoritative** reference for what “pillar” means in MCP-Bastion: how controls map to **`bastion.yaml`**, **`BastionConfig`**, and the **dashboard** `pillar_health` field. Use it whenever documentation needs a consistent definition of controls versus broader deployment features.

## Two useful counts

| Term | Count | What it includes |
|------|-------|------------------|
| **Request-path controls** | **10** | Toggles on `MCPBastionMiddleware` that can block, shape, or transform tool traffic (`BastionConfig` fields wired to `enable_*` on the middleware). |
| **Policy file surface** | **13** | Every top-level section in `bastion.yaml` that `load_config()` reads: the 10 controls above, plus **audit**, **alerts**, and **hot_reload**. |

Anything beyond that (OpenTelemetry, standalone dashboard, CLI, Docker, npm package scope) is a **product or deployment capability**, not an extra line in `bastion.yaml`. If other docs use a larger “full stack” count, **define scope there** and link back to this page so readers know what is included.

## Request-path controls (10)

These are enforced (when enabled) on the MCP tool-call path inside `MCPBastionMiddleware`.

| # | Pillar | `bastion.yaml` section | `BastionConfig` field |
|---|--------|------------------------|----------------------|
| 1 | Prompt injection defense | `prompt_guard` | `prompt_guard` |
| 2 | PII redaction | `pii` | `pii` |
| 3 | Rate limiting / iteration caps | `rate_limit` | `rate_limit` (+ `rate_limit_*` tuning) |
| 4 | Circuit breaker | `circuit_breaker` | `circuit_breaker` |
| 5 | Content filter | `content_filter` | `content_filter` (+ pattern / URL flags) |
| 6 | RBAC | `rbac` | `rbac` (+ `rbac_permissions`) |
| 7 | Schema validation | `schema_validation` | `schema_validation` |
| 8 | Replay guard | `replay_guard` | `replay_guard` (+ `replay_require_nonce`) |
| 9 | Cost tracker | `cost_tracker` | `cost_tracker` (+ cost caps) |
| 10 | Semantic cache | `semantic_cache` | `semantic_cache` |

**Programmatic access:** `from mcp_bastion import load_config, BastionConfig, build_middleware_from_config` — policy flows through **`BastionConfig`** and **`build_middleware_from_config()`**, which returns composed middleware for your MCP server.

## Policy sections outside the inner middleware (3)

| # | Area | `bastion.yaml` section | Role |
|---|------|------------------------|------|
| 11 | Audit logging | `audit` | `AuditLogMiddleware` composes outside the inner bastion stack when enabled; feeds structured events (and optional export to sinks). |
| 12 | Alert sinks | `alerts` | Slack / HTTP webhooks, retry and backoff, `alert_on` filters — driven from `alerts` when URLs are set and audit export is configured. |
| 13 | Hot reload | `hot_reload` | Reloads `bastion.yaml` without process restart when using `build_middleware_from_config()` with a file-backed config. |

## Dashboard `pillar_health`

The metrics layer builds **11** named rows in `MetricsStore._build_pillar_health()`:

- All **10** request-path controls above (with block/traffic-based status where applicable).
- **Audit log** as an observability row.

**Alerts**, **hot reload**, **OTEL**, and the **standalone dashboard / Prometheus** stack surface through **`bastion.yaml`**, environment variables, and separate processes—**`pillar_health`** focuses on request-path controls plus audit status. See [METRICS.md](METRICS.md) and the main README for dashboard APIs.

## Summary

- For **engineering and red-team tuning**, use the **10** request-path toggles plus **audit** / **alerts** / **hot_reload** as in `bastion.yaml.example` and [POLICY_AS_CODE.md](POLICY_AS_CODE.md).
- The dashboard **`pillar_health`** list has **11** rows (the ten request-path controls plus audit). **Alerts** and **hot reload** are configured in **`bastion.yaml`** and related docs; their status is reflected through audit and operations tooling rather than extra `pillar_health` rows.
- When stating a single “total pillar” number in README or release notes, **point here** or spell the scope (policy-only vs product stack).
