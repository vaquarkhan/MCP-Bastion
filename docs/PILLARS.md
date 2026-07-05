# Security pillars and `bastion.yaml` mapping

This page is the **authoritative** reference for what “pillar” means in MCP-Bastion: how controls map to **`bastion.yaml`**, **`BastionConfig`**, and the **dashboard** `pillar_health` field. Counts differ by **scope** (core toggles vs full policy file vs health rows)  -  use the tables below; avoid a single vague “N pillars” without defining scope.

## How to count (scope matters - several common totals)

| Term | Count | What it includes |
|------|-------|------------------|
| **Core request-path toggles** | **10** | Original `MCPBastionMiddleware` feature flags: prompt guard, PII, rate limit, circuit breaker, content filter, RBAC, schema validation, replay guard, cost tracker, semantic cache (`BastionConfig` fields wired to `enable_*` on the middleware). |
| **Extended request-path / policy features** | **8** | **Semantic firewall**, **sensitive classifier**, **external policy** (OPA/Cedar), **edge auth**, **tool allowlist**, **session tool-cap** (scope), **tool metadata guard**, and **shadow mode** (constructor flag on the middleware, not a YAML boolean). |
| **Combined “pillars” (core + extended, request path)** | **18** | **10 + 8** from the two rows above. This is the usual full stack count when you list **all** first-class request-path and policy features together. **Additional** capabilities (multi-tenant, audit hash chain, pricing hooks, telemetry, governance, etc.) are configured separately; see the extended table below. |
| **JSON-RPC deny codes** | **18** | Errors **-32001** through **-32020** in `mcp_bastion.errors` (includes Agent IAM -32019, server verification -32020). |
| **Policy file surface (`bastion.yaml`)** | **20+** | Top-level keys read by `load_config()`  -  core sections, **audit_hash_chain**, **behavior_fingerprint**, **cost_attribution**, **policy_engine**, **multi_tenant**, **governance**, **telemetry**, **tool_metadata_guard**, **edge_auth**, **tool_allowlist**, **session_limits**, **state_backend**, **sensitive_classifier**, **semantic_firewall**, plus **audit**, **alerts**, **hot_reload**, etc. Exact set evolves with `BastionConfig`; treat `bastion.yaml.example` + `config.py` as source of truth. |
| **Dashboard `pillar_health` rows** | **14** | Built in `MetricsStore._build_pillar_health()`: 14 named rows in code (Prompt Guard, PII, Rate Limiter, Circuit Breaker, Content Filter, RBAC, Schema Validation, Semantic Firewall, Sensitive Classifier, External Policy, Replay Guard, Cost Tracker, Semantic Cache, Audit Log). Not every config-only or auxiliary feature (e.g. multi-tenant, edge auth alone) has its own row. |

**Programmatic access:** `from mcp_bastion import load_config, BastionConfig, build_middleware_from_config`  -  policy flows through **`BastionConfig`** and **`build_middleware_from_config()`**, which returns composed middleware for your MCP server.

## Core request-path controls (10)

These are enforced (when enabled) on the MCP tool-call path inside `MCPBastionMiddleware`.

| # | Pillar | `bastion.yaml` section | `BastionConfig` field |
|---|--------|------------------------|----------------------|
| 1 | Prompt injection defense | `prompt_guard` | `prompt_guard` |
| 2 | PII redaction | `pii` | `pii` |
| 3 | Rate limiting / iteration caps | `rate_limit` | `rate_limit` (+ `rate_limit_*` tuning) |
| 4 | Circuit breaker | `circuit_breaker` | `circuit_breaker` |
| 5 | Content filter | `content_filter` | `content_filter` (+ pattern / URL flags) |
| 6 | RBAC | `rbac` | `rbac` (+ `rbac_permissions`) |
| 7 | Schema validation | `schema_validation` | `schema_validation` (+ `schema_validation.schemas` tool→arg type map in YAML) |
| 8 | Replay guard | `replay_guard` | `replay_guard` (+ `replay_require_nonce`) |
| 9 | Cost tracker | `cost_tracker` | `cost_tracker` (+ cost caps) |
| 10 | Semantic cache (lexical) | `semantic_cache` | `semantic_cache`  -  Jaccard word overlap, not embeddings; see [BENCHMARKS.md](BENCHMARKS.md) |

## Extended request-path and policy features (1.0.16+)

The following are **additionally** wired in `bastion.yaml` and `BastionConfig` (and reflected in JSON-RPC error codes **-32010** through **-32020** for deny outcomes where applicable  -  see `mcp_bastion/errors.py`).

| Area | `bastion.yaml` sections (typical) | What it does |
|------|----------------------------------|----------------|
| **Agent IAM (Confused Deputy)** | `agent_iam` | Map API tokens to **agent identities**; per-agent tool allow/block lists and optional rate limits. See [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md). |
| **Server cryptographic verification** | `server_verification` | SHA-256 manifest checksums at startup and per `tools/call`; `mcp-bastion manifest` CLI. |
| Semantic firewall | `semantic_firewall` | Blocks unsafe tool/argument **sequences** and injection-style patterns before execution. |
| Sensitive business classifier | `sensitive_classifier` | Weighted and optional local classifier to flag M&A / insider-style content. |
| External policy (OPA / Cedar) | `policy_engine` | Delegates allow/deny to **OPA** or **Cedar** CLI (`opa eval -d` / `cedar evaluate`). Set `fail_closed: true` to deny when the engine is unavailable. |
| Edge authentication | `edge_auth` | Optional shared-secret check on request **metadata** (e.g. gateway-issued token). |
| Tool allowlist | `tool_allowlist` | Enforce a fixed list of tool names. |
| Session scope / privilege creep | `session_limits` | Cap distinct tools per session via `max_unique_tools_per_session` (0 = off). |
| Tool metadata guard | `tool_metadata_guard` | Sanitize or drop poisoned `tools/list` metadata. **Requires** `content_filter` or `prompt_guard` enabled. |
| **Shadow mode** | `MCPBastionMiddleware(..., shadow_mode=True)` (programmatic) | Log-only / alternate handling for some block paths; does not remove other pillars. |
| Multi-tenant | `multi_tenant` | Per-tenant `bastion.yaml` resolution and `tenant_id` in audit context. |
| Audit hash chain | `audit_hash_chain` | Chained **hash** over audit records for tamper evidence; optional **anchor** webhook. |
| Pricing (FinOps) | (see `pillars/pricing` + `cost_attribution` in config) | **Usage** pricing signal hooks alongside cost caps. |
| Telemetry sinks | `telemetry` | Pluggable **HTTP/OTLP**-style export hooks for events/metrics. |
| Supply-chain / ops | `mcp_bastion doctor` CLI | **doctor** preflight; **governance** beacon optional under `governance`  -  see [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md), [CLI.md](CLI.md). |
| **Full MCP surface (2.0.0)** | (uses core pillar flags) | Guards **`resources/read`**, **`prompts/get`**, **`sampling/createMessage`**, **`elicitation/create`**  -  see [MCP_SURFACE_AND_SCALE.md](MCP_SURFACE_AND_SCALE.md). |
| **Distributed state (2.0.0)** | `state_backend` | **`memory`** (default, single process) or **`redis`** for shared rate/replay/cost/session state across replicas. |
| **Argument guards (2.0.0)** | `argument_guards` | JSONPath + regex **block/redact** on `tools/call` arguments (`pip install mcp-bastion-python[policy]`). Error **-32022**. |
| **Audit JSONL (2.0.0)** | `audit.jsonl_path` | Append-only compliance log; **`mcp-bastion tail`** CLI. |
| **Cost checkpoint (2.0.0)** | `cost_tracker.checkpoint_path` | Disk persistence for session totals across restarts (memory backend only). |
| **Principal-keyed FinOps (2.0.0)** | `cost_tracker` + `agent_iam` / `edge_auth` | Session and daily caps aggregate by authenticated **`principal_id`** (not client-supplied `session_id` rotation). Set cost via `context.metadata["cost"]` on each tool call. |
| Red-team / policy dev | `mcp_bastion redteam`, `policy_simulator` module | **redteam** harness; **policy_simulator** for dry-runs. |

Supporting modules in `src/mcp_bastion/` and `pillars/`: e.g. `policy_simulator.py`, `redteam.py`, `tenant.py`, `governance_beacon.py`, `doctor.py`.

## Policy sections outside the inner middleware (3)

| # | Area | `bastion.yaml` section | Role |
|---|------|------------------------|------|
| A | Audit logging | `audit` | `AuditLogMiddleware` composes outside the inner bastion stack when enabled; feeds structured events (and optional export to sinks). |
| B | Alert sinks | `alerts` | Slack / HTTP webhooks, retry and backoff, `alert_on` filters  -  driven from `alerts` when URLs are set and audit export is configured. |
| C | Hot reload | `hot_reload` | Reloads `bastion.yaml` without process restart when using `build_middleware_from_config()` with a file-backed config. |

## Dashboard `pillar_health`

The metrics layer (`MetricsStore._build_pillar_health()`) builds **14** named rows, aligned to block **kinds** and spend signals for:

Prompt Guard, PII redaction, rate limit, circuit breaker, content filter, RBAC, schema validation, **semantic firewall**, **sensitive classifier**, **external policy**, replay guard, cost tracker, semantic cache, and **audit** observability.

**Alerts**, **hot reload**, **OTEL**, and **standalone dashboard / Prometheus** surface through config and separate processes. See [METRICS.md](METRICS.md).

## Summary

- For **policy-as-code**, use **`bastion.yaml.example`**, [POLICY_AS_CODE.md](POLICY_AS_CODE.md), and the extended table above.
- For **error codes**, use the [README error table](../README.md#error-handling) (**-32001** … **-32016**).
- When stating a single “how many pillars” number, **name the scope**  -  for example: **18** = core **10** + extended **8**; **14** = dashboard `pillar_health` rows; **20+** = top-level `bastion.yaml` areas  -  or link to this page.
