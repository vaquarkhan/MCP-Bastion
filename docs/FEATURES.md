# Feature guide (all pillars)

How to enable and use every MCP-Bastion security control. For schema details see [POLICY_AS_CODE.md](POLICY_AS_CODE.md); for pillar counts see [PILLARS.md](PILLARS.md).

## Core request-path controls (10)

### 1. Prompt injection defense (`prompt_guard`)

Blocks jailbreak and injection payloads on inbound tool arguments and extended MCP methods.

```yaml
prompt_guard:
  enabled: true
  threshold: 0.85
  heuristic_fallback: true
  fail_open: false
  use_ungated_default: true    # ProtectAI DeBERTa (no HF gate); default
  # model_id: meta-llama/Llama-Prompt-Guard-2-86M  # only when use_ungated_default: false
```

- **Enable:** `prompt_guard.enabled: true`
- **Error code:** -32001
- **CLI:** `mcp-bastion redteam` for harness scores ([REDTEAM.md](REDTEAM.md))
- **Tip:** Default ML model is ungated (`use_ungated_default: true`). Keep `fail_open: false` in production. Set `use_ungated_default: false` only if you intentionally use gated Llama Prompt Guard + HF login.

### 2. PII redaction (`pii`)

Scrubs emails, phones, SSN-style patterns from tool outputs before they reach the model.

```yaml
pii:
  enabled: true
```

- **Enable:** `pii.enabled: true`
- **Error code:** -32002 (block) or silent redact depending on path
- **Dashboard:** PII row in `pillar_health`

### 3. Rate limiting (`rate_limit`)

Token bucket on iterations, timeout, and optional per-tool caps.

```yaml
rate_limit:
  enabled: true
  max_iterations: 15
  timeout_seconds: 60
  token_budget: 50000
  max_per_tool: 0
```

- **Enable:** `rate_limit.enabled: true`
- **Error code:** -32003
- **Multi-replica:** set `state_backend.type: redis` ([MCP_SURFACE_AND_SCALE.md](MCP_SURFACE_AND_SCALE.md))

### 4. Circuit breaker (`circuit_breaker`)

Per-tool failure threshold; opens circuit after repeated errors.

```yaml
circuit_breaker:
  enabled: true
```

- **Enable:** `circuit_breaker.enabled: true`
- **Error code:** -32004

### 5. Content filter (`content_filter`)

Blocks code execution patterns, file paths, URLs; supports allow/deny lists.

```yaml
content_filter:
  enabled: true
  block_code_execution: true
  block_file_paths: true
  block_urls: true
```

- **Enable:** `content_filter.enabled: true`
- **Error code:** -32005
- **Required for:** `tool_metadata_guard` (must also enable `content_filter` or `prompt_guard`)

### 6. RBAC (`rbac`)

Role-based tool access with fnmatch globs.

```yaml
rbac:
  enabled: true
  require_authenticated_identity: true
  permissions:
    viewer: ["read_*"]
    admin: ["*"]
```

- **Full guide:** [RBAC.md](RBAC.md)
- **Error code:** -32006

### 7. Schema validation (`schema_validation`)

Validates tool arguments against declared types per tool.

```yaml
schema_validation:
  enabled: true
  schemas:
    create_report:
      year: integer
      amount: number
```

- **Enable:** `schema_validation.enabled: true` + per-tool `schemas`
- **Error code:** -32007

### 8. Replay guard (`replay_guard`)

Detects duplicate request IDs / nonces.

```yaml
replay_guard:
  enabled: true
  require_nonce: false
```

- **Enable:** `replay_guard.enabled: true`
- **Error code:** -32008
- **Multi-replica:** Redis `state_backend`

### 9. Cost tracker (`cost_tracker`)

Session and daily spend caps keyed by authenticated principal.

```yaml
cost_tracker:
  enabled: true
  max_cost_per_session: 10.0
  max_cost_per_day: 100.0
  checkpoint_path: /var/lib/bastion/cost.ckpt
```

- **Enable:** `cost_tracker.enabled: true`
- **Set per-call cost:** `context.metadata["cost"]` on each tool call
- **Error code:** -32009
- **FinOps:** [BENCHMARKS.md](BENCHMARKS.md), [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md)

### 10. Semantic cache (`semantic_cache`)

Lexical (Jaccard) cache for repeated tool argument patterns.

```yaml
semantic_cache:
  enabled: true
  similarity_threshold: 0.85
```

- **Enable:** `semantic_cache.enabled: true`
- **Note:** Word overlap, not embeddings; see [BENCHMARKS.md](BENCHMARKS.md)

## Extended request-path controls (8)

### 11. Semantic firewall (`semantic_firewall`)

Blocks unsafe tool/argument sequences and injection-style chains.

```yaml
semantic_firewall:
  enabled: true
```

- **Error code:** -32010

### 12. Sensitive classifier (`sensitive_classifier`)

Flags M&A / insider-style business content.

```yaml
sensitive_classifier:
  enabled: true
  threshold: 0.7
```

- **Error code:** -32011

### 13. External policy (`policy_engine`)

Delegate allow/deny to OPA or Cedar CLI.

```yaml
policy_engine:
  enabled: true
  engine: opa
  fail_closed: true
  opa:
    policy_path: policies/bastion.rego
```

- **Error code:** -32012
- **Install:** `pip install mcp-bastion-python[policy]`

### 14. Edge auth (`edge_auth`)

Shared-secret check on request metadata (gateway-issued token).

```yaml
edge_auth:
  enabled: true
  metadata_key: bastion_edge_token
  secret_env: BASTION_EDGE_SECRET
```

- **Error code:** -32013
- **Guide:** [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md), [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md)

### 15. Tool allowlist (`tool_allowlist`)

Fixed list of permitted tool names.

```yaml
tool_allowlist:
  enabled: true
  tools: ["search_docs", "get_weather"]
```

- **Error code:** -32014
- **Pairs with:** `discovery_filter` to shrink `tools/list` ([BENCHMARKS.md](BENCHMARKS.md))

### 16. Session scope (`session_limits`)

Caps distinct tools per session (privilege creep prevention).

```yaml
session_limits:
  enabled: true
  max_unique_tools_per_session: 10
```

- **Error code:** -32015
- **Multi-replica:** Redis `state_backend`

### 17. Tool metadata guard (`tool_metadata_guard`)

Sanitizes poisoned `tools/list` metadata.

```yaml
tool_metadata_guard:
  enabled: true
```

- **Requires:** `content_filter` or `prompt_guard` enabled
- **Error code:** -32016

### 18. Shadow mode (programmatic)

Log-only evaluation for some block paths without denying.

```python
from mcp_bastion.middleware import MCPBastionMiddleware

middleware = MCPBastionMiddleware(..., shadow_mode=True)
```

- **Not a YAML boolean**; set on constructor for policy dry-runs

## Additional 2.0.0 capabilities

| Feature | YAML / CLI | Doc |
|---------|------------|-----|
| Agent IAM | `agent_iam` | [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md) |
| Server verification | `server_verification`, `mcp-bastion manifest` | [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md) |
| Argument guards | `argument_guards` | [MCP_SURFACE_AND_SCALE.md](MCP_SURFACE_AND_SCALE.md) |
| Full MCP surface | core flags on all methods | [MCP_SURFACE_AND_SCALE.md](MCP_SURFACE_AND_SCALE.md) |
| Redis state | `state_backend` | [MCP_SURFACE_AND_SCALE.md](MCP_SURFACE_AND_SCALE.md) |
| Audit JSONL | `audit.jsonl_path`, `mcp-bastion tail` | [CLI.md](CLI.md) |
| Cost-aware policy | `cost_policy` | [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md) |
| Governance attestation | `mcp-bastion attest export` | [CLI.md](CLI.md) |
| Boundary mode | `boundary_mode`, `serve --proxy` | [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md) |
| BYOI identity | `identity_adapter` | [ZERO_INFRA_STRATEGY.md](ZERO_INFRA_STRATEGY.md) |
| Secrets resolver | `secrets` | [ZERO_INFRA_STRATEGY.md](ZERO_INFRA_STRATEGY.md) |
| Syslog SIEM | `telemetry.sinks` | [SECURITY_OBSERVABILITY.md](SECURITY_OBSERVABILITY.md) |

## Supporting features (outside inner middleware)

| Feature | Section | Doc |
|---------|---------|-----|
| Audit logging | `audit` | [SECURITY_OBSERVABILITY.md](SECURITY_OBSERVABILITY.md) |
| Alert sinks | `alerts` | [METRICS.md](METRICS.md) |
| Hot reload | `hot_reload` | [POLICY_AS_CODE.md](POLICY_AS_CODE.md) |
| Multi-tenant | `multi_tenant` | [USE_CASES.md](USE_CASES.md) |
| OTEL / Prometheus | `telemetry`, dashboard | [OTEL.md](OTEL.md), [METRICS.md](METRICS.md) |
| Red-team harness | CLI | [REDTEAM.md](REDTEAM.md) |
| Supply-chain doctor | CLI | [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) |

## Enable everything (dev only)

Use `bastion.yaml.example` as a starting point. Production should enable only what you need and pair RBAC/FinOps with authenticated identity.

```bash
cp bastion.yaml.example bastion.yaml
mcp-bastion validate --config bastion.yaml
mcp-bastion serve --config bastion.yaml --http 8080
```

## Error code quick reference

| Code | Pillar |
|------|--------|
| -32001 | Prompt guard |
| -32002 | PII |
| -32003 | Rate limit |
| -32004 | Circuit breaker |
| -32005 | Content filter |
| -32006 | RBAC |
| -32007 | Schema validation |
| -32008 | Replay guard |
| -32009 | Cost tracker |
| -32010 | Semantic firewall |
| -32011 | Sensitive classifier |
| -32012 | External policy |
| -32013 | Edge auth |
| -32014 | Tool allowlist |
| -32015 | Session limits |
| -32016 | Tool metadata guard |
| -32019 | Agent IAM |
| -32020 | Server verification |
| -32022 | Argument guards |
| -32025 | Exfiltration canary (`canary_goallock`) |
| -32026 | Local LLM scanner |
| -32027 | ATR threat rules |

Full table: [README error handling](../README.md#error-handling)

## Runtime governance pillars (3.0+)

Opt-in enterprise controls for production MCP runtimes. See [ENTERPRISE_RUNTIME_CONTROLS.md](ENTERPRISE_RUNTIME_CONTROLS.md).

| Pillar | Config key |
|--------|------------|
| Exfiltration canary | `canary_goallock` |
| ATR YAML rules | `atr_rules` |
| Local LLM scanner | `llm_scanner` |
| Threat intel feeds | `threat_feeds` |
| Auto-repave | `auto_repave` |
| Secret pattern redaction | `secrets.redact_patterns` |
| Observe mode | `mode: observe` |

CLI: `mcp-bastion report --framework soc2 --audit ./audit.jsonl`
