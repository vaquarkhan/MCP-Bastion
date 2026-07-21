# Policy-as-Code (bastion.yaml)

Single config file controls MCP-Bastion policy. Use `bastion.yaml` in project root or set `BASTION_CONFIG` to a path.

**Canonical pillar list and counts** (request-path vs `bastion.yaml` vs dashboard): see [PILLARS.md](PILLARS.md).

## Example

Copy `bastion.yaml.example` to `bastion.yaml`:

```yaml
prompt_guard:
  enabled: true

pii:
  enabled: true

rate_limit:
  enabled: true
  max_iterations: 15
  timeout_seconds: 60
  token_budget: 50000

rbac:
  enabled: true
  permissions:
    default: ["read_data"]
    admin: ["*"]

cost_tracker:
  enabled: true
  max_cost_per_session: 0.50
  max_cost_per_day: 10.0

audit:
  enabled: true

alerts:
  slack_webhook:   # or set env SLACK_WEBHOOK_URL
  alert_on: [injection, rate_limit, cost]
  webhook_url: https://your-server.com/alerts
  webhooks:
    - https://hooks.slack.com/...
    - https://events.pagerduty.com/...
  retry_attempts: 3
  retry_backoff_seconds: 0.25
  retry_backoff_max_seconds: 2.0
  timeout_seconds: 5.0

content_filter:
  enabled: true
  block_code_execution: true
  block_file_paths: true
  block_urls: false
  allowlist_patterns: []
  denylist_patterns:
    - "(?i)password"

hot_reload:
  enabled: true
  poll_seconds: 2.0
```

## Load in code

```python
from mcp_bastion import load_config, build_middleware_from_config

# Load from bastion.yaml or BASTION_CONFIG; optional: load_config("path/to/bastion.yaml")
config = load_config()
middleware = build_middleware_from_config(config)
# Wire middleware into your MCP server
```

One-liner (load + build in one call):

```python
from mcp_bastion import build_middleware_from_config

middleware = build_middleware_from_config()
```

## Schema

| Section | Keys | Description |
|---------|------|-------------|
| prompt_guard | enabled | Meta PromptGuard for injection |
| pii | enabled | PII redaction (Presidio) |
| rate_limit | enabled, max_iterations, timeout_seconds, token_budget | Token bucket |
| circuit_breaker | enabled | Per-tool circuit breaker |
| content_filter | enabled, block_code_execution, block_file_paths, block_urls, allowlist_patterns, denylist_patterns | Content filter with explicit allow/deny tuning |
| rbac | enabled, permissions | Role -> list of tools |
| schema_validation | enabled | Input schema validation |
| replay_guard | enabled, require_nonce | Replay protection |
| cost_tracker | enabled, max_cost_per_session, max_cost_per_day, checkpoint_path | Cost budgets keyed by authenticated principal (2.0.0); set per-call cost in `metadata["cost"]` |
| semantic_cache | enabled | Semantic cache |
| audit | enabled | Audit log + metrics |
| alerts | slack_webhook, webhook_url, webhooks, alert_on, retry_attempts, retry_backoff_seconds, retry_backoff_max_seconds, timeout_seconds | Slack/generic webhook(s), alert kinds, and retry/backoff policy |
| hot_reload | enabled, poll_seconds | Reload `bastion.yaml` in process without restart |
| mcp_transport | enabled, mode, state_handle, protocol, discovery, stability | Hybrid stateful/stateless identity (opt-in). See [HYBRID_MCP_TRANSPORT.md](HYBRID_MCP_TRANSPORT.md) |
| state_backend | type, redis_url, key_prefix | Shared Redis state for multi-replica deploys |

Install PyYAML for YAML loading: `pip install pyyaml`.
