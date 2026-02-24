# Policy-as-Code (bastion.yaml)

Single config file controls all MCP-Bastion pillars. Use `bastion.yaml` in project root or set `BASTION_CONFIG` to a path.

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
| content_filter | enabled | Content filter |
| rbac | enabled, permissions | Role -> list of tools |
| schema_validation | enabled | Input schema validation |
| replay_guard | enabled, require_nonce | Replay protection |
| cost_tracker | enabled, max_cost_per_session, max_cost_per_day | Cost budgets |
| semantic_cache | enabled | Semantic cache |
| audit | enabled | Audit log + metrics |
| alerts | slack_webhook, webhook_url, webhooks, alert_on | Slack, generic webhook(s), and alert kinds |

Install PyYAML for YAML loading: `pip install pyyaml`.
