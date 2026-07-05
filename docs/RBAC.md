# RBAC (role-based access control)

MCP-Bastion RBAC limits which MCP **tools** each caller may invoke. It runs on the `tools/call` path inside `MCPBastionMiddleware` and returns JSON-RPC error **-32006** when access is denied.

Pair RBAC with **Agent IAM** or **edge auth** in production so roles are stamped by your gateway, not self-asserted by the client.

## Quick start

```yaml
# bastion.yaml
rbac:
  enabled: true
  require_authenticated_identity: true   # default; keep true in production
  permissions:
    default: []                          # deny by default
    viewer: ["read_*", "query"]
    analyst: ["read_*", "query", "create_report"]
    admin: ["*"]
```

Enable the middleware from config:

```python
from mcp_bastion import load_config, build_middleware_from_config

config = load_config("bastion.yaml")
middleware = build_middleware_from_config(config)
```

Validate before deploy:

```bash
mcp-bastion validate --config bastion.yaml
```

## How roles are resolved

RBAC reads the caller role from request **metadata**:

| Source | Field | Notes |
|--------|-------|-------|
| Authenticated identity | `context.metadata["role"]` or `["agent"]` | Used when `agent_iam` or `edge_auth` sets `bastion_authenticated_role` |
| Dev / unauthenticated | `metadata["role"]` | Only when `require_authenticated_identity: false` |

With `require_authenticated_identity: true` (default), RBAC **blocks** if no server-verified identity is present. This prevents clients from spoofing `"role": "admin"`.

### Production pattern: Agent IAM + RBAC

Use Agent IAM for **who** (token to agent identity) and RBAC for **what** (role to tool patterns):

```yaml
agent_iam:
  enabled: true
  token_metadata_key: bastion_agent_token
  agents:
    - id: support_bot
      token_env: BASTION_TOKEN_SUPPORT
      allowed_tools: ["search_docs", "get_ticket"]
      # IAM allowlist runs first; RBAC adds role-based fnmatch rules

rbac:
  enabled: true
  permissions:
    support: ["search_*", "get_*"]
    admin: ["*"]
```

Stamp role from your gateway via **BYOI identity adapter**:

```yaml
identity_adapter:
  enabled: true
  type: header
  header_name: X-Bastion-Role
  role_metadata_key: role
```

See [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md) and [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md).

## Permission patterns

| Pattern | Meaning | Example match |
|---------|---------|---------------|
| `*` | All tools | any tool name |
| Exact name | Single tool | `read_file` matches only `read_file` |
| `read_*` | fnmatch glob | `read_file`, `read_db` |
| `files_*` | Prefix glob | `files_list`, `files_upload` |

When multiple globs match, the **most specific** pattern wins (longest literal run).

## YAML reference

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Turn RBAC on |
| `require_authenticated_identity` | bool | `true` | Reject unauthenticated role claims |
| `permissions` | map | `{}` | Role name to list of tool names/globs |

Example roles from `bastion.yaml.example`:

```yaml
rbac:
  enabled: true
  permissions:
    default: ["*"]
    analyst: ["read_data", "query"]
    admin: ["*"]
```

## Error codes and troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Role 'X' cannot access tool 'Y'` | Tool not in role permissions | Add glob or exact name to role |
| `Role 'X' has no tool permissions` | Empty permission list for role | Set permissions or use `default` fallback |
| `role is not from an authenticated identity` | No IAM/edge auth | Enable `agent_iam` or `edge_auth`, or set `require_authenticated_identity: false` for local dev only |
| RBAC never fires | `rbac.enabled: false` | Set `enabled: true` and reload config |

Dashboard: check **RBAC** row under `pillar_health` when metrics are enabled ([METRICS.md](METRICS.md)).

## Benchmarks

Measured viewer/admin/nobody matrix: [BENCHMARKS.md](BENCHMARKS.md#rbac-tool-level-opt-in).

Regenerate locally:

```bash
PYTHONPATH=src python -m pytest tests/test_benchmarks_finops_rbac.py -q
```

## Related docs

- [FEATURES.md](FEATURES.md) - all 18 pillars
- [POLICY_AS_CODE.md](POLICY_AS_CODE.md) - full `bastion.yaml` schema
- [PILLARS.md](PILLARS.md) - pillar numbering and dashboard mapping
- [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md) - Agent IAM and server verification
- [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md) - RBAC attack walkthrough
