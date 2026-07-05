# Runtime Governance & Zero-Trust Control Plane

MCP-Bastion positions as the **Zero-Trust control plane** for Model Context Protocol deployments — runtime governance for multi-agent IAM and supply-chain verification at the MCP boundary.

## 1. Agent Identity & Access Management (Confused Deputy)

When multiple agents share one MCP server, each agent must carry a distinct identity and tool scope.

### Configure

```yaml
agent_iam:
  enabled: true
  token_metadata_key: bastion_agent_token   # JSON-RPC request metadata key
  require_token: true
  agents:
    - id: customer_support_bot
      token_env: BASTION_TOKEN_SUPPORT        # secret from environment
      allowed_tools: ["search_docs", "get_ticket_status"]
      blocked_tools: ["execute_sql", "delete_user"]
      rate_limit:
        max_iterations: 5
        timeout_seconds: 60
    - id: admin_bot
      token_env: BASTION_TOKEN_ADMIN
      allowed_tools: ["*"]
      blocked_tools: []
```

### Client wiring

Pass the agent token in MCP request metadata (exact key from `token_metadata_key`):

```python
context.metadata["bastion_agent_token"] = os.environ["BASTION_TOKEN_SUPPORT"]
```

Bastion will:

1. Authenticate the token (constant-time compare)
2. Stamp `agent_id` / `role` on the context for audit and RBAC
3. Enforce `blocked_tools` (hard deny) and `allowed_tools` (allow list)
4. Apply per-agent `rate_limit` when configured

Errors: `AuthenticationError` (-32013), `AgentAccessDeniedError` (-32019)

When `agent_iam` is enabled, the generic single-secret `edge_auth` pillar is skipped — use per-agent tokens instead.

## 2. Server cryptographic verification (supply chain)

Verify MCP server files match a trusted SHA-256 manifest before tool traffic flows.

### Generate manifest (after trusted build)

```bash
mcp-bastion manifest examples/llm_server.py pyproject.toml -o mcp-server.manifest.json
```

### Configure

```yaml
server_verification:
  enabled: true
  on_mismatch: block    # block | warn
  base_path: .
  manifest_path: mcp-server.manifest.json
  # or inline:
  # manifest:
  #   examples/llm_server.py: "abc123..."
```

At startup (and on each `tools/call` when enabled), Bastion compares on-disk hashes to the manifest. Mismatch raises `ServerVerificationError` (-32020) when `on_mismatch: block`.

### Doctor

```bash
mcp-bastion doctor --config bastion.yaml
```

Reports `agent_iam` and `server_verification` check status.

## Related

- [BEYOND_OWASP.md](BEYOND_OWASP.md)
- [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md)
- [PILLARS.md](PILLARS.md)
