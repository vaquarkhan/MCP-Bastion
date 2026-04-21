# MCP-Bastion JSON-RPC error codes

MCP-Bastion raises structured errors that map to JSON-RPC `error.code` values on the MCP wire. Clients can branch on `code` for policy-specific handling (for example showing a cost-limit UI vs a generic block).

Base type: `MCPBastionError` (`code=-32000` default).

| Code | Python exception | Typical cause |
|------|------------------|---------------|
| `-32001` | `PromptInjectionError` | PromptGuard / injection heuristics flagged the payload. |
| `-32002` | `RateLimitExceededError` | Iteration cap, session rate, or token bucket limit. |
| `-32003` | `TokenBudgetExceededError` | FinOps token budget exhausted for the session. |
| `-32004` | `CircuitBreakerOpenError` | Tool failures exceeded threshold; circuit is open. |
| `-32005` | `ContentFilterError` | Paths, secrets, URLs, or denylist content blocked. |
| `-32006` | `RBACError` | Role does not allow this tool. |
| `-32007` | `SchemaValidationError` | Tool arguments failed schema validation. |
| `-32008` | `ReplayAttackError` | Duplicate nonce / replay guard. |
| `-32009` | `CostBudgetExceededError` | Session cost budget exceeded. |
| `-32010` | `SemanticFirewallError` | Semantic firewall blocked intent or dangerous chain. |
| `-32011` | `ExternalPolicyDeniedError` | OPA or Cedar denied the request. |
| `-32012` | `SensitiveContentError` | Sensitive classifier flagged business-sensitive content. |
| `-32013` | `AuthenticationError` | `edge_auth` missing or invalid metadata token. |
| `-32014` | `ToolNotAllowedError` | Tool not on `tool_allowlist`. |
| `-32015` | `SessionScopeExceededError` | Too many distinct tools in one session (`session_limits`). |
| `-32016` | `ToolMetadataPoisoningError` | `tools/list` metadata failed safety checks (strip/block). |

## Programmatic access

```python
from mcp_bastion.errors import ContentFilterError, MCPBastionError

try:
    ...
except MCPBastionError as e:
    payload = e.to_mcp_error()  # {"code": int, "message": str}
```

## See also

- [CLI](CLI.md) — `mcp-bastion validate`, `redteam`, `dashboard`
- [Policy as code](POLICY_AS_CODE.md) — toggles that drive these errors
