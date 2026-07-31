# Reversible PII vault (abstraction + hydration)

Opt-in privacy mode that **tokenizes** PII instead of permanently destroying it - so agents/LLMs never see raw emails, SSNs, or phones, while MCP tools can still execute with the real values.

> **Default unchanged:** `pii.enabled: true` still uses **destructive** Presidio placeholders (`<EMAIL_ADDRESS>`, …). Vault is **OFF** until you set `pii_vault.enabled: true`.

## Why

Destructive masking breaks tool calling:

```text
Agent: "send invite to alice@example.com"
Destructive: "send invite to <EMAIL_ADDRESS>"  → calendar tool fails
Vault:       "send invite to {{pii:EMAIL_ADDRESS:a3f9…}}"
  → LLM never sees alice@…
  → next tools/call args hydrated back to alice@… before the MCP server runs
```

## Diagram

![PII vault abstract and hydrate](../images/mcp-bastion-pii-vault.svg)

## Enable

```yaml
pii:
  enabled: true

pii_vault:
  enabled: true      # default false
  ttl_seconds: 3600  # session map TTL (memory or Redis state_backend)
  # token_style: typed        # default — {{pii:TYPE:csprng}}
  # token_style: low_entropy  # optional — EMAIL_ADDRESS_1 / Person_A

# Recommended for multi-replica:
# state_backend:
#   type: redis
#   redis_url: redis://127.0.0.1:6379/0
```

No new required package dependencies. Detection uses existing Presidio (+ regex fallback for email/SSN/phone when Presidio is unavailable).

## Lifecycle

| Phase | When | Effect |
|-------|------|--------|
| **Abstract** | Outbound tool/resource text (middleware **and** HTTP proxy) | PII → tokens stored in session vault |
| **Hydrate** | Inbound `tools/call` arguments (middleware **and** proxy, before upstream) | Tokens → original plaintext for the MCP server |

### Token styles

| `token_style` | Example | Notes |
|---------------|---------|--------|
| `typed` (default) | `{{pii:EMAIL_ADDRESS:a3f9b2c1d4e5}}` | CSPRNG id - never a hash of plaintext |
| `low_entropy` (opt-in) | `EMAIL_ADDRESS_1`, `Person_A` | Lower uncanny-valley for LLMs; still session-scoped |

Same value within a session reuses the same token so the LLM stays coherent.

## Metrics

Dashboard / `MetricsStore` counters (when vault is enabled):

- `pii_vault_abstract_total` - outbound tokenizations
- `pii_vault_hydrate_total` - inbound restorations

## Streaming helper

`BufferedTokenRestorer` restores tokens split across chunks (`{{pii:` … `}}`). The HTTP proxy mutates **SSE** (`text/event-stream`) event-complete JSON-RPC `data:` frames and buffered JSON bodies.

## Security notes

- Session-scoped maps; TTL wipe; use Redis `state_backend` when load-balancing
- Do not log plaintext next to tokens in custom sinks
- Vault does **not** replace PromptGuard, RBAC, or FinOps

## Tutorial

Step-by-step: [PII_VAULT_TUTORIAL.md](PII_VAULT_TUTORIAL.md)

## Related

- [SECURITY.md](SECURITY.md) - OWASP / PII posture
- [MCP_SURFACE_AND_SCALE.md](MCP_SURFACE_AND_SCALE.md) - Redis `state_backend`
- [ZERO_INFRA_STRATEGY.md](ZERO_INFRA_STRATEGY.md) - memory default, Redis opt-in
