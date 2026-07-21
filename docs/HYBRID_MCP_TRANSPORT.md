# Hybrid stateful / stateless MCP transport

MCP is evolving from **session-coupled** transports toward **stateless, per-request** flows ([SEP-2575](https://modelcontextprotocol.io/), explicit state handles). MCP-Bastion supports **both** without breaking existing deployments.

<p align="center">
  <img
    src="../images/mcp-bastion-hybrid-transport.svg"
    alt="MCP-Bastion hybrid transport: stateful sessions and stateless state handles through security pillars and Redis-backed FinOps keys"
    width="960"
    style="max-width:100%; height:auto; border-radius:12px; border:1px solid #1e293b;"
  />
</p>

## Design principles (zero-infra preserved)

| Principle | What it means |
|-----------|----------------|
| **Opt-in** | `mcp_transport.enabled: false` by default — existing `bastion.yaml` files behave exactly as before. |
| **Middleware, not gateway** | Bastion **consumes** identity signals (session ID or explicit state handle). It does **not** mint MCP server state, host edge WASM ML stacks, or replace a full SaaS API gateway. |
| **Pairs with Redis** | Stateless load balancing needs shared counters. Use `state_backend: redis` so rate limits, cost caps, replay nonces, and agent-stability windows sync across replicas. |
| **Proxy discovery is optional** | `GET /.well-known/mcp.json` is served only when discovery is enabled on the **HTTP proxy** path (`mcp-bastion serve --proxy`). |

## Stateful vs stateless at a glance

| Signal | Mode | Rate / cost key |
|--------|------|-----------------|
| `MCP-Session-Id` header or host `session_id` | **Stateful** (legacy) | `tenant:…\|principal:…\|session:…` |
| Explicit `state_handle` in tool args / headers / `_meta` | **Stateless** | `tenant:…\|principal:…\|handle:…` |
| `initialize` / `notifications/initialized` | **Stateful** | Session-based |
| Per-request `MCP-Protocol-Version` (when enabled) | **Stateless** | Handle or anonymous key |

Mode resolution (`auto` default):

1. Forced `mode: stateful` or `mode: stateless` wins.
2. Init methods → stateful.
3. Explicit state handle → stateless.
4. Declared protocol version → stateless.
5. Non-placeholder session ID → stateful.
6. Otherwise → stateless.

## Configuration

Add to `bastion.yaml` (see [bastion.yaml.example](../bastion.yaml.example)):

```yaml
mcp_transport:
  enabled: true
  mode: auto   # auto | stateful | stateless

  state_handle:
    param_names: [state_handle, mcp_state_handle]
    header_names: [mcp-state-handle, x-mcp-state-handle]
    required_in_stateless: false
    min_length: 16

  protocol:
    enabled: true
    header: MCP-Protocol-Version
    allowed_versions: ["2024-11-05", "2025-03-26"]
    default_version: "2024-11-05"

  discovery:
    enabled: true   # HTTP proxy only
    card:
      name: my-protected-mcp
      version: "1.0.0"

  stability:
    enabled: true
    window_size: 5
    repeat_threshold: 3
    similarity_threshold: 0.92
    on_detect: inject   # inject | block | warn

state_backend:
  type: redis
  redis_url: redis://127.0.0.1:6379/0
```

### HTTP proxy + discovery

```bash
mcp-bastion serve --proxy http://127.0.0.1:9000/mcp --config bastion.yaml
curl -s http://127.0.0.1:8080/.well-known/mcp.json | jq .
```

Discovery paths: `/.well-known/mcp.json`, `/.well-known/mcp`.

## Agent stability (infinite loop mitigation)

When `stability.enabled: true`, Bastion tracks recent tool **outputs** per scope (session or state handle). Near-identical repeats trigger:

| `on_detect` | Behavior |
|-------------|----------|
| `inject` | Append a circuit-breaker hint to tool result content (default) |
| `block` | Raise `AgentLoopDetectedError` (`-32030`) |
| `warn` | Stamp metadata only; allow the response |

This complements (does not replace) **token-bucket rate limits** and **cost caps** — blunt financial guardrails plus early oscillation detection.

## Error codes

| Code | Exception | When |
|------|-----------|------|
| `-32028` | `InvalidStateHandleError` | Handle missing, too short, or invalid charset |
| `-32029` | `ProtocolVersionError` | Unsupported declared protocol version |
| `-32030` | `AgentLoopDetectedError` | Stability monitor `on_detect: block` |

## What is intentionally out of scope

These belong in dedicated edge/gateway products, not this library:

- Pre-compiled ONNX / WASM PromptGuard at Cloudflare Workers scale
- Semantic vector caching tiers and embedding pipelines
- MCP state-handle **minting** or server-side session registries
- DNS TXT discovery (Bastion serves HTTP server cards on the proxy only)

Bastion already provides **local** PromptGuard, Presidio PII, lexical semantic cache/firewall, and Redis-backed FinOps — the hybrid transport layer wires them to the correct **identity key** for stateless traffic.

## Code references

| Module | Role |
|--------|------|
| `src/mcp_bastion/mcp_transport.py` | Mode detection, handle validation, rate-limit keys |
| `src/mcp_bastion/discovery_card.py` | Server card builder |
| `src/mcp_bastion/proxy_server.py` | Discovery endpoint + header ingestion |
| `src/mcp_bastion/pillars/agent_stability.py` | Repetitive output monitor |
| `src/mcp_bastion/middleware.py` | `_apply_mcp_transport_context()` on guarded surfaces |

## Related docs

- [HYBRID_TRANSPORT_TUTORIAL.md](HYBRID_TRANSPORT_TUTORIAL.md) — step-by-step proxy walkthrough
- [MCP_SURFACE_AND_SCALE.md](MCP_SURFACE_AND_SCALE.md) — full MCP method guards + Redis
- [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md) — mandatory proxy deployment
- [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md) — FinOps token buckets
- [ZERO_INFRA_STRATEGY.md](ZERO_INFRA_STRATEGY.md) — library vs gateway boundary

## Tests

```bash
pytest tests/test_mcp_transport.py tests/test_discovery_card.py tests/test_proxy_server_coverage.py tests/test_agent_stability.py -q
```
