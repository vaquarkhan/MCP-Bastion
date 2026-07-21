# Hybrid stateful / stateless MCP transport tutorial

Step-by-step guide for running MCP-Bastion with **legacy session-based** clients and **stateless** clients (explicit state handles) on the same proxy - without breaking either path.

**Canonical reference:** [HYBRID_MCP_TRANSPORT.md](HYBRID_MCP_TRANSPORT.md)

<p align="center">
  <img
    src="../images/mcp-bastion-hybrid-transport.svg"
    alt="Hybrid MCP transport architecture"
    width="960"
    style="max-width:100%; height:auto; border-radius:12px; border:1px solid #1e293b;"
  />
</p>

---

## Prerequisites

- Python 3.10+
- `pip install mcp-bastion-python[policy,redis]` (Redis optional for single-process dev)
- An upstream MCP server on HTTP (streamable HTTP at `/mcp`), or use `examples/llm_server.py`

---

## Step 1 - Copy sample policy

```bash
cp examples/bastion-hybrid-transport.yaml bastion.yaml
mcp-bastion validate --config bastion.yaml
```

For local dev, `state_backend.type: memory` is fine. For **multiple proxy replicas** behind a load balancer, switch to Redis:

```yaml
state_backend:
  type: redis
  redis_url: redis://127.0.0.1:6379/0
```

---

## Step 2 - Start upstream MCP (loopback)

Bind upstream to **127.0.0.1** only so clients cannot bypass Bastion:

```bash
# Terminal A - example upstream
mcp-bastion serve --http 9000 --host 127.0.0.1
```

---

## Step 3 - Start Bastion HTTP proxy

```bash
# Terminal B - boundary proxy with hybrid transport
mcp-bastion serve --proxy http://127.0.0.1:9000/mcp --http 8080 --host 0.0.0.0 --config bastion.yaml
```

Clients connect to **port 8080**, not 9000.

---

## Step 4 - Discovery (no initialize handshake)

Orchestrators can discover capabilities before connecting:

```bash
curl -s http://127.0.0.1:8080/.well-known/mcp.json | jq .
```

Expected fields include `protocolVersions`, `transport.modes` (`stateful`, `stateless`), and `bastion.hybridTransport: true`.

---

## Step 5 - Stateful client (legacy)

Send MCP requests with a session header - behavior matches pre-3.2 deployments:

```bash
curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Content-Type: application/json" \
  -H "MCP-Session-Id: my-legacy-session-1234567890" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "echo", "arguments": {"message": "hello"}}
  }'
```

Bastion resolves `mcp_transport_mode: stateful` and keys rate/cost limits by session.

---

## Step 6 - Stateless client (explicit state handle)

Stateless clients pass a **server-minted** handle on every tool call (Bastion validates entropy; it does not mint handles):

```bash
HANDLE="client-state-handle-abc1234567890"

curl -s -X POST http://127.0.0.1:8080/mcp \
  -H "Content-Type: application/json" \
  -H "MCP-Protocol-Version: 2025-03-26" \
  -H "MCP-State-Handle: $HANDLE" \
  -d "{
    \"jsonrpc\": \"2.0\",
    \"id\": 2,
    \"method\": \"tools/call\",
    \"params\": {
      \"name\": \"echo\",
      \"arguments\": {\"message\": \"hello\", \"state_handle\": \"$HANDLE\"}
    }
  }"
```

Bastion resolves `mcp_transport_mode: stateless` and keys limits by `handle:$HANDLE` - consistent across load-balanced replicas when Redis is enabled.

---

## Step 7 - Agent stability (infinite loop mitigation)

With `stability.enabled: true`, repeated identical tool errors trigger graceful recovery:

| `on_detect` | Behavior |
|-------------|----------|
| `inject` (default) | Append circuit-breaker hint to tool result |
| `block` | Deny with `AgentLoopDetectedError` (`-32030`) |
| `warn` | Metadata flag only |

Test by forcing a tool to return the same error three times; the fourth response should include the stability hint (inject mode).

---

## Step 8 - In-process middleware (no proxy)

If you wrap your own server, enable the same `mcp_transport` block - middleware stamps identity on every guarded surface:

```python
from mcp_bastion import build_middleware_from_config

middleware = build_middleware_from_config("bastion.yaml")

async def handle_mcp(context, call_next):
    return await middleware(context, call_next)
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `InvalidStateHandleError` | Handle must be 16–256 URL-safe chars; set `required_in_stateless: false` during migration |
| `ProtocolVersionError` | Add client version to `protocol.allowed_versions` or disable `protocol.enabled` |
| Rate limits not shared across pods | Set `state_backend.type: redis` |
| Discovery 404 | Enable `mcp_transport.discovery.enabled` and use `serve --proxy` |
| Stateful clients broken after enable | Keep `mode: auto`; do not force `stateless` until clients migrate |

---

## Next steps

- [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md) - production proxy checklist
- [MCP_SURFACE_AND_SCALE.md](MCP_SURFACE_AND_SCALE.md) - Redis + full MCP method guards
- [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md) - FinOps token buckets
- [examples/bastion-hybrid-transport.yaml](../examples/bastion-hybrid-transport.yaml) - copy-paste config
