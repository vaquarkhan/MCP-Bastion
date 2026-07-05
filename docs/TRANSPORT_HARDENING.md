# Transport hardening for MCP HTTP servers

MCP-Bastion middleware runs **after** the MCP SDK accepts a request. Attacks that hit your **local HTTP transport** directly (browser CSRF, DNS rebinding against `localhost:8000`) must be mitigated at the network and transport layer.

## The threat

A developer runs an MCP server on `localhost:8000` with access to local files or credentials. A malicious website uses JavaScript to send JSON-RPC to that port. The browser becomes a bridge — bypassing the AI agent entirely.

## Mitigations

### 1. Bind to loopback only (native dev)

```bash
python examples/llm_server.py --http 8000 --host 127.0.0.1
```

Default in `examples/llm_server.py` is already `127.0.0.1`. Do **not** expose MCP HTTP on `0.0.0.0` on a developer laptop without authentication.

### 2. Docker

Container images may bind `0.0.0.0` so port publishing works (`-p 8080:8080`). Treat the published port as **trusted-network only** or place a reverse proxy with auth in front.

### 3. Edge authentication (Bastion)

Enable shared-secret checks on tool calls when a gateway injects metadata:

```yaml
edge_auth:
  enabled: true
  metadata_key: bastion_edge_token
  secret_env: BASTION_EDGE_SECRET
```

Browsers cannot forge this token unless the secret is leaked. Pair with a gateway that strips unauthenticated browser traffic.

### 4. Production pattern

```
Internet → TLS reverse proxy (OAuth/mTLS) → MCP server (private network)
                ↓
         edge_auth token in metadata
```

Never expose raw MCP HTTP to the public internet.

## What Bastion does not do (today)

- CORS / `Origin` validation at the HTTP layer
- DNS rebinding protection
- Per-IP rate limits on HTTP listeners

These belong in your proxy, API gateway, or a future Bastion `serve` transport module.

## Related

- [BEYOND_OWASP.md](BEYOND_OWASP.md)
- [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md)
