# HTTP reverse proxy for MCP (P2)

See [../docs/TRANSPORT_HARDENING.md](../docs/TRANSPORT_HARDENING.md) for the full threat model and [../docs/GATEWAY_BOUNDARY.md](../docs/GATEWAY_BOUNDARY.md) for the mandatory proxy boundary checklist.

## Quick start

```bash
# MCP server on loopback only (example)
PYTHONPATH=src python examples/llm_server.py --http 8080 --host 127.0.0.1

# Optional Caddy front door (blocks browser Origin → localhost)
docker compose -f deploy/docker-compose.proxy.yml up
```

## Production pattern

```
Internet → TLS (OAuth/mTLS) → Caddy/nginx → MCP on private network
                              ↓
                    edge_auth / agent_iam token in metadata
```

Never expose raw MCP HTTP on `0.0.0.0` on a developer laptop without authentication.
