# Gateway boundary mode

MCP-Bastion is **in-process middleware** by default: security applies only when traffic passes through the wrapped handler. An attacker with direct access to an unwrapped MCP port can bypass pillars entirely.

**Boundary mode** means treating Bastion as a **mandatory network hop**  -  the only MCP entrypoint clients can reach. This closes the structural gap vs commercial gateways without rewriting Bastion as a full SaaS product.

## Threat model

| Mode | Bypass risk | When to use |
|------|-------------|-------------|
| **Embedded middleware** | Host app must call `MCPBastionMiddleware` on every path | Libraries, single-process servers you control |
| **Proxy boundary** | Clients cannot reach upstream MCP except via Bastion | Production, multi-tenant, third-party MCP servers |
| **Embedded + network policy** | Defense in depth | Kubernetes / VPC with NetworkPolicy |

## Proxy boundary checklist

1. **Bind upstream MCP to loopback**  -  `127.0.0.1` only; never expose raw MCP on `0.0.0.0` without auth.
2. **Expose only the Bastion proxy**  -  Docker: [../Dockerfile](../Dockerfile) + [../deploy/docker-compose.proxy.yml](../deploy/docker-compose.proxy.yml); only port **8080** published.
3. **Require edge authentication**  -  enable `edge_auth` or `agent_iam` so anonymous clients cannot call tools:

```yaml
edge_auth:
  enabled: true
  secret_env: BASTION_EDGE_SECRET
agent_iam:
  enabled: true
  require_token: true
```

4. **TLS termination**  -  Caddy/nginx in front; see [../deploy/docker-compose.proxy.yml](../deploy/docker-compose.proxy.yml) and [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md).
5. **NetworkPolicy / security groups**  -  allow ingress to proxy port only; deny direct routes to upstream MCP port.
6. **No alternate transports**  -  if upstream offers stdio + HTTP, disable or firewall the path that skips Bastion.
7. **Stateless readiness (opt-in)**  -  enable `mcp_transport.discovery` on the proxy so orchestrators can `GET /.well-known/mcp.json` without hitting upstream. See [HYBRID_MCP_TRANSPORT.md](HYBRID_MCP_TRANSPORT.md).

## Docker quick start (boundary)

```bash
docker pull ghcr.io/vaquarkhan/mcp-bastion-proxy:v2.0.0
# Set BASTION_EDGE_SECRET; mount bastion.yaml with edge_auth + pillars enabled
docker run -p 8080:8080 -e BASTION_EDGE_SECRET=... ghcr.io/vaquarkhan/mcp-bastion-proxy:v2.0.0
```

Clients must send the edge token in request metadata (`bastion_edge_token` by default). Without it, requests fail closed when `edge_auth.enabled: true`.

## What Bastion cannot enforce alone

- **Kernel/network isolation**  -  use firewall, service mesh, or sidecar placement.
- **Per-user upstream OAuth to GitHub/Notion**  -  roadmap P2; use an external gateway until shipped.
- **Cryptographic attestation** that the host process loaded middleware  -  use proxy boundary + mTLS between client and proxy.

## Related docs

- [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md)
- [HYBRID_MCP_TRANSPORT.md](HYBRID_MCP_TRANSPORT.md)
- [INTEGRATION_MODELS.md](INTEGRATION_MODELS.md)
- [BENCHMARKS.md](BENCHMARKS.md)  -  FinOps and injection efficacy benchmarks
- [ROADMAP.md](ROADMAP.md) P2 (OIDC JWT, hardened `mcp-bastion serve`)
