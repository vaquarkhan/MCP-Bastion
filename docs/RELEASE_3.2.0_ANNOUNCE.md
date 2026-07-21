# Show HN / release draft — MCP-Bastion 3.2.0

Use or trim for HN, LinkedIn, or GitHub release notes.

---

## Title

**Show HN: MCP-Bastion 3.2 — hybrid stateful/stateless MCP transport without breaking legacy clients**

---

## Body

MCP-Bastion is a **zero-infra, drop-in middleware** for Model Context Protocol servers: prompt injection defense, PII redaction, agent IAM, FinOps caps, and audit — all local, no third-party safety API.

**3.2.0** adds opt-in support for the upcoming **stateless MCP** model while keeping **legacy session-based** clients working on the same proxy.

### What shipped

- **`mcp_transport`** (default OFF) — resolves identity from `MCP-Session-Id` *or* explicit `state_handle`
- **Per-request protocol version** validation (SEP-2575 readiness)
- **Discovery card** on HTTP proxy: `GET /.well-known/mcp.json`
- **Agent stability monitor** — detect repetitive tool-output loops (`inject` / `block` / `warn`)
- **70+ tests** for hybrid transport; backward compatible with pre-3.2 configs

### Quick start

```bash
pip install mcp-bastion-python==3.2.0
cp examples/bastion-hybrid-transport.yaml bastion.yaml
mcp-bastion serve --proxy http://127.0.0.1:9000/mcp --http 8080 --config bastion.yaml
curl -s http://127.0.0.1:8080/.well-known/mcp.json
```

### What we deliberately did NOT build

No edge WASM ML stack, no semantic vector cache product, no MCP state minting — stays a **library**, not a SaaS gateway.

### Links

- Repo: https://github.com/vaquarkhan/MCP-Bastion
- Tutorial: https://github.com/vaquarkhan/MCP-Bastion/blob/main/docs/HYBRID_TRANSPORT_TUTORIAL.md
- PyPI: https://pypi.org/project/mcp-bastion-python/3.2.0/
- Docker: `ghcr.io/vaquarkhan/mcp-bastion-proxy:v3.2.0`

---

## One-liner for social

> MCP-Bastion 3.2: run stateful *and* stateless MCP clients on one proxy — opt-in, zero-infra, 18 PyPI packages + Docker.
