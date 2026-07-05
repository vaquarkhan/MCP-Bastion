# Beyond OWASP MCP Top 10

OWASP MCP Top 10 covers agent-to-server risks at the protocol boundary. MCP-Bastion maps to all ten (see [README](../README.md)). This page covers **additional runtime threats** that OWASP does not list separately and how Bastion addresses them today.

| Threat | Bastion coverage | Config / notes |
|--------|------------------|----------------|
| **Browser → localhost MCP (CSRF / DNS rebind)** | Partial | Middleware cannot fix transport. Use `127.0.0.1` bind, `edge_auth`, reverse proxy. See [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md). |
| **Confused Deputy (multi-agent IAM)** | Primary | `agent_iam`: token → agent identity, per-tool allow/block, per-agent rate limits. See [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md). |
| **Registry typosquatting / tampered server** | Primary | `server_verification`: SHA-256 manifest checksums at startup and per request. |
| **stdio stdout JSON injection** | Gap | No byte-stream validator. Avoid `print()` in servers; pin deps; run `mcp-bastion doctor`. |
| **Context flooding (denial-of-wallet)** | Primary | `token_budget`, `output_budget`, `max_response_bytes`, `cost_tracker`. See [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md#8-context-flooding-denial-of-wallet). |
| **Multi-agent state poisoning** | Partial | `response_scan`, `prompt_guard`, RBAC, audit hash chain, `multi_tenant`. Separate trust zones per agent class. |
| **Semantic schema drift** | Partial | `tool_metadata_guard`, `hot_reload`, `doctor` / `redteam`. Enable metadata guard in production. |
| **Ransomware via RCE / injection** | Partial | `content_filter`, `prompt_guard`, `schema_validation`, `tool_allowlist`. Not a sandbox — pair with OS controls. |
| **Rogue MCP servers (supply chain)** | Partial | `doctor`, pip-audit, PyPI/npm provenance. Verify publisher before install. |

## Honest posture

Bastion defends **protocol economics and the agent boundary at runtime**. It does **not** replace transport hardening (localhost CSRF), stdio IPC integrity, or OS-level sandboxing. Use [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md) and a hardened `bastion.yaml` together.

## Related docs

- [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md) — concrete attack scenarios
- [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md) — HTTP / localhost guidance
- [PILLARS.md](PILLARS.md) — full control reference
- [ROADMAP.md](ROADMAP.md) — shipped vs pending (P1/P2)
