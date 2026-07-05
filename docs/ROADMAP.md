# Product roadmap — runtime governance & beyond

Status as of **1.0.18** (unreleased). See [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md) for configuration of shipped features.

## Shipped in this release (Zero-Trust control plane)

| Feature | Status | Config / CLI |
|---------|--------|--------------|
| **Agent Identity & RBAC** | ✅ Shipped | `agent_iam` — token → agent identity, allow/block tools, per-agent rate limits |
| **Server cryptographic verification** | ✅ Shipped | `server_verification` + `mcp-bastion manifest` |
| **PromptGuard fail-closed + heuristics** | ✅ Shipped | `prompt_guard.fail_open`, heuristic fallback |
| **Output budget byte cap** | ✅ Shipped | `output_budget.max_response_bytes` |
| **Beyond-OWASP docs** | ✅ Shipped | [BEYOND_OWASP.md](BEYOND_OWASP.md), [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md) |
| **Runtime governance guide** | ✅ Shipped | [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md) |

## OWASP MCP Top 10 + FinOps (prior releases)

All **10** OWASP risks and denial-of-wallet controls are covered at the MCP boundary — see README infographic `images/mcp-bastion-owasp-coverage.png`.

## Pending — recommended next (P1)

| Item | Why it matters | Notes |
|------|----------------|-------|
| **Dashboard `pillar_health` rows** for Agent IAM & server verification | Ops visibility for new deny codes (-32019, -32020) | Extend `MetricsStore._build_pillar_health()` |
| **`serve` transport hardening** | Localhost CSRF / DNS rebind on HTTP MCP | CORS, `Origin` check, bind guidance in [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md) |
| **Tool metadata fingerprint in `doctor`** | Detect poisoned `tools/list` drift between deploys | Hash tool names + descriptions at doctor time |
| **stdio stdout JSON validator** | Malformed stdout breaks MCP stdio transport | Byte-stream guard for non-JSON lines from server code |

## Pending — hardening & ecosystem (P2)

| Item | Why it matters | Notes |
|------|----------------|-------|
| **HTTP CSRF / reverse-proxy recipe** | Production pattern docs + example nginx/Caddy | Docs + optional reference compose |
| **npm audit remediation** | Supply chain for `@mcp-bastion/core` | Track and bump vulnerable transitive deps |
| **Signed manifest (Sigstore/cosign)** | Stronger supply chain than SHA-256 alone | Extend `server_verification` with signature keys |
| **Multi-agent session isolation** | State poisoning across agents on one server | Separate session namespaces per `agent_id` |
| **Registry publisher verification** | Typosquatting from public MCP registries | Integrate with `doctor` + governance beacon |

## Explicit non-goals (use OS / gateway instead)

- OS-level sandboxing (containers, seccomp, gVisor)
- Replacing enterprise IAM (OAuth/OIDC) — Bastion complements gateway-issued tokens via `edge_auth` / `agent_iam`
- LLM provider-side safety APIs — Bastion stays **100% local**

## How to contribute

Pick a **P1** row, open a GitHub issue referencing this doc, and submit a PR with tests. E2E patterns: [tests/test_runtime_governance_e2e.py](../tests/test_runtime_governance_e2e.py).
