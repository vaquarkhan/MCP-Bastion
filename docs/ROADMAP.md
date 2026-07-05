# Product roadmap — runtime governance & beyond

Status as of **2.0.0** (released 2026-07-05). See [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md) and the strategic **10/10 plan**: [ENGINEERING_10_10.md](ENGINEERING_10_10.md).

## Shipped (2.0.0)

| Feature | Status |
|---------|--------|
| Agent Identity & RBAC | ✅ `agent_iam` |
| Server SHA-256 verification | ✅ `server_verification` + `mcp-bastion manifest` |
| PromptGuard fail-closed + heuristics | ✅ |
| Zero-Trust README + infographic | ✅ |
| **`mcp-bastion serve` FastMCP fix (Bug A)** | ✅ `serve.run_streamable_http()` |
| **`schema_validation.schemas` in YAML (Bug B)** | ✅ + doctor warning if empty |
| **Red-team intended vs guard-unavailable scores** | ✅ `score_intended_blocked_pct` |
| **FinOps/RBAC benchmarks** | ✅ [BENCHMARKS.md](BENCHMARKS.md) |
| **HTTP transport hardening** | ✅ `transport_hardening` |
| **stdio stdout JSON guard** | ✅ `stdio_guard` |
| **Tool metadata fingerprint** | ✅ `mcp-bastion fingerprint` |
| **Dashboard IAM / verification / governance** | ✅ `pillar_health` + governance panel |
| **Manifest HMAC signatures** | ✅ `manifest --sign` |
| **Multi-agent session isolation** | ✅ `agent_iam.isolate_sessions` |
| **Resource URI IAM (write-path)** | ✅ `allowed_resources` / `blocked_resources` |
| **Registry publisher doctor check** | ✅ `governance.allowed_registry_names` |
| **Reverse-proxy recipe** | ✅ [deploy/](../deploy/README.md) |
| **Red-team IAM / schema drift cases** | ✅ extended suite |
| **npm audit clean** | ✅ 0 vulnerabilities in dev tree |
| **Full MCP surface guards** | ✅ `resources/read`, `prompts/get`, `sampling/createMessage`, `elicitation/create` |
| **Pluggable shared state (Redis)** | ✅ `state_backend` in bastion.yaml |

## Pending (P2+) — see [ENGINEERING_10_10.md](ENGINEERING_10_10.md)

| Item | Notes |
|------|-------|
| **Distributed state (Redis)** | ✅ Shipped in 2.0.0 — enable `state_backend.type: redis` |
| **Full MCP-surface coverage** | ✅ Shipped in 2.0.0 — see middleware `GUARDED_MCP_METHODS` |
| **Non-gated PromptGuard default + injection benchmark** | Layered detectors, tool-output scanning |
| **`mcp-bastion scan` (static tool poisoning)** | Rug-pull / shadow-tool detection |
| **OAuth 2.1 / OIDC JWT gateway** | Scopes → RBAC; per-user audit `sub` |
| **Sigstore/cosign** | HMAC today; full cosign integration later |
| **External security audit** | Linked report + disclosure track record |
| **OS sandbox** | Out of scope — use containers |

## Non-goals

OS sandboxing, replacing OAuth/OIDC, third-party LLM safety APIs.
