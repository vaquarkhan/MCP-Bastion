# Product roadmap — runtime governance & beyond

Status as of **1.0.19** (in progress). See [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md).

## Shipped (1.0.18+)

| Feature | Status |
|---------|--------|
| Agent Identity & RBAC | ✅ `agent_iam` |
| Server SHA-256 verification | ✅ `server_verification` + `mcp-bastion manifest` |
| PromptGuard fail-closed + heuristics | ✅ |
| Zero-Trust README + infographic | ✅ |

## Shipped (1.0.19 — this branch)

| Item | Status | Config / CLI |
|------|--------|--------------|
| **HTTP transport hardening** | ✅ | `transport_hardening` + `run_hardened_streamable_http` |
| **stdio stdout JSON guard** | ✅ | `stdio_guard` + `install_stdio_guard()` |
| **Tool metadata fingerprint** | ✅ | `tool_metadata_fingerprint` + `mcp-bastion fingerprint` |
| **Dashboard IAM / verification health** | ✅ | `pillar_health` rows |
| **Manifest HMAC signatures** | ✅ | `manifest --sign`, `BASTION_MANIFEST_SIGNING_KEY` |
| **Multi-agent session isolation** | ✅ | `agent_iam.isolate_sessions` |
| **Resource URI IAM (write-path)** | ✅ | `allowed_resources` / `blocked_resources` |
| **Registry publisher doctor check** | ✅ | `governance.allowed_registry_names` |
| **Reverse-proxy recipe** | ✅ | [deploy/](../deploy/README.md) Caddy + compose |
| **Red-team IAM / schema drift cases** | ✅ | `redteam` suite extended |

## Pending (P2+)

| Item | Notes |
|------|-------|
| **Sigstore/cosign** | HMAC today; full cosign integration later |
| **npm audit remediation** | Track `@mcp-bastion/core` transitive deps |
| **OS sandbox** | Out of scope — use containers |

## Non-goals

OS sandboxing, replacing OAuth/OIDC, third-party LLM safety APIs.
