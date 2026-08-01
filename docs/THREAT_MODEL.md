# Threat model (MCP-Bastion)

Public threat model for **MCP-Bastion** as a **zero-infra, in-process / protocol-level guardrail library**.
Bastion is the **guardrail brain** that composes with your MCP server or optional boundary proxy — not an IdP, SaaS control plane, or mandatory sidecar.

Related: [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md) · [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md) · [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md) · [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)

## Assets

| Asset | Why it matters |
|-------|----------------|
| MCP tool / resource / prompt surface | Agents act with your credentials and data |
| Tool arguments and results | Injection, exfil, second-order jailbreaks |
| PII / secrets in context | Leakage into logs, models, or egress tools |
| Session / agent identity | Confused deputy, privilege abuse |
| `bastion.yaml` policy | Incorrect policy = false sense of safety |
| Release artifacts (PyPI, npm, GHCR) | Supply-chain compromise |

## Actors

| Actor | Intent |
|-------|--------|
| Malicious or compromised user / agent | Jailbreak, privilege escalation, denial-of-wallet |
| Compromised MCP server / tool | Rug-pull tool defs, malicious outputs (second-order injection) |
| Cross-tenant / multi-agent peer | Session bleed, confused deputy |
| Supply-chain attacker | Poisoned dependency or unsigned image |
| Honest misconfiguration | Fail-open, missing identity, over-broad RBAC |

## Trust boundaries

```text
[ Agent / host ] --stdio/HTTP--> [ Optional edge gateway / proxy ]
                                      |
                                      v
                              [ MCP server process ]
                                      |
                         +------------+------------+
                         | MCP-Bastion middleware  |  ← in-process (default)
                         | (bastion.yaml policy)   |
                         +------------+------------+
                                      |
                                      v
                              [ Tools / data / APIs ]
```

- **In-process:** Bastion sees the same tool calls the server sees; strongest for toxic-flow / taint.
- **Optional `serve --proxy`:** same policy at a network boundary when the host cannot load the library — still **BYOI** (no login server).
- **Identity:** Bastion **consumes** gateway-stamped headers or JWTs; it does not run OAuth authorization or credential vaults.

## Abuse cases (mapped to controls)

| Abuse | Primary controls |
|-------|------------------|
| Prompt injection / jailbreak | `prompt_guard`, heuristics, `response_scan` |
| Second-order injection in tool output | `response_scan` (+ optional PromptGuard ML on outputs) |
| PII / secret leakage | `pii`, `pii_vault`, `secrets`, content filter |
| Toxic flow: sensitive read → external write | `toxic_flow` taint tracker, `semantic_firewall` chains |
| Privilege / confused deputy | `agent_iam`, `rbac`, `identity_adapter` (optional JWT verify) |
| Tool rug-pull / catalog drift | `tool_metadata_fingerprint`, live pin |
| Denial-of-wallet / cascades | `rate_limit`, `cost_tracker`, `cost_policy`, `circuit_breaker` |
| Path / shell exfil in args | `content_filter` |
| Ungrounded path claims in answers | `grounding_guard` |
| Supply chain | SBOM, PyPI/npm OIDC, Sigstore-signed GHCR images |

## Out of scope (by design)

- Hosting an OAuth/OIDC **authorization server** or user login UI
- Managed SIEM / ClickHouse / SaaS dashboard as a requirement
- Replacing your API gateway or LLM provider proxy
- Guaranteeing model honesty (Bastion gates **MCP I/O**, not model weights)

## Residual risk

- ML PromptGuard can false-positive; corroboration (`require_ml_corroboration`) and fail-closed trade recall vs availability.
- Regex response scan alone misses novel framings — enable `response_scan.use_prompt_guard` for ML depth.
- BYOI with `verify: false` trusts the edge; enable JWT verify when Bastion is the first crypto check.
- Optional Redis state is shared-fate with Redis availability (rate limits / vault).

## Verification

- Policy dry-run: `mcp-bastion validate` / `policy_simulator`
- Attack pack: `mcp-bastion redteam --config bastion.yaml`
- Session evidence: `mcp-bastion attest export`
- CI pairing with [MCP Test Harness](https://github.com/vaquarkhan/mcp-test-harness): [BASTION_AND_TEST_HARNESS.md](BASTION_AND_TEST_HARNESS.md)
