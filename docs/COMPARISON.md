# MCP-Bastion vs other approaches

Quick reference for evaluators comparing MCP-Bastion to **static scanners**, **API/MCP gateways**, and **unguarded MCP servers**.

MCP-Bastion is **cost-aware runtime governance** on the MCP path: embed in your server or run a Bastion-wrapped proxy. Full positioning: [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md).

---

## Category map

| Category | Examples | Primary question they answer |
|----------|----------|------------------------------|
| **Scanner** | mcp-scan, Invariant | "Is this tool definition poisoned *before* deploy?" |
| **Gateway** | Arcade, Enkrypt, Zuplo, ThinkWatch | "Who is the user and how do we route API/MCP traffic?" |
| **Cost-aware runtime governance** | **MCP-Bastion** | "What ran, what did it cost, what was blocked — and how does **live spend** change allow/deny/route?" |

Scanners do not see spend at runtime. Gateways treat cost as billing, not as a **control plane**. Bastion is the only OSS MCP stack with a credible **denial-of-wallet** story *and* a path to **budget-driven policy** (degrade, filter, approve — not only hard block).

---

## At a glance

| Capability | Unguarded MCP server | Thin MCP reverse proxy | Full AI + MCP gateway | **MCP-Bastion** |
|------------|----------------------|-------------------------|------------------------|-----------------|
| Drop-in library (`pip` / npm) | n/a | ❌ | ❌ | ✅ |
| Policy-as-code (`bastion.yaml`) | ❌ | partial | UI + DB config | ✅ |
| Prompt injection (ML + heuristics) | ❌ | partial | partial | ✅ PromptGuard + response scan |
| PII redaction (Presidio) | ❌ | rare | partial | ✅ |
| Agent IAM + tool allowlists | ❌ | partial | ✅ | ✅ `agent_iam` |
| Supply-chain manifest verification | ❌ | ❌ | partial | ✅ SHA-256 + HMAC |
| FinOps caps (principal-based) | ❌ | partial | billing only | ✅ session + daily + **cost-as-policy** (3.0+) |
| Governance attestation export | ❌ | ❌ | partial logs | 🔜 signed session bundle (3.0) |
| Full MCP surface guards | ❌ | partial | varies | ✅ tools + resources + prompts + sampling + elicitation |
| OPA / Cedar external policy | ❌ | ❌ | rare | ✅ |
| Per-user upstream OAuth to GitHub/Notion | ❌ | rare | ✅ (gateway products) | 🔜 [ROADMAP](ROADMAP.md) P2 |
| Unified OpenAI/Anthropic API proxy | ❌ | ❌ | ✅ | ❌ non-goal |
| Admin console + MCP app store | ❌ | ❌ | ✅ | dashboard = metrics/governance (not full store) |
| OWASP MCP Top 10 mapping | ❌ | partial | partial | ✅ [BEYOND_OWASP.md](BEYOND_OWASP.md) |

Legend: ✅ shipped · 🔜 planned · ❌ not focus / not offered

---

## When to choose MCP-Bastion

- You need **runtime governance** with **live cost** as a security signal (denial-of-wallet, chargeback, budget-driven degradation).
- You **own the MCP server code** (Python/TS) and want guardrails **in-process** with minimal latency.
- You need **auditable, version-controlled policy** (`bastion.yaml`) and a path to **compliance-grade attestation**.
- You care about **tool poisoning, PII, injection, and spend** on the MCP path specifically.

## When to add a gateway product instead (or as well)

- You need a **single front door** for all LLM API traffic **and** MCP with virtual keys and SSO.
- You must enforce **per-user OAuth** to upstream MCP servers (GitHub, Notion, …) with a credential vault.
- You want a **turnkey admin UI**, MCP catalog, and multi-tenant key management without writing code.

Many teams use **both**: gateway for identity and routing, MCP-Bastion **inside** or **in front of** each MCP server for deep MCP-specific controls.

---

## Feature depth (MCP-Bastion pillars)

See [PILLARS.md](PILLARS.md) for the full mapping. Highlights vs a typical proxy:

| Area | Typical proxy | MCP-Bastion |
|------|---------------|-------------|
| Rate / cost keys | `session_id` or API key only | Authenticated **principal** + tenant-global daily budget |
| RBAC trust | Self-asserted `metadata.role` | Requires **Agent IAM** or **edge auth** by default |
| Content filter | Regex on raw strings | Normalize (URL-decode, NFKC, shell obfuscation) then match |
| External policy | Often fail-open | **`fail_closed` default** for OPA/Cedar |
| Audit latency | OTEL probe every request | **Negative cache** when observability unconfigured |

---

## Roadmap alignment

Flagship: [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md). Backlog: [ROADMAP.md](ROADMAP.md) (P0 cost policy, P2 boundary, P3 behavioral fingerprint).
