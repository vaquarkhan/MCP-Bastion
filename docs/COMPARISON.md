# MCP-Bastion vs other approaches

Quick reference for evaluators comparing MCP-Bastion to **unguarded MCP servers**, **thin reverse proxies**, and **full AI/MCP gateways** (e.g. ThinkWatch-class products).

MCP-Bastion is **middleware + policy-as-code**: embed in your MCP server or run a Bastion-wrapped proxy. It is not a replacement for your IdP or a full LLM API router.

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
| FinOps caps (principal-based) | ❌ | partial | ✅ | ✅ session + daily + Redis |
| Full MCP surface guards | ❌ | partial | varies | ✅ tools + resources + prompts + sampling + elicitation |
| OPA / Cedar external policy | ❌ | ❌ | rare | ✅ |
| Per-user upstream OAuth to GitHub/Notion | ❌ | rare | ✅ (gateway products) | 🔜 [ROADMAP](ROADMAP.md) P2 |
| Unified OpenAI/Anthropic API proxy | ❌ | ❌ | ✅ | ❌ non-goal |
| Admin console + MCP app store | ❌ | ❌ | ✅ | dashboard = metrics/governance (not full store) |
| OWASP MCP Top 10 mapping | ❌ | partial | partial | ✅ [BEYOND_OWASP.md](BEYOND_OWASP.md) |

Legend: ✅ shipped · 🔜 planned · ❌ not focus / not offered

---

## When to choose MCP-Bastion

- You **own the MCP server code** (Python/TS) and want guardrails **in-process** with minimal latency.
- You need **auditable, version-controlled policy** (`bastion.yaml`) in CI/CD.
- You care about **tool poisoning, PII, injection, and denial-of-wallet** on the MCP path specifically.
- You want to **keep your existing LLM provider setup** and secure MCP only.

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

Planned work inspired by gateway-class products but scoped to our middleware model: [ROADMAP.md](ROADMAP.md) (P2 identity, P4 discoverability).
