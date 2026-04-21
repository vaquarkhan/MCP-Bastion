# MCP security landscape (why runtime controls matter)

This note supports **security documentation**: it summarizes widely discussed MCP risk patterns and incidents from **industry reporting (2025-2026)**. It is **not legal advice** and **not a primary source** for any specific breach; always rely on vendor advisories, CVE databases, and your own counsel for contractual claims.

- **OWASP MCP Top 10:** [OWASP MCP Top 10 project](https://owasp.org/www-project-mcp-top-10/)  
- **How MCP-Bastion maps to those controls:** [OWASP_MCP_TOP10.md](OWASP_MCP_TOP10.md)  
- **Discuss or propose edits:** [Open a GitHub issue](https://github.com/vaquarkhan/MCP-Bastion/issues/new?labels=documentation%2Csecurity)

## Reported incident themes (illustrative)

Since MCP adoption accelerated, public write-ups and vendor post-mortems have repeatedly highlighted the same failure modes:

| Period (reported) | Theme | What went wrong (pattern) | Why middleware helps |
|--------------------|--------|---------------------------|-------------------------|
| Spring 2025 | **Tool poisoning / metadata abuse** | Malicious or misleading tool descriptions or parameters steer agents into unintended side effects (e.g., data sent to the wrong destination). | **`tool_metadata_guard`** on `tools/list` (strip/block poisoned descriptions), prompt guard, semantic firewall, content filter, optional **tool allowlist**, audit forensics. |
| Mid 2025 | **Over-privileged tokens (“confused deputy”)** | The MCP server runs as a service identity; the agent triggers actions with that identity’s scope, not the end-user’s least privilege. | RBAC + OPA/Cedar, session tool caps, rate/cost limits, sensitive classifier. |
| Mid 2025 | **Prompt injection → secret exfiltration** | Untrusted text causes the model to emit or use secrets (e.g., CI tokens) in tool arguments. | Prompt guard, **secret-shaped payload blocking**, PII redaction, audit exports to your SIEM. |
| 2025 | **Supply chain / typosquatting** | Unofficial or similarly named MCP packages or configs broaden the attack surface. | `mcp-bastion doctor`, governance registry beacon, **your** SDLC and package pinning. |
| 2025 | **Injection / unsafe execution** | Unsanitized inputs reach `exec`, shells, or path traversal in integrations. | Content filter, schema validation, circuit breaker. |
| Late 2025 | **Hosted-platform scale incidents** | Centralized registries or build pipelines compromised → many downstream integrations affected. | Defense in depth: Bastion at the edge **plus** platform vendor controls and blast-radius isolation. |

## Three recurring “kill chains”

1. **Tool poisoning (TPA):** instructions hidden in tool metadata or prompts cause the model to pick a dangerous tool path while the user believes the task is benign.  
2. **Confused deputy:** the agent inherits the **server’s** credentials, not a human-scoped session, so horizontal/vertical privilege escalation is easier.  
3. **Supply-chain / “slopsquatting”:** names and packages that look official get pulled into agent workflows without strong inventory or review.

## Technical mitigations (where Bastion fits)

| Mitigation | Bastion | You still own |
|------------|---------|----------------|
| Isolate / validate tool inputs | Content filter, schema validation, semantic firewall | Secure tool implementations, OS-level sandboxing (e.g., gVisor, Wasm) where appropriate |
| Tiered, short-lived credentials | Secret pattern blocking, session limits, policy engines | Vault, OAuth/OIDC, per-user delegation at the gateway |
| Observable, tamper-aware audit | Structured audit + hash chain + **telemetry sinks** (Datadog, New Relic, Splunk, or HTTPS to AWS/Azure/GCP) | SIEM retention, SOAR playbooks, on-call |

**Summary:** MCP moved risks from theory to **production blast radius**. MCP-Bastion is an **inline control plane** that enforces policy and ships evidence to the observability stack you already use, without replacing cloud IAM, vaults, or vendor patches.

## Suggested wording for documentation and RFIs

These statements are written to be **accurate and reviewable** under security scrutiny:

1. **“When your MCP gateway runs MCP-Bastion, the attack patterns behind high-profile 2025 MCP incidents (tool poisoning in **metadata**, prompt-driven secret misuse, and runaway tool scope) are **interrupted at the protocol edge**: dangerous tools and arguments are blocked or removed, and every decision is **audited** to Datadog, Splunk, New Relic, or your cloud SIEM.”**
2. **“That does not replace OS sandboxes or vendor patches for RCE classes; it means the **agent kill chain** most product teams can actually control (MCP messages, tools, and tenants) is **governed** instead of left to model luck.”**
3. **“We map to the OWASP MCP Top 10 in product and documentation so security reviewers get a **checklist-backed** view of controls, not a black box.”** (See [OWASP_MCP_TOP10.md](OWASP_MCP_TOP10.md).)

**Avoid** absolute claims such as “this incident can never happen” without scoping. Prefer **“when MCP traffic flows through Bastion with recommended policy”** and link this document for limits of responsibility.
