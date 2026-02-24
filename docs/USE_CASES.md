# Real Use Cases

MCP-Bastion fits into production environments where MCP servers expose tools to LLMs or automated agents. Below are concrete use cases and how to apply the middleware.

---

## 1. Enterprise MCP Gateway

**Scenario:** Your company runs an internal MCP server that exposes databases, APIs, and internal tools to ChatGPT, Claude, or custom agents. You need to ensure no prompt injection reaches backend systems, no PII leaves the boundary, and no single session can exhaust resources.

**Apply MCP-Bastion:**

- Wrap the MCP server with `MCPBastionMiddleware` (PromptGuard, PII redaction, rate limit).
- Use `bastion.yaml` for policy-as-code so security and platform teams can tune limits and alerts without code changes.
- Run the dashboard (`mcp-bastion dashboard --port 7000`) for real-time blocked counts, PII redacted, and cost; wire alerts to Slack or PagerDuty for injection and rate-limit events.

**Result:** Every tool call is checked for injection and rate limits; outbound content is redacted; audit logs and metrics support compliance and incident response.

---

## 2. LLM-Powered Product (e.g. Chat, Copilot)

**Scenario:** Your product uses MCP to let an LLM call tools (search, read files, run queries). Users might try jailbreaks or send prompts that trigger unintended tool use. You also must avoid leaking customer PII into the model or logs.

**Apply MCP-Bastion:**

- Integrate the middleware in the same process as your MCP server (Python FastMCP or TypeScript SDK).
- Enable prompt injection detection so adversarial prompts are blocked before tools run.
- Enable PII redaction on tool/resource responses so SSN, email, phone are masked before they reach the LLM or client.
- Set rate limits and token budget per session to cap cost and prevent runaway loops.

**Result:** Malicious or jailbreak prompts are blocked; PII in tool outputs is redacted; cost and iteration caps prevent abuse.

---

## 3. Internal Tools and Dev Assistants

**Scenario:** Developers use an MCP server (e.g. GitHub, filesystem, build tools) from an IDE or CLI. You want to allow normal use but block dangerous patterns (e.g. reading `/etc/passwd`, executing arbitrary code) and enforce per-user or per-session limits.

**Apply MCP-Bastion:**

- Use content filter to block sensitive paths and custom patterns (e.g. `api_key`, `password`).
- Use RBAC so that “viewer” can only call read-only tools; “admin” can call write or dangerous tools.
- Use rate limiting so a single session cannot flood the server.

**Result:** Risky paths and code execution are blocked; role-based access is enforced; resource exhaustion is limited.

---

## 4. SaaS Offering MCP to Customers

**Scenario:** Your SaaS exposes MCP endpoints so customers can connect their agents. You need multi-tenant safety: one customer’s agent must not exceed quotas, inject prompts that access other tenants’ data, or leak PII from your responses.

**Apply MCP-Bastion:**

- Use rate limits and cost tracker per session (or per tenant ID in `session_id`/metadata).
- Enable prompt injection detection so cross-tenant or malicious prompts are blocked.
- Enable PII redaction on tool responses so customer data is masked in logs and in responses to the LLM.
- Use audit logging and the dashboard to monitor blocked requests and per-tenant usage.

**Result:** Per-tenant quotas and cost caps; injection and PII controls; observable metrics for support and compliance.

---

## 5. Compliance and Audit (SOC2, HIPAA-Relevant)

**Scenario:** You must demonstrate that tool calls are logged, that sensitive data is not sent to third parties, and that malicious or abusive use is blocked.

**Apply MCP-Bastion:**

- Use `AuditLogMiddleware` with an export callback that writes to your existing logging or SIEM (e.g. JSON logs, CloudWatch, Datadog).
- Enable PII redaction so that PII never leaves the middleware in cleartext in outbound responses.
- Use the dashboard and `GET /api/metrics` (or Prometheus `/metrics`) to report on blocked count, PII redacted count, and top tools.

**Result:** Structured audit trail (who, what, when, blocked/allowed); reduced PII exposure; metrics for compliance and incident review.

---

## Quick Reference

| Use case              | Key features                                              |
|-----------------------|-----------------------------------------------------------|
| Enterprise gateway    | PromptGuard, PII redaction, rate limit, bastion.yaml, dashboard |
| LLM product           | Prompt injection, PII redaction, rate limit, cost tracker  |
| Internal tools        | Content filter, RBAC, rate limit                          |
| SaaS / multi-tenant   | Rate limit, cost tracker, RBAC, audit, dashboard         |
| Compliance / audit    | AuditLogMiddleware, PII redaction, metrics, dashboard     |

See [SETUP_GUIDE.md](../SETUP_GUIDE.md) for setup and [POLICY_AS_CODE.md](POLICY_AS_CODE.md) for `bastion.yaml` options.
