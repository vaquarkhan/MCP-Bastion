# Security coverage, OWASP MCP Top 10 alignment, and observability hooks

This page ties together **what MCP-Bastion does**, how it maps to the **industry MCP risk catalog (OWASP MCP Top 10)**, **classes of attacks** you mitigate in practice, and **where to plug in external logging and monitoring tools**.

> **Note on “AWS Top 10 MCP”:** AWS does not publish a separate “Top 10 MCP vulnerabilities” list. The widely referenced catalog is the **[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)** (Model Context Protocol risks). The same MCP threats apply when you run agents on **AWS** (ECS, EKS, Lambda, EC2), other clouds, or on-prem—MCP-Bastion sits at the **MCP boundary**, independent of where the server runs.

---

## 1. Feature highlights (MCP-Bastion)

| **Capability** | **What it does** | **Why it matters** |
|----------------|------------------|--------------------|
| **Prompt injection defense** | Meta PromptGuard classifies tool arguments; malicious payloads can be blocked before execution. | Stops jailbreak-style instructions from reaching tools or leaking context. |
| **PII redaction** | Presidio detects and masks entities in outbound tool/resource content. | Reduces accidental PII in model context, logs, and downstream storage. |
| **Rate limiting** | Max iterations, session timeout, token budget. | Stops runaway agents and **denial-of-wallet** / abuse patterns. |
| **Cost tracker** | Per-session (and optional daily) spend caps. | FinOps guardrails when tools bill APIs. |
| **Content filter** | Block file paths, code execution patterns, URLs; allowlist/denylist. | Mitigates path traversal-style abuse and risky content. |
| **Circuit breaker** | Disable tools after repeated failures. | Limits blast radius of flaky or hostile tools. |
| **RBAC** | Tool-level permissions by role (from request metadata). | Enforces least-privilege for multi-tenant or multi-role setups. |
| **Schema validation** | Validate tool arguments against JSON Schema before execution. | Prevents malformed or bypass attempts at the boundary. |
| **Replay guard** | Nonce tracking to block duplicate requests. | Reduces replay of sensitive actions. |
| **Semantic cache** | Optional similarity-based caching for tool semantics. | Performance; pair with policy so cache does not bypass checks. |
| **Audit logging** | Structured trail of decisions (allow/deny, reasons). | Evidence for SOC, compliance, and incident review. |
| **Alerts** | Slack + generic webhooks with retry/backoff. | Real-time notification into chat or ticketing pipelines. |
| **Dashboard + metrics API** | Live UI, JSON `/api/metrics`, Prometheus `/metrics`. | Operator and SOC visibility without extra agents. |
| **OpenTelemetry (optional)** | OTLP export for traces when enabled. | Drop into existing APM (Datadog, Honeycomb, Jaeger, AWS ADOT, etc.). |

For step-by-step attack demos, see [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md).

---

## 2. OWASP MCP Top 10 — how MCP-Bastion maps

The [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) lists the highest-impact MCP risks. No product “fixes” every item alone—some require **organizational** controls (inventory, SDLC, identity). Below is an honest mapping: **Primary** = direct technical control in MCP-Bastion; **Partial** = meaningful mitigation or prerequisite to pair with other practices; **Process** = governance / engineering outside this middleware.

| **ID** | **Risk (summary)** | **MCP-Bastion role** |
|--------|--------------------|----------------------|
| **MCP01** | Token / secret exposure in memory, logs, or context | **Partial:** PII redaction limits sensitive data in outbound content; audit events reduce blind spots. **Process:** rotate credentials, short-lived tokens, secret hygiene outside MCP. |
| **MCP02** | Privilege escalation / scope creep | **Primary:** RBAC, rate limits, cost caps. **Process:** periodic permission reviews. |
| **MCP03** | Tool poisoning (malicious or misleading tools) | **Partial:** PromptGuard + content filter + circuit breaker limit impact; **Process:** trust only signed/trusted server packages and reviews. |
| **MCP04** | Supply chain / dependency tampering | **Partial:** circuit breaker and observability limit blast radius. **Process:** dependency pinning, SBOM, trusted builds. |
| **MCP05** | Command injection & unsafe execution | **Primary:** content filter + injection defense on arguments; blocks many unsafe patterns before execution. |
| **MCP06** | Intent / workflow subversion | **Partial:** rate limits, replay guard, schema validation reduce automated abuse. |
| **MCP07** | Weak authentication & authorization | **Primary:** RBAC at tool boundary. **Process:** strong identity for MCP HTTP/SSE is still your platform’s job. |
| **MCP08** | Lack of audit & telemetry | **Primary:** audit middleware, metrics, dashboard, Prometheus, optional OTEL. |
| **MCP09** | Shadow / unknown MCP servers | **Partial:** centralized policy + metrics make sanctioned servers observable. **Process:** inventory and allowlisting of endpoints. |
| **MCP10** | Context injection & oversharing | **Primary:** PII redaction; injection defense reduces hostile context in tool args. **Process:** session isolation policies at the app layer. |

---

## 3. Major security *issue classes* you mitigate (not one-off “past incidents”)

MCP-Bastion is designed against **recurring attack patterns** seen in agent and MCP deployments (see [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md)):

- **Prompt injection / jailbreaks** in tool arguments → blocked before execution when classified as malicious.
- **PII leakage** in tool outputs → masked before reaching models or clients.
- **Rate and cost exhaustion** → token bucket, iteration caps, optional cost budgets.
- **Path traversal / sensitive paths in arguments** → content filter blocks risky file paths.
- **Unauthorized tool use** → RBAC by role.
- **Replay of the same request** → replay guard with nonces.
- **Invalid or schema-bypass inputs** → JSON Schema validation at the boundary.

These are **classes of vulnerabilities** teams historically patched ad hoc; MCP-Bastion centralizes them as policy-driven middleware.

---

## 4. Integration hooks to logs, metrics, and cloud tools

Use these paths to feed **Splunk, Datadog, Grafana, Elastic, CloudWatch, Microsoft Sentinel**, or internal SOAR:

| **Integration** | **How** | **Typical destination** |
|-------------------|---------|-------------------------|
| **Slack** | `SlackAlertSink` via `alerts.slack_webhook` or `SLACK_WEBHOOK_URL` in `bastion.yaml` | Chat ops, on-call |
| **Generic webhook** | `WebhookAlertSink` via `webhook_url` / `BASTION_WEBHOOK_URL` / `alerts.webhooks[]` — JSON POST with retries | **PagerDuty Events**, **Microsoft Teams** incoming webhooks, custom APIs, small **SIEM** HTTP collectors |
| **Python logging** | `LoggingAlertSink` (alerts to std logging) | **Fluent Bit**, **Fluentd**, **Vector** → Splunk HEC, Elastic, Loki, **Amazon CloudWatch Logs** |
| **Prometheus** | Dashboard `GET /metrics` (when dashboard process runs) | **Grafana**, **Datadog** Agent (Prometheus check), **Amazon Managed Prometheus** |
| **JSON metrics** | `GET /api/metrics` | Custom pollers, **Datadog** custom metrics via agent, cron jobs |
| **OpenTelemetry** | Optional `pip install mcp-bastion-python[otel]`, set `OTEL_EXPORTER_OTLP_ENDPOINT` | **Honeycomb**, **Jaeger**, **AWS Distro for OpenTelemetry** → **X-Ray** / partner APM |
| **Custom audit pipeline** | `AuditLogMiddleware(export_callback=...)` + `make_audit_export_callback` | **Amazon Kinesis**, **Kafka**, **S3**-bound lambdas, proprietary SIEM bulk APIs |

**Wiring example (alerts + metrics):** see [dashboard/README.md](../dashboard/README.md) and [POLICY_AS_CODE.md](POLICY_AS_CODE.md) for `bastion.yaml` alert fields (`retry_attempts`, `timeout_seconds`, etc.).

### Large-scale deployments: policy distribution and fleet visibility

MCP-Bastion enforces policy **on each MCP server process** using **`bastion.yaml`** (and optional **hot reload** when loaded via `build_middleware_from_config()`). For **many nodes or regions**, teams typically pair that with the **same mechanisms they already use for fleet software**:

- **GitOps** (for example Argo CD or Flux) to render and roll out `bastion.yaml` from a trusted repository.
- **Kubernetes** ConfigMaps or Secrets mounted into pods, plus your standard rollout strategy.
- **Configuration management** (Ansible, Chef, Puppet, Salt) or **image baking** when MCP servers are VM- or AMI-based.

**Central visibility** comes from shipping metrics and traces to your **existing** observability plane: **Prometheus** remote write, **OpenTelemetry** collectors, or polling **`/api/metrics`** into Datadog, Grafana Cloud, or similar—so operators see blocks, latency, and cost **across** instances without a separate Bastion-hosted control plane.

### SOC, SIEM, and compliance-oriented audit trails

Structured **audit events** (allow/deny, tool, reason, tenant, trace identifiers) flow through **`AuditLogMiddleware`** and optional **`make_audit_export_callback`** wiring. From there you forward JSON to destinations your security team already operates:

- **HTTP collectors** and **generic webhooks** (rows above) for near-real-time SIEM ingestion.
- **Fluent Bit / Vector / CloudWatch** paths for log pipelines into **Splunk**, **Elastic**, **Microsoft Sentinel**, or regional equivalents.
- **Custom export callbacks** for **Kafka**, **Amazon Kinesis**, **S3**-triggered processors, or vendor bulk APIs.

For **regulatory retention and immutability**, rely on your **SIEM or log archive** (WORM storage, legal hold, signed journals) as the system of record; MCP-Bastion supplies **consistent, parseable events** at the MCP boundary so those platforms can index, correlate, and retain them under your existing compliance program.

---

## 5. Related docs

- [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md) — concrete scenarios and outcomes  
- [METRICS.md](METRICS.md) — dashboard, Prometheus, overhead  
- [OTEL.md](OTEL.md) — OpenTelemetry setup  
- [POLICY_AS_CODE.md](POLICY_AS_CODE.md) — `bastion.yaml` alerts and pillars  

External reference: [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
