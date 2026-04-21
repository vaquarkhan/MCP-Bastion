# MCP-Bastion feature matrix

High-level map of enterprise and security capabilities. Policy keys live in `bastion.yaml` (see [POLICY_AS_CODE.md](POLICY_AS_CODE.md)); CLI in [CLI.md](CLI.md).

| Area | Capability | Notes |
|------|------------|--------|
| Threat | Prompt injection (PromptGuard) | Local model scoring |
| Threat | Content filter | Paths, code, URLs, allow/deny patterns |
| Threat | Semantic firewall | Tool intent / chain heuristics |
| Threat | Sensitive content classifier | Beyond PII; optional `transformers` |
| Data | PII redaction (Presidio) | Outbound tool/resource content |
| Access | RBAC | Role → allowed tools in YAML |
| Access | OPA / Cedar | `policy_engine` optional |
| Resilience | Rate limit, circuit breaker, replay guard | DoW / abuse protection |
| FinOps | Cost tracker + attribution | Provider/model/tool/dataset; pricing overrides |
| Compliance | Audit log + **hash chain** | Tamper-evident exports; `POST /api/audit/verify` |
| Operations | Behavior fingerprint | Session tool-sequence drift anomalies |
| SaaS | Multi-tenant | Per-tenant YAML under `multi_tenant.config_dir` |
| Assurance | `mcp-bastion redteam` | OWASP LLM-style report JSON |
| Observability | Dashboard + Prometheus | `/` and `/metrics` |
| Observability | OTEL + zero-config | Grafana, Datadog probe, AWS CloudWatch fallback |

For architecture context see [USE_CASES.md](USE_CASES.md) and [SECURITY.md](SECURITY.md).
