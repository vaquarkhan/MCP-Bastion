# OWASP MCP Top 10 (2025 beta): how MCP-Bastion maps

This document is for **security alignment and documentation**: each [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) risk is paired with **product controls**, **CLI / process hooks**, and **customer responsibilities**. MCP-Bastion is runtime middleware; some risks are only fully addressed with **platform practices** (vaults, SDLC, inventory) alongside Bastion.

| ID | Risk (short) | Bastion mitigations | You still need |
|----|----------------|---------------------|----------------|
| **MCP01** | Token / secret mishandling | Optional `content_filter.block_secrets` (high-confidence patterns), PII redaction, audit + hash chain, rate/cost limits | Short-lived tokens, secret managers, never logging raw secrets |
| **MCP02** | Privilege escalation & scope creep | RBAC, OPA/Cedar external policy, optional `session_limits.max_unique_tools_per_session`, rate limits, semantic firewall | Least-privilege IAM, periodic access reviews |
| **MCP03** | Tool poisoning & shadow tools | Optional **`tool_metadata_guard`** on `tools/list` (description + schema), strict `tool_allowlist`, schema validation, semantic firewall, prompt guard | Curated tool manifests, code review of tool servers; host must route list results through Bastion |
| **MCP04** | Supply chain | `mcp-bastion doctor` (optional `pip-audit`), reproducible builds in **your** CI | SBOM, dependency pinning, signed artifacts |
| **MCP05** | Insecure tool invocation / injection | Content filter (paths, code), schema validation, prompt guard | Safe tool implementations, OS sandboxing |
| **MCP06** | Broken function-level authorization / intent | Prompt guard, semantic firewall, sensitive classifier, external policy | Business rules in OPA/Rego aligned to data classes |
| **MCP07** | Inadequate authentication / transport | Optional `edge_auth` (compare `context.metadata[metadata_key]` to env secret); combine with your gateway mTLS/JWT | Strong transport auth in front of MCP |
| **MCP08** | Insufficient logging & integrity | Audit middleware, optional hash-chain anchors, Prometheus/OTEL hooks, alerts | Central SIEM, retention policy |
| **MCP09** | Shadow MCP & governance | Optional `governance.registry_url` startup beacon + **your** registry | Org-wide MCP inventory, approvals |
| **MCP10** | Excessive agency / context oversharing | PII redaction, tenant-scoped semantic cache keys, sensitive classifier, multi-tenant configs | Data minimization, DLP at egress |

## Documentation guidance

- Prefer: **“Maps to / aligns with OWASP MCP Top 10”** and link this page.
- Prefer: **“With Bastion on the MCP path, the *classes* of abuse seen in public 2025 MCP incidents, especially tool-poisoning *payloads* and confused-deputy *tool abuse*, are blocked or stripped before execution, with audit to your SIEM.”** (Accurate when `tools/call` **and** `tools/list` traverse Bastion and policies are on.)
- Avoid: **“Eliminates all ten risks”** or **“This incident cannot happen”**; vendor RCEs, supply-chain token theft, and wrong IAM still require patches, sandboxes, and vaults **outside** middleware.

## Red-team coverage

Run:

```bash
mcp-bastion redteam --config bastion.yaml
```

The JSON report includes **`mcp_top10_summary`** (blocked vs attempts per **MCP01**-**MCP10** tag). Tighten `bastion.yaml` (allowlist, `block_secrets`, `edge_auth`, session limits) to increase blocked percentages for your deployment profile.
