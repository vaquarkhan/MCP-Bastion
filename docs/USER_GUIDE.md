# MCP-Bastion User Guide

**Version:** 4.0.0  
**Audience:** Platform engineers, security architects, and developers deploying Model Context Protocol (MCP) servers with AI agents  
**Last updated:** 2026-07-31

This guide is the end-to-end handbook for MCP-Bastion: from first install through production proxy deployment, privacy controls, security pillars, and release hygiene. It follows the same documentation shape used by large open-source and cloud platforms—**concepts → getting started → how-to → reference → operations**.

---

## 1. What is MCP-Bastion?

MCP-Bastion is **security and governance middleware** for the [Model Context Protocol](https://modelcontextprotocol.io/). It sits on the request and response path of MCP tools, resources, prompts, and related surfaces, enforcing policy **before** untrusted model-driven actions reach your systems—and **before** sensitive tool output re-enters the model context.

| Property | Design choice |
|----------|----------------|
| Deployment model | Drop-in library or HTTP boundary proxy |
| Policy surface | Single `bastion.yaml` (policy-as-code) |
| Defaults | Safe; advanced features are **opt-in** |
| Infrastructure | Zero mandatory cloud deps (memory default; Redis optional) |
| Overhead target | Low-millisecond path for common pillars |

MCP-Bastion is **not** an LLM provider, an agent framework, or a full API gateway replacement. It composes with FastMCP, custom MCP servers, and upstream MCP HTTP endpoints.

### 1.1 Problems it addresses

- **Prompt injection / jailbreaks** on tool arguments and MCP surfaces  
- **PII and secret leakage** into model context (destructive redact or reversible vault)  
- **Context-window bloat** from oversized `tools/list` catalogs  
- **Tool poisoning** via drifted or malicious tool metadata  
- **Denial-of-wallet** and runaway agent loops (rate, cost, session scope)  
- **Privilege sprawl** (RBAC, Agent IAM, allowlists)  
- **Supply-chain integrity** for MCP server artifacts  

### 1.2 Release lineage (4.0.0)

Version **4.0.0** adds a major feature bundle while keeping defaults non-breaking:

- Reversible **PII vault** (abstract + hydrate), including HTTP proxy and SSE  
- **Schema minimization** for `tools/list`  
- **Live tool-catalog pin** against metadata drift  

See [CHANGELOG.md](../CHANGELOG.md).

---

## 2. Architecture overview

```text
┌──────────────┐     JSON-RPC / MCP      ┌─────────────────────┐
│  AI agent /  │ ───────────────────────►│  MCP-Bastion        │
│  MCP client  │◄─────────────────────── │  middleware / proxy │
└──────────────┘   redacted / vaulted    └──────────┬──────────┘
                                                    │ allowed + hydrated
                                                    ▼
                                         ┌─────────────────────┐
                                         │  Your MCP server /  │
                                         │  upstream tools     │
                                         └─────────────────────┘
```

**Two deployment shapes**

1. **In-process middleware** — wrap your Python MCP server; Bastion runs in the same process.  
2. **HTTP proxy (`serve --proxy`)** — Bastion terminates client HTTP, enforces policy, forwards to an upstream MCP URL. Same `bastion.yaml`.

Policy evaluation is pillar-based. Each pillar can allow, block, redact, or annotate. Shadow/`observe` mode records would-be blocks without enforcing them.

---

## 3. Getting started

### 3.1 Prerequisites

- Python **3.11+** recommended  
- An MCP server (FastMCP or custom) **or** an upstream MCP HTTP endpoint  
- Optional: Redis for multi-replica state; Docker for containerized proxy  

### 3.2 Install

```bash
pip install "mcp-bastion-python==4.0.0"
```

FastMCP convenience wrapper:

```bash
pip install mcp-bastion-fastmcp
```

Docker proxy image:

```bash
docker pull ghcr.io/vaquarkhan/mcp-bastion-proxy:v4.0.0
```

### 3.3 Minimal FastMCP path

```python
from mcp.server.fastmcp import FastMCP
from mcp_bastion_fastmcp import secure_fastmcp

mcp = FastMCP("demo")
secure_fastmcp(mcp)  # wire Bastion into tool dispatch immediately after construction

@mcp.tool()
def hello(name: str) -> str:
    return f"Hello, {name}"
```

This enables core defaults (prompt guard, PII redaction, rate limit). For full policy, use `bastion.yaml` (next section).

### 3.4 Policy-as-code path

```bash
cp bastion.yaml.example bastion.yaml
# edit bastion.yaml
export BASTION_CONFIG=./bastion.yaml
```

```python
from mcp_bastion.config import build_middleware_from_config, load_config

mw = build_middleware_from_config(load_config())
# compose mw onto your MCP server request path
```

Validate before deploy:

```bash
mcp-bastion validate
mcp-bastion doctor
```

---

## 4. Configuration model

All runtime behavior is driven by **`bastion.yaml`**. Missing keys use safe defaults. Advanced pillars stay **disabled** until explicitly enabled.

### 4.1 Essential blocks

| Block | Purpose | Default posture |
|-------|---------|-----------------|
| `prompt_guard` | Injection / jailbreak detection | On |
| `pii` | Destructive PII redaction on outputs | On |
| `pii_vault` | Reversible tokenize / hydrate | **Off** |
| `rate_limit` | Iteration / token budgets | On |
| `discovery_filter` | Allowlist + schema minimize | Off |
| `tool_metadata_fingerprint` | Catalog pin / drift | Off |
| `agent_iam` / `rbac` | Privilege controls | Off until wired |
| `boundary_mode` / `transport_hardening` | Proxy hardening | See examples |
| `state_backend` | memory or Redis | memory |

Full schema: [POLICY_AS_CODE.md](POLICY_AS_CODE.md).  
Pillar map: [PILLARS.md](PILLARS.md).  
Feature enablement: [FEATURES.md](FEATURES.md).

### 4.2 Example: production-oriented starter

```yaml
audit:
  enabled: true

prompt_guard:
  enabled: true
  heuristic_fallback: true

pii:
  enabled: true

pii_vault:
  enabled: false          # set true for reversible tokens
  ttl_seconds: 3600

rate_limit:
  enabled: true
  max_iterations: 30

discovery_filter:
  enabled: false
  minimize_schemas: true  # shrink tools/list tokens without removing tools
  max_description_chars: 160

tool_metadata_fingerprint:
  enabled: true
  pin_on_first_seen: true
  on_drift: warn          # use block in high-assurance environments

transport_hardening:
  enabled: true
```

---

## 5. Run paths

### 5.1 In-process middleware

Use when you own the MCP server code. Attach `build_middleware_from_config()` via `compose_middleware` or FastMCP helpers. See [TUTORIALS.md](TUTORIALS.md).

### 5.2 HTTP proxy (boundary)

Use when the upstream MCP server is third-party or you need un-bypassable enforcement at the edge.

```bash
mcp-bastion serve --proxy --upstream http://127.0.0.1:9000/mcp \
  --host 127.0.0.1 --port 8080
```

Clients talk to Bastion; Bastion forwards allowed traffic upstream. With **PII vault** enabled, the proxy:

1. **Hydrates** vault tokens in inbound `tools/call` arguments  
2. **Abstracts / redacts** PII on upstream JSON and SSE (`text/event-stream`) results  

Guides: [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md), [HYBRID_TRANSPORT_TUTORIAL.md](HYBRID_TRANSPORT_TUTORIAL.md), [CLI.md](CLI.md).

### 5.3 Hybrid MCP transport

Opt-in `mcp_transport` supports session and explicit state-handle modes for SEP-style readiness. See [HYBRID_MCP_TRANSPORT.md](HYBRID_MCP_TRANSPORT.md).

---

## 6. Privacy: PII redaction and reversible vault

### 6.1 Destructive redaction (default)

With `pii.enabled: true` (default), outbound tool/resource text uses Presidio-style placeholders (`<EMAIL_ADDRESS>`, …). Raw PII does not return to the model. Tool calling that needs the real value may break—that is intentional for high-assurance redaction.

### 6.2 Reversible vault (opt-in)

```yaml
pii:
  enabled: true
pii_vault:
  enabled: true
  ttl_seconds: 3600
  # token_style: typed         # {{pii:EMAIL_ADDRESS:…}}
  # token_style: low_entropy   # EMAIL_ADDRESS_1 / Person_A
```

**Lifecycle**

1. **Abstract** — outbound text: PII → session tokens  
2. **Hydrate** — inbound `tools/call` args: tokens → plaintext for the MCP server  

Token IDs are CSPRNG for `typed` style (never a hash of plaintext). Maps live in `state_backend` (use Redis for multi-replica).

Docs: [PII_VAULT.md](PII_VAULT.md), [PII_VAULT_TUTORIAL.md](PII_VAULT_TUTORIAL.md).

---

## 7. Context engineering and catalog integrity

### 7.1 Schema minimization

Large tool catalogs consume tens of thousands of tokens before the user prompt. Opt-in minimization truncates descriptions and strips nested JSON Schema `description` fields on `tools/list` **without removing tools**:

```yaml
discovery_filter:
  minimize_schemas: true
  max_description_chars: 160
  strip_schema_descriptions: true
```

Combine with `discovery_filter.enabled` + `tool_allowlist` to also hide non-allowlisted tools.

### 7.2 Live catalog pin

Detect tool-poisoning drift at runtime:

```yaml
tool_metadata_fingerprint:
  enabled: true
  pin_on_first_seen: true
  on_drift: block   # or warn
```

Or pin to a fingerprint file from `mcp-bastion fingerprint`.

Docs: [SCHEMA_MINIMIZE_LIVE_PIN.md](SCHEMA_MINIMIZE_LIVE_PIN.md).

---

## 8. Security pillars (reference map)

| Concern | Primary pillars |
|---------|-----------------|
| Injection | `prompt_guard`, `response_scan`, `semantic_firewall`, `content_filter` |
| Privacy / DLP | `pii`, `pii_vault`, secret redaction |
| Privilege | `rbac`, `agent_iam`, `tool_allowlist`, `argument_guards` |
| Integrity | `server_verification`, `tool_metadata_fingerprint`, `tool_metadata_guard` |
| Availability / FinOps | `rate_limit`, `cost_tracker`, `cost_policy`, `output_budget`, `session_limits` |
| Behavior | `behavior_fingerprint`, `agent_stability` |
| Boundary | `transport_hardening`, `boundary_mode`, `edge_auth` |

Deep dives: [FEATURE_DEEP_DIVE.md](FEATURE_DEEP_DIVE.md) (issue → solution → benefits), [FEATURES.md](FEATURES.md), [ENTERPRISE_RUNTIME_CONTROLS.md](ENTERPRISE_RUNTIME_CONTROLS.md), [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md).

---

## 9. Observability and operations

### 9.1 Dashboard

```bash
mcp-bastion dashboard --demo
```

Shows KPIs (requests, blocks, PII, vault abstract/hydrate), governance tiles, and forensics.

### 9.2 Metrics

- In-process `MetricsStore`  
- Prometheus scrape endpoint on the dashboard (`/metrics`) including `mcp_bastion_pii_vault_*`  

See [METRICS.md](METRICS.md), [SECURITY_OBSERVABILITY.md](SECURITY_OBSERVABILITY.md), [OTEL.md](OTEL.md).

### 9.3 Doctor and red team

```bash
mcp-bastion doctor
mcp-bastion redteam
```

---

## 10. Production checklist

1. **Pin versions** — `mcp-bastion-python==4.0.0` (or current release).  
2. **Validate config** — `mcp-bastion validate` in CI.  
3. **Choose deployment shape** — middleware vs `serve --proxy`.  
4. **Enable transport hardening** for HTTP.  
5. **Wire identity** — `agent_iam` / `edge_auth` / `identity_adapter` before relying on RBAC.  
6. **Decide PII mode** — destructive vs vault; Redis if multi-replica vault.  
7. **Shrink catalogs** — allowlist and/or `minimize_schemas`.  
8. **Pin catalogs** — `pin_on_first_seen` or fingerprint file in high-assurance envs.  
9. **Export attestation / audit** as required by your compliance program.  
10. **SBOM / CRA** — `python scripts/generate_sbom.py` ([CRA_SBOM_TUTORIAL.md](CRA_SBOM_TUTORIAL.md)).

---

## 11. End-to-end scenario (worked example)

**Goal:** Protect a calendar MCP server behind Bastion so agents never see raw emails, while invite tools still receive real addresses.

1. Install `mcp-bastion-python==4.0.0`.  
2. Copy `examples/bastion-pii-vault.yaml` → `bastion.yaml`; set `pii_vault.enabled: true`.  
3. Run upstream MCP on `127.0.0.1:9000`.  
4. Start proxy:  
   `mcp-bastion serve --proxy --upstream http://127.0.0.1:9000/mcp --port 8080`  
5. Point the agent at `http://127.0.0.1:8080/mcp`.  
6. Observe tool results containing `{{pii:EMAIL_ADDRESS:…}}` (or `EMAIL_ADDRESS_1` if low-entropy).  
7. Confirm subsequent `tools/call` args are hydrated before upstream execution.  
8. Enable `minimize_schemas` and `pin_on_first_seen` for catalog hygiene.  
9. Run `mcp-bastion doctor` and review dashboard vault counters.

---

## 12. Related documentation

| Topic | Document |
|-------|----------|
| Feature deep dive (issue → solution → benefits) | [FEATURE_DEEP_DIVE.md](FEATURE_DEEP_DIVE.md) |
| Quick start | [QUICK_START.md](QUICK_START.md) |
| Detailed tutorial | [DETAILED_TUTORIAL.md](DETAILED_TUTORIAL.md) |
| CLI reference | [CLI.md](CLI.md) |
| Policy schema | [POLICY_AS_CODE.md](POLICY_AS_CODE.md) |
| Dashboard | [../dashboard/README.md](../dashboard/README.md) |
| Developer / release | [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) |
| Supply chain | [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) |
| Security policy | [SECURITY.md](SECURITY.md) / root [SECURITY.md](../SECURITY.md) |

---

## 13. Support and community

- **Issues:** https://github.com/vaquarkhan/MCP-Bastion/issues  
- **Website:** https://vaquarkhan.github.io/MCP-Bastion/  
- **PyPI:** https://pypi.org/project/mcp-bastion-python/  

---

*This guide describes MCP-Bastion 4.0.0. Feature availability depends on your installed package version and `bastion.yaml` settings.*
