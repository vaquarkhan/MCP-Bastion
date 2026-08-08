# Feature deep dive — issue, solution, and benefits

**Version:** 4.0.0  
**Audience:** Security architects, platform engineers, and reviewers who need *why* each control exists—not only how to flip a YAML switch  
**Companion docs:** [DOCUMENTATION_HANDBOOK.md](DOCUMENTATION_HANDBOOK.md) (visual handbook), [FEATURES.md](FEATURES.md) (enablement), [PILLARS.md](PILLARS.md) (counts & mapping), [ATTACK_DEMOS.md](ATTACK_DEMOS.md) (runnable + GIFs), [MULTI_LANGUAGE_SUITE.md](MULTI_LANGUAGE_SUITE.md) (all languages), [dashboard/README.md](../dashboard/README.md) (UI), [USER_GUIDE.md](USER_GUIDE.md) (end-to-end handbook)

This document walks **every major MCP-Bastion capability**—request-path pillars, privacy, FinOps, runtime governance, proxy/transport, the **local dashboard**, CLI/ops, and compliance—using a fixed template:

| Section | Meaning |
|---------|---------|
| **The issue** | Real failure mode if the control is absent |
| **How Bastion solves it** | Mechanism on the MCP request/response path (or offline tool) |
| **Benefits** | Concrete outcomes for security, cost, or operations |
| **Enable** | Primary `bastion.yaml` / CLI knobs (defaults noted) |
| **Signals** | JSON-RPC error code, dashboard surface, metrics |

> **Defaults:** Code defaults (`BastionConfig`) keep most advanced pillars **off**. Prompt guard, PII redaction, rate limit, audit, and transport hardening lean **on**. Treat `bastion.yaml.example` as a stronger starter posture, not the library default.

---

## How to read this guide

```text
AI agent / MCP client
        │  JSON-RPC (tools, resources, prompts, …)
        ▼
┌───────────────────────────┐
│  MCP-Bastion middleware   │  ← pillars evaluate here
│  or HTTP boundary proxy   │
└─────────────┬─────────────┘
              │ allowed / redacted / vaulted
              ▼
        Your MCP server / tools
```

Each pillar can **allow**, **block**, **redact**, **tokenise**, or **observe** (log would-be blocks without denying). Dashboard and Prometheus consume the same metrics store.

---

# Part A — Core request-path pillars (10)

## A1. Prompt injection defense (`prompt_guard`)

### The issue
Agents pass untrusted text into tool arguments. Attackers (or poisoned retrieved content) embed jailbreaks—“ignore previous instructions”, exfiltrate secrets, escalate privileges. Without inbound screening, a single successful injection can drive arbitrary tool use.

### How Bastion solves it
`prompt_guard` scores inbound text with an ML classifier (default: ungated ProtectAI DeBERTa) plus heuristic fallback. High-risk payloads are blocked before the tool runs. The same path covers extended MCP surfaces (`resources/read`, `prompts/get`, sampling, elicitation) when those methods are used.

### Benefits
- Stops classic jailbreak / injection before tool execution  
- Fail-closed option for production (`fail_open: false`)  
- Works without Hugging Face gated models by default  

### Enable
```yaml
prompt_guard:
  enabled: true          # default ON
  threshold: 0.85
  heuristic_fallback: true
  fail_open: false
  use_ungated_default: true
```

### See Bastion help (scripted GIF)

![Prompt guard attack defense demo](images/attack-demos/01-prompt-guard.gif)

*Attack → Bastion evaluate → **BLOCKED -32001** → value: tool never runs.*  
Run: `PYTHONPATH=src python -m examples.attack_demos --only prompt_guard` · Gallery: [ATTACK_DEMOS.md](ATTACK_DEMOS.md)

### Signals
| | |
|--|--|
| Error | **-32001** |
| Dashboard | `pillar_health` → Prompt Guard; governance tiles; attack matrix |
| Ops | `mcp-bastion redteam` for harness scores |
| Demo | GIF above · `python -m examples.attack_demos --only prompt_guard` |

---

## A2. PII redaction (`pii`)

### The issue
Tool outputs often contain emails, phones, SSNs, or account numbers. That data flows straight into the model context and may land in logs, traces, or vendor training pipelines—creating privacy and regulatory exposure.

### How Bastion solves it
With `pii.enabled`, Bastion runs Presidio-style detection on **outbound** tool/resource text and replaces matches with **destructive** placeholders (data is not recoverable). This is the default privacy path when you only need to stop leakage, not round-trip identity to backends.

### Benefits
- Prevents raw PII from re-entering the LLM context  
- Low operational friction (no vault key management)  
- Complements (does not replace) reversible vault when workflows need hydrate  

### Enable
```yaml
pii:
  enabled: true          # default ON
```

### See Bastion help (scripted GIF)

![PII redaction attack defense demo](images/attack-demos/02-pii.gif)

*Outbound SSN/email scrubbed before the model sees them.*  
Run: `PYTHONPATH=src python -m examples.attack_demos --only pii`

### Signals
| | |
|--|--|
| Error / path | silent redact (or block path depending on config) |
| Dashboard | `pillar_health` → PII Redaction; KPI `pii_redacted` |
| Demo | GIF above · `python -m examples.attack_demos --only pii` |
| Related | Reversible mode → [§ C1 PII vault](#c1-reversible-pii-vault-pii_vault) |

---

## A3. Rate limiting (`rate_limit`)

### The issue
Runaway agents loop: thousands of tool calls, huge token burn, or DoS against upstream APIs (“denial of wallet”). Per-tool storms can also exhaust quotas.

### How Bastion solves it
Token-bucket style limits on iterations, wall-clock timeout, optional token budget, and optional per-tool caps. Counters key by principal/session; with Redis `state_backend`, limits stay correct across replicas.

### Benefits
- Caps cost and blast radius of agent loops  
- Protects upstream MCP servers and SaaS quotas  
- Multi-replica safe with Redis  

### Enable
```yaml
rate_limit:
  enabled: true          # default ON
  max_iterations: 15
  timeout_seconds: 60
  token_budget: 50000
  max_per_tool: 0
```

### See Bastion help (scripted GIF)

![Rate limit attack defense demo](images/attack-demos/03-rate-limit.gif)

*Agent loop stopped — denial-of-wallet contained (**-32002**).*  
Run: `PYTHONPATH=src python -m examples.attack_demos --only rate_limit`

### Signals
| | |
|--|--|
| Error | **-32002** (`RateLimitExceededError`) |
| Dashboard | Rate Limiter row; block reasons; governance |
| Demo | GIF above · `python -m examples.attack_demos --only rate_limit` |

---

## A4. Circuit breaker (`circuit_breaker`)

### The issue
A flaky or poisoned tool fails repeatedly. Agents retry aggressively, amplifying outages and cost without making progress.

### How Bastion solves it
Tracks consecutive failures **per tool**. After a threshold, the circuit **opens** and further calls to that tool are rejected until recovery.

### Benefits
- Contains cascading failure  
- Saves spend on known-bad tools  
- Gives operators a clear “open circuit” signal  

### Enable
```yaml
circuit_breaker:
  enabled: true          # default OFF
```

### Signals
| | |
|--|--|
| Error | **-32004** |
| Dashboard | Circuit Breaker in `pillar_health` |

---

## A5. Content filter (`content_filter`)

### The issue
Even without full jailbreaks, args may contain shell snippets, absolute paths, credential strings, or URLs that expand blast radius (path traversal, RCE patterns, secret exfil).

### How Bastion solves it
Pattern and allow/deny list checks on inbound arguments: block code execution patterns, file paths, URLs, and/or secrets. Also supports allowlists for controlled exceptions.

### Benefits
- Fast, deterministic guard for high-risk string shapes  
- Foundation for `tool_metadata_guard` (must pair with content filter or prompt guard)  
- Tunable aggressiveness per environment  

### Enable
```yaml
content_filter:
  enabled: true          # default OFF
  block_code_execution: true
  block_file_paths: true
  block_urls: false
  block_secrets: false
```

### See Bastion help (scripted GIF)

![Content filter attack defense demo](images/attack-demos/04-content-filter.gif)

*`/etc/passwd`-style paths blocked (**-32005**).*  
Run: `PYTHONPATH=src python -m examples.attack_demos --only content_filter`

### Signals
| | |
|--|--|
| Error | **-32005** |
| Dashboard | Content Filter row |
| Demo | GIF above · `python -m examples.attack_demos --only content_filter` |

---

## A6. RBAC (`rbac`)

### The issue
Every agent identity sees every tool. A compromised or over-privileged agent can call admin tools (delete, wire transfers, IAM changes) that should never be in its role.

### How Bastion solves it
Maps **roles → tool name globs** (`fnmatch`). Optional `require_authenticated_identity` refuses anonymous callers. Identity comes from Agent IAM tokens, edge auth, or identity adapters (BYOI from an upstream gateway).

### Benefits
- Least privilege for tool surfaces  
- Clear deny reason for SOC / forensics  
- Works with Agent IAM for confused-deputy defense  

### Enable
```yaml
rbac:
  enabled: true          # default OFF
  require_authenticated_identity: true
  permissions:
    viewer: ["read_*", "search_*"]
    admin: ["*"]
```

See [RBAC.md](RBAC.md).

### See Bastion help (scripted GIF)

![RBAC attack defense demo](images/attack-demos/05-rbac.gif)

*`viewer` cannot call `write` (**-32006**).*  
Run: `PYTHONPATH=src python -m examples.attack_demos --only rbac`

### Signals
| | |
|--|--|
| Error | **-32006** |
| Dashboard | RBAC row; `/api/governance`; Agents panel when IAM is on |
| Demo | GIF above · `python -m examples.attack_demos --only rbac` |

---

## A7. Schema validation (`schema_validation`)

### The issue
Models invent wrong types or missing fields (`year: "twenty"`). Bad args cause silent corruption, backend errors, or injection via unexpected shapes.

### How Bastion solves it
Validates tool arguments against declared per-tool schemas (types and required fields) before invocation.

### Benefits
- Fail fast with a policy error instead of opaque tool failures  
- Reduces injection via type confusion  
- Documents expected contracts next to policy  

### Enable
```yaml
schema_validation:
  enabled: true          # default OFF
  schemas:
    create_report:
      year: integer
      amount: number
```

### See Bastion help (scripted GIF)

![Schema validation attack defense demo](images/attack-demos/06-schema.gif)

*Missing/wrong arg types rejected (**-32007**).*  
Run: `PYTHONPATH=src python -m examples.attack_demos --only schema`

### Signals
| | |
|--|--|
| Error | **-32007** |
| Dashboard | Schema Validation row |
| Demo | GIF above · `python -m examples.attack_demos --only schema` |

---

## A8. Replay guard (`replay_guard`)

### The issue
Captured MCP requests (or buggy clients) are resent. Idempotent-looking tools may double-charge, double-email, or reopen sessions.

### How Bastion solves it
Tracks request IDs / optional nonces and rejects duplicates within the retention window. Redis shares state across replicas.

### Benefits
- Mitigates replay and accidental double-submit  
- Important for financial or mutating tools  

### Enable
```yaml
replay_guard:
  enabled: true          # default OFF
  require_nonce: false
```

### See Bastion help (scripted GIF)

![Replay guard attack defense demo](images/attack-demos/07-replay.gif)

*Duplicate nonce rejected (**-32008**).*  
Run: `PYTHONPATH=src python -m examples.attack_demos --only replay`

### Signals
| | |
|--|--|
| Error | **-32008** |
| Dashboard | Replay Guard row |
| Demo | GIF above · `python -m examples.attack_demos --only replay` |

---

## A9. Cost tracker (`cost_tracker`)

### The issue
Without a spend ceiling, a single agent session or day can burn unlimited LLM + tool cost. Finance has no runtime kill-switch.

### How Bastion solves it
Accumulates principal-keyed session and daily cost (from `context.metadata["cost"]` or attribution helpers). Blocks further calls when caps are hit. Optional checkpoint path for persistence.

### Benefits
- Hard FinOps backstop  
- Per-user / per-tenant accountability when identity is present  
- Feeds cost-aware policy and dashboard burn charts  

### Enable
```yaml
cost_tracker:
  enabled: true          # default OFF
  max_cost_per_session: 10.0
  max_cost_per_day: 100.0
```

### See Bastion help (scripted GIF)

![Cost tracker attack defense demo](images/attack-demos/08-cost.gif)

*Session spend cap hard-stops further calls (**-32009**).*  
Run: `PYTHONPATH=src python -m examples.attack_demos --only cost`

### Signals
| | |
|--|--|
| Error | **-32009** |
| Dashboard | Cost Tracker row; cost KPIs; FinOps panels |
| Demo | GIF above · `python -m examples.attack_demos --only cost` |

---

## A10. Semantic cache (`semantic_cache`)

### The issue
Agents re-ask near-identical tool calls (same lookup phrased slightly differently), wasting latency and money.

### How Bastion solves it
Lexical (Jaccard) similarity cache over argument patterns. Near-duplicate calls can reuse prior results without hitting the tool again.

### Benefits
- Lower tool load and token spend on repetitive workflows  
- No embedding infra required (word-overlap cache)  

### Enable
```yaml
semantic_cache:
  enabled: true          # default OFF
  similarity_threshold: 0.85
```

### Signals
| | |
|--|--|
| Dashboard | Semantic Cache row (telemetry) |
| Detail | [BENCHMARKS.md](BENCHMARKS.md) |

---

# Part B — Extended request-path & FinOps controls

## B1. Semantic firewall (`semantic_firewall`)

### The issue
Individually benign tools become dangerous in **sequence** (e.g. read secrets → send email → delete). Single-call scanners miss multi-step abuse.

### How Bastion solves it
Tracks unsafe tool/argument **chains** and blocks sequences that match policy heuristics.

### Benefits
- Defense in depth beyond one-shot prompt guard  
- Targets agentic “kill chains”  

### Enable / signals
`semantic_firewall.enabled: true` (default OFF) · Error **-32010** · Dashboard Semantic Firewall

---

## B2. Sensitive classifier (`sensitive_classifier`)

### The issue
Business-sensitive content (M&A, insider information) may leave via tool args or outputs without looking like classic PII.

### How Bastion solves it
Classifier with configurable threshold flags sensitive business language and can block the call.

### Benefits
- Extra layer for regulated or deal-sensitive environments  
- Tunable threshold for precision/recall trade-off  

### Enable / signals
`sensitive_classifier.enabled` (default OFF) · **-32011** · Dashboard Sensitive Classifier

---

## B3. External policy engine (`policy_engine`)

### The issue
Enterprises already invest in OPA/Cedar. Duplicating that logic only in Bastion YAML creates drift.

### How Bastion solves it
Delegates allow/deny to an external engine (OPA or Cedar CLI) with fail-closed option. Bastion remains the enforcement point on the MCP path.

### Benefits
- One policy source of truth for platform teams  
- Composable with existing compliance tooling  

### Enable / signals
`policy_engine` + `pip install mcp-bastion-python[policy]` · **-32012** · Dashboard External Policy

---

## B4. Edge auth (`edge_auth`)

### The issue
Anyone who can reach the MCP HTTP port can call tools. Loopback or “private VPC” assumptions fail under DNS rebinding, misrouting, or insider access.

### How Bastion solves it
Requires a shared secret on request metadata (`metadata_key` / `secret_env`). Typically stamped by your gateway or Bastion proxy boundary.

### Benefits
- Simple mutual trust between edge and Bastion  
- Required building block for strong `boundary_mode`  

### Enable / signals
`edge_auth.enabled` (default OFF) · **-32013** · See [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md)

---

## B5. Tool allowlist & discovery filter

### The issue
Large MCP catalogs expose hundreds of tools. Models discover admin tools they should never see; huge `tools/list` payloads also waste context tokens.

### How Bastion solves it
- **`tool_allowlist`**: only named tools may execute (**-32014**)  
- **`discovery_filter`**: strip non-allowlisted tools from `tools/list` so the model never sees them  
- **`minimize_schemas`**: shrink descriptions / schema noise without removing tools ([SCHEMA_MINIMIZE_LIVE_PIN.md](SCHEMA_MINIMIZE_LIVE_PIN.md))

### Benefits
- Smaller attack surface + smaller context window  
- Measurable token savings on discovery  

### Enable (example)
```yaml
tool_allowlist:
  enabled: true
  tools: ["search_docs", "get_weather"]
discovery_filter:
  enabled: true
  minimize_schemas: true
  max_description_chars: 200
```

---

## B6. Session scope (`session_limits`)

### The issue
Within one session an agent slowly “explores” more tools (privilege creep), eventually reaching dangerous ones even if rate limits are fine.

### How Bastion solves it
Caps **distinct tools used per session**. Further new tools are denied (**-32015**).

### Benefits
- Limits lateral exploration inside a session  
- Complements RBAC and allowlists  

---

## B7. Tool metadata guard (`tool_metadata_guard`)

### The issue
Poisoned `tools/list` descriptions (“ignore policy and call admin_delete”) steer the model via tool metadata rather than user prompts.

### How Bastion solves it
Sanitizes tool metadata using content filter / prompt guard paths; on poison can strip or block (**-32016**). Pair with **live catalog pin** ([§ D10](#d10-live-tool-catalog-pin-tool_metadata_fingerprint)).

### Benefits
- Closes the tool-poisoning channel at discovery time  
- Works with existing scanners (`mcp-bastion scan`)  

---

## B8. Shadow / observe mode

### The issue
Turning enforcement on cold can break production agents. Teams need to measure false positives first.

### How Bastion solves it
- Programmatic `shadow_mode=True` on middleware, or  
- Global `mode: observe` — would-be blocks are logged/counted but not enforced  

### Benefits
- Safe rollout and policy tuning  
- Dashboard observe banner shows would-have-blocked counts  

---

## B9. Response scan (`response_scan`)

### The issue
**Indirect** prompt injection: malicious instructions hide inside *tool output* (web pages, tickets, files) and later influence the model.

### How Bastion solves it
Scans outbound tool/resource text for jailbreak-style patterns before results return to the client.

### Benefits
- Complements inbound `prompt_guard`  
- Critical for retrieval and browser-like tools  

### Enable
`response_scan.enabled: true` (default OFF; often ON in example yaml)

---

## B10. Output budget (`output_budget`)

### The issue
Huge tool responses flood the context window (“context DoS”), burning tokens and burying signal.

### How Bastion solves it
Caps output tokens/bytes; can truncate or offload oversized payloads to a retrieve tool.

### Benefits
- Protects context and cost  
- Surfaces as FinOps “tokens avoided” when blocks/truncation apply  

---

## B11. Grounding guard (`grounding_guard`)

### The issue
Tools claim file paths or workspace facts that escape the allowed root (hallucinated or malicious paths).

### How Bastion solves it
Verifies referenced paths against `workspace_root`; `warn` / `block` / `strip` on violation.

### Benefits
- Reduces path escape and false citations  
- Useful for coding-agent MCP servers  

---

## B12. Cost-aware policy & attribution (`cost_policy`, `cost_attribution`)

### The issue
Hard caps alone are blunt. Teams want degrade/approve workflows as spend approaches budget, and accurate per-call estimates.

### How Bastion solves it
- **`cost_attribution`**: estimate USD per call (default ON for telemetry)  
- **`cost_policy`**: degrade, route, or require approval near budget; expensive-chain detection (**-32023 / -32024**)

### Benefits
- Graduated FinOps instead of only hard stop  
- Dashboard actual vs would-have-been burn  

See [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md).

---

## B13. Argument guards (`argument_guards`)

### The issue
You need precise rules on nested JSON fields (e.g. block `$.headers.Authorization` patterns) beyond free-text filters.

### How Bastion solves it
JSONPath + regex rules to block or redact structured arguments (**-32022**). Extra: `pip install mcp-bastion-python[policy]` where required.

### Benefits
- Surgical controls for high-risk fields  
- Clear forensics (“which path matched”)  

---

# Part C — Privacy & secrets

## C1. Reversible PII vault (`pii_vault`)

### The issue
Destructive redaction breaks workflows: CRM tools need the real email to send mail; DBs need the real customer id. Teams either leak PII to the model or break the tool.

### How Bastion solves it
**Opt-in vault** (default OFF):

1. **Abstract** outbound text → tokens like `{{pii:EMAIL:a1b2}}` before the model sees it  
2. Store mapping in memory or Redis (TTL)  
3. **Hydrate** inbound tool args so backends receive real values  
4. Works on in-process middleware **and** HTTP proxy / SSE mutate paths  

### Benefits
- Models never see raw PII; tools still work  
- Zero mandatory cloud KMS (local/Redis store)  
- Dashboard counters: abstract / hydrate totals  

### Enable
```yaml
pii_vault:
  enabled: true          # default OFF — opt-in
  ttl_seconds: 3600
  token_style: typed     # see PII_VAULT.md
```

Full guide: [PII_VAULT.md](PII_VAULT.md) · Tutorial: [PII_VAULT_TUTORIAL.md](PII_VAULT_TUTORIAL.md)

---

## C2. Secret pattern redaction (`secrets.redact_patterns`)

### The issue
API keys and bearer tokens appear in tool output even when PII detectors miss them.

### How Bastion solves it
Configurable regex strategies (`replace` / `hash` / `mask` / `remove`) on outbound results.

### Benefits
- Catches credential-shaped strings PII engines miss  
- Complements `content_filter.block_secrets` on inbound  

---

## C3. Secrets resolver (`secrets.provider`)

### The issue
Policies and manifests must not bake production secrets into git.

### How Bastion solves it
Resolve secret references from env (or vault stubs) at runtime.

### Benefits
- Safer config for edge auth and signing keys  
- Aligns with zero-infra posture  

---

# Part D — Runtime governance & enterprise

## D1. Agent IAM (`agent_iam`)

### The issue
**Confused deputy:** a powerful MCP server acts on behalf of whoever calls it. Without per-agent identity, one stolen session owns all tools.

### How Bastion solves it
Maps bearer/agent tokens → agent profiles with allow/block tool lists, per-agent rates, and optional session isolation (**-32019**).

### Benefits
- True multi-agent least privilege  
- Dashboard Agents panel (denials + scope map)  

See [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md).

---

## D2. Server verification (`server_verification`)

### The issue
Supply-chain or host compromise swaps the MCP server binary/scripts. Clients still “trust” the same URL.

### How Bastion solves it
SHA-256 manifest check at start and on `tools/call` (**-32020**). Optional signature via env. Build manifests with `mcp-bastion manifest`.

### Benefits
- Detects tampered server artifacts  
- Evidence for compliance / attestation  

---

## D3. Exfiltration canary (`canary_goallock`)

### The issue
Data-exfil attacks ask the model/tool chain to echo secrets or session tokens out through args.

### How Bastion solves it
Plants a session canary; blocks if the canary reappears in outbound args (**-32025**).

### Benefits
- High-signal trap for copy-out / goal-hijack patterns  
- Works in observe mode for tuning  

---

## D4. ATR YAML rules (`atr_rules`)

### The issue
Threat patterns evolve faster than code releases. Security teams want community/YAML pattern packs.

### How Bastion solves it
Loads YAML rules from a directory into the content-filter path (**-32027**), with severity gating.

### Benefits
- Hot-updatable pattern packs without rebuilding Bastion  
- Shared ATR-style intelligence  

---

## D5. Local LLM scanner (`llm_scanner`)

### The issue
Heuristics are uncertain on borderline prompts; cloud LLM judges add latency, cost, and data residency risk.

### How Bastion solves it
Optional **local** Ollama (or compatible) second-tier judge when heuristics are unsure (**-32026**). Fail-open design so scanner outages do not brick traffic.

### Benefits
- Stronger judgment without mandatory cloud  
- Still zero-infra by default (feature off)  

---

## D6. Threat intel feeds (`threat_feeds`)

### The issue
Static regex packs go stale.

### How Bastion solves it
Background fetch of remote pattern feeds into scanners with hot reload.

### Benefits
- Fresher indicators without redeploy  
- Opt-in network dependency only when enabled  

---

## D7. Auto-repave (`auto_repave`)

### The issue
Under attack, operators need automatic containment (rotate canary, reset session scope, kill sessions)—not only alerts.

### How Bastion solves it
Threshold-triggered actions: rotate canary, reset scope, terminate sessions.

### Benefits
- Faster incident response automation  
- Reduces dwell time during active abuse  

---

## D8. Behavioral fingerprint (`behavior_fingerprint`)

### The issue
Stolen credentials or prompt malware change *how* an agent uses tools (new tools, rate spikes) even when each call looks individually valid.

### How Bastion solves it
Learns a per-agent baseline; flags drift and rate spikes (**-32031**). Optional `audit_metrics` feeds insights.

### Benefits
- Anomaly detection beyond static allowlists  
- Dashboard Insights / anomalies  

See [BEHAVIOR_FINGERPRINT.md](BEHAVIOR_FINGERPRINT.md).

---

## D9. Boundary mode (`boundary_mode`)

### The issue
Middleware-only installs can be bypassed if clients talk to the raw MCP port.

### How Bastion solves it
Requires proxy-style auth (edge_auth or agent_iam) so enforcement is mandatory at the boundary.

### Benefits
- Un-bypassable control plane when paired with `serve --proxy`  
- Checklist in [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md)  

---

## D10. Live tool-catalog pin (`tool_metadata_fingerprint`)

### The issue
After first discovery, an attacker changes tool descriptions or names (poison / drift). Clients keep trusting the endpoint.

### How Bastion solves it
Hashes `tools/list`; on first seen can pin; on drift `warn` or `block` (**-32032**). Works with `mcp-bastion fingerprint` baselines.

### Benefits
- Detects live catalog poisoning  
- Complements schema minimize and metadata guard  

See [SCHEMA_MINIMIZE_LIVE_PIN.md](SCHEMA_MINIMIZE_LIVE_PIN.md).

---

## D11. Governance attestation & multi-tenant

### The issue
Auditors ask: which policy hash ran, for which tenant, on which session?

### How Bastion solves it
- **`governance.attestation_enabled`**: per-session events for `mcp-bastion attest export`  
- **`multi_tenant`**: per-tenant yaml + `tenant_id` in audit  

### Benefits
- Exportable evidence packs  
- Isolation story for SaaS platforms  

---

## D12. Distributed state & hot reload

| Capability | Issue | Solution | Benefit |
|------------|-------|----------|---------|
| `state_backend: redis` | Memory limits wrong across replicas | Shared rate/replay/cost/vault/fingerprint | Correct fleet enforcement |
| `hot_reload` | Restarts to change policy | Reload `bastion.yaml` live | Faster incident response |

---

# Part E — Proxy, transport & stability

## E1. HTTP boundary proxy (`mcp-bastion serve --proxy`)

### The issue
In-process middleware only protects servers that opt in. Desktop clients and third-party MCP URLs need a URL-swap enforcement point.

### How Bastion solves it
Bastion terminates client HTTP, applies the same `bastion.yaml`, forwards to upstream, and can mutate JSON/SSE for vault abstract/hydrate.

### Benefits
- Same policy for any language upstream  
- Harder to bypass than library-only wraps  

---

## E2. Transport hardening (`transport_hardening`)

### The issue
Localhost MCP HTTP is vulnerable to browser-origin CSRF and DNS rebinding.

### How Bastion solves it
Host allowlists, `block_browser_origin`, `require_loopback` (**-32021**). Default leans **ON**.

### Benefits
- Safer local agent setups  
- Governance “transport” tile  

See [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md).

---

## E3. Hybrid MCP transport & agent stability (`mcp_transport`)

### The issue
Mixed stateful/stateless MCP deployments confuse session affinity; agents also enter tight retry loops on similar calls.

### How Bastion solves it
- Modes: stateful / stateless / auto; discovery card; protocol readiness (**-32028 / -32029**)  
- **Stability**: detect repeated similar calls → inject / block / warn (**-32030**)  

### Benefits
- Cleaner multi-replica MCP hosting  
- Loop mitigation without killing legitimate retries entirely  

See [HYBRID_MCP_TRANSPORT.md](HYBRID_MCP_TRANSPORT.md). *(Not a dedicated dashboard panel—middleware/proxy concern.)*

---

## E4. Identity adapter (BYOI)

### The issue
Enterprises already authenticate at API gateways; Bastion should not invent a second identity system.

### How Bastion solves it
`identity_adapter` consumes header / JWT claims stamped upstream and feeds RBAC / cost keys.

### Benefits
- Fits existing SSO / gateway stacks  
- Keeps Bastion zero-infra  

---

# Part F — Dashboard (local UI)

The dashboard is an **optional local app** (`mcp-bastion dashboard`)—read-only over local artifacts + in-process metrics. No login, no DB, no mandatory cloud. See [dashboard/README.md](../dashboard/README.md).

### The issue (why a dashboard exists)
CLI metrics and JSONL are enough for machines, not for humans. Security and FinOps stakeholders need posture grades, “how do I fix this?”, live attack pressure, RBAC denials, and cost savings—without standing up a SIEM project on day one.

### How Bastion solves it
A zero-infra UI over the same metrics store, scan JSON under `.bastion/scan/`, audit JSONL, and attestation artifacts. Demo mode (`--demo`) seeds sample data for tours.

### Benefits
- Single pane for runtime + static posture + FinOps  
- Issue guides map findings → Bastion YAML knobs → OWASP refs  
- Exportable compliance bundles  

---

## F1. Overview KPIs

| | |
|--|--|
| **Issue** | No at-a-glance health |
| **Solution** | Requests, block %, top threat, users/tenants |
| **Benefit** | Instant “are we under pressure?” signal |

---

## F2. Pillar health

| | |
|--|--|
| **Issue** | Unclear which controls are live vs idle |
| **Solution** | Status rows for Prompt Guard, PII, Rate, Circuit, Content, RBAC, Schema, Semantic Firewall, Sensitive Classifier, External Policy, Replay, Agent IAM, Server Verification, Cost, Semantic Cache, Audit |
| **Benefit** | Config ↔ runtime alignment for operators |

---

## F3. Security posture (A–F grades)

| | |
|--|--|
| **Issue** | Pre-deploy risk is invisible until production incidents |
| **Solution** | Grades from `scan` / `scan --skills` / `osv-scan` / `audit` JSON |
| **Benefit** | Ship/no-ship style signal before agents go live |

---

## F4. Static prevalidation

| | |
|--|--|
| **Issue** | Tool definitions hide poison / schema smells |
| **Solution** | Sonar-style issue list (`/api/prevalidate`) |
| **Benefit** | Fix catalog problems before runtime |

---

## F5. Issue guides (“how to fix”)

| | |
|--|--|
| **Issue** | Findings without remediation stall teams |
| **Solution** | PMD-style guides: why → fix steps → Bastion knobs → OWASP |
| **Benefit** | Turns alerts into actionable policy changes |

---

## F6. OWASP / ASI / MCP / LLM heatmaps

| | |
|--|--|
| **Issue** | Hard to see coverage vs industry taxonomies |
| **Solution** | Tabbed heatmaps; click cells for sample findings |
| **Benefit** | Maps Bastion pillars to known threat lists |

See [TAXONOMY.md](TAXONOMY.md).

---

## F7. Live attack matrix

| | |
|--|--|
| **Issue** | Category pressure is buried in logs |
| **Solution** | Live intensity by attack category + samples/traces |
| **Benefit** | SOC-style situational awareness on the MCP path |

---

## F8. Runtime governance tiles

| | |
|--|--|
| **Issue** | RBAC/IAM/transport state is opaque |
| **Solution** | Tiles for RBAC, prompt guard, rate/cost, PII, schema, content filter, Agent IAM, server verification, transport |
| **Benefit** | Policy posture readable by non-developers |

---

## F9. Cost burn & reduction (FinOps)

| | |
|--|--|
| **Issue** | Security blocks look like “lost productivity”; savings are invisible |
| **Solution** | Actual vs would-have-been spend/tokens; charts; blocked-issue table |
| **Benefit** | Quantifies ROI of guards (tokens avoided by blocks) |

---

## F10. Posture drift

| | |
|--|--|
| **Issue** | Allow/block mix shifts quietly over days |
| **Solution** | Daily series from audit JSONL + drift Δ + top drivers |
| **Benefit** | Catch regressions after policy or model changes |

---

## F11. Forensics (Trace / Reproduce)

| | |
|--|--|
| **Issue** | “Why was this blocked?” takes log archaeology |
| **Solution** | Row list + side panel Overview / Trace / Reproduce |
| **Benefit** | Faster incident review and red-team replay |

---

## F12. Agents panel

| | |
|--|--|
| **Issue** | Confused-deputy denials lack an identity view |
| **Solution** | Denied-by-agent + Agent IAM scope map |
| **Benefit** | Validates IAM design under real traffic |

---

## F13. Alerts, insights, observe banner

| | |
|--|--|
| **Issue** | Anomalies and observe-mode would-blocks are easy to miss |
| **Solution** | SSE alerts, heuristic insights, observe would-have-blocked counts |
| **Benefit** | Safer rollouts and faster paging into Slack/HTTP via `alerts` config |

---

## F14. Compliance evidence

| | |
|--|--|
| **Issue** | Auditors want hashes, reports, and bundles—not raw JSONL |
| **Solution** | Policy/attestation hashes; SOC2/GDPR/ISO/NIST/ASI report or zip |
| **Benefit** | Evidence pack without claiming certification |

---

## F15. Date filters, onboarding, Prometheus

| Capability | Benefit |
|------------|---------|
| Date filters | Scope forensics, trends, matrix, downloads |
| Onboarding checklist | First-run guidance for new installs |
| `/metrics` Prometheus | Scrape vault + pillar counters from the dashboard process |
| `--demo` | Seeded tour for stakeholders |

---

# Part G — CLI & operations toolkit

| Command | Issue it addresses | How it helps |
|---------|-------------------|--------------|
| `validate` | Invalid yaml ships to prod | Schema/lint gate in CI |
| `serve` / `serve --proxy` | Need a process or boundary | Runs middleware host or HTTP proxy |
| `dashboard` | Need a UI | Local security + FinOps board |
| `doctor` | Misconfig / supply-chain gaps | Preflight + hints |
| `redteam` | Unknown harness score | OWASP/MCP scores vs current policy |
| `scan` / `scan --skills` | Poisoned tool defs / skills | Static grade A–F → posture |
| `fingerprint` | No catalog baseline | Emit hash JSON for pin/scan |
| `manifest` / `--sign` | No server integrity file | Feeds `server_verification` |
| `audit` | Desktop client configs risky | Local MCP client-config audit |
| `osv-refresh` / `osv-scan` | Dependency CVEs unknown | Offline (opt-in online) CVE view |
| `attest export` | Session evidence needed | Governance attestation JSON |
| `report` | Framework evidence needed | MD reports from audit JSONL |
| `tail` | Live audit watch | Tail JSONL during incidents |

Full reference: [CLI.md](CLI.md).

---

# Part H — Compliance & supply chain

## H1. CycloneDX SBOM & CRA posture

### The issue
EU CRA / OpenSSF expectations require machine-readable dependency inventories and vulnerability-handling process—not only runtime firewalls.

### How Bastion solves it
- Generate CycloneDX `bom.json` via `scripts/generate_sbom.py` / documented CI  
- Map runtime pillars to steward/Article 14 style controls in docs  
- Vulnerability disclosure via root [SECURITY.md](SECURITY.md)

### Benefits
- Artifacts for customers’ CRA inheritance narratives  
- No runtime behavior change required for SBOM generation  

See [CRA_COMPLIANCE.md](CRA_COMPLIANCE.md) · [CRA_SBOM_TUTORIAL.md](CRA_SBOM_TUTORIAL.md).

---

## H2. Release provenance

### The issue
Consumers need confidence that `mcp-bastion-python` / images came from this CI, not a typosquat.

### How Bastion solves it
PyPI Trusted Publishing (OIDC), container publishes to GHCR, documented npm provenance path when npm is bootstrapped.

### Benefits
- Supply-chain integrity for Bastion itself  
- See [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)  

---

# Quick enablement matrix (starter → hardened)

| Stage | Turn on |
|-------|---------|
| **Minimum** | `prompt_guard`, `pii`, `rate_limit` (defaults) + `transport_hardening` |
| **Team MCP** | + `content_filter`, `replay_guard`, `response_scan`, `tool_allowlist` / `discovery_filter` |
| **Privacy workflows** | + `pii_vault` (keep destructive `pii` or choose vault path carefully) |
| **FinOps** | + `cost_tracker`, `output_budget`, `cost_policy`, dashboard FinOps |
| **Identity** | + `edge_auth` or `agent_iam` + `rbac` + `boundary_mode` / proxy |
| **Enterprise** | + canary, ATR, behavior fingerprint, server verification, observe→enforce |
| **Evidence** | audit JSONL, `attest export`, `report`, SBOM in CI, dashboard compliance |

---

# Error code index

| Code | Control |
|------|---------|
| -32001 | Prompt guard |
| -32002 | PII |
| -32003 | Rate limit |
| -32004 | Circuit breaker |
| -32005 | Content filter |
| -32006 | RBAC |
| -32007 | Schema validation |
| -32008 | Replay guard |
| -32009 | Cost tracker |
| -32010 | Semantic firewall |
| -32011 | Sensitive classifier |
| -32012 | External policy |
| -32013 | Edge auth |
| -32014 | Tool allowlist |
| -32015 | Session scope |
| -32016 | Tool metadata guard |
| -32019 | Agent IAM |
| -32020 | Server verification |
| -32021 | Transport hardening |
| -32022 | Argument guards |
| -32023 / -32024 | Cost policy / expensive chain |
| -32025 | Canary |
| -32026 | LLM scanner |
| -32027 | ATR rules |
| -32028 / -32029 | Hybrid protocol / state handle |
| -32030 | Agent stability loop |
| -32031 | Behavior fingerprint |
| -32032 | Live catalog drift |

---

# Related reading

| Doc | Use when |
|-----|----------|
| [FEATURES.md](FEATURES.md) | Copy-paste YAML enablement |
| [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md) | Worked attack scenarios |
| [USER_GUIDE.md](USER_GUIDE.md) | Install → production checklist |
| [PILLARS.md](PILLARS.md) | Canonical counts & yaml map |
| [METRICS.md](METRICS.md) | Prometheus / effectiveness |
| [ZERO_INFRA_STRATEGY.md](ZERO_INFRA_STRATEGY.md) | Design constraints vs gateways |
