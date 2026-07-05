# Cost-Aware Runtime Governance

**The flagship bet for MCP-Bastion.**

> *Nobody owns the phrase "cost-aware runtime governance for AI agents." We plant that flag with code we already ship — and extend it with policies that treat **live spend** as a first-class security signal, not an afterthought metric.*

---

## Category of one

| Competitor class | Examples | What they optimize for |
|------------------|----------|------------------------|
| **Scanners** | mcp-scan, Invariant | Static tool definitions, poisoned descriptions, pre-deploy checks |
| **Gateways** | Arcade, Enkrypt, Zuplo, ThinkWatch | Identity, routing, OAuth, API keys, upstream credential vault |
| **MCP-Bastion** | *(this product)* | **Runtime governance on the MCP path** — allow/deny/route using **policy + live cost + attestation** |

Scanners do not see spend. Gateways treat cost as billing, not as a **control plane**. Bastion already has the only credible **denial-of-wallet** story in OSS MCP (principal-keyed caps, output budget, discovery filter, benchmarks). The bet is to make **cost-aware policy** the whole product identity — not one pillar among eighteen.

---

## What we already ship (2.0.0)

Honest foundation — not vapor:

| Capability | Where |
|------------|--------|
| Principal-keyed session + daily caps | `cost_tracker`, `budget_principal`, Redis `state_backend` |
| Denial-of-wallet benchmarks | [BENCHMARKS.md](BENCHMARKS.md) — output budget, discovery filter, RBAC |
| Per-call cost attribution | `metadata["cost"]`, `cost_attribution`, dashboard spend tiles |
| Agent / tenant identity | `agent_iam`, `multi_tenant`, edge auth |
| Hash-chained audit | `audit_hash_chain` — tamper-evident event stream |
| Full MCP surface guards | tools, resources, prompts, sampling, elicitation |

**Gap today:** caps mostly **hard-block** at threshold. The next step is **budget-driven degradation** and **expensive-chain prevention** — policy that *routes* or *downgrades* instead of only denying.

---

## Cost-aware policy (concrete product)

Policies that make **allow / deny / route** decisions using **live spend**, not only pattern matching.

### 1. Budget-driven degradation

When a session or tenant nears budget, **automatically**:

| Trigger | Action (configurable) |
|---------|------------------------|
| Session ≥ 80% of `max_cost_per_session` | Downgrade to cheaper model (via metadata hook / integration) |
| Session ≥ 90% | Force **discovery filter** (minimal tool catalog) |
| Session ≥ 95% | Require **approval** / elicitation gate before expensive tools |
| Daily tenant cap | Hard block or read-only tool set |

**YAML sketch (target 3.0):**

```yaml
cost_policy:
  enabled: true
  rules:
    - when: session_spend_pct >= 80
      action: degrade_model
      target: gpt-4o-mini
    - when: session_spend_pct >= 90
      action: enable_discovery_filter
    - when: session_spend_pct >= 95
      action: require_approval
```

### 2. Expensive-chain prevention

Block or throttle **tool sequences** whose **projected cost** exceeds a threshold **before** execution.

- Estimate from: tool pricing table + argument token count + historical p95 latency cost
- Semantic firewall extension: sequence rules weighted by **cumulative spend**
- Audit: `projected_cost_usd`, `sequence_id`, `blocked_reason: expensive_chain`

### 3. Per-agent / per-tenant chargeback

- Budgets keyed on authenticated `principal_id` (already shipped)
- Dashboard: **showback** by agent, tenant, tool; **forecast** from burn rate
- Export: CSV / JSON for FinOps teams; optional webhook to billing systems

---

## Four features that make it stick (ranked)

### 1. Compliance-grade attestation *(the moat)*

Turn hash-chained audit into a **signed, exportable governance attestation** per agent session:

- Policy version (`bastion.yaml` hash)
- Controls that fired (pillar + layer)
- Blocked vs allowed actions
- **Total cost** and attribution

**Why:** Makes Bastion the **system of record** for agent governance — what enterprises buy and cannot rip out. No OSS MCP competitor ships exportable attestation tied to spend.

**Ship target:** 3.0 · `mcp-bastion attest export --session …` · optional HMAC with `BASTION_MANIFEST_SIGNING_KEY` — **shipped in [Unreleased]**

### 2. Un-bypassable boundary mode *(kills the #1 criticism)*

Hardened **proxy / sidecar** that enforces the same `bastion.yaml` regardless of host cooperation.

- Mandatory network hop (see [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md))
- Helm chart + NetworkPolicy defaults
- mTLS between client and proxy (phase 2)

**Why:** "Cooperative in-process library" is the honest critique. Boundary mode lets us compete with Arcade/Zuplo on **deployment**, while keeping middleware embed path for developers.

**Ship target:** 3.1 · documented K8s path + proxy e2e CI gate

### 3. Behavioral fingerprinting / adaptive defense *(research-credible)*

Learn **per-agent baselines** in shadow mode; flag deviations:

- Tools called, argument shapes, rates, **spend velocity**
- Alert on anomaly + optional auto-tighten rate/cost caps

**Why:** Pairs with FinOps telemetry; beats static scanners on novel abuse; story mcp-scan cannot tell.

**Ship target:** 3.2 · `behavior_fingerprint` pillar extension + dashboard anomaly panel

### 4. Real semantic layer + bundled default model *(honest claims)*

- Replace lexical Jaccard cache with **optional embedding** similarity (lexical remains zero-dep default)
- Embedding-based injection scoring alongside heuristics
- **Non-gated** bundled classifier so offline is not regex-only

**Why:** Closes two honest caveats ("semantic" cache, heuristic-only injection). Makes marketing claims literally true.

**Ship target:** 3.0 (classifier) · 3.2 (embedding cache)

---

## Release sequencing (flagship-aligned)

| Release | Theme | Headline |
|---------|-------|----------|
| **3.0** | Cost-aware policy v1 | Budget degradation rules, expensive-chain prevention, attestation export, non-gated PromptGuard |
| **3.1** | Un-bypassable boundary | Hardened proxy Helm, OIDC JWT edge, MCP `-32050` auth UX |
| **3.2** | Adaptive + semantic | Behavioral fingerprinting, embedding cache, chargeback forecast dashboard |
| **3.3** | Enterprise maturity | Sigstore, SBOM, OLAP audit sink, external security audit |

Security depth (scan, tool drift) stays in the train — it supports governance attestation, not a separate product story.

---

## Messaging (use verbatim if helpful)

- **One-liner:** *Cost-aware runtime governance for AI agents.*
- **Elevator:** *MCP-Bastion is the policy and attestation layer on the MCP path — it stops abuse, proves what ran, and governs spend before the wallet drains.*
- **vs scanner:** *We govern at runtime with live cost, not only at deploy time.*
- **vs gateway:** *We secure MCP deeply — injection, poisoning, FinOps — and embed anywhere; gateway mode when you need an un-bypassable hop.*

---

## Related docs

- [ROADMAP.md](ROADMAP.md) — prioritized backlog
- [BENCHMARKS.md](BENCHMARKS.md) — measured FinOps + injection efficacy
- [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md) — boundary mode checklist (2.0.0)
- [COMPARISON.md](COMPARISON.md) — vs scanners and gateways
- [ENGINEERING_10_10.md](ENGINEERING_10_10.md) — engineering milestones
