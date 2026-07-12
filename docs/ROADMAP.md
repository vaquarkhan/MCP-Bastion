# Product roadmap  -  cost-aware runtime governance

**Guiding rule:** [ZERO_INFRA_STRATEGY.md](ZERO_INFRA_STRATEGY.md)  -  stay a **zero-infra, drop-in library**; be the **guardrail brain** that composes with any gateway.

Status as of **main** post-3.0 governance merge (2026-07-05).

**Flagship bet:** [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md)  -  own *cost-aware runtime governance for AI agents* (policy + live spend + attestation). Deep engineering milestones: [ENGINEERING_10_10.md](ENGINEERING_10_10.md). Competitive positioning: [COMPARISON.md](COMPARISON.md).

**Current release:** [3.1.2](https://pypi.org/project/mcp-bastion-python/3.1.2/) · Docker `v3.1.2` · integration packages **3.1.2**

---

## Flagship: four features that stick (ranked)

| # | Feature | Moat | Target | Doc |
|---|---------|------|--------|-----|
| **1** | **Compliance-grade attestation** | Signed session export: policy version, controls fired, blocks, cost | **3.0** | [COST_AWARE_GOVERNANCE.md §1](COST_AWARE_GOVERNANCE.md#1-compliance-grade-attestation-the-moat) |
| **2** | **Un-bypassable boundary mode** | Hardened proxy/sidecar; same `bastion.yaml` without host cooperation | **3.1** | [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md) |
| **3** | **Behavioral fingerprinting** | Per-agent baselines (tools, args, rates, spend) in shadow mode | **3.2** | [COST_AWARE_GOVERNANCE.md §3](COST_AWARE_GOVERNANCE.md#3-behavioral-fingerprinting--adaptive-defense-research-credible) |
| **4** | **Real semantic layer + bundled model** | Embedding cache + non-gated classifier; offline not regex-only | **3.0 / 3.2** | [ENGINEERING_10_10.md §1, §4](ENGINEERING_10_10.md) |

**Cost-aware policy** (budget-driven degradation, expensive-chain prevention, chargeback/forecast) ships across **3.0–3.2**  -  see [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md).

---

## Shipped (2.0.0)

| Feature | Status |
|---------|--------|
| Agent Identity & RBAC | ✅ `agent_iam` |
| Server SHA-256 verification | ✅ `server_verification` + `mcp-bastion manifest` |
| PromptGuard fail-closed + heuristics | ✅ |
| FinOps principal caps (no session rotation bypass) | ✅ `budget_principal` + tenant-global daily budget |
| RBAC requires authenticated identity | ✅ `require_authenticated_identity` + config validation |
| OTEL negative cache (audit path latency) | ✅ |
| content_filter normalization + shell patterns | ✅ |
| external_policy fail-closed default | ✅ |
| Zero-Trust README + infographics | ✅ |
| **`mcp-bastion serve` FastMCP fix** | ✅ `serve.run_streamable_http()` |
| **`schema_validation.schemas` in YAML** | ✅ + doctor warning if empty |
| **Red-team intended vs guard-unavailable scores** | ✅ `score_intended_blocked_pct` |
| **FinOps/RBAC benchmarks** | ✅ [BENCHMARKS.md](BENCHMARKS.md) |
| **HTTP transport hardening** | ✅ `transport_hardening` |
| **stdio stdout JSON guard** | ✅ `stdio_guard` |
| **Tool metadata fingerprint** | ✅ `mcp-bastion fingerprint` |
| **Dashboard IAM / verification / governance** | ✅ `pillar_health` + governance panel |
| **Manifest HMAC signatures** | ✅ `manifest --sign` |
| **Multi-agent session isolation** | ✅ `agent_iam.isolate_sessions` |
| **Resource URI IAM (write-path)** | ✅ `allowed_resources` / `blocked_resources` |
| **Registry publisher doctor check** | ✅ `governance.allowed_registry_names` |
| **Reverse-proxy recipe** | ✅ [deploy/](../deploy/README.md) |
| **Full MCP surface guards** | ✅ `resources/read`, `prompts/get`, `sampling/createMessage`, `elicitation/create` |
| **Pluggable shared state (Redis)** | ✅ `state_backend` in bastion.yaml |
| **JSONPath argument guards** | ✅ `argument_guards` |
| **Audit JSONL + `mcp-bastion tail`** | ✅ |
| **Cost checkpoint (memory backend)** | ✅ |
| **`cost_policy` + attestation + boundary mode** | ✅ [Unreleased on main] |
| **`mcp-bastion serve --proxy`** (boundary, same config) | 🟡 |
| **BYOI `identity_adapter`** | 🟡 |
| **Secrets resolver + syslog SIEM sink** | 🟡 |

---

## Future roadmap (3.0+)

Prioritized by **security ROI**, **production adoption**, and **discoverability**. Effort: **S** (days–1 week), **M** (2–4 weeks), **L** (1–2 months), **XL** (quarter+).

### P0  -  Cost-aware policy (target: 3.0–3.2) **flagship**

| Feature | Effort | Why implement | Acceptance |
|---------|--------|---------------|------------|
| **`cost_policy` rules engine** (degrade model, force discovery filter, require approval) | M | Spend as control signal, not only hard block | Session at 80% budget triggers configured action; pytest |
| **Expensive-chain prevention** (projected sequence cost before run) | M | Stops denial-of-wallet *chains* before execution | Semantic-firewall + cost projection blocks over-threshold sequence |
| **Governance attestation export** (signed session bundle) | M | Enterprise system-of-record; moat #1 | `mcp-bastion attest export`; includes policy hash + cost |
| **Dashboard chargeback / forecast** | M | FinOps buyers need showback | Per-agent spend + burn-rate forecast tile |
| **Per-model cost weighting** in caps | S | gpt-4o should burn budget faster | Configurable multipliers |

See [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md).

---

### P1  -  Security depth (target: 3.0)

Highest value; closes audit gaps and matches mcp-scan / Invariant class tooling.

| Feature | Effort | Why implement | Acceptance |
|---------|--------|---------------|------------|
| **Non-gated PromptGuard default** (ONNX / small classifier, no HF login) | M | Heuristic-only mode is bypassable; offline installs need real ML | Benchmark recall/FPR published; `doctor` reports active layer |
| **Layered injection scoring** (heuristic + ML + attribution in audit) | M | Operators need to know *which* layer blocked a request | Audit/metrics show per-layer reason |
| **Second-order injection scan** (tool outputs + resources, not only inbound args) | M | Exfil via tool results is a top MCP attack path | Red-team case blocked + attributed to `response_scan` |
| **`mcp-bastion scan`** static tool-definition scanner | M | Parity with mcp-scan; rug-pull / homoglyph / embedded prompts in `tools/list` | ✅ Shipped 3.0 — CLI report flags poisoned description + drift |
| **Live tool-definition pinning** (hash on first sight, block on drift) | M | Extends server verification from files to runtime catalog | Drift scenario blocked in integration test |
| **Shadow / typosquat tool detection** | S | `read_file` vs `read_fi1e` across servers | Scanner flags homoglyph pair |
| **Bundled injection benchmark corpus** | S | Honest marketing; CI regression gate | `tests/` + [BENCHMARKS.md](BENCHMARKS.md) table |

See [ENGINEERING_10_10.md §1–2](ENGINEERING_10_10.md).

---

### P2  -  Identity, proxy UX, and MCP client compatibility (target: 3.1–3.2)

Closes the biggest *gateway* gap vs products like ThinkWatch **without** building a full AI API proxy.

| Feature | Effort | Why implement | Acceptance |
|---------|--------|---------------|------------|
| **OAuth 2.1 / OIDC JWT at edge** (issuer, audience, scopes → RBAC / Agent IAM) | L | Real `sub` on audit; no self-asserted roles in prod | Expired/wrong-scope JWT denied; valid scope allowed |
| **MCP auth-required catalog UX** (`_meta.requires_user_auth`, JSON-RPC `-32050` + authorize URL) | M | Cursor / Claude Desktop expect catalog + auth prompt, not empty list | Compliant client can drive user to authorize |
| **Per-user upstream credential vault** (encrypted OAuth/PAT per user + server, optional) | XL | “Upstream sees real user” for multi-tenant MCP hubs | GitHub MCP call audited with user `sub` + upstream identity |
| **Virtual API keys with lifecycle** (issue, rotate, grace period, `surfaces` allowlist) | L | Enterprise key governance; separate dev/CI keys | Key rotation without downtime; audit ties to key id |
| **Standalone hardened proxy mode** (`mcp-bastion serve --proxy`) | M | **Tier 1:** un-bypassable boundary, same code | 🟡 HTTP proxy + guarded JSON-RPC |
| **BYOI identity adapters** (header / JWT claim) | S | Per-user governance without auth server | 🟡 `identity_adapter` in bastion.yaml |
| **Secrets resolver** (env + vault optional extras) | M | BYO vault; no secrets in git | 🟡 `secrets.provider` interface |
| **Syslog / Kafka SIEM sinks** | S | BYO backend vs managed ClickHouse | 🟡 syslog shipped; Kafka 🔜 |
| **SSO for dashboard** (OIDC login for admin UI, not only edge bearer) | M | Teams want Okta/Azure AD on the console | Dashboard login via OIDC; RBAC from claims |

See [ENGINEERING_10_10.md §3](ENGINEERING_10_10.md).

---

### P3  -  FinOps, rate limits, and scale (target: 3.2–3.3)

| Feature | Effort | Why implement | Acceptance |
|---------|--------|---------------|------------|
| **Behavioral fingerprinting** (per-agent baseline + anomaly) | L | **Moat #3:** adaptive defense tied to spend telemetry | Shadow mode learns baseline; anomaly flags in audit + dashboard |
| **Calendar-aligned budgets** (daily / weekly / monthly token caps in Redis) | M | FinOps teams think in billing periods, not rolling windows only | Budget resets on period boundary; pytest + benchmark |
| **Multi-window rate limits** (1m / 1h / 1d stacks per principal) | M | Burst vs sustained abuse need different windows | Stacked rules enforced; denial names winning rule |
| **Per-model token weighting** for quotas | S | gpt-4o bursts should consume budget faster than small models | Configurable multipliers in cost/rate paths |
| **Optional embedding semantic cache** (lexical remains default) | M | **Moat #4:** honest "semantic" claims | Flag-gated; benchmark shows hit rate vs lexical |
| **Prometheus export hardening** (multi-worker doc + scrape auth recipe) | S | Fleet deployments need one metrics endpoint story | [METRICS.md](METRICS.md) + compose example |
| **ClickHouse / OLAP audit sink** (optional, behind plugin) | L | Large fleets want SQL analytics on audit | Optional sink; not required for core install |

See [ENGINEERING_10_10.md §4](ENGINEERING_10_10.md).

---

### P4  -  Discoverability, docs, and adoption (ongoing)

Low engineering cost; improves GitHub search and time-to-first-demo (learned from high-star MCP gateway repos).

| Feature | Effort | Why implement | Acceptance |
|---------|--------|---------------|------------|
| **GitHub repo topics** (`mcp-security`, `mcp-gateway`, `prompt-injection`, …) | S | #1 GitHub search fix; ThinkWatch uses 8+ topics | Topics visible on repo About |
| **Homepage URL** (GitHub Pages or custom domain) | S | Professional signal; links from registry | Set in repo settings |
| **README comparison table** (vs proxy-only / unguarded MCP) | S | Scannable differentiation in 30 seconds | Table in README + [COMPARISON.md](COMPARISON.md) |
| **60-second quick start** (Docker + pip above the fold) | S | Stars correlate with instant demo | First screen: install + run |
| **Star history chart** | S | Social proof on README | Embedded chart |
| **Curated MCP recipes** (YAML templates: GitHub MCP + bastion.yaml) | M | “MCP store lite” without building full OAuth UI | `examples/recipes/` + docs |
| **`mcp-bastion init`** interactive wizard | M | Lowers first `bastion.yaml` | Generates config + runs doctor |
| **Production adoption stories** | S | Trust for enterprise evaluators | Linked in README |
| **Optional README.zh-CN** | S | Wider reach | Translated quick start + links |

---

### P5  -  Maturity, supply chain, and enterprise (target: 3.3+)

| Feature | Effort | Why implement | Acceptance |
|---------|--------|---------------|------------|
| **Sigstore / cosign image signing** | M | Enterprise procurement asks for signed artifacts | Verify workflow in [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md) |
| **SBOM per release** (Python wheel + Docker) | S | SOC2 / vendor questionnaires | Attached to GitHub Release |
| **External security audit** (published report) | L | Independent validation of claims | Linked report + CVE process |
| **npm `@mcp-bastion/core` publish** (scope + Trusted Publishers) | S | TS developers discover via npm | Package live on npmjs |
| **E2E integration test matrix** (OPA, OTEL, webhooks, multi-tenant, hot-reload) | M | Today many paths are unit-tested only | CI job with tagged scenarios |
| **Helm chart** (proxy + dashboard + Redis optional) | M | K8s buyers expect `helm install` | Chart in `deploy/helm/` |
| **VS Code / JetBrains JSON Schema** for `bastion.yaml` | S | IDE autocomplete reduces misconfig | Schema published + docs |

See [ENGINEERING_10_10.md §5](ENGINEERING_10_10.md).

---

## Explicit non-goals

We will **not** optimize for parity with full **AI API gateways** (OpenAI/Anthropic chat proxy, provider routing UI, ClickHouse-first product). Those are different products. MCP-Bastion stays:

- **Embeddable** (`pip install`, middleware, `bastion.yaml`)
- **MCP-native** (full method surface, OWASP MCP Top 10, tool poisoning)
- **Local-first** (no mandatory third-party safety API)

Also out of scope:

- **OS-level sandboxing** (use containers / gVisor in your platform)
- **Replacing your IdP** (we integrate OAuth/OIDC; we don’t ship Okta)
- **Mandatory cloud SaaS** for core security features

---

## Suggested release sequencing

| Release | Theme | Headline items |
|---------|-------|----------------|
| **3.0** | **Cost-aware governance v1** | `cost_policy` degradation, expensive-chain prevention, attestation export, non-gated PromptGuard, `mcp-bastion scan` |
| **3.1** | **Un-bypassable boundary** | Hardened proxy Helm, OIDC JWT edge, MCP `-32050` auth catalog UX, virtual key lifecycle (phase 1) |
| **3.2** | **Adaptive + semantic** | Behavioral fingerprinting, embedding cache, chargeback forecast dashboard, calendar budgets |
| **3.3** | Enterprise maturity | Sigstore, SBOM, optional audit OLAP sink, external audit |

Order within a release can shift based on contributor capacity and user demand. **P0 cost-aware policy** and **attestation (moat #1)** trump discoverability (P4) for semver minors.

---

## How to influence the roadmap

- Open a [GitHub issue](https://github.com/vaquarkhan/MCP-Bastion/issues) with **use case + threat model + acceptance test**.
- PRs welcome for benchmark fixtures, docs, and pillar implementations that include tests and `bastion.yaml` examples.
