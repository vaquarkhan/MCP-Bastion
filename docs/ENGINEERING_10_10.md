# Engineering roadmap: weak dimensions → 10/10

This document turns independent review findings into **concrete, testable milestones** tied to the current codebase. It complements the release checklist in [ROADMAP.md](ROADMAP.md).

**Flagship lens:** [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md) — cost-aware runtime governance for AI agents. The four ranked moats:

1. Compliance-grade attestation  
2. Un-bypassable boundary mode  
3. Behavioral fingerprinting / adaptive defense  
4. Real semantic layer + bundled default model  

---

**Already fixed in 2.0.0 (do not re-file as open bugs):**

| ID | Issue | Fix |
|----|-------|-----|
| **A** | `mcp-bastion serve` crash (`FastMCP.run(host=…)`) | `serve.run_streamable_http()` sets `mcp.settings.host/port`; regression in `tests/test_serve.py` |
| **B** | `schema_validation.enabled` with no YAML schemas | `schema_validation.schemas` → `SchemaValidator`; doctor warns on empty schemas |
| — | Red-team 100% when ML gated | `score_intended_blocked_pct` vs `score_guard_unavailable_pct` in `redteam.py` |

---

## 1. Prompt-injection depth (Medium → 10/10)

**Gap today:** One gated HF model (Llama-Prompt-Guard) plus short regex heuristics; fail-closed when ML unavailable can blanket-block unrelated traffic.

**Code anchors:** `pillars/prompt_guard.py`, `pillars/response_scanner.py`, `doctor.py` (`prompt_guard_ml` check).

| Milestone | Work |
|-----------|------|
| Non-gated default | Ship a **pip-installable** default classifier (e.g. `protectai/deberta-v3-base-prompt-injection-v2` or ONNX-quantized guard). Keep Llama-Prompt-Guard as opt-in upgrade. |
| Layered detectors | Combine: (a) regex/heuristics, (b) local classifier, (c) canary tokens in tool descriptions, (d) argument-shape allowlists. Expose **blended score + per-layer attribution** in audit/metrics. |
| Second-order injection | Extend `response_scanner` to run the same classifier stack on **tool outputs and resource content**, not only inbound args. |
| Published evaluation | Injection benchmark harness (labeled corpus); report **recall, precision, FPR** per layer in CI or `docs/BENCHMARKS.md`. |

**10/10 acceptance test:**

- Benchmark table published (recall on labeled injection set, FPR on benign traffic).
- Non-gated default blocks standard jailbreak payloads out of the box.
- Tool-output injection case blocked and attributed to `response_scan` layer.

---

## 2. Tool-poisoning / shadow-MCP detection (Medium → 10/10)

**Gap today:** Runtime content filtering; leaders (mcp-scan, Invariant) add **static** tool-definition scanning and rug-pull detection.

**Code anchors:** `pillars/tool_metadata_guard.py`, `server_verification.py`, `tool_metadata_fingerprint.py`, `doctor.py`.

| Milestone | Work |
|-----------|------|
| Static `tools/list` scanner | First-class scanner: homoglyphs, zero-width chars, “ignore/override” phrasing, prompts embedded in descriptions/schemas. CLI: `mcp-bastion scan <server>` with report comparable to mcp-scan. |
| Tool-definition pinning | Hash each tool definition on first sight; **alert/block on drift** (rug pull). Extend server verification from **files** to **live tool manifests**. |
| Shadow / duplicate tools | Flag same tool name from different servers; typosquat (`read_file` vs `read_fi1e`). |
| Cross-origin escalation | Detect tool A referencing capabilities of server B. |

**10/10 acceptance test:**

- `mcp-bastion scan` statically flags a poisoned description and a definition drift scenario with a human-readable report.

---

## 3. Gateway maturity: OAuth, secrets, per-user identity (Behind → 10/10)

**Gap today:** In-process middleware; Agent IAM uses static tokens. Arcade-style gateways add OAuth, vaulting, and verified user identity.

**Code anchors:** `pillars/agent_iam.py`, `pillars/edge_auth.py`, `serve.py`, `transport_hardening.py`, `deploy/`, audit log fields.

| Milestone | Work |
|-----------|------|
| Real identity | OAuth 2.1 / OIDC JWT validation (issuer, audience, expiry, **scopes**). Map scopes → tool permissions (unify with RBAC / Agent IAM). |
| Secrets vaulting | Vault / AWS Secrets Manager / env-injection adapters so upstream API keys never enter LLM context. |
| Per-user audit | Verified `sub` (or equivalent) on every `tools/call` in audit + forensics (today: `tenant_id`, `trace_id`, optional self-asserted `role`). |
| Standalone proxy mode | Hardened `mcp-bastion serve` (TLS, body size limits, documented Docker gateway). **Bug A fix is prerequisite** — shipped via `run_streamable_http`. |

**10/10 acceptance test:**

- Deploy proxy with JWT: expired / wrong scope → **denied**; valid scope → **allowed**; upstream secret **never** in logs or tool payloads.

---

## 4. Context / FinOps depth (Good → 10/10) — **flagship pillar**

**Gap today:** Output budget and discovery filter work but savings are **input-dependent**; “semantic cache” is lexical Jaccard; caps **hard-block** instead of **degrading** under budget pressure.

**Bet:** Own [cost-aware runtime governance](COST_AWARE_GOVERNANCE.md) — live spend drives allow/deny/route, not only pattern match.

**Code anchors:** `pillars/cost_tracker.py`, `pillars/budget_principal.py`, `pillars/output_budget.py`, `middleware.py` (`discovery_filter`), `pillars/semantic_cache.py`, [BENCHMARKS.md](BENCHMARKS.md).

| Milestone | Work |
|-----------|------|
| Cost-aware policy | `cost_policy` rules: degrade model, force discovery filter, require approval at spend thresholds |
| Expensive-chain prevention | Project sequence cost before run; block/throttle via semantic firewall + pricing table |
| Attestation export | Signed session bundle: policy hash, controls fired, blocks, total cost |
| Chargeback dashboard | Per-agent/tenant showback + burn-rate forecast |
| Optional embedding cache | Real semantic cache behind a flag; keep lexical as zero-dep default |
| Honest metrics | Keep published benchmarks; avoid flat “X% prompt reduction” marketing |

**10/10 acceptance test:**

- Session at 80% budget triggers configured degradation (not silent allow).
- Expensive tool chain blocked before execution with `projected_cost_usd` in audit.
- `mcp-bastion attest export` produces verifiable session bundle.
- Benchmark doc + pytest suite stay green.

---

## 5. Maturity / backing (Early → 10/10)

**Gap today:** Young project; npm audit criticals in dev tree; single-maintainer perception.

| Milestone | Work |
|-----------|------|
| Third-party validation | External security audit or academic collaboration; coordinated disclosure track record beyond [SECURITY.md](../SECURITY.md). |
| Governance | CODEOWNERS, multiple reviewers, published release cadence, signed releases (Sigstore, PyPI Trusted Publishing, npm provenance — partially started in [SUPPLY_CHAIN.md](SUPPLY_CHAIN.md)). |
| Adoption signals | Production user stories, integration matrix (Claude Desktop, Cursor, Windsurf). |
| Clean supply chain | SBOM, SLSA provenance, pinned deps, **green** `pip-audit` / `npm audit` (runtime + dev). |

**10/10 acceptance test:**

- Linked audit report, signed artifacts, >1 active maintainer, clean dependency scans in CI.

---

## What reviewers correctly retraced (not bugs)

- **Cost tracker** — works with `llm_provider` / `llm_model` / `llm_*_tokens` or `cost` metadata (wrong keys in manual test).
- **`fail_open`** — duplicate YAML key in test config caused false “not honored” report; parser is correct.

## Not yet E2E-validated (unit tests only)

Requires external services or alternate MCP paths: OPA/Cedar, OTEL collector, live webhooks, multi-tenant, hot-reload, `tools/list` path (metadata guard, discovery filter), shadow mode, telemetry sinks, audit hash chain. Track under [ROADMAP.md](ROADMAP.md) P2+ or integration-test matrix.

---

## Suggested priority order

1. **Cost-aware policy + attestation** — flagship moat; builds on 2.0.0 FinOps (highest enterprise ROI).
2. **Prompt-injection** non-gated default + benchmark table (closes honest security caveat).
3. **Un-bypassable boundary** — hardened proxy Helm + e2e (kills in-process critique).
4. **`mcp-bastion scan`** static tool scanner (competitive parity with mcp-scan).
5. **Behavioral fingerprinting** — adaptive defense tied to spend telemetry.
6. **JWT/OIDC gateway** path (unify with Agent IAM).
7. **Maturity** — audit, npm/pip audit green, Sigstore.
