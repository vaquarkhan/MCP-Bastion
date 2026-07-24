# Changelog

**Current release:** **3.3.1** (2026-07-24) - [PyPI](https://pypi.org/project/mcp-bastion-python/3.3.1/) · [Docker `v3.3.1`](https://github.com/vaquarkhan/MCP-Bastion/pkgs/container/mcp-bastion-proxy)

All notable changes to this project are documented in this file.

## [Unreleased]

## [3.3.1] - 2026-07-24

Patch release: **CRA / OpenSSF steward docs + CycloneDX SBOM pipeline** - **no runtime or API breaking changes**. All **18 PyPI packages**, npm, Docker, and MCP Registry bumped to **3.3.1**.

### Added

- **CycloneDX SBOM (CRA / OpenSSF):** `scripts/generate_sbom.py` emits `bom.json` / `bom-npm.json` from manifests (no new runtime deps). Fail-safe upload on `publish-mcp.yml` and `publish-docker.yml`.
- **CRA Article 14 VDP addendum:** root [SECURITY.md](SECURITY.md) ENISA SRP escalation + 48h acknowledgement SLA; docs [CRA_COMPLIANCE.md](docs/CRA_COMPLIANCE.md), [CRA_SBOM_TUTORIAL.md](docs/CRA_SBOM_TUTORIAL.md), diagram `images/mcp-bastion-cra-sbom.svg`.
- **Tests:** `tests/test_generate_sbom.py` for SBOM generator coverage.

## [3.3.0] - 2026-07-21

Minor release: **behavioral fingerprinting** middleware pillar - **opt-in, default OFF** (no breaking changes). All **18 PyPI packages**, npm, Docker, and MCP Registry bumped to **3.3.0**.

### Added

- **Behavioral fingerprinting pillar:** per-principal tool baseline learning, drift and rate-spike detection (`behavior_fingerprint.enabled`); `warn` (default) or `block`; Redis-backed via `state_backend`.
- **Docs:** [docs/BEHAVIOR_FINGERPRINT.md](docs/BEHAVIOR_FINGERPRINT.md), [docs/RELEASE_3.2.0_ANNOUNCE.md](docs/RELEASE_3.2.0_ANNOUNCE.md).
- **Tests:** unit + E2E middleware coverage for warn/block modes.

### Changed

- **`behavior_fingerprint` defaults:** middleware pillar **disabled** by default; legacy `audit_metrics` path remains **enabled** (3.2.0-compatible dashboard anomalies).

## [3.2.0] - 2026-07-21

Feature release: hybrid **stateful / stateless MCP transport** for SEP-2575 readiness - opt-in, backward compatible. All **18 PyPI packages**, npm, Docker, and MCP Registry bumped to **3.2.0**.

### Added

- **Hybrid stateful / stateless MCP transport (`mcp_transport`):** opt-in identity layer for legacy `MCP-Session-Id` and stateless explicit state handles. Per-request protocol version validation, deterministic FinOps keys, HTTP proxy discovery card (`/.well-known/mcp.json`), and agent stability monitor (`inject` / `block` / `warn`).
- **Docs:** [docs/HYBRID_MCP_TRANSPORT.md](docs/HYBRID_MCP_TRANSPORT.md), [docs/HYBRID_TRANSPORT_TUTORIAL.md](docs/HYBRID_TRANSPORT_TUTORIAL.md), architecture diagram `images/mcp-bastion-hybrid-transport.svg`.
- **Example:** [examples/bastion-hybrid-transport.yaml](examples/bastion-hybrid-transport.yaml).
- **Tests:** unit + E2E coverage for transport modes, discovery, proxy discovery, agent stability middleware wiring.

### Changed

- **`bastion.yaml.example`:** documents `mcp_transport` block (default OFF).
- Tutorial 6 in [docs/TUTORIALS.md](docs/TUTORIALS.md); [docs/Advanced_Tutorials.md](docs/Advanced_Tutorials.md) index restored.

## [3.1.2] - 2026-07-12

Patch release: forensics master-detail UX - Trace / Reproduce live in a side panel (auto-select first row). All **18 PyPI packages**, npm, Docker, and MCP Registry bumped to **3.1.2**.

### Changed

- **Blocked requests (forensics):** lean table + sticky Overview / Trace / Reproduce detail on wide screens; auto-selects the first row; JS self-heals stale HTML layouts.
- Dashboard `ui_revision` `v37-forensics-autoselect`.

## [3.1.1] - 2026-07-12

Patch release: complete dashboard tour captures (how-to-fix + FinOps + RBAC), posture-drift panel, and governance tiles for core policy pillars. All **18 PyPI packages**, npm, Docker, and MCP Registry bumped to **3.1.1**.

### Added

- **Posture drift panel:** daily allow/block charts, drift Δ, top kinds/tools, recent blocks from local audit JSONL (`/api/trends`).
- **Governance tiles for core policy:** RBAC, prompt guard, rate limit, cost, PII, schema, content filter alongside Agent IAM / supply-chain / transport.
- **12-slide tour GIF:** includes PMD-style **how to fix** modal and **token reduction / cost savings** FinOps panel; regenerate via `scripts/capture_dashboard_demo.py`.

### Changed

- Demo mode enables RBAC and common pillars so the board matches seeded blocks.
- `dashboard/README.md` documents the full slide list and FinOps / issue-guide / RBAC surfaces.

## [3.1.0] - 2026-07-12

Feature release: local dashboard posture / OWASP / FinOps panels, PMD-style issue guides, and Sonar-style prevalidation - still zero-infra (no DB, login, or cloud). All **18 PyPI packages**, npm, Docker, and MCP Registry bumped to **3.1.0**.

### Added

- **Dashboard security posture:** letter grades from local `.bastion/scan/` JSON (catalog, skills, OSV, risk audit); demo seed via `MCP_BASTION_DEMO=1` / `--demo`.
- **Static prevalidation:** `/api/prevalidate` - Sonar-style issue list from the same local scan artifacts (not SonarQube).
- **Issue guides:** bundled PMD-style rule cards (`issue_guides.py`) with why / how to fix / Bastion knobs / OWASP refs; `/api/issue-guide?check=` or `?id=ASI02`; findings and taxonomy cells open the guide in the UI.
- **OWASP heatmaps + attack matrix:** ASI / MCP / LLM tabs, live attack categories under pressure, compliance evidence reports + date filters, observe-mode banner, agents / trends / onboarding panels.
- **FinOps cost burn & reduction:** actual vs would-have-been spend/tokens; tokens saved (output budget / discovery filter / cache); **tokens/$ avoided by blocks**; charts + blocked-issues table on the dashboard.
- **Demo captures:** `scripts/capture_dashboard_demo.py` (9-slide tour GIF at ~5s/frame); assets under `images/mcp-bastion-dashboard*.png|gif`.

### Changed

- Dashboard remains a **read-only** view over in-process metrics + local files ([docs/ZERO_INFRA_STRATEGY.md](docs/ZERO_INFRA_STRATEGY.md), [dashboard/README.md](dashboard/README.md)).
- Docs: README, developer guide, tutorials, FEATURES, METRICS, TAXONOMY, CLI, QUICK_START updated for 3.1.0 dashboard features.

## [3.0.1] - 2026-07-12

Patch release: client-side scan suite expansion (audit, schema, skills, OSV), taxonomy, and prior PromptGuard/scan polish. All **18 PyPI packages**, npm, Docker, and MCP Registry bumped to **3.0.1**.

### Added

- **`mcp-bastion audit`:** local MCP risk audit of client configs (over-broad tools, standing credential smells, filesystem-server hints). ASCII text + JSON; `--fail-on` for CI.
- **Filesystem policy pack:** `examples/bastion-filesystem-guards.yaml` and `examples/filesystem_env_deny_demo.py` (allow README, deny `.env` / `.git/config`).
- **`mcp-bastion scan` schema checks:** structural inputSchema preconditions (unbounded strings, free-form objects, unconstrained numerics). On by default within scan; `--no-schema-checks` to disable.
- **`mcp-bastion scan --skills`:** offline agent skill file scanning (over-broad grants, credential path refs, name mismatch).
- **`mcp-bastion osv-refresh` / `osv-scan`:** offline-first OSV dependency CVE lookup; online querybatch opt-in and fail-open.
- **ASI taxonomy:** verified OWASP Agentic Top 10 (ASI01-10) tags in `taxonomy.py` + `report --framework asi` pillar mapping; JSON scan/audit findings include `taxonomy`.
- **Docs:** [docs/TAXONOMY.md](docs/TAXONOMY.md), scan-suite graphic `images/mcp-bastion-scan-suite.png`.
- **Census script:** `scripts/census_public_mcp.py` grades public/local tool catalogs into `docs/census/` (metadata only).

### Fixed

- **PromptGuard default:** `use_ungated_default` now defaults to **true** (ProtectAI DeBERTa, no HF login). Gated Llama Prompt Guard remains opt-in. Fail-closed (`fail_open: false`) unchanged so missing ML still blocks unverified traffic.
- **`mcp-bastion scan` output:** ASCII-only console strings (no em-dash/ellipsis mojibake on Windows cp1252).
- **Compliance report:** SOC2/GDPR `pii_redaction` controls also count audit pillars named `pii` (legacy/simulators).
- **MCP Registry publish:** pin `mcp-publisher` to **v1.7.9** (OIDC audience `https://registry.modelcontextprotocol.io`).
- **npm publish workflow:** clear bootstrap path when `@mcp-bastion/core` is missing (requires one-time `NPM_TOKEN`); fail loudly instead of silent `continue-on-error`.

### Changed

- All **18 PyPI packages**, npm `@mcp-bastion/core`, Docker images, and MCP Registry bumped to **3.0.1**.

## [3.0.0] - 2026-07-11

Feature release: runtime governance pillars for production MCP deployments. All new controls are opt-in via `bastion.yaml`.

### Added

- **Exfiltration canary** (`canary_goallock`): session token injection and outbound argument scanning (-32025).
- **ATR YAML rules** (`atr_rules`): community threat rules merged into `content_filter` denylist (-32027).
- **Local LLM scanner** (`llm_scanner`): optional Ollama-compatible second tier, fail-open (-32026).
- **Threat intel feeds** (`threat_feeds`): background refresh of remote regex rules.
- **Auto-repave** (`auto_repave`): threshold-based automated containment actions.
- **Secret pattern redaction** (`secrets.redact_patterns`): `replace` | `hash` | `mask` | `remove` on tool outputs.
- **Observe mode** (`mode: observe`): shadow enforcement without denying requests.
- **CLI:** `mcp-bastion report` for framework-mapped compliance evidence from audit JSONL.
- **Docs:** [ENTERPRISE_RUNTIME_CONTROLS.md](docs/ENTERPRISE_RUNTIME_CONTROLS.md), sample `atr-rules/` directory.

### Changed

- All **18 PyPI packages**, npm `@mcp-bastion/core`, Docker images, and MCP Registry bumped to **3.0.0**.

## [2.0.2] - 2026-07-05

Patch release: correct runtime version metadata, CI coverage gate, and GitHub Pages site refresh.

### Fixed

- **`mcp_bastion.__version__`** and **CITATION.cff** now match `pyproject.toml` (2.0.1 PyPI wheel reported `2.0.0` at import time).
- All **17 integration** `__version__` strings synced with package metadata.

### Added

- **Coverage tests** for `budget_principal.py` and OTEL Grafana/CloudWatch detection paths (clears 92% gate).

### Changed

- GitHub Pages site (`docs/site/`) updated to **2.0.2** PyPI links.
- All **18 PyPI packages**, npm `@mcp-bastion/core`, Docker images, and MCP Registry republished at **2.0.2**.

## [2.0.1] - 2026-07-05

Patch release: developer documentation, community support files, CI coverage restoration, and republication of all 18 PyPI packages plus Docker images.

### Added

- **[docs/RBAC.md](docs/RBAC.md):** Role-based access control guide (fnmatch globs, Agent IAM pairing, troubleshooting).
- **[docs/FEATURES.md](docs/FEATURES.md):** How-to for all 18 security pillars and 2.0.0 capabilities.
- **[docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md):** Repo layout, local dev, tests, release checklist.
- **[FUNDING.md](FUNDING.md)** and **[SUPPORT.md](SUPPORT.md):** Sponsorship, commercial licensing, and support paths.
- **CI coverage tests** for proxy server, secrets resolver, CLI, telemetry sinks, and Tier 1 modules (restores 92% gate).

### Changed

- Documentation em dash cleanup across markdown files.
- All **18 PyPI packages** (core + 17 integrations) bumped to **2.0.1**.
- Docker `BASTION_VERSION` and GHCR tags updated to **v2.0.1**.

## [2.0.0] - 2026-07-05 (feature release)

Major release consolidating runtime governance hardening, critical bug fixes, benchmarks, and dashboard updates.

### Added

- **Cost-aware policy engine (`cost_policy`):** Live spend rules - `degrade_model`, `force_discovery_filter`, `require_approval` at session spend thresholds; **expensive-chain** blocking for projected multi-tool cost.
- **Governance attestation export:** Per-session event log + `mcp-bastion attest export --session …` with optional HMAC signing (`BASTION_MANIFEST_SIGNING_KEY`); policy hash from `bastion.yaml`.
- **Boundary mode:** `boundary_mode.enabled` enforces proxy authentication on every tool call (requires `edge_auth` or `agent_iam`); startup validation fails if misconfigured.
- **Non-gated PromptGuard default:** `prompt_guard.use_ungated_default` selects `ProtectAI/deberta-v3-base-prompt-injection-v2` (no Hugging Face gate).
- **E2E tests:** `tests/test_cost_policy_e2e.py`, `tests/test_attestation.py`, `tests/test_boundary_mode.py`, `tests/test_governance_integrations_e2e.py` (OPA/OTLP/Slack paths).
- **Flagship strategy:** [docs/COST_AWARE_GOVERNANCE.md](docs/COST_AWARE_GOVERNANCE.md) - cost-aware runtime governance positioning, four ranked moats, 3.0-3.3 release alignment.
- **Gateway boundary guide:** [docs/GATEWAY_BOUNDARY.md](docs/GATEWAY_BOUNDARY.md) - mandatory proxy mode checklist (loopback upstream, edge_auth, NetworkPolicy).
- **Injection efficacy benchmark:** `benchmarks/injection_efficacy.py`, `tests/test_injection_efficacy.py`, row in [docs/BENCHMARKS.md](docs/BENCHMARKS.md).
- **Integration packages 2.0.0:** all 17 `mcp-bastion-*` PyPI integrations published at **2.0.0** (tag `integration-v2.0.0`).
- **Zero-infra Tier 1:** [docs/ZERO_INFRA_STRATEGY.md](docs/ZERO_INFRA_STRATEGY.md) - guardrail-brain positioning vs gateway products.
- **`mcp-bastion serve --proxy`:** HTTP boundary mode forwarding to upstream MCP with identical `bastion.yaml` enforcement.
- **BYOI identity adapters:** `identity_adapter` (header / JWT claim) stamps gateway-authenticated principals for RBAC and FinOps caps.
- **Pluggable secrets resolver:** `secrets.provider` interface (env default; Vault / AWS SM / GCP SM via optional deps).
- **Syslog SIEM sink:** `telemetry.sinks` format `syslog` (RFC 5424 UDP).

- **FinOps/RBAC benchmarks:** [BENCHMARKS.md](docs/BENCHMARKS.md), `scripts/generate_benchmark_report.py`, `tests/test_benchmarks_finops_rbac.py`.
- **Dashboard governance panel:** `/api/governance`, pillar health for IAM and server verification.
- **HTTP transport hardening:** `transport_hardening`, hardened streamable HTTP path.
- **stdio stdout JSON guard:** `stdio_guard` + `install_stdio_guard()`.
- **Tool metadata fingerprint:** `tool_metadata_fingerprint` + `mcp-bastion fingerprint`.
- **Manifest HMAC signatures:** `manifest --sign`, `BASTION_MANIFEST_SIGNING_KEY`.
- **Multi-agent session isolation:** `agent_iam.isolate_sessions`.
- **Resource URI IAM (write-path):** `allowed_resources` / `blocked_resources`.
- **Registry publisher doctor check:** `governance.allowed_registry_names`.
- **Reverse-proxy recipe:** [deploy/](deploy/README.md) Caddy + compose.
- **Forensics:** `agent_id` on audit entries and dashboard forensics table.
- **CLI:** `mcp-bastion --version`.

### Fixed

- **`mcp-bastion serve` crash (Bug A):** FastMCP `run()` no longer accepts `host`/`port`; use `run_streamable_http()` / uvicorn hardened path.
- **`schema_validation.schemas` in YAML (Bug B):** schemas parsed from config; doctor fails when enabled with empty schemas.
- **Red-team reporting:** separate `score_intended_blocked_pct` vs guard-unavailable; honest interpretation in reports.
- **npm audit:** dev dependencies updated (vite, vitest); **0 vulnerabilities** in workspace.
- **doctor pip-audit:** fallback to `python -m pip_audit` when binary missing.
- **Denial-of-wallet bypass:** cost/rate caps aggregate by authenticated `principal_id` and tenant-global daily budget (not client-supplied `session_id` rotation).
- **RBAC self-asserted role:** `require_authenticated_identity` defaults to true; role trusted only after Agent IAM or edge auth marks the context.
- **OTEL audit latency:** negative cache on observability probe so unconfigured OTEL does not block ~420 ms per request.
- **content_filter obfuscation:** URL-decode, unicode-normalize, and shell-pattern expansion (`rm -rf`, pipe-to-sh, base64 piped shell) before matching.
- **external_policy fail-open:** `fail_closed` defaults to true when OPA/Cedar is enabled; config validation requires policy dirs when fail-closed.
- **PromptGuard ML load:** negative cache (`_ml_load_failed`) skips repeated Hugging Face downloads after auth failure.
- **Session cost cap on `tools/call`:** `cost_tracker.record()` now passes `principal_id` / `tenant_id` on the tool-call path so `max_cost_per_session` matches `check()` keys (was silently bypassed after principal-keyed FinOps hardening).
- **tool_metadata_guard no-op:** startup fails when enabled without content_filter or prompt_guard; doctor reports misconfiguration.

### Changed

- Docker proxy image installs `mcp-bastion-python==2.0.0` from PyPI at build time (tag publish runs after PyPI is green).
- npm `@mcp-bastion/core` **2.0.0** (semver major aligned with Python).
- Integration packages depend on `mcp-bastion-python>=2.0.0`.
- Author attribution corrected to **Vaquar Khan** across LICENSE, CITATION.cff, and package metadata.
- **Full MCP surface guards:** `resources/read`, `prompts/get`, `sampling/createMessage`, `elicitation/create` run prompt/content/PII/response-scan pillars (not only `tools/call`).
- **Pluggable shared state:** `state_backend` (`memory` default, `redis` for multi-replica rate limits, replay nonces, cost budgets, session scope).
- **Tests:** `tests/test_mcp_surface_guard.py`, `tests/test_state_backend.py`, `tests/test_config.py` (state_backend), `tests/test_doctor.py` (Redis ping).
- **Docs:** [docs/MCP_SURFACE_AND_SCALE.md](docs/MCP_SURFACE_AND_SCALE.md) · infographic `images/mcp-bastion-mcp-surface-scale.png`.
- **JSONPath argument guards:** block/redact tool arguments via `argument_guards` (`pip install mcp-bastion-python[policy]`).
- **RBAC fnmatch globs:** role permissions support `read_*`-style patterns with specificity-aware matching.
- **Audit JSONL sink:** `audit.jsonl_path` append-only file + `mcp-bastion tail` CLI.
- **Cost checkpoint:** optional `cost_tracker.checkpoint_path` for restart-safe session totals (memory backend).
- **Tests:** `tests/test_argument_guards.py`, `tests/test_audit_jsonl.py`, `tests/test_cost_checkpoint.py`, `tests/test_cli_tail.py`.

## [1.0.18] - 2026-07-05

### Added

- **Runtime governance:** Agent Identity & RBAC (`agent_iam`), server SHA-256 verification (`server_verification`), `mcp-bastion manifest` CLI.
- **Security:** PromptGuard heuristic fallback and fail-closed default; `max_response_bytes` on output budget; errors `-32018`–`-32020`.
- **Docs:** [RUNTIME_GOVERNANCE.md](docs/RUNTIME_GOVERNANCE.md), [ROADMAP.md](docs/ROADMAP.md), [BEYOND_OWASP.md](docs/BEYOND_OWASP.md), [TRANSPORT_HARDENING.md](docs/TRANSPORT_HARDENING.md); runtime governance infographic in README.
- **Tests:** End-to-end config → middleware tests in `tests/test_runtime_governance_e2e.py`.

### Changed

- Docker proxy and dashboard images pin `mcp-bastion-python==1.0.18` at build time (`ARG BASTION_VERSION`).
- Server verification re-checks checksums on every `tools/call` (`force=True`).

## [1.0.17] - 2026-07-05

### Added

- **FinOps:** Token budget wired on tool calls, per-tool session caps, optional output budget (truncate/offload with `bastion_get_offloaded`), optional tiktoken counting.
- **Security:** Response injection scan on outbound tool/resource text, discovery filter for `tools/list`, grounding guard for ungrounded file paths (`GroundingViolationError`, -32017).
- **Docs:** OWASP MCP Top 10 infographic and mapping table in README; updates to [SECURITY_OBSERVABILITY.md](docs/SECURITY_OBSERVABILITY.md).

### Changed

- Docker proxy image pins `mcp-bastion-python==1.0.17` at build time (`ARG BASTION_VERSION`).

## [1.0.16] - 2026-04-24

PyPI, npm, and MCP registry publish **1.0.16**; extended pillars (semantic firewall, sensitive classifier, external policy, etc.) and the documentation below are part of this line.

### Documentation

- [PILLARS.md](docs/PILLARS.md) and [README](README.md): aligned pillar counts with code  -  **18** combined request-path (10 + 8 extended), **14** `pillar_health` dashboard rows (`MetricsStore._build_pillar_health()`), **20+** `bastion.yaml` top-level areas; removed stale “11 / 13” phrasing in the doc index table.

- **README:** **PyPI total downloads** use the live [Shields.io / PePy](https://img.shields.io/pepy/dt/mcp-bastion-python) badge (clicks through to [pepy.tech](https://pepy.tech/projects/mcp-bastion-python)). The old static pepy “total” line badge and the scheduled `update-downloads` workflow / `scripts/update_download_badge.py` were removed; [SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) no longer lists that workflow.

- [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) reframed: free community use with **citation/attribution**, **copyright** and anti–misattribution, and a shorter note on when a **separate commercial** agreement may still apply (governing text remains [LICENSE](LICENSE)). README, `packages/core`, and integration readmes updated for consistency.

### Added

- **Docker on GHCR:** [`.github/workflows/publish-docker.yml`](.github/workflows/publish-docker.yml) builds and pushes `mcp-bastion-proxy` and `mcp-bastion-dashboard` to [GitHub Container Registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry) on every **`v*`** tag (and supports manual **workflow_dispatch** with a custom tag; `latest` is updated only on `v*` tag pushes). [README](README.md) and [DOCKER.md](DOCKER.md) document pull links.

### Fixed

- Dashboard demo metrics respect `BastionConfig` so disabled pillars (for example prompt guard, replay guard) are not faked; synthetic data uses a `demo/...` tool prefix and the default tenant from config.
- `blocked_by_kind` and pillar health: normalize tool-intent and semantic firewall reasons before generic injection matching so "injection-like" argument text is not misclassified.
- Auto-tune latency spike alerts are suppressed until enough samples (warmup) to avoid one-off cold-start noise.
- Cost summary includes `unattributed_usd` when totals are not fully attributed to providers; demo `record_cost` calls use provider dimensions.
- Tests expanded for demo metrics, live traffic helpers, and reason normalization; line coverage for `mcp_bastion` remains at or above 92%.

## Earlier

See [releases](https://github.com/vaquarkhan/MCP-Bastion/releases) and git history for versions before **1.0.16**.
