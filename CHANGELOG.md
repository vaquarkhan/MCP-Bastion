# Changelog

**Current release:** **2.0.2** (2026-07-05) - [PyPI](https://pypi.org/project/mcp-bastion-python/2.0.2/) · [Docker `v2.0.2`](https://github.com/vaquarkhan/MCP-Bastion/pkgs/container/mcp-bastion-proxy)

All notable changes to this project are documented in this file.

## [Unreleased]

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
