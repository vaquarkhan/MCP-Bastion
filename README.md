<p align="center">
  <img src="images/mcp-bastian.png" alt="MCP-Bastion" width="520" />
</p>

# MCP-Bastion

<!-- mcp-name: io.github.vaquarkhan/mcp-bastion -->

[![PyPI Version](https://img.shields.io/pypi/v/mcp-bastion-python)](https://pypi.org/project/mcp-bastion-python/)
[![Total downloads](https://static.pepy.tech/personalized-badge/mcp-bastion-python?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=total)](https://pepy.tech/projects/mcp-bastion-python)
[![Python](https://img.shields.io/pypi/pyversions/mcp-bastion-python)](https://pypi.org/project/mcp-bastion-python/)
[![CI](https://img.shields.io/github/actions/workflow/status/vaquarkhan/MCP-Bastion/ci.yml?branch=main&label=CI)](https://github.com/vaquarkhan/MCP-Bastion/actions/workflows/ci.yml)
[![License: Source Available](https://img.shields.io/badge/license-Source%20Available-orange.svg)](LICENSE)

**Enterprise-Grade Security Middleware for the Model Context Protocol**

> Releases are published to npm and PyPI via GitHub Actions on tag push.

**Documentation:** structured paths for **policy** and **LLM integration** live in [docs/README.md](docs/README.md) and [docs/index.md](docs/index.md). **Community:** open a GitHub **Issue** for bugs or gaps, a **Discussion** for integration questions (if enabled on the repo), or a **PR** for docs and examples—those help every adopter.

**Hello world (minimal Bastion on code):** see **[docs/QUICK_START.md](docs/QUICK_START.md)** — FastMCP helper `secure_fastmcp(mcp)` (wires `MCPBastionMiddleware` into tool dispatch), or two-line `build_middleware_from_config()` for full `bastion.yaml` policy, plus a **CI validate** snippet for pipeline-driven installs.

The Model Context Protocol (MCP) has rapidly become the universally accepted standard for connecting AI agents to enterprise databases and APIs. However, this connectivity introduces a massive new attack surface: unpredictable, non-deterministic agentic behavior.

MCP-Bastion is a lightweight, drop-in security middleware designed to wrap around any existing Python or TypeScript MCP server. Instead of relying on passive logging, human-in-the-loop approvals, or third-party APIs, MCP-Bastion provides an active, 100% local defense layer. It intercepts standard JSON-RPC traffic to stop threats before they cross the enterprise boundary.

Under 5ms proxy overhead. MCP-Bastion provides:

- **Prompt Injection Defense:** Meta PromptGuard runs locally to block adversarial payloads and jailbreaks.
- **PII Redaction:** Uses Microsoft Presidio to detect and mask PII before it reaches the LLM context.
- **Infinite Loop Protection:** Token buckets and cycle detection stop runaway agents from burning API budget.

Secure your MCP server without changing business logic.

---

## Core Features

**Zero-Click Prompt Injection Prevention**

Integrates Meta's PromptGuard model locally to detect and block malicious payloads, jailbreaks, and adversarial tokenization before they reach your external tools.

**PII Redaction**

Microsoft Presidio scans outbound tool results and masks PII (redaction, substitution, generalization).

**Infinite Loop and Denial of Wallet Protection**

Implements stateful cycle detection and configurable FinOps token-bucket algorithms to automatically terminate runaway agents and prevent massive API bill overruns.

**100% Local Execution (Data Privacy)**

All security classification and data redaction happen entirely within the local memory space of your server. Sensitive data never leaves your enterprise network for third-party safety evaluations.

**Low Latency**

Drop-in middleware, under 5ms overhead.

**Framework Integration**

Hooks into MCP SDKs (TypeScript, Python) and FastMCP via standard middleware. No business logic changes.

### Complete feature catalog

**Pillar definitions:** Security controls, `bastion.yaml` sections, and how they relate to dashboard health rows are documented in [docs/PILLARS.md](docs/PILLARS.md) (canonical reference; avoids ambiguous “total pillar” counts). The same page lists **extended** features restored in 1.0.16+ (semantic firewall, sensitive classifier, external policy, edge auth, tool allowlist, session scope, tool metadata guard, multi-tenant, audit hash chain, pricing hooks, telemetry sinks, **red team** and **doctor** CLIs, etc.).

> **Deeper context:** [docs/SECURITY_OBSERVABILITY.md](docs/SECURITY_OBSERVABILITY.md) — **OWASP MCP Top 10** alignment, attack scenarios, and SIEM/log integrations. **Framework add-ons** (LangChain, OpenAI, Bedrock, …) are listed under [Framework Integrations](#framework-integrations) below.

#### Threat prevention & content safety

| Feature | What you get |
|--------|----------------|
| **Prompt injection defense** | Meta **PromptGuard** scores tool arguments; malicious / jailbreak-style payloads can be blocked before execution (local inference, no third-party API). |
| **Content filter** | Block **shell/code execution** patterns, **sensitive file paths**, and **URLs**; optional **allowlist** / **denylist** regex or substring rules. |
| **PII redaction** | **Microsoft Presidio** detects many entity types in outbound tool/resource text (SSN, email, phone, cards, passport, IBAN, licenses, etc.—see Presidio docs). |

#### Access control, integrity & abuse

| Feature | What you get |
|--------|----------------|
| **RBAC** | **Tool-level** allow/deny by **role** (from request metadata); map roles to tool names in `bastion.yaml`. |
| **Schema validation** | Validate `tools/call` arguments against **JSON Schema** before the tool runs (block malformed or bypass attempts). |
| **Replay guard** | **Nonce** tracking to reject replayed requests (configurable **require_nonce**). |
| **Rate limiting** | **Token-bucket** style limits: **max iterations** per session, **timeout**, **token budget**—stops runaway loops and brute-force patterns. |
| **Circuit breaker** | Stop calling tools that fail repeatedly (limits blast radius of bad upstreams or poisoned tools). |

#### FinOps & performance

| Feature | What you get |
|--------|----------------|
| **Cost tracker** | Per-**session** and optional per-**day** USD caps; blocks when budget is exceeded. |
| **Semantic cache** | Optional **similarity-based** caching for tool semantics (reduce duplicate expensive calls). |
| **Low overhead** | Middleware on the hot path targeting **&lt;5 ms** typical overhead (see [docs/METRICS.md](docs/METRICS.md)). |

#### Audit, metrics & alerting

| Feature | What you get |
|--------|----------------|
| **Audit logging** | Structured **allow/deny** decisions with **reason**, **tool**, **tenant_id**, **trace_id**, **request_id**—feed SOC / compliance. |
| **Alert sinks** | **Slack** incoming webhook; **generic HTTP** webhooks (PagerDuty, Teams, custom APIs); **multiple URLs**; **retry**, **backoff**, **timeout** in `bastion.yaml`. |
| **In-memory metrics** | **Global MetricsStore**: requests, blocks, PII counts, cost, per-tool stats, latency samples, rolling **time series** buckets. |
| **Real-time dashboard** | **Web UI** with a top **KPI summary** (totals, block %, top threat, active users/tenants), **traffic & block charts**, **blocked-by-reason/kind** (with readable reasons / tooltips), **PII by entity** (severity-style coloring, e.g. high-risk types emphasized), **top tools**, **cost by user**, **latency P50/P95/P99**, **forensics table** (tenant filter, trace/replay helpers), **recent alerts**, **insights & anomalies** (heuristic signals), **dark/light theme**, **Prometheus** `/metrics`, **JSON** `/api/metrics`, loading/empty guidance instead of a blank first paint. |
| **OpenTelemetry** | Optional **OTLP** span export — `pip install mcp-bastion-python[otel]` — [docs/OTEL.md](docs/OTEL.md). |

#### Policy, packaging & developer experience

| Feature | What you get |
|--------|----------------|
| **Policy-as-code** | Single **`bastion.yaml`**: toggles for all request-path controls plus audit, alerts, and hot reload ([docs/PILLARS.md](docs/PILLARS.md)); load via `load_config` / `build_middleware_from_config`. |
| **Hot reload** | Optional **reload `bastion.yaml` on change** without restarting the MCP server ([docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md)). |
| **Composable middleware** | **`compose_middleware`** ordering; **`MCPBastionMiddleware`** flags for each pillar. |
| **CLI** | **`mcp-bastion validate`**, **`serve`** (HTTP MCP), **`dashboard`** (optional **`--reload`** / **`--demo`**), **`redteam`**, **`doctor`** — [docs/CLI.md](docs/CLI.md). |
| **Python + TypeScript** | **`mcp-bastion-python`** on PyPI; **`@mcp-bastion/core`** on npm for TypeScript MCP servers (rate limits in-process; prompt/PII via optional sidecar). |
| **Containers** | **Dockerfile**, **docker-compose** profiles (proxy + optional dashboard) — [DOCKER.md](DOCKER.md). **Prebuilt images (GHCR):** [`mcp-bastion-proxy`](https://github.com/vaquarkhan/MCP-Bastion/pkgs/container/mcp-bastion-proxy), [`mcp-bastion-dashboard`](https://github.com/vaquarkhan/MCP-Bastion/pkgs/container/mcp-bastion-dashboard) — published on each `v*` tag ([publish-docker.yml](.github/workflows/publish-docker.yml)). |

### Real-Time Dashboard and Alerts

**🎥 Demo (screen recording):** [Watch on Vimeo](https://vimeo.com/1186084574) — overview of the dashboard and metrics (link opens the player on Vimeo).

Run the optional dashboard for a live view of requests, blocked count, PII redacted, cost, top tools, and recent alerts.

```bash
mcp-bastion dashboard --port 7000
# or: PYTHONPATH=src python dashboard/app.py
```

| URL | What it returns |
|-----|-----------------|
| [http://localhost:7000/](http://localhost:7000/) | Charts, KPIs, **forensics**, **insights & anomalies**, alerts, **tool drill-down** (signal vs global block rate), theme toggle |
| [http://localhost:7000/api/metrics](http://localhost:7000/api/metrics) | JSON: `requests_total`, `blocked_total`, `blocked_pct`, `pii_redacted_total`, `cost_total`, `blocked_by_reason`, `blocked_by_kind`, `top_tools`, `tool_stats`, `cost_by_user`, `time_series`, `latency_ms`, `dashboard_insights`, `blocked_incidents`, `alerts`, … |
| [http://localhost:7000/api/health](http://localhost:7000/api/health) | `{"status": "ok"}` |
| [http://localhost:7000/metrics](http://localhost:7000/metrics) | Prometheus text format for Grafana/Datadog |

*Dashboard: total requests, blocked count and %, PII redacted, cost; blocked-by-reason bars; top tools; cost by user; recent alerts — open [http://localhost:7000/](http://localhost:7000/) while `mcp-bastion dashboard` is running.*

- **Alerts:** Slack webhook and cost-threshold alerts. See [dashboard/README.md](dashboard/README.md).

### Documentation: Use Cases, Attacks, Metrics, Tutorials

**Adoption paths (start-to-finish):**

| Goal | Read in order |
|------|----------------|
| **Policy-as-code (`bastion.yaml`)** | [docs/PILLARS.md](docs/PILLARS.md) → [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md) → `bastion.yaml.example` → [docs/CLI.md](docs/CLI.md) (`validate`) |
| **LLM clients (OpenAI, Claude, Gemini, …)** | [docs/LLM_INTEGRATION.md](docs/LLM_INTEGRATION.md) → [docs/INTEGRATION_MODELS.md](docs/INTEGRATION_MODELS.md) → [examples/](examples/) (`llm_*.py`) |
| **FastMCP / TypeScript / third-party MCP** | [docs/TUTORIALS.md](docs/TUTORIALS.md) → [docs/DETAILED_TUTORIAL.md](docs/DETAILED_TUTORIAL.md) |
| **Fleet rollout of `bastion.yaml` + SIEM / SOC audit** | [docs/SECURITY_OBSERVABILITY.md](docs/SECURITY_OBSERVABILITY.md) → [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md) |
| **Minimal “hello world” + CI / registries** | [docs/QUICK_START.md](docs/QUICK_START.md) → [examples/ci/README.md](examples/ci/README.md) → [docs/DISCOVERY.md](docs/DISCOVERY.md) |

Full index: **[docs/README.md](docs/README.md)** (docs hub) · published site entry: **[docs/index.md](docs/index.md)** · quick wrap: **[docs/QUICK_START.md](docs/QUICK_START.md)** · discovery: **[docs/DISCOVERY.md](docs/DISCOVERY.md)** · contribute: **[CONTRIBUTING.md](CONTRIBUTING.md)**.

| Doc | Description |
|-----|-------------|
| [docs/index.md](docs/index.md) | GitHub Pages-ready docs home |
| [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md) | **`bastion.yaml` reference**: keys, examples, hot reload, alerts |
| [docs/LLM_INTEGRATION.md](docs/LLM_INTEGRATION.md) | **LLM integration**: OpenAI, Claude, Gemini, Mistral, Grok (stdio + HTTP configs) |
| [docs/DETAILED_TUTORIAL.md](docs/DETAILED_TUTORIAL.md) | Step-by-step implementation tutorial for new teams |
| [docs/USE_CASES.md](docs/USE_CASES.md) | Real use cases: enterprise gateway, LLM products, internal tools, SaaS, compliance |
| [docs/ATTACK_PREVENTION.md](docs/ATTACK_PREVENTION.md) | Examples showing how MCP-Bastion prevents real attacks (injection, PII leak, rate exhaustion, path traversal, RBAC, replay) |
| [docs/PILLARS.md](docs/PILLARS.md) | Canonical pillar list: 10 request-path controls, 13 `bastion.yaml` sections, 11 dashboard health rows |
| [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) | CI merge gates, releases, npm provenance, PyPI Trusted Publishing |
| [docs/INTEGRATION_MODELS.md](docs/INTEGRATION_MODELS.md) | Middleware + `bastion.yaml` vs “change base URL”; bridge for Python, TS, Desktop, HTTP, integrations |
| [examples/ci/README.md](examples/ci/README.md) | Copy-paste GitHub Actions snippet to run `mcp-bastion validate` on your policy file |
| [docs/REDTEAM.md](docs/REDTEAM.md) | Interpreting harness / red-team scores; which `bastion.yaml` pillars to enable; Node vs Python **scope** (`packages/core/README.md`) |
| [docs/SECURITY_OBSERVABILITY.md](docs/SECURITY_OBSERVABILITY.md) | **OWASP MCP Top 10**, integration hooks, **fleet-scale `bastion.yaml` rollout**, **SIEM / SOC audit** patterns |
| [docs/METRICS.md](docs/METRICS.md) | Performance overhead (&lt;5ms) and effectiveness metrics (dashboard, Prometheus, OTEL) |
| [docs/TUTORIALS.md](docs/TUTORIALS.md) | Tutorials: integrating with FastMCP, TypeScript, GitHub MCP, and open-source MCP servers |
| [docs/GITHUB_PAGES.md](docs/GITHUB_PAGES.md) | Publish docs as a GitHub Pages website from this same repo |
| [docs/QUICK_START.md](docs/QUICK_START.md) | Minimal FastMCP / `bastion.yaml` / CI snippets (time-to-value) |
| [docs/DISCOVERY.md](docs/DISCOVERY.md) | Registry and ecosystem discovery checklist |
| [docs/ROADMAP.md](docs/ROADMAP.md) | High-level directions; execution tracked in GitHub Issues |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor guide and **`good first issue`** ideas |

### One-Line Docker

**Prebuilt images (after the first [publish-docker](.github/workflows/publish-docker.yml) run, usually on a `v*` release tag):**

```bash
docker pull ghcr.io/vaquarkhan/mcp-bastion-proxy:latest
docker run -p 8080:8080 ghcr.io/vaquarkhan/mcp-bastion-proxy:latest
# Dashboard (optional, port 7000):
# docker pull ghcr.io/vaquarkhan/mcp-bastion-dashboard:latest
# docker run -p 7000:7000 ghcr.io/vaquarkhan/mcp-bastion-dashboard:latest
```

**Build locally** (any revision):

```bash
docker build -t mcp-bastion/proxy .
docker run -p 8080:8080 mcp-bastion/proxy
```

MCP endpoint: `http://localhost:8080/mcp`. Use `docker-compose up -d` for proxy; add `--profile with-dashboard` for the dashboard. See [DOCKER.md](DOCKER.md) (includes GHCR pull commands and **package** links for forks: replace `vaquarkhan` with your org or user in image paths).

### Policy-as-Code (bastion.yaml)

Single config file controls policy (see [docs/PILLARS.md](docs/PILLARS.md) for pillar definitions). Copy `bastion.yaml.example` to `bastion.yaml`, then:

```python
from mcp_bastion import build_middleware_from_config
middleware = build_middleware_from_config()
```

See [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md).

Tip: set `hot_reload.enabled: true` in `bastion.yaml` to apply policy changes without restarting your MCP server when using `build_middleware_from_config()`.

### CLI for developers

```bash
mcp-bastion validate              # validate bastion.yaml
mcp-bastion serve --http 8080     # run MCP server with config
mcp-bastion dashboard --port 7000 # run metrics dashboard
```

See [docs/CLI.md](docs/CLI.md).

### Continuous integration (this repository)

On every pull request and push to `main`, [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs:

1. `pip install -e ".[dev,policy,dashboard]"` — install the Python package with tests, YAML policy loading, and FastAPI for dashboard tests.
2. `mcp-bastion validate --config bastion.yaml.example` — ensure the example policy file loads.
3. `pytest --cov=mcp_bastion --cov-fail-under=92` — full Python test suite with **≥92%** line coverage on `src/mcp_bastion` (see `[tool.coverage.*]` in `pyproject.toml` for measured paths and gates).
4. `npm ci` and `npm test` — TypeScript workspace tests.

To validate **your** repo’s `bastion.yaml` in CI without cloning MCP-Bastion, see [examples/ci/README.md](examples/ci/README.md).

### OpenTelemetry

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to export tool-call spans to OTLP. Install optional deps: `pip install mcp-bastion-python[otel]`. See [docs/OTEL.md](docs/OTEL.md).

### Webhook alerts and external logging

Use **Slack** (`slack_webhook` / `SLACK_WEBHOOK_URL`), a **generic HTTP webhook** (`webhook_url` / `BASTION_WEBHOOK_URL`), or **multiple URLs** (`alerts.webhooks` in `bastion.yaml`). POSTs can drive **PagerDuty**, **Microsoft Teams**, **Datadog Events**, or any HTTP collector your SIEM exposes. Configure **retry/backoff** in `bastion.yaml` (`retry_attempts`, `retry_backoff_seconds`, `retry_backoff_max_seconds`, `timeout_seconds`).

**Metrics & traces:** scrape the dashboard **`/metrics`** (Prometheus) or poll **`/api/metrics`** (JSON) for Grafana, Datadog, or custom pollers. Set **`OTEL_EXPORTER_OTLP_ENDPOINT`** for traces to Jaeger, Honeycomb, **AWS ADOT**, etc. (`pip install mcp-bastion-python[otel]`). Route **Python logs** (including `LoggingAlertSink`) through **Fluent Bit**, **Vector**, or the **CloudWatch agent** into Splunk / Elastic / CloudWatch Logs.

See **[docs/SECURITY_OBSERVABILITY.md](docs/SECURITY_OBSERVABILITY.md)** for the full integration table and **OWASP MCP Top 10** alignment.

---

<p align="center">
  <img
    src="images/mcp-bastian-features.png"
    alt="MCP-Bastion features at a glance — pillars, dashboard, and integrations"
    width="920"
    style="max-width:100%; height:auto; border-radius:12px;"
  />
</p>

## Why MCP-Bastion

- **Active enforcement** — Intercepts MCP tool traffic so policies (prompt injection checks, PII handling, content rules, RBAC, and more) run before tools execute and before sensitive results propagate.
- **Local-first classification** — PromptGuard and Presidio run in your environment; you are not required to send prompts to a third-party API for guardrail scoring.
- **Stateful guardrails** — Per-session rate limits, iteration caps, token budgets, and cost tracking to reduce runaway loops and unexpected spend.
- **Composable integration** — Use `bastion.yaml` with `build_middleware_from_config()` or wire `MCPBastionMiddleware` / `wrapWithMcpBastion` in Python or TypeScript. For a separate process in front of an upstream MCP server, use a wrapper or proxy you control; see [docs/INTEGRATION_MODELS.md](docs/INTEGRATION_MODELS.md).

---

## Structure

| Path | Description |
|------|-------------|
| `src/mcp_bastion/` | Python package: PromptGuard, Presidio, rate limiting, RBAC, etc. |
| `packages/core/` | TypeScript package: rate limiting in-process; prompt/PII via sidecar (MCP_BASTION_URL) |
| `examples/` | Python examples ([examples/README.md](examples/README.md)) |
| `dashboard/` | Real-time dashboard UI and metrics API ([dashboard/README.md](dashboard/README.md)) |
| `bastion.yaml.example` | Policy-as-code sample; copy to `bastion.yaml` ([docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md)) |
| `scripts/validate_checklist.py` | Enterprise validation runner |
| `VALIDATION_CHECKLIST.md` | Validation guide and MCP Inspector steps |
| `SETUP_GUIDE.md` | Setup, config, and validation |
| `DOCKER.md` | Docker one-line run and compose |

### Example Files

| File | Purpose |
|------|---------|
| `examples/python_server_example.py` | Minimal middleware chain |
| `examples/full_demo.py` | Multi-pillar stack (core toggles: rate limit, PII, RBAC, … — see **docs/PILLARS.md**) |
| `examples/llm_server.py` | Shared MCP server for LLM clients |
| `examples/llm_openai_example.py` | OpenAI |
| `examples/llm_claude_example.py` | Claude |
| `examples/llm_gemini_example.py` | Gemini |
| `examples/llm_mistral_example.py` | Mistral |
| `examples/llm_grok_example.py` | Grok (xAI) |
| `examples/server_with_config.py` | Policy-as-code (bastion.yaml) |

## Installation

**Python**

```bash
uv add mcp-bastion-python
# or
pip install mcp-bastion-python
# pinned latest
pip install mcp-bastion-python==1.0.16
```

**Prerequisites (recommended)**

- **PII redaction:** Presidio expects the spaCy English model. After install, run:  
  `python -m spacy download en_core_web_sm`  
  Without it, PII analysis can fail at runtime.
- **Policy-as-Code (`bastion.yaml`):** install YAML support:  
  `pip install mcp-bastion-python[policy]`  
  (adds `pyyaml`; otherwise you may get `ImportError` when loading policy files).
- **PromptGuard fail-open:** if the PromptGuard model fails to load or inference errors, MCP-Bastion **allows** the request and logs a warning. Treat this as a security degradation and fix the model/runtime before production.

The PyPI wheel ships the full `mcp_bastion` tree (including `config`, `cli`, `otel`, dashboard metrics, and alert sinks). If you use an older wheel that omits modules, upgrade to the current release.

**TypeScript**

```bash
npm install @mcp-bastion/core
```

[npm](https://www.npmjs.com/package/@mcp-bastion/core)

### Framework Integrations

Drop-in security for your favorite LLM framework. Each package auto-installs `mcp-bastion-python`. **Downloads** for each row point to [pypistats.org](https://pypistats.org/) (trends) and [pepy.tech](https://pepy.tech/) (cumulative) for that PyPI name.

```bash
pip install mcp-bastion-langchain      # LangChain agents and tools
pip install mcp-bastion-openai         # OpenAI GPT API calls
pip install mcp-bastion-anthropic      # Anthropic Claude API calls
pip install mcp-bastion-bedrock        # AWS Bedrock runtime
pip install mcp-bastion-gemini         # Google Gemini
pip install mcp-bastion-crewai         # CrewAI agent crews
pip install mcp-bastion-llamaindex     # LlamaIndex RAG pipelines
pip install mcp-bastion-groq           # Groq inference
pip install mcp-bastion-mistral        # Mistral AI
pip install mcp-bastion-cohere         # Cohere
pip install mcp-bastion-azure          # Azure OpenAI Service
pip install mcp-bastion-vertexai       # Google Cloud Vertex AI
pip install mcp-bastion-huggingface    # Hugging Face Inference
pip install mcp-bastion-deepseek       # DeepSeek AI
pip install mcp-bastion-together       # Together AI
pip install mcp-bastion-fireworks      # Fireworks AI
pip install mcp-bastion-fastmcp       # FastMCP servers
```

| Package | Protects | Version | Downloads |
|---------|----------|---------|-----------|
| [mcp-bastion-langchain](https://pypi.org/project/mcp-bastion-langchain/) | LangChain | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-langchain) · [pepy](https://pepy.tech/projects/mcp-bastion-langchain) |
| [mcp-bastion-openai](https://pypi.org/project/mcp-bastion-openai/) | OpenAI GPT | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-openai) · [pepy](https://pepy.tech/projects/mcp-bastion-openai) |
| [mcp-bastion-anthropic](https://pypi.org/project/mcp-bastion-anthropic/) | Anthropic Claude | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-anthropic) · [pepy](https://pepy.tech/projects/mcp-bastion-anthropic) |
| [mcp-bastion-bedrock](https://pypi.org/project/mcp-bastion-bedrock/) | AWS Bedrock | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-bedrock) · [pepy](https://pepy.tech/projects/mcp-bastion-bedrock) |
| [mcp-bastion-gemini](https://pypi.org/project/mcp-bastion-gemini/) | Google Gemini | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-gemini) · [pepy](https://pepy.tech/projects/mcp-bastion-gemini) |
| [mcp-bastion-crewai](https://pypi.org/project/mcp-bastion-crewai/) | CrewAI | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-crewai) · [pepy](https://pepy.tech/projects/mcp-bastion-crewai) |
| [mcp-bastion-llamaindex](https://pypi.org/project/mcp-bastion-llamaindex/) | LlamaIndex | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-llamaindex) · [pepy](https://pepy.tech/projects/mcp-bastion-llamaindex) |
| [mcp-bastion-groq](https://pypi.org/project/mcp-bastion-groq/) | Groq | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-groq) · [pepy](https://pepy.tech/projects/mcp-bastion-groq) |
| [mcp-bastion-mistral](https://pypi.org/project/mcp-bastion-mistral/) | Mistral AI | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-mistral) · [pepy](https://pepy.tech/projects/mcp-bastion-mistral) |
| [mcp-bastion-cohere](https://pypi.org/project/mcp-bastion-cohere/) | Cohere | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-cohere) · [pepy](https://pepy.tech/projects/mcp-bastion-cohere) |
| [mcp-bastion-azure](https://pypi.org/project/mcp-bastion-azure/) | Azure OpenAI | 0.1.3 | [pypistats](https://pypistats.org/packages/mcp-bastion-azure) · [pepy](https://pepy.tech/projects/mcp-bastion-azure) |
| [mcp-bastion-vertexai](https://pypi.org/project/mcp-bastion-vertexai/) | Vertex AI | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-vertexai) · [pepy](https://pepy.tech/projects/mcp-bastion-vertexai) |
| [mcp-bastion-huggingface](https://pypi.org/project/mcp-bastion-huggingface/) | Hugging Face | 0.1.3 | [pypistats](https://pypistats.org/packages/mcp-bastion-huggingface) · [pepy](https://pepy.tech/projects/mcp-bastion-huggingface) |
| [mcp-bastion-deepseek](https://pypi.org/project/mcp-bastion-deepseek/) | DeepSeek AI | 0.1.3 | [pypistats](https://pypistats.org/packages/mcp-bastion-deepseek) · [pepy](https://pepy.tech/projects/mcp-bastion-deepseek) |
| [mcp-bastion-together](https://pypi.org/project/mcp-bastion-together/) | Together AI | 0.1.3 | [pypistats](https://pypistats.org/packages/mcp-bastion-together) · [pepy](https://pepy.tech/projects/mcp-bastion-together) |
| [mcp-bastion-fireworks](https://pypi.org/project/mcp-bastion-fireworks/) | Fireworks AI | 0.1.3 | [pypistats](https://pypistats.org/packages/mcp-bastion-fireworks) · [pepy](https://pepy.tech/projects/mcp-bastion-fireworks) |
| [mcp-bastion-fastmcp](https://pypi.org/project/mcp-bastion-fastmcp/) | FastMCP servers | 0.1.2 | [pypistats](https://pypistats.org/packages/mcp-bastion-fastmcp) · [pepy](https://pepy.tech/projects/mcp-bastion-fastmcp) |

## Publish (PyPI / npm)

- **PyPI:** `python -m build && twine upload dist/*` (or use GitHub Actions on tag).
- **npm:** From repo root, `cd packages/core && npm publish --access public` (or use Trusted Publishers).
- Version is set in `pyproject.toml` (Python), `packages/core/package.json` (npm), and `server.json` (MCP registry). Bump before releasing.

## Developer Guide

Integration examples for Python and TypeScript.

---

### Quick Start (Python)

Add MCP-Bastion to an existing MCP server in three steps:

```python
from mcp_bastion import MCPBastionMiddleware, compose_middleware

# 1. Create the security middleware
bastion = MCPBastionMiddleware(
    enable_prompt_guard=True,
    enable_pii_redaction=True,
    enable_rate_limit=True,
)

# 2. Compose with your middleware chain (Bastion runs first)
middleware = compose_middleware(bastion)

# 3. Pass the composed middleware to your MCP server
# (integration depends on your server framework)
```

**Examples:**

| Example | Description |
|---------|-------------|
| `examples/python_server_example.py` | Basic middleware chain |
| `examples/full_demo.py` | Full middleware stack: add, PII, rate limit, prompt injection, etc. |
| `examples/llm_openai_example.py` | MCP server for OpenAI |
| `examples/llm_claude_example.py` | MCP server for Claude |
| `examples/llm_gemini_example.py` | MCP server for Gemini |
| `examples/llm_mistral_example.py` | MCP server for Mistral |
| `examples/llm_grok_example.py` | MCP server for Grok (xAI, HTTP only) |

```bash
# Windows: $env:PYTHONPATH="src"; python examples/full_demo.py
# Linux/Mac: PYTHONPATH=src python examples/full_demo.py
```

**LLM integration:** See [docs/LLM_INTEGRATION.md](docs/LLM_INTEGRATION.md) for copy-paste config for OpenAI, Claude, Gemini, Mistral, and Grok.

**Enterprise validation:**

```bash
PYTHONPATH=src python scripts/validate_checklist.py
```

See `VALIDATION_CHECKLIST.md` and `SETUP_GUIDE.md`.

---

### Python Tutorial: FastMCP Server

FastMCP server with MCP-Bastion.

**Step 1: Install dependencies**

```bash
pip install mcp mcp-bastion-python
```

**Step 2: Create your server file** (`server.py`)

```python
from mcp.server.fastmcp import FastMCP
from mcp_bastion import MCPBastionMiddleware, compose_middleware

# Create the MCP server
mcp = FastMCP("My Secure Server")

# Create MCP-Bastion middleware
# It intercepts tool calls and resource reads before they execute
bastion = MCPBastionMiddleware(
    enable_prompt_guard=True,   # Block malicious prompts via PromptGuard
    enable_pii_redaction=True,  # Mask PII in outgoing content
    enable_rate_limit=True,     # Cap at 15 iterations, 60s timeout
)

# Compose middleware chain (pass to your server's middleware config if supported)
middleware = compose_middleware(bastion)

# Register a tool (protected when middleware is wired into your server)
@mcp.tool()
def get_weather(city: str) -> str:
    """Get weather for a city."""
    return f"Weather in {city}: 22C, sunny"

# Resource (PII redacted)
@mcp.resource("user://profile/{user_id}")
def get_profile(user_id: str) -> str:
    """Get user profile. PII redacted."""
    return f"User {user_id}: John Doe, SSN 123-45-6789, john@example.com"

if __name__ == "__main__":
    mcp.run(transport="streamable-http")
```

**Step 3: Run the server**

```bash
python server.py
```

MCP-Bastion:
- Scans tool args for prompt injection
- Redacts PII from resource responses
- Blocks sessions over 15 calls or 60s

**Alternative: Policy-as-Code**

Use `bastion.yaml` instead of code. Copy `bastion.yaml.example` to `bastion.yaml`, then:

```python
from mcp_bastion import build_middleware_from_config
middleware = build_middleware_from_config()
```

See [docs/POLICY_AS_CODE.md](docs/POLICY_AS_CODE.md) and `examples/server_with_config.py`.

---

### Python: Custom Rate Limits

Custom config example:

```python
from mcp_bastion import MCPBastionMiddleware
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine

# Stricter limits
rate_limiter = TokenBucketRateLimiter(
    max_iterations=10,
    timeout_seconds=30,
    token_budget=25_000,
)

# Higher threshold = fewer blocks, more risk
prompt_guard = PromptGuardEngine(threshold=0.92)

bastion = MCPBastionMiddleware(
    prompt_guard=prompt_guard,
    rate_limiter=rate_limiter,
    enable_prompt_guard=True,
    enable_pii_redaction=True,
    enable_rate_limit=True,
)

# Disable PII redaction if your data has no PII
bastion_no_pii = MCPBastionMiddleware(enable_pii_redaction=False)
```

---

### Python: Custom Middleware

Extend `Middleware` to add logging, metrics, or custom logic:

```python
from mcp_bastion.base import Middleware, MiddlewareContext, compose_middleware

class LoggingMiddleware(Middleware):
    async def on_message(self, context, call_next):
        result = await call_next(context)
        # log method, elapsed, etc.
        return result

middleware = compose_middleware(bastion, LoggingMiddleware())
```

See `examples/full_demo.py` for a complete example.

---

### TypeScript: Wrap an MCP Server

**Step 1: Install dependencies**

```bash
npm install @modelcontextprotocol/sdk @mcp-bastion/core
```

**Step 2: Create your server** (`server.ts`)

```typescript
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  wrapWithMcpBastion,
  wrapCallToolHandler,
} from "@mcp-bastion/core";

const server = new Server({ name: "my-mcp-server", version: "1.0.0" });

// Wrap the server with MCP-Bastion (rate limiting only by default)
// For prompt injection and PII, run the Python sidecar and set sidecarUrl
wrapWithMcpBastion(server, {
  enableRateLimit: true,
  maxIterations: 15,
  timeoutMs: 60_000,
  // Optional: enable ML features via Python sidecar
  sidecarUrl: process.env.MCP_BASTION_SIDECAR || "",
  enablePromptGuard: !!process.env.MCP_BASTION_SIDECAR,
  enablePiiRedaction: !!process.env.MCP_BASTION_SIDECAR,
});

// Register tools (handlers are automatically wrapped)
server.setRequestHandler("tools/call" as any, async (request) => {
  if (request.params?.name === "get_weather") {
    return {
      content: [{ type: "text", text: "Sunny, 22C" }],
      isError: false,
    };
  }
  throw new Error("Unknown tool");
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main();
```

**Step 3: Run with rate limiting only**

```bash
npx tsx server.ts
```

**Step 4: Run with full ML features (Python sidecar)**

For prompt injection and PII redaction, run a Python HTTP service that exposes `/prompt-guard` and `/pii-redact` endpoints (see the Python package for sidecar implementation). Then:

```bash
# Start the Python sidecar, then the TypeScript server
MCP_BASTION_SIDECAR=http://localhost:8000 npx tsx server.ts
```

---

### TypeScript: Wrap Individual Handlers

Wrap specific handlers only:

```typescript
import {
  wrapCallToolHandler,
  wrapReadResourceHandler,
} from "@mcp-bastion/core";
import {
  CallToolRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// Wrap only the tool handler
const safeToolHandler = wrapCallToolHandler(
  async (request) => {
    // Your tool logic
    return { content: [{ type: "text", text: "OK" }], isError: false };
  },
  { enableRateLimit: true, maxIterations: 10 }
);

// Wrap only the resource handler (for PII redaction)
const safeResourceHandler = wrapReadResourceHandler(
  async (request) => {
    const contents = await fetchResource(request.params.uri);
    return { contents };
  },
  { sidecarUrl: "http://localhost:8000", enablePiiRedaction: true }
);

server.setRequestHandler(CallToolRequestSchema, safeToolHandler);
server.setRequestHandler(ReadResourceRequestSchema, safeResourceHandler);
```

---

### Configuration Reference

| Option | Python | TypeScript | Default | Description |
|--------|--------|------------|---------|-------------|
| `enable_prompt_guard` | Yes | Yes | `True` (Python) / `False` (TS) | Block malicious prompts via PromptGuard |
| `enable_pii_redaction` | Yes | Yes | `True` (Python) / `False` (TS) | Mask PII in outgoing content |
| `enable_rate_limit` | Yes | Yes | `True` | Enforce iteration and timeout caps |
| `max_iterations` | Via `TokenBucketRateLimiter` | Yes | 15 | Max tool calls per session |
| `timeout_seconds` / `timeoutMs` | Via `TokenBucketRateLimiter` | Yes | 60 | Session timeout |
| `token_budget` | Via `TokenBucketRateLimiter` | - | 50,000 | FinOps token cap per request |
| `sidecarUrl` | - | Yes | `""` | Python sidecar URL for ML features |
| `threshold` | Via `PromptGuardEngine` | - | 0.85 | Malicious probability cutoff |
| `setLogLevel` | - | Yes | `"info"` | TypeScript: `"debug"` \| `"info"` \| `"warn"` \| `"error"` |

---

### Error Handling

When MCP-Bastion blocks a request, it returns standard MCP/JSON-RPC errors:

| Code | Exception | When |
|------|-----------|------|
| -32001 | `PromptInjectionError` | Tool args contain jailbreak/injection |
| -32002 | `RateLimitExceededError` | Session exceeds iteration or timeout limit |
| -32003 | `TokenBudgetExceededError` | Session exceeds token budget |
| -32004 | `CircuitBreakerOpenError` | Tool’s circuit breaker is open after failures |
| -32005 | `ContentFilterError` | Content filter matched a blocked pattern |
| -32006 | `RBACError` | Caller not allowed to use this tool |
| -32007 | `SchemaValidationError` | Tool arguments failed schema validation |
| -32008 | `ReplayAttackError` | Duplicate nonce / replay detected |
| -32009 | `CostBudgetExceededError` | Session cost budget exceeded |
| -32010 | `SemanticFirewallError` | Tool sequence / argument pattern failed semantic firewall |
| -32011 | `ExternalPolicyDeniedError` | OPA/Cedar (or other external) policy denied the request |
| -32012 | `SensitiveContentError` | Sensitive-business classifier above threshold |
| -32013 | `AuthenticationError` | Edge / gateway authentication (metadata token) failed |
| -32014 | `ToolNotAllowedError` | Tool not on allowlist |
| -32015 | `SessionScopeExceededError` | Too many distinct tools per session (scope creep) |
| -32016 | `ToolMetadataPoisoningError` | Tool list / metadata failed safety checks |

```python
# Python: exceptions
from mcp_bastion.errors import (
    PromptInjectionError,
    RateLimitExceededError,
    TokenBudgetExceededError,
    CircuitBreakerOpenError,
    ContentFilterError,
    RBACError,
    SchemaValidationError,
    ReplayAttackError,
    CostBudgetExceededError,
    SemanticFirewallError,
    ExternalPolicyDeniedError,
    SensitiveContentError,
    AuthenticationError,
    ToolNotAllowedError,
    SessionScopeExceededError,
    ToolMetadataPoisoningError,
)
import logging
logger = logging.getLogger(__name__)

try:
    result = await middleware(context, call_next)
except (
    PromptInjectionError,
    RateLimitExceededError,
    TokenBudgetExceededError,
    CircuitBreakerOpenError,
    ContentFilterError,
    RBACError,
    SchemaValidationError,
    ReplayAttackError,
    CostBudgetExceededError,
    SemanticFirewallError,
    ExternalPolicyDeniedError,
    SensitiveContentError,
    AuthenticationError,
    ToolNotAllowedError,
    SessionScopeExceededError,
    ToolMetadataPoisoningError,
) as e:
    logger.warning("blocked: %s", e.to_mcp_error())
```

```typescript
// TypeScript: handlers return isError: true
import { logger, setLogLevel } from "@mcp-bastion/core";
setLogLevel("debug");  // optional: "debug" | "info" | "warn" | "error"
const result = await guardedHandler(request);
if (result.isError) {
  logger.error("blocked", result.content);
}
```

---

### Testing

MCP Inspector:

```bash
# Start your guarded server
python server.py   # or: npx tsx server.ts

# In another terminal, launch the Inspector
npx -y @modelcontextprotocol/inspector
```

Connect via HTTP (`http://localhost:8000/mcp`) or stdio, then:
1. List tools and call one with benign arguments (should succeed)
2. Call a tool with "Ignore previous instructions" (should be blocked)
3. Trigger 16+ tool calls in one session (should hit rate limit)

---

## Testing

```bash
# Python (PYTHONPATH=src on Windows: $env:PYTHONPATH="src")
pytest tests/ -v

# TypeScript
npm run test --workspace=@mcp-bastion/core

# Full validation checklist (build, pillars, latency)
PYTHONPATH=src python scripts/validate_checklist.py

# MCP Inspector (manual)
npx -y @modelcontextprotocol/inspector
```

## Third-Party Components

See `NOTICE` for licenses. MCP-Bastion uses Meta Llama Prompt Guard 2 (Llama 4 Community License) and Microsoft Presidio. For OWASP-relevant mitigations, dependency audit, and reporting vulnerabilities, see [docs/SECURITY.md](docs/SECURITY.md).

## License

MCP-Bastion is distributed under the **MCP-Bastion Community and Commercial License** ([LICENSE](LICENSE)).

- **Free** for non‑commercial use when you **cite MCP-Bastion** and the **copyright** notice (see [CITATION.cff](CITATION.cff); you can list *your* name, team, or org as authors or as who used the software, while still including the project and repository in the credit).
- **Copyright** is retained. Do not remove license or copyright text, and do not republish a duplicate of the work as if it were unrelated software without meeting the License terms.
- **Commercial use** (as defined in the License) may still require a **separate written agreement** — see [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).

See also:

- [LICENSE](LICENSE)
- [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md)
- [CITATION.cff](CITATION.cff)
