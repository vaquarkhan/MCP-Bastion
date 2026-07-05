# MCP-Bastion Docs Hub

This folder is the central documentation source and can be published as a GitHub Pages site.

Current Python package release: **`mcp-bastion-python==2.0.0`** ([PyPI](https://pypi.org/project/mcp-bastion-python/2.0.0/)) — major release with runtime governance hardening, audit fixes, FinOps/RBAC benchmarks, and dashboard governance panel.

## Start here

| Doc | Description |
|-----|-------------|
| [QUICK_START.md](QUICK_START.md) | **Minimal code** to wrap FastMCP or load `bastion.yaml`; CI snippet for pipelines |
| [index.md](index.md) | Landing page for docs website (GitHub Pages home) |
| [DETAILED_TUTORIAL.md](DETAILED_TUTORIAL.md) | End-to-end tutorial from install to production checks |
| [POLICY_AS_CODE.md](POLICY_AS_CODE.md) | Full `bastion.yaml` schema and examples |
| [PILLARS.md](PILLARS.md) | Canonical mapping: base controls, **extended** policy features (1.0.16+), FinOps/context pillars (1.0.17+), runtime governance (1.0.18+, shipped in **2.0.0**), `bastion.yaml` ↔ dashboard |
| [BENCHMARKS.md](BENCHMARKS.md) | **Measured** RBAC matrix, output-budget reduction, discovery filter, lexical cache — pytest + `scripts/generate_benchmark_report.py` |
| [MCP_SURFACE_AND_SCALE.md](MCP_SURFACE_AND_SCALE.md) | **2.0.0:** full MCP method guards + Redis `state_backend` for multi-replica deploys |
| [REDTEAM.md](REDTEAM.md) | Interpreting harness scores; **`mcp-bastion redteam`** |
| [Advanced_Tutorials.md](Advanced_Tutorials.md) | Index of deeper docs (points to **DETAILED_TUTORIAL**, **TUTORIALS**, **PILLARS**, …) |
| [CLI.md](CLI.md) | `mcp-bastion` CLI (`validate`, `serve`, `dashboard`, `redteam`, `doctor`, …) |
| [LLM_INTEGRATION.md](LLM_INTEGRATION.md) | OpenAI/Claude/Gemini/Mistral/Grok integration patterns |
| [INTEGRATION_MODELS.md](INTEGRATION_MODELS.md) | How Bastion fits stdio, HTTP, Python, TypeScript, and frameworks |
| [TUTORIALS.md](TUTORIALS.md) | Popular MCP integration approaches |

### Reading paths

1. **Policy-as-code only:** [PILLARS.md](PILLARS.md) → [POLICY_AS_CODE.md](POLICY_AS_CODE.md) → [CLI.md](CLI.md) (`validate`).
2. **LLM desktop or API clients:** [LLM_INTEGRATION.md](LLM_INTEGRATION.md) → [INTEGRATION_MODELS.md](INTEGRATION_MODELS.md) → [../examples/README.md](../examples/README.md).
3. **Production hardening:** [SECURITY.md](SECURITY.md) → [SECURITY_OBSERVABILITY.md](SECURITY_OBSERVABILITY.md) (includes **fleet-scale policy** and **SIEM / SOC audit** patterns) → [METRICS.md](METRICS.md).

## Security and operations

| Doc | Description |
|-----|-------------|
| [SECURITY.md](SECURITY.md) | OWASP mapping, mitigations, vulnerability reporting |
| [BEYOND_OWASP.md](BEYOND_OWASP.md) | Threats outside OWASP Top 10 (localhost CSRF, context flooding, schema drift) |
| [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md) | HTTP / localhost binding and edge_auth guidance |
| [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md) | Agent IAM (Confused Deputy) and server checksum verification |
| [ROADMAP.md](ROADMAP.md) | **Future roadmap (3.0+):** P1–P5 priorities, release sequencing, non-goals |
| [COMPARISON.md](COMPARISON.md) | MCP-Bastion vs unguarded MCP, thin proxy, full AI/MCP gateway |
| [ENGINEERING_10_10.md](ENGINEERING_10_10.md) | Strategic 10/10 plan: injection depth, tool scan, OAuth gateway, maturity |
| [ATTACK_PREVENTION.md](ATTACK_PREVENTION.md) | Attack scenarios and prevention walkthroughs |
| [METRICS.md](METRICS.md) | Metrics, dashboard, Prometheus and effectiveness guidance |
| [OTEL.md](OTEL.md) | OpenTelemetry setup and spans |
| [USE_CASES.md](USE_CASES.md) | Architecture and deployment use cases |

## Growth & contribution

| Doc | Description |
|-----|-------------|
| [DISCOVERY.md](DISCOVERY.md) | Checklist: registries, awesome lists, PyPI/npm metadata for discovery |
| [ROADMAP.md](ROADMAP.md) | High-level directions (use GitHub Issues for execution) |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute; **`good first issue`** suggestions |

## Repo-level docs

| Doc | Description |
|-----|-------------|
| [../README.md](../README.md) | Main project README |
| [../SETUP_GUIDE.md](../SETUP_GUIDE.md) | Setup, configuration, and validation flow |
| [../VALIDATION_CHECKLIST.md](../VALIDATION_CHECKLIST.md) | Validation checklist and acceptance criteria |
| [../examples/README.md](../examples/README.md) | Example-by-example instructions |
| [../DOCKER.md](../DOCKER.md) | Docker and compose usage |
| [../dashboard/README.md](../dashboard/README.md) | Dashboard endpoints and UI behavior |
| [GITHUB_PAGES.md](GITHUB_PAGES.md) | Publish this docs folder as GitHub Pages |
