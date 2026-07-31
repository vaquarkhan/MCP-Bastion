# MCP-Bastion Docs Hub

This folder is the central documentation source and can be published as a GitHub Pages site.

Current Python package release: **`mcp-bastion-python==4.0.0`** ([PyPI](https://pypi.org/project/mcp-bastion-python/)) - reversible PII vault + proxy mutate + schema minimize / live catalog pin (all opt-in) + CRA SBOM; see [CHANGELOG](../CHANGELOG.md).

## Start here

| Doc | Description |
|-----|-------------|
| [USER_GUIDE.md](USER_GUIDE.md) | **End-to-end handbook** (concepts → install → config → proxy → vault → ops) — also published at [GitHub Pages Docs](https://vaquarkhan.github.io/MCP-Bastion/guide/) |
| [FEATURES.md](FEATURES.md) | **How-to for all 18 pillars** - enable, configure, error codes |
| [RBAC.md](RBAC.md) | **RBAC deep dive** - roles, fnmatch globs, Agent IAM pairing |
| [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) | **Developer help** - repo layout, local dev, tests, release |
| [QUICK_START.md](QUICK_START.md) | **Minimal code** to wrap FastMCP or load `bastion.yaml`; CI snippet for pipelines |
| [index.md](index.md) | Landing page for docs website (GitHub Pages home) |
| [DETAILED_TUTORIAL.md](DETAILED_TUTORIAL.md) | End-to-end tutorial from install to production checks |
| [POLICY_AS_CODE.md](POLICY_AS_CODE.md) | Full `bastion.yaml` schema and examples |
| [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md) | Agent IAM, server verification, supply-chain checks |
| [ENTERPRISE_RUNTIME_CONTROLS.md](ENTERPRISE_RUNTIME_CONTROLS.md) | **3.0+** runtime governance pillars (canary, ATR, LLM scanner, threat feeds, auto-repave, secret redaction) |
| [PILLARS.md](PILLARS.md) | Canonical mapping: base controls, **extended** policy features (1.0.16+), FinOps/context pillars (1.0.17+), runtime governance (1.0.18+, shipped in **2.0.0**), **enterprise controls (3.0.0+)**, scan suite / audit (**3.0.1**), dashboard panels (**3.1.0**), `bastion.yaml` ↔ dashboard |
| [../dashboard/README.md](../dashboard/README.md) | **Local dashboard (3.1.0)** - posture, prevalidate, issue guides, FinOps actual vs would-have-been |
| [PUBLISHING_NPM_AND_REGISTRY.md](PUBLISHING_NPM_AND_REGISTRY.md) | npm bootstrap + MCP Registry OIDC publisher pin |
| [TAXONOMY.md](TAXONOMY.md) | ASI / MCP / LLM finding tags |
| [BENCHMARKS.md](BENCHMARKS.md) | **Measured** RBAC matrix, output-budget reduction, discovery filter, lexical cache - pytest + `scripts/generate_benchmark_report.py` |
| [MCP_SURFACE_AND_SCALE.md](MCP_SURFACE_AND_SCALE.md) | **2.0.0:** full MCP method guards + Redis `state_backend` for multi-replica deploys |
| [HYBRID_MCP_TRANSPORT.md](HYBRID_MCP_TRANSPORT.md) | **Opt-in:** stateful + stateless MCP transport, discovery card, agent stability |
| [BEHAVIOR_FINGERPRINT.md](BEHAVIOR_FINGERPRINT.md) | **3.3.0 (opt-in):** per-agent baseline drift + rate spikes |
| [PII_VAULT.md](PII_VAULT.md) | **Opt-in:** reversible PII tokenization (abstract + hydrate) |
| [PII_VAULT_TUTORIAL.md](PII_VAULT_TUTORIAL.md) | Enable vault, verify abstract/hydrate, Redis tip |
| [CRA_COMPLIANCE.md](CRA_COMPLIANCE.md) | **CRA / OpenSSF:** SBOM + Article 14 posture (no runtime change) |
| [CRA_SBOM_TUTORIAL.md](CRA_SBOM_TUTORIAL.md) | Generate / download CycloneDX `bom.json` |
| [REDTEAM.md](REDTEAM.md) | Interpreting harness scores; **`mcp-bastion redteam`** |
| [Advanced_Tutorials.md](Advanced_Tutorials.md) | Index of deeper docs (points to **DETAILED_TUTORIAL**, **TUTORIALS**, **PILLARS**, …) |
| [CLI.md](CLI.md) | `mcp-bastion` CLI (`validate`, `serve`, `serve --proxy`, `attest export`, …) |
| [ZERO_INFRA_STRATEGY.md](ZERO_INFRA_STRATEGY.md) | **Guiding rule:** zero-infra guardrail brain; Tier 1-4 vs gateway products |
| [../FUNDING.md](../FUNDING.md) | Sponsorship, commercial licensing, sustainability |
| [../SUPPORT.md](../SUPPORT.md) | Where to get help; issue expectations |
| [LLM_INTEGRATION.md](LLM_INTEGRATION.md) | OpenAI/Claude/Gemini/Mistral/Grok integration patterns |
| [INTEGRATION_MODELS.md](INTEGRATION_MODELS.md) | How Bastion fits stdio, HTTP, Python, TypeScript, and frameworks |
| [TUTORIALS.md](TUTORIALS.md) | Popular MCP integration approaches |

### Reading paths

1. **Policy-as-code only:** [FEATURES.md](FEATURES.md) → [RBAC.md](RBAC.md) → [PILLARS.md](PILLARS.md) → [POLICY_AS_CODE.md](POLICY_AS_CODE.md) → [CLI.md](CLI.md) (`validate`).
2. **Contributors:** [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) → [CONTRIBUTING.md](../CONTRIBUTING.md).
3. **LLM desktop or API clients:** [LLM_INTEGRATION.md](LLM_INTEGRATION.md) → [INTEGRATION_MODELS.md](INTEGRATION_MODELS.md) → [../examples/README.md](../examples/README.md).
4. **Production hardening:** [SECURITY.md](SECURITY.md) → [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md) → [SECURITY_OBSERVABILITY.md](SECURITY_OBSERVABILITY.md) (includes **fleet-scale policy** and **SIEM / SOC audit** patterns) → [METRICS.md](METRICS.md).

## Security and operations

| Doc | Description |
|-----|-------------|
| [SECURITY.md](SECURITY.md) | OWASP mapping, mitigations, vulnerability reporting |
| [CRA_COMPLIANCE.md](CRA_COMPLIANCE.md) | CRA Article 14 + CycloneDX SBOM (steward MVP docs) |
| [BEYOND_OWASP.md](BEYOND_OWASP.md) | Threats outside OWASP Top 10 (localhost CSRF, context flooding, schema drift) |
| [TRANSPORT_HARDENING.md](TRANSPORT_HARDENING.md) | HTTP / localhost binding and edge_auth guidance |
| [GATEWAY_BOUNDARY.md](GATEWAY_BOUNDARY.md) | **2.0.0+:** mandatory proxy boundary - loopback upstream, edge_auth, NetworkPolicy checklist |
| [RUNTIME_GOVERNANCE.md](RUNTIME_GOVERNANCE.md) | Agent IAM (Confused Deputy) and server checksum verification |
| [ROADMAP.md](ROADMAP.md) | **Future roadmap (3.0+):** P0 cost-aware policy, P1-P5 priorities, release sequencing |
| [COST_AWARE_GOVERNANCE.md](COST_AWARE_GOVERNANCE.md) | **Flagship bet:** cost-aware runtime governance - category positioning, four moats, messaging |
| [COMPARISON.md](COMPARISON.md) | MCP-Bastion vs scanners, gateways, unguarded MCP |
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
