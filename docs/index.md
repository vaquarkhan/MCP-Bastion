---
layout: default
title: MCP-Bastion Docs
---

# MCP-Bastion Documentation

Secure MCP servers with local-first middleware for prompt injection defense, PII redaction, rate/cost controls, audit, and observability.

## Why teams adopt MCP-Bastion

MCP-Bastion helps teams ship AI agents faster without exposing enterprise systems to uncontrolled tool execution.

- **Reduce security risk:** blocks prompt injection and suspicious tool payloads before execution.
- **Protect sensitive data:** redacts PII in responses before it reaches downstream clients or models.
- **Control cost and blast radius:** enforces rate limits, token budgets, and cost guardrails.
- **Improve operational confidence:** built-in dashboard (KPI strip, charts, forensics), alerts, telemetry, plus **red team** and **doctor** CLIs for repeatable checks.

## Value proposition

### Build agent features safely, not slowly

Instead of building custom guardrails for every MCP server, use one middleware layer that can be reused across teams and tools.

### Lower incident and compliance exposure

Security controls are policy-driven (`bastion.yaml`) and can be hot-reloaded, so governance changes happen without risky deploy loops.

### Production-ready observability

With dashboard metrics, Prometheus endpoint, and OTEL hooks, your security and platform teams can monitor adoption and risk from day one.

## Quick Start

1. Install:
   - `pip install mcp-bastion-python`
2. Create policy file:
   - copy `bastion.yaml.example` to `bastion.yaml`
3. Build middleware from config:
   - `from mcp_bastion import build_middleware_from_config`
4. Run dashboard:
   - `mcp-bastion dashboard --port 7000`

## Fast path

- **[Quick start (minimal code + CI)](QUICK_START.md)** — wrap FastMCP or load `bastion.yaml` in two lines; validate in pipelines  
- **[Discovery checklist](DISCOVERY.md)** — registries and lists for ecosystem visibility  
- **[Contributing](../CONTRIBUTING.md)** — **`good first issue`**-friendly tasks  

## Documentation map

| Your goal | Start here |
|-------------|------------|
| **Configure `bastion.yaml`** | [PILLARS.md](PILLARS.md) → [POLICY_AS_CODE.md](POLICY_AS_CODE.md) → repo `bastion.yaml.example` |
| **Connect Claude, ChatGPT, OpenAI, Gemini, …** | [LLM_INTEGRATION.md](LLM_INTEGRATION.md) → [INTEGRATION_MODELS.md](INTEGRATION_MODELS.md) |
| **FastMCP, npm server, or proxy patterns** | [TUTORIALS.md](TUTORIALS.md) → [DETAILED_TUTORIAL.md](DETAILED_TUTORIAL.md) |
| **Prove RBAC & token savings with numbers** | [BENCHMARKS.md](BENCHMARKS.md) — pytest suite + reproducible RBAC / output-budget / discovery / cache metrics |

Hub with all files: [Docs README](README.md).

## Documentation

- [Quick start](QUICK_START.md) — minimal FastMCP / `bastion.yaml` / CI
- [Discovery checklist](DISCOVERY.md) — registries and ecosystem lists
- [Roadmap](ROADMAP.md) — directions (Issues for delivery)
- [Benchmarks (RBAC & context reduction)](BENCHMARKS.md) — measured output-budget, discovery, cache, RBAC matrix
- [Supply chain & releases](SUPPLY_CHAIN.md) — CI merge gates, automated releases, npm provenance, PyPI OIDC
- [Integration models](INTEGRATION_MODELS.md) — middleware vs URL-swap gateways; how each stack gets Bastion in front of MCP
- [Detailed Tutorial](DETAILED_TUTORIAL.md)
- [Policy as Code](POLICY_AS_CODE.md)
- [CLI Reference](CLI.md)
- [LLM Integration](LLM_INTEGRATION.md)
- [Metrics and Dashboard](METRICS.md)
- [Security, OWASP MCP Top 10, observability, fleet rollout, SIEM audit](SECURITY_OBSERVABILITY.md)
- [Security Guidance](SECURITY.md)
- [GitHub Pages Setup](GITHUB_PAGES.md)

## Core Capabilities

- Prompt injection defense with PromptGuard.
- PII redaction with Presidio.
- Rate limiting and token budgets.
- Cost tracking and alerts.
- Content filtering with allowlist/denylist rules.
- Optional hot-reload of `bastion.yaml`.
- Dashboard + Prometheus + OTEL observability.

## Feature highlights

| Capability | Outcome |
|---|---|
| Prompt injection defense | Stops unsafe instructions before tool execution |
| PII redaction | Masks sensitive entities in outbound content |
| Rate and cost controls | Prevents runaway loops and budget overruns |
| Content filter allow/deny rules | Blocks risky content while allowing trusted internal patterns |
| Audit and alerts | Creates actionable security event trails |
| Dashboard and metrics API | Enables SOC/Platform visibility and trend tracking |

## Ideal users

- AI platform teams operating shared MCP infrastructure
- Enterprise security teams defining guardrail policy
- Product teams shipping MCP-powered copilots and assistants
- Consultants and integrators deploying secure agent stacks for clients

## Get started in 10 minutes

1. Install package.
2. Copy `bastion.yaml.example` to `bastion.yaml`.
3. Build middleware from config.
4. Run your MCP server and dashboard.
5. Validate with attack and rate-limit smoke tests.

See the complete flow in [Detailed Tutorial](DETAILED_TUTORIAL.md).

For repository-level overview and install details, start at [README](../README.md).

## Community and feedback

Questions, integration notes, and bug reports help everyone adopting MCP-Bastion. Use **GitHub Issues** for defects and feature ideas, and **GitHub Discussions** (if enabled on the repository) for Q&A and deployment patterns. **Pull requests** for docs and examples are especially welcome.
