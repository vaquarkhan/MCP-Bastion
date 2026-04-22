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
- **Improve operational confidence:** built-in dashboard, alerts, and telemetry for real-time visibility.

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

## Documentation

- [Detailed Tutorial](DETAILED_TUTORIAL.md)
- [Policy as Code](POLICY_AS_CODE.md)
- [CLI Reference](CLI.md)
- [LLM Integration](LLM_INTEGRATION.md)
- [Metrics and Dashboard](METRICS.md)
- [Security, OWASP MCP Top 10, and observability integrations](SECURITY_OBSERVABILITY.md)
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
