"""
Background traffic for dashboard demos (same behavior as examples/dashboard_demo.py -- live loop).

When MCP_BASTION_DEMO is enabled, the dashboard can spawn this loop so KPIs and charts move
without a separate MCP server. Disable with MCP_BASTION_DEMO_LIVE=0 or mcp-bastion dashboard --no-live.

Seeding respects :class:`~mcp_bastion.config.BastionConfig` (same as ``demo_dashboard_metrics``)
so disabled pillars are not faked in ``blocked_by_kind`` / ``pillar_health``.
"""

from __future__ import annotations

import random
import threading
from typing import TYPE_CHECKING

from mcp_bastion.pillars.metrics import MetricsStore

if TYPE_CHECKING:
    from mcp_bastion.config import BastionConfig


def _dtool(t: str) -> str:
    return f"demo/{t}" if not t.startswith("demo/") else t


def _allow_reason(cfg: BastionConfig, reason: str) -> bool:
    from mcp_bastion.demo_dashboard_metrics import _demo_kind_allowed

    k = MetricsStore._normalize_reason_kind(reason)
    return _demo_kind_allowed(cfg, k)


def live_simulator(
    stop: threading.Event,
    rng: random.Random,
    config: BastionConfig | None = None,
) -> None:
    """Periodically record demo requests/blocks/cost/PII/latency into MetricsStore."""
    from mcp_bastion.config import load_config

    cfg = config if config is not None else load_config()
    tenant = (cfg.multi_tenant_default_tenant or "default").strip() or "default"
    tools = tuple(
        _dtool(t)
        for t in (
            "read_file",
            "write_file",
            "web_search",
            "invoke_github",
            "query_llm",
            "query_db",
        )
    )
    reasons = (
        "rate limit: too many requests",
        "Prompt injection blocked by guard",
        "RBAC: cannot access tool for role viewer",
        "schema validation failed: missing required field",
        "circuit breaker tripped on upstream",
    )
    users = ("alice@acme.com", "bob@acme.com", "dana@acme.com")
    pii_types = (
        "EMAIL_ADDRESS",
        "PERSON",
        "PHONE_NUMBER",
        "LOCATION",
        "ORGANIZATION",
        "DATE_TIME",
        "IP_ADDRESS",
        "URL",
        "CREDIT_CARD",
        "US_SSN",
        "NRP",
    )

    while not stop.wait(rng.uniform(0.25, 1.1)):
        store = MetricsStore.get()
        roll = rng.random()
        if roll < 0.68:
            store.record_request(rng.choice(tools), tenant=tenant)
        elif roll < 0.86:
            reason = rng.choice(reasons)
            if _allow_reason(cfg, reason):
                store.record_blocked(
                    reason,
                    rng.choice(tools),
                    tenant_id=tenant,
                )
        elif roll < 0.92:
            store.record_cost(
                rng.uniform(0.001, 0.06),
                rng.choice(users),
                {"llm_provider": "openai", "llm_model": "gpt-4o-mini"},
                tenant=tenant,
            )
        elif roll < 0.96:
            if cfg.pii and rng.random() < 0.5:
                if rng.random() < 0.15:
                    a, b = rng.sample(pii_types, 2)
                    store.record_pii_entities({a: rng.randint(1, 2), b: rng.randint(1, 2)})
                else:
                    store.record_pii_entities({rng.choice(pii_types): rng.randint(1, 4)})
            else:
                store.record_request(rng.choice(tools), tenant=tenant)
        else:
            store.record_tool_latency_ms(rng.choice(tools), rng.uniform(8.0, 90.0))
        store.record_latency_ms(rng.uniform(4.0, 62.0))
        if roll > 0.985:
            store.add_alert("demo", "Synthetic alert from live demo loop", "warning")
