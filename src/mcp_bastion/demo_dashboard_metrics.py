"""
Synthetic metrics for the dashboard (KPIs, time series, forensics, insights).

Bundled in the package so `pip install` and any cwd still get demo data without
`examples/dashboard_demo.py` on disk.

**Config-aware seeding:** pass the same :class:`mcp_bastion.config.BastionConfig` your
Bastion process uses (e.g. from :func:`mcp_bastion.config.load_config`) so the demo
does not show pillar activity for controls that are **off** in `bastion.yaml`, and
so tenant / tool names stay aligned (default tenant, ``demo/...`` tool prefix).
"""

from __future__ import annotations

import math
import random
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from mcp_bastion.pillars.metrics import TIME_BUCKET_COUNT, TIME_BUCKET_SECONDS, MetricsStore

if TYPE_CHECKING:
    from mcp_bastion.config import BastionConfig


def _demo_tool(name: str) -> str:
    """Prefix so Top Tools / drill-down are clearly distinct from real tool names."""
    return f"demo/{name}" if not name.startswith("demo/") else name


def _demo_kind_allowed(cfg: BastionConfig, kind: str) -> bool:
    """Only inject synthetic *blocked* events for kinds whose pillar is enabled in config."""
    if kind == "injection":
        return bool(cfg.prompt_guard)
    if kind == "rate_limit":
        return bool(cfg.rate_limit)
    if kind == "rbac":
        return bool(cfg.rbac)
    if kind == "cost":
        return bool(cfg.cost_tracker)
    if kind == "schema_validation":
        return bool(cfg.schema_validation)
    if kind == "replay":
        return bool(cfg.replay_guard)
    if kind == "content_filter":
        return bool(cfg.content_filter)
    if kind == "circuit_breaker":
        return bool(cfg.circuit_breaker)
    if kind == "semantic_firewall":
        return bool(cfg.semantic_firewall)
    if kind == "sensitive_classifier":
        return bool(cfg.sensitive_classifier)
    if kind == "external_policy":
        return (cfg.policy_engine_type or "none") != "none"
    if kind == "agent_iam":
        return bool(cfg.agent_iam_enabled)
    if kind == "server_verification":
        return bool(cfg.server_verification_enabled)
    return True


def _inject_demo_time_series(store: object, rng: random.Random) -> None:
    """Populate _time_buckets for the full rolling window (see MetricsStore)."""
    t = time.time()
    bid = int(t // TIME_BUCKET_SECONDS)
    start_bid = bid - TIME_BUCKET_COUNT + 1
    for b in range(start_bid, bid + 1):
        i = b - start_bid
        w1 = 0.5 + 0.5 * math.sin(i / 2.7)
        w2 = 0.5 + 0.5 * math.cos(i / 4.3)
        drift = i * 1.15
        allowed = int(22 + 58 * w1 + 32 * w2 + drift + rng.randint(-6, 20))
        allowed = max(20, min(allowed, 220))

        if i < TIME_BUCKET_COUNT - 3:
            blocked = 2 + rng.randint(0, 4)
            if i % 5 == 0:
                blocked += rng.randint(8, 18)
            elif i % 7 == 3:
                blocked += rng.randint(3, 10)
            elif rng.random() < 0.22:
                blocked += rng.randint(2, 8)
        else:
            blocked = 24 + rng.randint(0, 14)
            allowed = max(35, allowed - 30)

        blocked = max(0, min(blocked, 85))
        store._time_buckets[b] = [allowed, blocked]


def seed_metrics(rng: random.Random, config: BastionConfig | None = None) -> None:
    """Rich static demo data for the dashboard (same entry point as examples/dashboard_demo.py)."""
    from mcp_bastion.config import load_config

    cfg = config if config is not None else load_config()
    store = MetricsStore.get()
    store.reset()

    tenant = (cfg.multi_tenant_default_tenant or "default").strip() or "default"

    tools = (
        "read_file",
        "write_file",
        "query_db",
        "web_search",
        "invoke_github",
        "query_llm",
        "delete_repo",
        "submit_form",
        "sensitive_action",
        "invoke_model",
    )
    demo_tools = tuple(_demo_tool(t) for t in tools)
    users = (
        "alice@acme.com",
        "bob@acme.com",
        "dana@acme.com",
        "eve@acme.com",
        "service-ci",
    )

    for _ in range(380):
        store.record_request(rng.choice(demo_tools), tenant=tenant)

    blocks = (
        ("Prompt injection blocked by guard", "query_llm"),
        ("rate limit: too many requests", "web_search"),
        ("RBAC: cannot access tool for role viewer", "delete_repo"),
        ("Cost budget exceeded for session", "invoke_model"),
        ("schema validation failed: missing required field", "submit_form"),
        ("replay or nonce reuse detected", "sensitive_action"),
        ("content filter: path traversal attempt", "read_file"),
        ("circuit breaker tripped on upstream", "invoke_model"),
        ("Agent 'support-bot' is not permitted to call tool 'delete_repo' (blocked by policy)", "delete_repo"),
        ("checksum verification failed for server module", "read_file"),
    )
    nblk = 0
    for reason, tool in blocks:
        kind = MetricsStore._normalize_reason_kind(reason)
        if not _demo_kind_allowed(cfg, kind):
            continue
        for _ in range(rng.randint(4, 14)):
            nblk += 1
            agent = "support-bot" if "Agent '" in reason else ""
            store.record_blocked(
                reason,
                _demo_tool(tool),
                tenant_id=tenant,
                agent_id=agent,
                trace_id=f"trc-seed-{nblk:04d}",
                request_id=f"req-seed-{nblk:04d}",
                forensic_trace=[
                    {"pillar": "audit_log", "status": "allowed", "detail": "request accepted"},
                    {
                        "pillar": kind if kind != "other" else "policy",
                        "status": "blocked",
                        "detail": reason[:200],
                    },
                ],
            )

    if _demo_kind_allowed(cfg, "rate_limit") and cfg.rate_limit:
        for _ in range(95):
            nblk += 1
            store.record_blocked(
                "rate limit: too many requests",
                _demo_tool("web_search"),
                tenant_id=tenant,
                trace_id=f"trc-seed-{nblk:04d}",
                request_id=f"req-seed-{nblk:04d}",
                forensic_trace=[
                    {"pillar": "rate_limiter", "status": "blocked", "detail": "rate limit: too many requests"},
                ],
            )

    if _demo_kind_allowed(cfg, "cost") and cfg.cost_tracker:
        hot_tool = _demo_tool("invoke_model")
        for _ in range(22):
            store.record_request(hot_tool, tenant=tenant)
        for _ in range(14):
            nblk += 1
            store.record_blocked(
                "Cost budget exceeded for session",
                hot_tool,
                tenant_id=tenant,
                trace_id=f"trc-seed-{nblk:04d}",
                request_id=f"req-seed-{nblk:04d}",
                forensic_trace=[
                    {"pillar": "cost_tracker", "status": "blocked", "detail": "Cost budget exceeded for session"},
                ],
            )

    if cfg.pii:
        store.record_pii_entities(
            {
                "EMAIL_ADDRESS": 52,
                "PERSON": 34,
                "PHONE_NUMBER": 19,
                "LOCATION": 14,
                "ORGANIZATION": 21,
                "DATE_TIME": 27,
                "IP_ADDRESS": 11,
                "URL": 16,
                "CREDIT_CARD": 6,
                "US_SSN": 5,
                "US_DRIVER_LICENSE": 4,
                "NRP": 8,
                "MEDICAL_LICENSE": 3,
                "US_PASSPORT": 2,
                "CRYPTO": 2,
            }
        )

    store.record_cost(
        18.5,
        "finops-demo",
        {"llm_provider": "openai", "llm_model": "gpt-4o"},
        tenant=tenant,
    )
    for _ in range(45):
        store.record_cost(
            round(rng.uniform(0.02, 0.35), 4),
            rng.choice(users),
            {
                "llm_provider": "openai",
                "llm_model": "gpt-4o-mini",
            },
            tenant=tenant,
        )

    # FinOps / cost-reduction demo: tokens saved by output budget + discovery filter.
    store.record_tokens_used(1_250_000)
    store.record_tokens_saved(
        420_000,
        source="output_budget",
        provider="openai",
        model="gpt-4o-mini",
        as_output=True,
    )
    store.record_tokens_saved(
        95_000,
        source="discovery_filter",
        provider="openai",
        model="gpt-4o-mini",
        as_output=False,
    )
    store.record_tokens_saved(
        38_000,
        source="semantic_cache",
        provider="openai",
        model="gpt-4o-mini",
        as_output=True,
    )

    for _ in range(520):
        store.record_latency_ms(rng.uniform(4.0, 14.0))
    for _ in range(200):
        store.record_latency_ms(rng.uniform(10.0, 28.0))
    for _ in range(120):
        store.record_latency_ms(rng.uniform(120.0, 420.0))

    for tool in demo_tools:
        for _ in range(45):
            store.record_tool_latency_ms(tool, rng.uniform(4.0, 155.0))

    if cfg.prompt_guard:
        store.add_alert("injection", "Suspicious system prompt pattern in session k9", "critical")
    store.add_alert("rate_limit", "Spike on web_search from tenant-7", "warning")
    if cfg.cost_tracker:
        store.add_alert("cost", "Daily burn approaching 80% of budget", "warning")
    if cfg.pii:
        store.add_alert("pii", "Elevated EMAIL_ADDRESS detections on query_llm", "warning")
    store.add_alert("demo", "Synthetic policy review: tighten RBAC on delete_repo", "warning")

    _inject_demo_time_series(store, rng)
    store._metrics.window_start = (datetime.now(timezone.utc) - timedelta(seconds=90)).isoformat()
