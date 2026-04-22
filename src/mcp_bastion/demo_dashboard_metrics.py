"""
Synthetic metrics for the dashboard (KPIs, time series, forensics, insights).

Bundled in the package so `pip install` and any cwd still get demo data without
`examples/dashboard_demo.py` on disk.
"""

from __future__ import annotations

import math
import random
import time
from datetime import datetime, timedelta, timezone

from mcp_bastion.pillars.metrics import TIME_BUCKET_COUNT, TIME_BUCKET_SECONDS, MetricsStore


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


def seed_metrics(rng: random.Random) -> None:
    """Rich static demo data for the dashboard (same behavior as examples/dashboard_demo.py)."""
    store = MetricsStore.get()
    store.reset()

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
    users = (
        "alice@acme.com",
        "bob@acme.com",
        "dana@acme.com",
        "eve@acme.com",
        "service-ci",
    )

    for _ in range(380):
        store.record_request(rng.choice(tools))

    blocks = (
        ("Prompt injection blocked by guard", "query_llm"),
        ("rate limit: too many requests", "web_search"),
        ("RBAC: cannot access tool for role viewer", "delete_repo"),
        ("Cost budget exceeded for session", "invoke_model"),
        ("schema validation failed: missing required field", "submit_form"),
        ("replay or nonce reuse detected", "sensitive_action"),
        ("content filter: path traversal attempt", "read_file"),
        ("circuit breaker tripped on upstream", "invoke_model"),
    )
    tenants_cycle = ("acme-prod", "acme-staging", "tenant-demo", "default")
    nblk = 0
    for reason, tool in blocks:
        for _ in range(rng.randint(4, 14)):
            nblk += 1
            tid = tenants_cycle[nblk % len(tenants_cycle)]
            store.record_blocked(
                reason,
                tool,
                tenant_id=tid,
                trace_id=f"trc-seed-{nblk:04d}",
                request_id=f"req-seed-{nblk:04d}",
            )

    for _ in range(95):
        nblk += 1
        store.record_blocked(
            "rate limit: too many requests",
            "web_search",
            tenant_id=tenants_cycle[nblk % len(tenants_cycle)],
            trace_id=f"trc-seed-{nblk:04d}",
            request_id=f"req-seed-{nblk:04d}",
        )

    hot_tool = "invoke_model"
    for _ in range(22):
        store.record_request(hot_tool)
    for _ in range(14):
        nblk += 1
        store.record_blocked(
            "Cost budget exceeded for session",
            hot_tool,
            tenant_id="acme-prod",
            trace_id=f"trc-seed-{nblk:04d}",
            request_id=f"req-seed-{nblk:04d}",
        )

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

    store.record_cost(18.5, "finops-demo")
    for _ in range(45):
        store.record_cost(round(rng.uniform(0.02, 0.35), 4), rng.choice(users))

    for _ in range(520):
        store.record_latency_ms(rng.uniform(4.0, 14.0))
    for _ in range(200):
        store.record_latency_ms(rng.uniform(10.0, 28.0))
    for _ in range(120):
        store.record_latency_ms(rng.uniform(120.0, 420.0))

    for tool in tools:
        for _ in range(45):
            store.record_tool_latency_ms(tool, rng.uniform(4.0, 155.0))

    store.add_alert("rate_limit", "Spike on web_search from tenant-7", "warning")
    store.add_alert("injection", "Suspicious system prompt pattern in session k9", "critical")
    store.add_alert("cost", "Daily burn approaching 80% of budget", "warning")
    store.add_alert("pii", "Elevated EMAIL_ADDRESS detections on query_llm", "warning")
    store.add_alert("demo", "Synthetic policy review: tighten RBAC on delete_repo", "warning")

    _inject_demo_time_series(store, rng)
    store._metrics.window_start = (datetime.now(timezone.utc) - timedelta(seconds=90)).isoformat()
