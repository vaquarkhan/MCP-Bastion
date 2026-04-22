"""Bundled dashboard demo seed (works without examples/ on disk)."""

import random

from mcp_bastion.demo_dashboard_metrics import seed_metrics
from mcp_bastion.pillars.metrics import MetricsStore


def test_seed_metrics_populates_store():
    seed_metrics(random.Random(42))
    m = MetricsStore.get().get_metrics()
    assert m["requests_total"] > 100
    assert len(m["time_series"]) >= 10
    assert m.get("blocked_total", 0) > 0
