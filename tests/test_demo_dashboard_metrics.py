"""Bundled dashboard demo seed (works without examples/ on disk)."""

import random

import pytest

from mcp_bastion.demo_dashboard_metrics import _demo_kind_allowed, _demo_tool, seed_metrics
from mcp_bastion.pillars.metrics import MetricsStore


def test_seed_metrics_populates_store():
    from mcp_bastion.config import BastionConfig

    # Full on so synthetic blocks still appear; real dashboards pass load_config() from bastion.yaml.
    seed_metrics(random.Random(42), config=BastionConfig())
    m = MetricsStore.get().get_metrics()
    assert m["requests_total"] > 100
    assert len(m["time_series"]) >= 10
    # Block count is zero if every pillar is off in config (demo no longer fakes disabled pillars)
    assert m.get("blocked_total", 0) >= 0


def test_seed_metrics_cost_pii_alerts_branches():
    from mcp_bastion.config import BastionConfig

    cfg = BastionConfig(
        cost_tracker=True,
        prompt_guard=True,
        pii=True,
    )
    seed_metrics(random.Random(7), config=cfg)
    m = MetricsStore.get().get_metrics()
    assert float(m.get("cost_total", 0)) > 0
    assert any(a.get("kind") == "cost" for a in m.get("alerts", []))


def test_demo_tool_prefix_idempotent():
    assert _demo_tool("invoke_model") == "demo/invoke_model"
    assert _demo_tool("demo/invoke_model") == "demo/invoke_model"


@pytest.mark.parametrize(
    ("field", "value", "kind", "expected"),
    [
        ("semantic_firewall", True, "semantic_firewall", True),
        ("semantic_firewall", False, "semantic_firewall", False),
        ("sensitive_classifier", True, "sensitive_classifier", True),
        ("sensitive_classifier", False, "sensitive_classifier", False),
    ],
)
def test_demo_kind_allowed_semantic_sensitivity(field, value, kind, expected):
    from mcp_bastion.config import BastionConfig

    cfg = BastionConfig(**{field: value})
    assert _demo_kind_allowed(cfg, kind) is expected


def test_demo_kind_allowed_external_policy():
    from mcp_bastion.config import BastionConfig

    assert _demo_kind_allowed(
        BastionConfig(policy_engine_type="opa"), "external_policy"
    )
    assert not _demo_kind_allowed(
        BastionConfig(policy_engine_type="none"), "external_policy"
    )


def test_demo_kind_allowed_unknown_kinds_still_inject():
    from mcp_bastion.config import BastionConfig

    assert _demo_kind_allowed(BastionConfig(), "weird_synthetic")
