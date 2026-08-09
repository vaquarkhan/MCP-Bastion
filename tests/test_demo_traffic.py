"""Bundled demo traffic scenarios for dashboard validation."""

from mcp_bastion.demo_traffic import load_demo_traffic_scenarios, seed_from_scenarios
from mcp_bastion.pillars.metrics import MetricsStore


def test_load_demo_traffic_scenarios_has_blocks() -> None:
    data = load_demo_traffic_scenarios()
    assert data.get("name")
    batches = data.get("seed_batches") or {}
    assert batches.get("blocks")
    assert batches.get("allowed_tools")


def test_seed_from_scenarios_populates_store() -> None:
    MetricsStore.get().reset()
    from mcp_bastion.config import BastionConfig

    cfg = BastionConfig(
        prompt_guard=True,
        rate_limit=True,
        rbac=True,
        pii=True,
        cost_tracker=True,
        schema_validation=True,
        content_filter=True,
        agent_iam_enabled=True,
        server_verification_enabled=True,
        semantic_firewall=True,
    )
    info = seed_from_scenarios(config=cfg)
    assert info.get("source") == "demo_traffic_scenarios.json"
    m = MetricsStore.get().get_metrics()
    assert int(m.get("requests_total") or 0) > 0
    assert int(m.get("blocked_total") or 0) > 0
