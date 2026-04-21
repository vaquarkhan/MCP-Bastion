"""Tests for policy simulator shadow mode."""

import pytest

from mcp_bastion.config import BastionConfig
from mcp_bastion.policy_simulator import _build_shadow_config, simulate_policy


@pytest.mark.asyncio
async def test_policy_simulator_reports_would_block_for_content_filter():
    events = [
        {
            "request_id": "r1",
            "session_id": "s1",
            "action": "ALLOWED",
            "replay_payload": {
                "params": {
                    "name": "search",
                    "arguments": {"path": "/etc/passwd"},
                }
            },
        }
        ,
        {
            "request_id": "r1",
            "session_id": "s1",
            "action": "ALLOWED",
            "replay_payload": {
                "params": {
                    "name": "search",
                    "arguments": {"path": "/etc/passwd"},
                }
            },
        }
    ]
    result = await simulate_policy(
        events,
        overrides={
            "prompt_guard": {"enabled": False},
            "content_filter": {"enabled": True},
        },
    )
    assert result["events_evaluated"] == 2
    assert result["would_block_count"] >= 1
    assert "would_block_by_pillar" in result


@pytest.mark.asyncio
async def test_policy_simulator_semantic_firewall_override():
    events = [
        {
            "request_id": "r2",
            "session_id": "s2",
            "action": "ALLOWED",
            "replay_payload": {
                "params": {
                    "name": "get_weather",
                    "arguments": {"city": "x'; DROP TABLE users; --"},
                }
            },
        }
    ]
    result = await simulate_policy(
        events,
        overrides={"semantic_firewall": {"enabled": True}, "prompt_guard": {"enabled": False}},
    )
    assert result["events_evaluated"] == 1
    assert "semantic_firewall" in result["config"]


def test_build_shadow_config_from_none_overrides():
    cfg = _build_shadow_config(
        None,
        {
            "prompt_guard": {"enabled": True},
            "pii": {"enabled": True},
            "rate_limit": {"enabled": True},
            "circuit_breaker": {"enabled": True},
            "content_filter": {"enabled": False},
            "rbac": {"enabled": True},
            "schema_validation": {"enabled": True},
            "replay_guard": {"enabled": True},
            "cost_tracker": {
                "enabled": True,
                "max_cost_per_session": 1.0,
                "max_cost_per_day": 2.0,
            },
            "semantic_cache": {"enabled": True},
            "semantic_firewall": {"enabled": False},
            "sensitive_classifier": {
                "enabled": True,
                "threshold": 0.5,
                "use_transformers": True,
                "model_name": "custom-model",
                "block_labels": ["a", "b"],
            },
            "policy_engine": {
                "type": "opa",
                "opa": {"policy_dir": "/p", "query": "data.q"},
                "cedar": {"policies_dir": "/c", "schema": "/s.json"},
            },
            "rate_limit": {
                "enabled": True,
                "max_iterations": 9,
                "timeout_seconds": 3.0,
                "token_budget": 100,
            },
        },
    )
    assert cfg.prompt_guard is True
    assert cfg.pii is True
    assert cfg.sensitive_classifier_threshold == 0.5
    assert cfg.sensitive_classifier_use_transformers is True
    assert cfg.sensitive_classifier_model_name == "custom-model"
    assert cfg.sensitive_classifier_block_labels == ["a", "b"]
    assert cfg.policy_engine_type == "opa"
    assert cfg.opa_policy_dir == "/p"
    assert cfg.opa_query == "data.q"
    assert cfg.cedar_policies_dir == "/c"
    assert cfg.cedar_schema_path == "/s.json"
    assert cfg.rate_limit_max_iterations == 9
    assert cfg.rate_limit_timeout_seconds == 3.0
    assert cfg.rate_limit_token_budget == 100
    assert cfg.cost_max_per_session == 1.0
    assert cfg.cost_max_per_day == 2.0


def test_build_shadow_config_from_base_preserves_and_disables_heavy_defaults():
    base = BastionConfig(prompt_guard=True, pii=True)
    cfg = _build_shadow_config(base, {})
    assert cfg.prompt_guard is False
    assert cfg.pii is False


@pytest.mark.asyncio
async def test_simulate_policy_regression_and_miss_counters():
    events = [
        {
            "request_id": "r1",
            "session_id": "s1",
            "action": "ALLOWED",
            "replay_payload": {"params": {"name": "read_file", "arguments": {"path": "../../etc/passwd"}}},
        },
        {
            "request_id": "r2",
            "session_id": "s2",
            "action": "BLOCKED",
            "replay_payload": {"params": {"name": "read_file", "arguments": {"path": "ok"}}},
        },
    ]
    result = await simulate_policy(
        events,
        overrides={"content_filter": {"enabled": True}, "prompt_guard": {"enabled": False}},
    )
    assert result["regressions"] >= 1
    assert result["misses"] >= 1
    assert result["would_block_pct"] >= 0.0
