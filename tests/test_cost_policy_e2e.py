"""End-to-end tests for cost-aware policy engine."""

from __future__ import annotations

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import CostPolicyApprovalRequiredError, ExpensiveChainError
from mcp_bastion.pillars.cost_policy import CostPolicyEngine, CostPolicyRule, ExpensiveChainConfig
from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.middleware import MCPBastionMiddleware


def _mw_with_policy(
    *,
    cap: float = 1.0,
    rules: list[CostPolicyRule] | None = None,
    expensive: ExpensiveChainConfig | None = None,
) -> MCPBastionMiddleware:
    ct = CostTracker(max_cost_per_session=cap, max_cost_per_day=100.0)
    policy = CostPolicyEngine(rules=rules, expensive_chain=expensive or ExpensiveChainConfig())
    return MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        cost_tracker=ct,
        cost_policy=policy,
        enable_cost_tracker=True,
        enable_cost_policy=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_governance_attestation=False,
    )


@pytest.mark.asyncio
async def test_cost_policy_degrade_model_at_spend_threshold():
    mw = _mw_with_policy(
        cap=0.25,
        rules=[CostPolicyRule(session_spend_pct_gte=80, action="degrade_model", target_model="gpt-4o-mini")],
    )
    mw.cost_tracker.record(0.20, session_id="s1", principal_id="anonymous:default", tenant_id="default")

    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "search", "arguments": {}}},
        request_id="r1",
        session_id="s1",
        metadata={"cost": 0.01},
    )

    async def handler(c):
        return {"ok": True}

    assert await mw(ctx, handler) == {"ok": True}
    assert ctx.metadata.get("_cost_policy_degrade_model") == "gpt-4o-mini"
    assert any("degrade_model" in a for a in ctx.metadata.get("cost_policy_actions", []))


@pytest.mark.asyncio
async def test_cost_policy_require_approval_blocks_without_metadata():
    mw = _mw_with_policy(
        cap=0.25,
        rules=[CostPolicyRule(session_spend_pct_gte=95, action="require_approval")],
    )
    mw.cost_tracker.record(0.24, session_id="s1", principal_id="anonymous:default", tenant_id="default")

    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "search", "arguments": {}}},
        request_id="r1",
        session_id="s1",
        metadata={"cost": 0.01},
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(CostPolicyApprovalRequiredError, match="approval required"):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_cost_policy_require_approval_allows_with_metadata():
    mw = _mw_with_policy(
        cap=0.25,
        rules=[CostPolicyRule(session_spend_pct_gte=95, action="require_approval")],
    )
    mw.cost_tracker.record(0.24, session_id="s1", principal_id="anonymous:default", tenant_id="default")

    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "search", "arguments": {}}},
        request_id="r1",
        session_id="s1",
        metadata={"cost": 0.01, "bastion_cost_approval": "approved-by-ops"},
    )

    async def handler(c):
        return {"ok": True}

    assert await mw(ctx, handler) == {"ok": True}


@pytest.mark.asyncio
async def test_cost_policy_expensive_chain_blocks():
    mw = _mw_with_policy(
        expensive=ExpensiveChainConfig(
            enabled=True,
            max_projected_cost_usd=0.60,
            tool_costs={"expensive_api": 0.35},
            default_tool_cost_usd=0.05,
        ),
    )

    async def handler(c):
        return {"ok": True}

    ctx1 = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "expensive_api", "arguments": {}}},
        request_id="r1",
        session_id="chain-s",
        metadata={"cost": 0.35},
    )
    assert await mw(ctx1, handler) == {"ok": True}

    ctx2 = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "expensive_api", "arguments": {}}},
        request_id="r2",
        session_id="chain-s",
        metadata={"cost": 0.35},
    )
    with pytest.raises(ExpensiveChainError, match="projected tool-chain cost"):
        await mw(ctx2, handler)


@pytest.mark.asyncio
async def test_cost_policy_force_discovery_filter_metadata():
    mw = _mw_with_policy(
        cap=0.25,
        rules=[CostPolicyRule(session_spend_pct_gte=90, action="force_discovery_filter")],
    )
    mw.cost_tracker.record(0.23, session_id="s1", principal_id="anonymous:default", tenant_id="default")

    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "search", "arguments": {}}},
        request_id="r1",
        session_id="s1",
        metadata={"cost": 0.01},
    )

    async def handler(c):
        return {"ok": True}

    assert await mw(ctx, handler) == {"ok": True}
    assert ctx.metadata.get("_cost_policy_force_discovery_filter") is True


def test_cost_policy_from_config_yaml_shape():
    engine = CostPolicyEngine.from_config(
        {
            "rules": [
                {"when": {"session_spend_pct_gte": 80}, "action": "degrade_model", "target_model": "mini"},
            ],
            "expensive_chain": {"enabled": True, "max_projected_cost_usd": 2.0, "tool_costs": {"x": 1.0}},
        }
    )
    assert len(engine.rules) == 1
    assert engine.rules[0].target_model == "mini"
    assert engine.expensive_chain.enabled is True
    assert engine.expensive_chain.tool_costs["x"] == 1.0
