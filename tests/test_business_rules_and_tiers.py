import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import BusinessRuleDeniedError, ToxicFlowError
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.business_rules import BusinessRuleEngine, _lookup, _MISSING
from mcp_bastion.pillars.toxic_flow import ToxicFlowTracker


def test_business_rule_operations_and_staging_prod_guard():
    engine = BusinessRuleEngine(
        [
            {"tool": "pay_*", "param": "$.amount", "op": "max", "value": 100},
            {"tool": "deploy", "param": "region", "op": "not_in", "value": ["us-east-1"]},
            {"tool": "tag", "param": "env", "op": "eq", "value": "prod"},
            {"tool": "tag", "param": "env", "op": "neq", "value": "dev"},
            {"tool": "spend", "param": "amount", "op": "min", "value": 10},
            {"tool": "route", "param": "dest", "op": "in", "value": ["blocked"]},
            {"tool": "route", "param": "dest", "op": "env_deny", "value": ["prod"]},
            {"tool": "x", "param": "n", "op": "weird"},
        ],
        deny_prod_env_from_staging_caller=True,
    )
    with pytest.raises(BusinessRuleDeniedError) as exc:
        engine.check("pay_invoice", {"amount": 101}, {})
    assert exc.value.code == -32047
    engine.check("pay_invoice", {"amount": 100}, {})
    with pytest.raises(BusinessRuleDeniedError):
        engine.check("deploy", {"region": "eu-west-1"}, {})
    engine.check("deploy", {"region": "us-east-1"}, {})
    with pytest.raises(BusinessRuleDeniedError):
        engine.check("deploy", {"environment": "production"}, {"env": "staging"})
    engine.check("deploy", {"environment": "staging"}, {"env": "staging"})
    with pytest.raises(BusinessRuleDeniedError):
        engine.check("tag", {"env": "prod"}, {})
    with pytest.raises(BusinessRuleDeniedError):
        engine.check("tag", {"env": "qa"}, {})
    with pytest.raises(BusinessRuleDeniedError):
        engine.check("spend", {"amount": 5}, {})
    with pytest.raises(BusinessRuleDeniedError):
        engine.check("spend", {"amount": "x"}, {})
    with pytest.raises(BusinessRuleDeniedError):
        engine.check("pay_invoice", {"amount": "x"}, {})
    with pytest.raises(BusinessRuleDeniedError):
        engine.check("route", {"dest": "blocked"}, {})
    with pytest.raises(BusinessRuleDeniedError):
        engine.check("route", {"dest": "prod-west"}, {})
    with pytest.raises(BusinessRuleDeniedError):
        engine.check("x", {"n": 1}, {})
    # Missing param → no deny for that rule
    engine.check("pay_invoice", {}, {})


def test_lookup_paths():
    assert _lookup({"a": {"b": 1}}, "$.a.b") == 1
    assert _lookup([{"z": 9}], "0.z") == 9
    assert _lookup({"a": 1}, "$") == {"a": 1}
    assert _lookup({"a": 1}, "missing") is _MISSING
    assert _lookup({"a": {"b": 2}}, "a..b") == 2


def test_private_data_class_blocks_egress_without_explicit_sink_when_opted_in():
    tracker = ToxicFlowTracker(enabled=True, block_private_to_egress=True)
    tracker.mark("s1", kinds=[], data_class="private", tool="read_customer")
    with pytest.raises(ToxicFlowError):
        tracker.check_egress("send_webhook", {"body": "customer payload"}, "s1")
    tracker2 = ToxicFlowTracker(enabled=True, block_private_to_egress=False)
    tracker2.mark("s2", kinds=["pii"], tool="read")
    # Without sink and without opt-in, no block
    tracker2.check_egress("send_webhook", {"body": "x"}, "s2")


@pytest.mark.asyncio
async def test_business_rules_run_before_handler_and_action_tier_is_stamped():
    called = False
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_business_rules=True,
        business_rules=BusinessRuleEngine(
            [{"tool": "transfer", "param": "amount", "op": "max", "value": 50}]
        ),
        tool_action_tiers={"transfer": "high_write"},
    )
    ctx = MiddlewareContext(
        message={
            "method": "tools/call",
            "params": {"name": "transfer", "arguments": {"amount": 75}},
        },
        metadata={},
    )

    async def handler(_ctx):
        nonlocal called
        called = True
        return {}

    with pytest.raises(BusinessRuleDeniedError):
        await mw(ctx, handler)
    assert called is False
    assert ctx.metadata["action_tier"] == "high_write"
    assert ctx.metadata["tool_catalog"]["action_tier"] == "high_write"
