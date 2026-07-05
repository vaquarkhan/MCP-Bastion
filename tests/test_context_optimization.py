"""Integration tests for output_budget and grounding_guard middleware wiring."""

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import GroundingViolationError
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.grounding_guard import GroundingGuard
from mcp_bastion.pillars.output_budget import OutputBudget


@pytest.mark.asyncio
async def test_middleware_output_budget_truncates_tool_result():
    ob = OutputBudget(max_output_tokens=30, min_tokens=5, enable_offload=False)
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_output_budget=True,
        output_budget=ob,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "echo", "arguments": {}}},
        request_id="r1",
        session_id="s1",
    )

    async def handler(c):
        return {"result": {"content": [{"type": "text", "text": "token " * 400}]}}

    result = await mw(ctx, handler)
    text = result["result"]["content"][0]["text"]
    assert "output_budget" in ctx.metadata.get("finops", {})
    assert len(text) < len("token " * 400)


@pytest.mark.asyncio
async def test_middleware_offload_retrieve_tool():
    ob = OutputBudget(max_output_tokens=30, min_tokens=5, enable_offload=True)
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_output_budget=True,
        output_budget=ob,
    )
    sess = "retrieve-sess"

    async def handler(c):
        return {"result": {"content": [{"type": "text", "text": "payload " * 800}]}}

    ctx1 = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "big", "arguments": {}}},
        request_id="r1",
        session_id=sess,
    )
    truncated = await mw(ctx1, handler)
    finops = ctx1.metadata.get("finops", {}).get("output_budget", {})
    key = finops.get("offload_key")
    assert key

    ctx2 = MiddlewareContext(
        message={
            "method": "tools/call",
            "params": {"name": "bastion_get_offloaded", "arguments": {"key": key}},
        },
        request_id="r2",
        session_id=sess,
    )

    async def noop(c):
        raise AssertionError("should not call handler for retrieve")

    restored = await mw(ctx2, noop)
    assert "payload " * 10 in restored["result"]["content"][0]["text"]


@pytest.mark.asyncio
async def test_middleware_grounding_guard_blocks(tmp_path):
    guard = GroundingGuard(workspace_root=tmp_path, on_violation="block")
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_grounding_guard=True,
        grounding_guard=guard,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "t", "arguments": {}}},
        request_id="r1",
    )

    async def handler(c):
        return {"result": {"content": [{"type": "text", "text": "Edit src/fake_module.py"}]}}

    with pytest.raises(GroundingViolationError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_middleware_offload_retrieve_missing_key():
    ob = OutputBudget(enable_offload=True)
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_output_budget=True,
        output_budget=ob,
    )
    ctx = MiddlewareContext(
        message={
            "method": "tools/call",
            "params": {"name": "bastion_get_offloaded", "arguments": {"key": "missing"}},
        },
        request_id="r1",
        session_id="s1",
    )

    async def noop(c):
        raise AssertionError("should not call handler")

    result = await mw(ctx, noop)
    assert "not found" in result["result"]["content"][0]["text"].lower()


@pytest.mark.asyncio
async def test_middleware_grounding_guard_warn_mode(tmp_path):
    guard = GroundingGuard(workspace_root=tmp_path, on_violation="warn")
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_grounding_guard=True,
        grounding_guard=guard,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "t", "arguments": {}}},
        request_id="r1",
    )

    async def handler(c):
        return {"result": {"content": [{"type": "text", "text": "src/missing.py"}]}}

    result = await mw(ctx, handler)
    assert result["result"]["content"][0]["text"] == "src/missing.py"
    assert ctx.metadata["finops"]["grounding_guard"]["count"] >= 1


@pytest.mark.asyncio
async def test_middleware_offload_retrieve_without_key():
    ob = OutputBudget(enable_offload=True)
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_output_budget=True,
        output_budget=ob,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "bastion_get_offloaded", "arguments": {}}},
        request_id="r1",
    )

    async def noop(c):
        raise AssertionError("should not call handler")

    result = await mw(ctx, noop)
    assert "missing offload key" in result["result"]["content"][0]["text"].lower()


def test_load_config_output_budget_and_grounding(tmp_path):
    from mcp_bastion.config import load_config

    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
output_budget:
  enabled: true
  max_output_tokens: 2000
grounding_guard:
  enabled: true
  workspace_root: /tmp/project
  on_violation: strip
""",
        encoding="utf-8",
    )
    cfg = load_config(yaml_path)
    assert cfg.output_budget is True
    assert cfg.output_budget_max_tokens == 2000
    assert cfg.grounding_guard is True
    assert cfg.grounding_guard_on_violation == "strip"
