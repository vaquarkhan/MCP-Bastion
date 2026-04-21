"""tools/list response scanning (tool poisoning in descriptions)."""

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import ToolMetadataPoisoningError
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


@pytest.mark.asyncio
async def test_tool_metadata_guard_removes_tool_with_path_in_description():
    cf = ContentFilter(block_file_paths=True, block_code_execution=False)
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=50),
        content_filter=cf,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_content_filter=True,
        enable_tool_metadata_guard=True,
        tool_metadata_guard_on_poison="remove_tool",
    )
    ctx = MiddlewareContext(
        message={"method": "tools/list", "id": 1},
        request_id="r1",
        metadata={},
    )

    async def handler(c):
        return {
            "tools": [
                {"name": "safe_tool", "description": "Does harmless things"},
                {"name": "bad_tool", "description": "Reads /etc/passwd for debugging"},
            ]
        }

    out = await mw(ctx, handler)
    assert isinstance(out, dict)
    tools = out.get("tools", [])
    assert len(tools) == 1
    assert tools[0]["name"] == "safe_tool"
    assert "bad_tool" in ctx.metadata.get("tool_metadata_guard", {}).get("removed_tools", [])


@pytest.mark.asyncio
async def test_tool_metadata_guard_block_all_raises():
    cf = ContentFilter(block_file_paths=True, block_code_execution=False)
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=50),
        content_filter=cf,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_content_filter=True,
        enable_tool_metadata_guard=True,
        tool_metadata_guard_on_poison="block_all",
    )
    ctx = MiddlewareContext(
        message={"method": "tools/list", "id": 1},
        request_id="r1",
        metadata={},
    )

    async def handler(c):
        return {"tools": [{"name": "x", "description": "path /etc/shadow"}]}

    with pytest.raises(ToolMetadataPoisoningError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_nested_result_tools_dict():
    cf = ContentFilter(block_file_paths=True, block_code_execution=False)
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=50),
        content_filter=cf,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_content_filter=True,
        enable_tool_metadata_guard=True,
        tool_metadata_guard_on_poison="remove_tool",
    )
    ctx = MiddlewareContext(message={"method": "tools/list", "id": 2}, request_id="r2", metadata={})

    async def handler(c):
        return {"result": {"tools": [{"name": "a", "description": "ok"}, {"name": "b", "description": "../secret"}]}}

    out = await mw(ctx, handler)
    inner = out.get("result", {})
    assert len(inner.get("tools", [])) == 1
    assert inner["tools"][0]["name"] == "a"
