"""OWASP MCP Top 10-oriented controls (allowlist, edge auth, session scope, secrets)."""

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import (
    AuthenticationError,
    ContentFilterError,
    SessionScopeExceededError,
    ToolNotAllowedError,
)
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


@pytest.mark.asyncio
async def test_tool_allowlist_blocks_unknown():
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=50),
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_tool_allowlist=True,
        tool_allowlist={"allowed_tool"},
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "other_tool", "arguments": {}}},
        request_id="r1",
        session_id="s1",
        metadata={},
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(ToolNotAllowedError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_edge_auth_requires_metadata_token():
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=50),
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_edge_auth=True,
        edge_auth_metadata_key="bastion_edge_token",
        edge_auth_secret="supersecret",
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "t", "arguments": {}}},
        request_id="r1",
        session_id="s1",
        metadata={},
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(AuthenticationError):
        await mw(ctx, handler)

    ctx2 = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "t", "arguments": {}}},
        request_id="r2",
        session_id="s1",
        metadata={"bastion_edge_token": "supersecret"},
    )
    out = await mw(ctx2, handler)
    assert out == {"ok": True}


@pytest.mark.asyncio
async def test_session_max_distinct_tools():
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=50),
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        session_max_unique_tools=2,
    )

    async def handler(c):
        return {"ok": True}

    sid = "sess-scope"
    for tool in ("a", "b"):
        ctx = MiddlewareContext(
            message={"method": "tools/call", "params": {"name": tool, "arguments": {}}},
            request_id=f"r-{tool}",
            session_id=sid,
            metadata={},
        )
        await mw(ctx, handler)

    ctx3 = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "c", "arguments": {}}},
        request_id="r-c",
        session_id=sid,
        metadata={},
    )
    with pytest.raises(SessionScopeExceededError):
        await mw(ctx3, handler)


def test_content_filter_block_secrets_aws_key():
    cf = ContentFilter(
        block_code_execution=False,
        block_file_paths=False,
        block_secrets=True,
    )
    with pytest.raises(ContentFilterError):
        cf.check("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
