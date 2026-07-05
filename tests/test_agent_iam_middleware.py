"""Middleware integration tests for Agent IAM."""

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import AgentAccessDeniedError
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.agent_iam import AgentIAM, AgentPolicy
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


def _support_iam() -> AgentIAM:
    return AgentIAM(
        [
            AgentPolicy(
                agent_id="customer_support_bot",
                token="support-secret",
                allowed_tools=frozenset({"search_docs", "get_ticket_status"}),
                blocked_tools=frozenset({"execute_sql", "delete_user"}),
            )
        ],
        token_metadata_key="bastion_agent_token",
        require_token=True,
    )


@pytest.mark.asyncio
async def test_middleware_agent_iam_blocks_destructive_tool():
    """Support bot token cannot call delete_user."""
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(fail_open=True),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        agent_iam=_support_iam(),
        enable_agent_iam=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={
            "method": "tools/call",
            "params": {"name": "delete_user", "arguments": {"id": 1}},
        },
        request_id="r1",
        metadata={"bastion_agent_token": "support-secret"},
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(AgentAccessDeniedError, match="delete_user"):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_middleware_agent_iam_allows_permitted_tool():
    """Support bot token can call search_docs."""
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(fail_open=True),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        agent_iam=_support_iam(),
        enable_agent_iam=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={
            "method": "tools/call",
            "params": {"name": "search_docs", "arguments": {"q": "billing"}},
        },
        request_id="r1",
        metadata={"bastion_agent_token": "support-secret"},
    )

    async def handler(c):
        return {"ok": True}

    result = await mw(ctx, handler)
    assert result == {"ok": True}
    assert ctx.metadata.get("agent_id") == "customer_support_bot"
