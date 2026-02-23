"""Tests for base middleware abstractions."""

import pytest

from mcp_bastion.base import Middleware, MiddlewareContext, compose_middleware


def test_middleware_context_copy():
    """MiddlewareContext.copy returns new context with updated fields."""
    ctx = MiddlewareContext(
        message={"x": 1},
        metadata={"a": 1},
        request_id="r1",
        session_id="s1",
    )
    copy = ctx.copy(message={"y": 2}, request_id="r2")
    assert copy.message == {"y": 2}
    assert copy.metadata == {"a": 1}
    assert copy.request_id == "r2"
    assert copy.session_id == "s1"


@pytest.mark.asyncio
async def test_middleware_on_call_tool():
    """Middleware.on_call_tool delegates to on_message by default."""
    mw = Middleware()
    ctx = MiddlewareContext(message={"method": "tools/call"}, metadata={})

    async def handler(c):
        return "tool_result"

    result = await mw.on_call_tool(ctx, handler)
    assert result == "tool_result"


@pytest.mark.asyncio
async def test_middleware_on_read_resource():
    """Middleware.on_read_resource delegates to on_message by default."""
    mw = Middleware()
    ctx = MiddlewareContext(message={}, metadata={})

    async def handler(c):
        return "resource_result"

    result = await mw.on_read_resource(ctx, handler)
    assert result == "resource_result"


@pytest.mark.asyncio
async def test_compose_middleware_empty_passthrough():
    """Empty compose_middleware returns passthrough."""
    composed = compose_middleware()

    async def handler(ctx):
        return "passthrough"

    result = await composed(MiddlewareContext(message={}, metadata={}), handler)
    assert result == "passthrough"
