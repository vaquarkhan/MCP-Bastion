"""Tests for MCP-Bastion middleware."""

import pytest

from mcp_bastion.base import Middleware, MiddlewareContext, compose_middleware
from mcp_bastion.errors import PromptInjectionError, RateLimitExceededError
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


@pytest.mark.asyncio
async def test_middleware_passthrough():
    """Middleware passes context through when no interception."""
    class PassMiddleware(Middleware):
        pass

    async def call_next(ctx):
        return ctx.metadata.get("result", "ok")

    mw = PassMiddleware()
    ctx = MiddlewareContext(message={"method": "ping"}, metadata={})
    result = await mw(ctx, call_next)
    assert result == "ok"


@pytest.mark.asyncio
async def test_compose_middleware():
    """Composed middleware runs in order."""
    order = []

    class A(Middleware):
        async def on_message(self, ctx, call_next):
            order.append("a_in")
            result = await call_next(ctx)
            order.append("a_out")
            return result

    class B(Middleware):
        async def on_message(self, ctx, call_next):
            order.append("b_in")
            result = await call_next(ctx)
            order.append("b_out")
            return result

    composed = compose_middleware(A(), B())

    async def final(ctx):
        order.append("final")
        return "done"

    result = await composed(MiddlewareContext(message={}, metadata={}), final)
    assert result == "done"
    assert order == ["a_in", "b_in", "final", "b_out", "a_out"]


def test_rate_limiter_allows_within_limit():
    """Rate limiter allows iterations within cap."""
    limiter = TokenBucketRateLimiter(max_iterations=3, timeout_seconds=120)
    for _ in range(3):
        allowed, err = limiter.check_iteration(request_id="req1")
        assert allowed, err
        limiter.consume_iteration(request_id="req1")


def test_rate_limiter_blocks_over_limit():
    """Rate limiter blocks when iteration cap exceeded."""
    limiter = TokenBucketRateLimiter(max_iterations=2, timeout_seconds=120)
    limiter.consume_iteration(request_id="req2")
    limiter.consume_iteration(request_id="req2")
    allowed, err = limiter.check_iteration(request_id="req2")
    assert not allowed
    assert "Maximum iterations" in (err or "")


def test_mcp_bastion_error_format():
    """MCPBastionError produces valid MCP error structure."""
    err = RateLimitExceededError("test message")
    obj = err.to_mcp_error()
    assert obj["code"] == -32002
    assert "test" in obj["message"] or "rate" in obj["message"].lower()
