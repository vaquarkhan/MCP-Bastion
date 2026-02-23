"""Tests for v2 middleware (circuit breaker, content filter, RBAC, schema, replay, cost, cache)."""

import pytest

from mcp_bastion.base import MiddlewareContext, compose_middleware
from mcp_bastion.errors import (
    ContentFilterError,
    CostBudgetExceededError,
    RBACError,
    RateLimitExceededError,
    ReplayAttackError,
    SchemaValidationError,
)
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.rbac import RBAC
from mcp_bastion.pillars.replay_guard import ReplayGuard
from mcp_bastion.pillars.schema_validation import SchemaValidator
from mcp_bastion.pillars.semantic_cache import SemanticCache


@pytest.mark.asyncio
async def test_content_filter_blocks_in_middleware():
    """Content filter blocks suspicious path in middleware."""
    cf = ContentFilter(block_file_paths=True)
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        content_filter=cf,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_content_filter=True,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "read", "arguments": {"path": "/etc/passwd"}}},
        request_id="r1",
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(ContentFilterError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_content_filter_disabled_passthrough():
    """Content filter disabled allows pass."""
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        content_filter=ContentFilter(block_file_paths=True),
        enable_content_filter=False,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "read", "arguments": {"path": "/etc/passwd"}}},
    )

    async def handler(c):
        return {"ok": True}

    result = await mw(ctx, handler)
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_circuit_breaker_in_middleware():
    """Circuit breaker opens after failures."""
    from mcp_bastion.pillars.circuit_breaker import CircuitBreaker

    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        circuit_breaker=cb,
        enable_circuit_breaker=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_content_filter=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "flaky"}},
        request_id="r1",
    )

    async def failing(c):
        raise RuntimeError("fail")

    with pytest.raises(RuntimeError):
        await mw(ctx, failing)
    with pytest.raises(RuntimeError):
        await mw(ctx, failing)

    from mcp_bastion.errors import CircuitBreakerOpenError
    with pytest.raises(CircuitBreakerOpenError):
        await mw(ctx, failing)


@pytest.mark.asyncio
async def test_rbac_blocks_in_middleware():
    """RBAC blocks unauthorized tool access."""
    rbac = RBAC({"admin": ["read"], "viewer": ["read"]})
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        rbac=rbac,
        enable_rbac=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "write", "arguments": {}}},
        request_id="r1",
        metadata={"role": "viewer"},
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(RBACError, match="cannot access tool"):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_rbac_allows_in_middleware():
    """RBAC allows authorized tool access."""
    rbac = RBAC({"admin": ["read", "write"]})
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        rbac=rbac,
        enable_rbac=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "read", "arguments": {}}},
        request_id="r1",
        metadata={"role": "admin"},
    )

    async def handler(c):
        return {"ok": True}

    result = await mw(ctx, handler)
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_schema_validation_blocks_in_middleware():
    """Schema validation blocks invalid input."""
    sv = SchemaValidator({"add": {"a": int, "b": int}})
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        schema_validator=sv,
        enable_schema_validation=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "add", "arguments": {"a": 1}}},
        request_id="r1",
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(SchemaValidationError, match="Missing required"):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_replay_guard_blocks_duplicate_in_middleware():
    """Replay guard blocks duplicate nonce."""
    rg = ReplayGuard(require_nonce=True)
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        replay_guard=rg,
        enable_replay_guard=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": {}, "nonce": "n1"}},
        request_id="r1",
    )

    async def handler(c):
        return {"ok": True}

    await mw(ctx, handler)
    with pytest.raises(ReplayAttackError, match="Duplicate nonce"):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_cost_tracker_blocks_over_budget_in_middleware():
    """Cost tracker blocks when over budget."""
    ct = CostTracker(max_cost_per_session=0.10)
    ct.record(0.15, session_id="s1")
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        cost_tracker=ct,
        enable_cost_tracker=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": {}}},
        request_id="r1",
        session_id="s1",
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(CostBudgetExceededError, match="exceeds limit"):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_semantic_cache_returns_cached():
    """Semantic cache returns cached result for similar query."""
    sc = SemanticCache(similarity_threshold=0.9)
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        semantic_cache=sc,
        enable_semantic_cache=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )

    call_count = 0

    async def handler(c):
        nonlocal call_count
        call_count += 1
        return {"content": [{"type": "text", "text": f"result-{call_count}"}]}

    ctx1 = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "search", "arguments": {"q": "hello world"}}},
        request_id="r1",
    )
    result1 = await mw(ctx1, handler)
    assert call_count == 1

    ctx2 = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "search", "arguments": {"q": "hello world"}}},
        request_id="r2",
    )
    result2 = await mw(ctx2, handler)
    assert call_count == 1
    assert result1 == result2
