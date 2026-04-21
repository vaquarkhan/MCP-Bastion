"""Tests for v2 middleware (circuit breaker, content filter, RBAC, schema, replay, cost, cache)."""

import pytest

from mcp_bastion.base import MiddlewareContext, compose_middleware
from mcp_bastion.errors import (
    ContentFilterError,
    CostBudgetExceededError,
    ExternalPolicyDeniedError,
    RBACError,
    RateLimitExceededError,
    ReplayAttackError,
    SemanticFirewallError,
    SensitiveContentError,
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
from mcp_bastion.pillars.metrics import MetricsStore
from mcp_bastion.pillars.semantic_cache import SemanticCache
from mcp_bastion.pillars.semantic_firewall import SemanticFirewall
from mcp_bastion.pillars.sensitive_classifier import SensitiveContentClassifier


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


@pytest.mark.asyncio
async def test_semantic_firewall_blocks_mismatch():
    sf = SemanticFirewall()
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        semantic_firewall=sf,
        enable_semantic_firewall=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "get_weather", "arguments": {"city": "'; DROP TABLE"}}},
        request_id="r1",
        session_id="s1",
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(SemanticFirewallError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_shadow_mode_records_would_block_without_raising():
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=1),
        shadow_mode=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=True,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": {}}},
        request_id="r1",
        session_id="s1",
    )

    async def handler(c):
        return {"ok": True}

    await mw(ctx, handler)
    result = await mw(ctx, handler)
    assert result == {"ok": True}
    assert any(x.get("pillar") == "rate_limit" for x in ctx.metadata.get("shadow_blocked", []))


@pytest.mark.asyncio
async def test_external_policy_denies():
    class DenyPolicy:
        def evaluate(self, input_obj):
            return False, "external_policy: OPA denied"

    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        external_policy=DenyPolicy(),
        enable_prompt_guard=False,
        enable_external_policy=True,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "read", "arguments": {}}},
        request_id="r1",
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(ExternalPolicyDeniedError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_cost_attribution_from_llm_tokens():
    store = MetricsStore.get()
    store.reset()
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        enable_prompt_guard=False,
        enable_rate_limit=False,
        enable_cost_attribution=True,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "read", "arguments": {}}},
        request_id="r1",
        session_id="user-a",
    )
    ctx.metadata["llm_provider"] = "openai"
    ctx.metadata["llm_model"] = "gpt-4o-mini"
    ctx.metadata["llm_input_tokens"] = 1_000_000
    ctx.metadata["llm_output_tokens"] = 0

    async def handler(c):
        return {"ok": True}

    await mw(ctx, handler)
    m = store.get_metrics()
    assert m["cost_total"] == pytest.approx(0.15, rel=1e-5)
    assert m["cost_attribution"]["by_provider"].get("openai") == pytest.approx(0.15, rel=1e-5)


@pytest.mark.asyncio
async def test_sensitive_classifier_blocks():
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        sensitive_classifier=SensitiveContentClassifier(threshold=0.2),
        enable_prompt_guard=False,
        enable_rate_limit=False,
        enable_sensitive_classifier=True,
    )
    ctx = MiddlewareContext(
        message={
            "method": "tools/call",
            "params": {"name": "chat", "arguments": {"text": "Confidential merger and acquisition roadmap"}},
        },
        request_id="r-sensitive",
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(SensitiveContentError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_tenant_id_resolved_from_session_and_written_to_metadata():
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        enable_prompt_guard=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": {}}},
        request_id="r-tenant",
        session_id="tenant:acme|s-1",
    )

    async def handler(c):
        return {"ok": True}

    await mw(ctx, handler)
    assert ctx.metadata.get("tenant_id") == "acme"
