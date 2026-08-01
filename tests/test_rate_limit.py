"""Tests for rate limit pillar."""

import time
from unittest.mock import patch

import pytest

from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


def test_rate_limiter_cleanup_expired_session():
    """Expired session is cleaned up and allows fresh start."""
    limiter = TokenBucketRateLimiter(max_iterations=2, timeout_seconds=0.05)
    limiter.consume_iteration(session_id="s1")
    limiter.consume_iteration(session_id="s1")
    check = limiter.check_iteration(session_id="s1")
    assert not check.allowed
    time.sleep(0.1)
    check = limiter.check_iteration(session_id="s1")
    assert check.allowed


def test_rate_limiter_token_budget_exhausted():
    """Token budget exhausted blocks with token_budget violation."""
    limiter = TokenBucketRateLimiter(max_iterations=100, token_budget=10)
    for _ in range(2):
        check = limiter.check_iteration(session_id="s1")
        assert check.allowed
        limiter.consume_iteration(session_id="s1", tokens=5)
    check = limiter.check_iteration(session_id="s1")
    assert not check.allowed
    assert check.violation == "token_budget"
    assert "token" in (check.message or "").lower()


def test_rate_limiter_consume_with_tokens():
    """Consume iteration with token count."""
    limiter = TokenBucketRateLimiter(max_iterations=5, token_budget=100)
    limiter.consume_iteration(session_id="s1", tokens=50)
    check = limiter.check_iteration(session_id="s1")
    assert check.allowed


def test_rate_limiter_per_tool_cap():
    """Per-tool session cap blocks only the saturated tool."""
    limiter = TokenBucketRateLimiter(max_iterations=100, max_per_tool=2)
    for _ in range(2):
        check = limiter.check_iteration(session_id="s1", tool_name="search")
        assert check.allowed
        limiter.consume_iteration(session_id="s1", tool_name="search")
    check = limiter.check_iteration(session_id="s1", tool_name="search")
    assert not check.allowed
    assert check.violation == "per_tool"
    check_other = limiter.check_iteration(session_id="s1", tool_name="read_file")
    assert check_other.allowed


def test_rate_limiter_session_timeout_exceeded():
    """Session timeout exceeded when elapsed > timeout (mock _cleanup_expired)."""
    limiter = TokenBucketRateLimiter(max_iterations=10, timeout_seconds=60)
    limiter.consume_iteration(session_id="s1")
    with patch.object(limiter, "_cleanup_expired"):
        state = limiter._sessions["s1"]
        state.started_at = time.time() - 100
        check = limiter.check_iteration(session_id="s1")
        assert not check.allowed
        assert check.violation == "timeout"
        assert "timeout" in (check.message or "").lower()


def test_rate_limiter_reset_session():
    """Reset session clears state."""
    limiter = TokenBucketRateLimiter(max_iterations=2)
    limiter.consume_iteration(session_id="s1")
    limiter.consume_iteration(session_id="s1")
    check = limiter.check_iteration(session_id="s1")
    assert not check.allowed
    limiter.reset_session(session_id="s1")
    check = limiter.check_iteration(session_id="s1")
    assert check.allowed


def test_rate_limiter_redis_wall_clock_across_peers():
    """A-6: started_at is wall clock so Redis peers share a comparable clock."""
    from mcp_bastion.pillars.state_backend import MemoryStateBackend

    backend = MemoryStateBackend()
    a = TokenBucketRateLimiter(max_iterations=10, timeout_seconds=60, backend=backend)
    a.consume_iteration(session_id="shared")
    raw = backend.get_json("ratelimit:shared")
    assert raw is not None
    raw["started_at"] = time.time() - 120
    backend.set_json("ratelimit:shared", raw, ttl_seconds=60)
    b = TokenBucketRateLimiter(max_iterations=10, timeout_seconds=60, backend=backend)
    check = b.check_iteration(session_id="shared")
    assert check.allowed  # expired session cleaned → fresh
    for _ in range(10):
        assert b.check_and_consume(session_id="shared").allowed
    assert not b.check_and_consume(session_id="shared").allowed


def test_rate_limiter_check_and_consume_is_atomic():
    """A-7: check_and_consume increments under one lock."""
    limiter = TokenBucketRateLimiter(max_iterations=2)
    assert limiter.check_and_consume(session_id="s1").allowed
    assert limiter.check_and_consume(session_id="s1").allowed
    assert not limiter.check_and_consume(session_id="s1").allowed
    assert limiter._sessions["s1"].iterations == 2


def test_rate_limiter_rejects_negative_tokens():
    """Negative token usage must be rejected."""
    limiter = TokenBucketRateLimiter(max_iterations=5, token_budget=100)
    with pytest.raises(ValueError, match="tokens"):
        limiter.consume_iteration(session_id="s1", tokens=-1)


def test_rate_limiter_rejects_negative_max_per_tool():
    with pytest.raises(ValueError, match="max_per_tool"):
        TokenBucketRateLimiter(max_per_tool=-1)


def test_rate_limiter_add_tokens_and_compat_wrapper():
    """Post-call token accounting + RateLimiter compatibility shim."""
    from mcp_bastion.errors import RateLimitExceededError
    from mcp_bastion.pillars.rate_limit import RateLimiter
    from mcp_bastion.pillars.state_backend import MemoryStateBackend

    limiter = TokenBucketRateLimiter(max_iterations=5, token_budget=100)
    assert limiter.check_and_consume(session_id="t1", tokens=10).allowed
    limiter.add_tokens(session_id="t1", tokens=5)
    assert limiter._sessions["t1"].tokens_used == 15
    limiter.add_tokens(session_id="t1", tokens=0)
    with pytest.raises(ValueError, match="tokens"):
        limiter.add_tokens(session_id="t1", tokens=-1)
    with pytest.raises(ValueError, match="tokens"):
        limiter.check_and_consume(session_id="t1", tokens=-1)

    wrap = RateLimiter(max_requests=2, window_seconds=60, session_id="wrap")
    wrap.check()
    wrap.check()
    with pytest.raises(RateLimitExceededError):
        wrap.check()

    with pytest.raises(ValueError, match="max_iterations"):
        TokenBucketRateLimiter(max_iterations=0)
    with pytest.raises(ValueError, match="timeout_seconds"):
        TokenBucketRateLimiter(timeout_seconds=0)
    with pytest.raises(ValueError, match="token_budget"):
        TokenBucketRateLimiter(token_budget=0)

    backend = MemoryStateBackend()
    shared = TokenBucketRateLimiter(
        max_iterations=5, token_budget=100, timeout_seconds=60, backend=backend
    )
    assert shared.check_and_consume(session_id="sb", tokens=1, tool_name="t").allowed
    shared.add_tokens(session_id="sb", tokens=3)
    raw = backend.get_json("ratelimit:sb")
    assert raw is not None
    assert raw["tokens_used"] == 4
    # Expired shared session is reset inside check_and_consume
    raw["started_at"] = time.time() - 120
    backend.set_json("ratelimit:sb", raw, ttl_seconds=60)
    assert shared.check_and_consume(session_id="sb").allowed
