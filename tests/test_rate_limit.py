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
        state.started_at = time.monotonic() - 100
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


def test_rate_limiter_rejects_negative_tokens():
    """Negative token usage must be rejected."""
    limiter = TokenBucketRateLimiter(max_iterations=5, token_budget=100)
    with pytest.raises(ValueError, match="tokens"):
        limiter.consume_iteration(session_id="s1", tokens=-1)


def test_rate_limiter_rejects_negative_max_per_tool():
    with pytest.raises(ValueError, match="max_per_tool"):
        TokenBucketRateLimiter(max_per_tool=-1)
