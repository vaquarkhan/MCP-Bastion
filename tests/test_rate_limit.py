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
    allowed, _ = limiter.check_iteration(session_id="s1")
    assert not allowed
    time.sleep(0.1)
    allowed, err = limiter.check_iteration(session_id="s1")
    assert allowed


def test_rate_limiter_token_budget_exhausted():
    """Token budget exhausted blocks."""
    limiter = TokenBucketRateLimiter(max_iterations=100, token_budget=10)
    for _ in range(2):
        allowed, _ = limiter.check_iteration(session_id="s1")
        assert allowed
        limiter.consume_iteration(session_id="s1", tokens=5)
    allowed, err = limiter.check_iteration(session_id="s1")
    assert not allowed
    assert "token" in (err or "").lower()


def test_rate_limiter_consume_with_tokens():
    """Consume iteration with token count."""
    limiter = TokenBucketRateLimiter(max_iterations=5, token_budget=100)
    limiter.consume_iteration(session_id="s1", tokens=50)
    allowed, _ = limiter.check_iteration(session_id="s1")
    assert allowed


def test_rate_limiter_session_timeout_exceeded():
    """Session timeout exceeded when elapsed > timeout (mock _cleanup_expired)."""
    limiter = TokenBucketRateLimiter(max_iterations=10, timeout_seconds=60)
    limiter.consume_iteration(session_id="s1")
    with patch.object(limiter, "_cleanup_expired"):
        state = limiter._sessions["s1"]
        state.started_at = time.monotonic() - 100
        allowed, err = limiter.check_iteration(session_id="s1")
        assert not allowed
        assert "timeout" in (err or "").lower()


def test_rate_limiter_reset_session():
    """Reset session clears state."""
    limiter = TokenBucketRateLimiter(max_iterations=2)
    limiter.consume_iteration(session_id="s1")
    limiter.consume_iteration(session_id="s1")
    allowed, _ = limiter.check_iteration(session_id="s1")
    assert not allowed
    limiter.reset_session(session_id="s1")
    allowed, _ = limiter.check_iteration(session_id="s1")
    assert allowed


def test_rate_limiter_rejects_negative_tokens():
    """Negative token usage must be rejected."""
    limiter = TokenBucketRateLimiter(max_iterations=5, token_budget=100)
    with pytest.raises(ValueError, match="tokens"):
        limiter.consume_iteration(session_id="s1", tokens=-1)
