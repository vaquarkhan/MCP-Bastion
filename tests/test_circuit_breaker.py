"""Tests for circuit breaker."""

import pytest

from mcp_bastion.errors import CircuitBreakerOpenError
from mcp_bastion.pillars.circuit_breaker import CircuitBreaker


def test_circuit_breaker_closed_allows():
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0)
    cb.check("tool1")
    cb.check("tool1")


def test_circuit_breaker_opens_after_failures():
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0)
    cb.record_failure("tool1")
    cb.record_failure("tool1")
    cb.record_failure("tool1")

    with pytest.raises(CircuitBreakerOpenError) as exc:
        cb.check("tool1")
    assert "tool1" in str(exc.value)
    assert "Circuit open" in str(exc.value)


def test_circuit_breaker_success_resets_half_open():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
    cb.record_failure("t")
    cb.record_failure("t")
    with pytest.raises(CircuitBreakerOpenError):
        cb.check("t")

    import time
    time.sleep(0.15)
    cb.check("t")
    cb.record_success("t")
    cb.check("t")


def test_circuit_breaker_reset():
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=10.0)
    cb.record_failure("t")
    cb.record_failure("t")
    cb.record_failure("t")
    with pytest.raises(CircuitBreakerOpenError):
        cb.check("t")

    cb.reset("t")
    cb.check("t")


def test_circuit_breaker_reset_all():
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout=10.0)
    cb.record_failure("a")
    cb.record_failure("b")
    with pytest.raises(CircuitBreakerOpenError):
        cb.check("a")
    cb.reset()
    assert len(cb._circuits) == 0
    cb.check("a")
    cb.check("b")


def test_circuit_breaker_reset_none_clears_all():
    """Explicitly cover reset(None) branch (else: self._circuits.clear())."""
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=10.0)
    cb.record_failure("x")
    cb.record_failure("y")
    cb.reset(None)
    assert len(cb._circuits) == 0


def test_circuit_breaker_unknown_tool_default():
    cb = CircuitBreaker()
    cb.check("")
    cb.check(None)  # type: ignore[arg-type]


def test_circuit_breaker_open_raises_with_message():
    """Circuit breaker raises with retry-after message when open."""
    from mcp_bastion.errors import CircuitBreakerOpenError

    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=10.0)
    for _ in range(2):
        cb.record_failure("flaky")
    try:
        cb.check("flaky")
        pytest.fail("Expected CircuitBreakerOpenError")
    except CircuitBreakerOpenError as e:
        assert "Retry after" in str(e)


def test_circuit_breaker_reset_single_tool():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=10.0)
    cb.record_failure("a")
    cb.record_failure("a")
    with pytest.raises(CircuitBreakerOpenError):
        cb.check("a")
    cb.reset("a")
    cb.check("a")
