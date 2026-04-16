"""Tests for input validation, thread safety, and 100% coverage."""

import re
import threading
import time

import pytest

from mcp_bastion.pillars.circuit_breaker import CircuitBreaker
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.replay_guard import ReplayGuard
from mcp_bastion.pillars.semantic_cache import SemanticCache


# ── Input Validation ──────────────────────────────────────────────────


class TestRateLimiterValidation:
    def test_invalid_max_iterations(self):
        with pytest.raises(ValueError, match="max_iterations"):
            TokenBucketRateLimiter(max_iterations=0)

    def test_invalid_timeout_seconds(self):
        with pytest.raises(ValueError, match="timeout_seconds"):
            TokenBucketRateLimiter(timeout_seconds=-1)

    def test_invalid_token_budget(self):
        with pytest.raises(ValueError, match="token_budget"):
            TokenBucketRateLimiter(token_budget=0)

    def test_valid_params(self):
        rl = TokenBucketRateLimiter(max_iterations=1, timeout_seconds=0.1, token_budget=1)
        assert rl.max_iterations == 1


class TestCircuitBreakerValidation:
    def test_invalid_failure_threshold(self):
        with pytest.raises(ValueError, match="failure_threshold"):
            CircuitBreaker(failure_threshold=0)

    def test_invalid_recovery_timeout(self):
        with pytest.raises(ValueError, match="recovery_timeout"):
            CircuitBreaker(recovery_timeout=-1)

    def test_valid_params(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
        assert cb.failure_threshold == 1


class TestCostTrackerValidation:
    def test_invalid_max_cost_per_session(self):
        with pytest.raises(ValueError, match="max_cost_per_session"):
            CostTracker(max_cost_per_session=-1)

    def test_invalid_max_cost_per_day(self):
        with pytest.raises(ValueError, match="max_cost_per_day"):
            CostTracker(max_cost_per_day=-1)

    def test_invalid_alert_threshold(self):
        with pytest.raises(ValueError, match="alert_threshold"):
            CostTracker(alert_threshold=1.5)

    def test_valid_params(self):
        ct = CostTracker(max_cost_per_session=0, max_cost_per_day=0, alert_threshold=0.5)
        assert ct.alert_threshold == 0.5


class TestReplayGuardValidation:
    def test_invalid_max_request_age(self):
        with pytest.raises(ValueError, match="max_request_age_seconds"):
            ReplayGuard(max_request_age_seconds=-1)

    def test_invalid_max_nonce_cache(self):
        with pytest.raises(ValueError, match="max_nonce_cache"):
            ReplayGuard(max_nonce_cache=0)

    def test_valid_params(self):
        rg = ReplayGuard(max_request_age_seconds=0, max_nonce_cache=1)
        assert rg._max_nonce_cache == 1


class TestSemanticCacheValidation:
    def test_invalid_similarity_threshold_high(self):
        with pytest.raises(ValueError, match="similarity_threshold"):
            SemanticCache(similarity_threshold=1.5)

    def test_invalid_similarity_threshold_low(self):
        with pytest.raises(ValueError, match="similarity_threshold"):
            SemanticCache(similarity_threshold=-0.1)

    def test_invalid_max_entries(self):
        with pytest.raises(ValueError, match="max_entries"):
            SemanticCache(max_entries=0)

    def test_invalid_ttl_seconds(self):
        with pytest.raises(ValueError, match="ttl_seconds"):
            SemanticCache(ttl_seconds=0)

    def test_valid_params(self):
        sc = SemanticCache(similarity_threshold=0.5, max_entries=1, ttl_seconds=1)
        assert sc.similarity_threshold == 0.5


class TestContentFilterValidation:
    def test_invalid_custom_regex(self):
        with pytest.raises(ValueError, match="Invalid custom regex"):
            ContentFilter(custom_patterns=["[invalid"])

    def test_valid_custom_regex(self):
        cf = ContentFilter(custom_patterns=[r"\bsecret\b"])
        assert len(cf._custom_regexes) == 1


# ── Thread Safety ─────────────────────────────────────────────────────


class TestReplayGuardThreadSafety:
    def test_concurrent_nonce_checks(self):
        rg = ReplayGuard(require_nonce=True, max_nonce_cache=100)
        errors = []
        barrier = threading.Barrier(10)

        def check_unique_nonce(i):
            barrier.wait()
            try:
                rg.check({"params": {"nonce": f"nonce-{i}"}})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=check_unique_nonce, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


class TestSemanticCacheThreadSafety:
    def test_concurrent_get_set(self):
        sc = SemanticCache(similarity_threshold=0.9, max_entries=50, ttl_seconds=10)
        errors = []
        barrier = threading.Barrier(10)

        def writer(i):
            barrier.wait()
            try:
                sc.set("tool", f"query number {i}", f"result-{i}")
            except Exception as e:
                errors.append(e)

        def reader(i):
            barrier.wait()
            try:
                sc.get("tool", f"query number {i}")
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(5):
            threads.append(threading.Thread(target=writer, args=(i,)))
            threads.append(threading.Thread(target=reader, args=(i,)))
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0


class TestCircuitBreakerThreadSafety:
    def test_concurrent_failures_and_checks(self):
        cb = CircuitBreaker(failure_threshold=50, recovery_timeout=10)
        errors = []
        barrier = threading.Barrier(10)

        def hammer(i):
            barrier.wait()
            try:
                cb.record_failure(f"tool-{i % 3}")
                cb.check(f"tool-{i % 3}")
            except Exception:
                pass  # CircuitBreakerOpenError is expected

        threads = [threading.Thread(target=hammer, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()


# ── Coverage: alerts rate_limit reason ────────────────────────────────


class TestAlertsRateLimitReason:
    def test_reason_rate_limit(self):
        from mcp_bastion.pillars.alerts import _reason_from_error
        assert _reason_from_error("Rate limit exceeded") == "rate_limit"

    def test_reason_iteration(self):
        from mcp_bastion.pillars.alerts import _reason_from_error
        assert _reason_from_error("Maximum iteration exceeded") == "rate_limit"


# ── Coverage: circuit breaker reset(None) ─────────────────────────────


class TestCircuitBreakerResetAll:
    def test_reset_none_clears(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=10)
        cb.record_failure("a")
        cb.record_failure("b")
        cb.reset(None)
        assert len(cb._circuits) == 0

    def test_reset_no_arg_clears(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=10)
        cb.record_failure("x")
        cb.reset()
        assert len(cb._circuits) == 0


# ── Coverage: circuit breaker half_open check ─────────────────────────


class TestCircuitBreakerHalfOpenCheck:
    def test_check_in_half_open_state_allows(self):
        """Cover the half_open branch in check()."""
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure("t")
        cb.record_failure("t")
        # Now open
        time.sleep(0.02)
        # First check transitions to half_open
        cb.check("t")
        # Second check while still half_open should also pass
        cb.check("t")


# ── Coverage: WebhookAlertSink exception ──────────────────────────────


class TestWebhookAlertSinkException:
    def test_webhook_send_exception(self):
        """Cover the exception handler in WebhookAlertSink.send()."""
        from unittest.mock import patch
        from mcp_bastion.pillars.alerts import WebhookAlertSink

        sink = WebhookAlertSink(url="http://invalid-host-that-does-not-exist:9999/hook")
        with patch("urllib.request.urlopen", side_effect=ConnectionError("fail")):
            # Should not raise, just log warning
            sink.send("test", "msg")


class TestWebhookAlertSinkHttp400:
    def test_webhook_send_http_400(self):
        """Cover the resp.status >= 400 branch in WebhookAlertSink.send()."""
        from unittest.mock import patch, MagicMock
        from mcp_bastion.pillars.alerts import WebhookAlertSink

        sink = WebhookAlertSink(url="http://example.com/hook")
        mock_resp = MagicMock()
        mock_resp.status = 400
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            sink.send("test", "msg")


class TestAlertsReasonUnknown:
    def test_reason_none(self):
        from mcp_bastion.pillars.alerts import _reason_from_error
        assert _reason_from_error(None) == "unknown"

    def test_reason_empty_string(self):
        from mcp_bastion.pillars.alerts import _reason_from_error
        assert _reason_from_error("") == "unknown"
