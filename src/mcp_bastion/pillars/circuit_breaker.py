"""
Circuit breaker pattern for MCP-Bastion.

Auto-disable failing tools after N failures. Fail fast when external APIs are down.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CircuitState:
    """Per-tool circuit state."""

    failures: int = 0
    last_failure_at: float = 0.0
    state: str = "closed"  # closed | open | half_open


from mcp_bastion.errors import CircuitBreakerOpenError as _CircuitBreakerOpenError


def _make_circuit_error(tool: str, message: str) -> _CircuitBreakerOpenError:
    return _CircuitBreakerOpenError(f"{tool}: {message}")


class CircuitBreaker:
    """
    Circuit breaker per tool. Opens after failure_threshold failures.
    Waits recovery_timeout before allowing retry (half-open).
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if recovery_timeout <= 0:
            raise ValueError("recovery_timeout must be > 0")
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self._circuits: dict[str, CircuitState] = defaultdict(CircuitState)
        self._lock = threading.Lock()

    def _get_tool_key(self, tool: str) -> str:
        return tool or "default"

    def record_success(self, tool: str) -> None:
        """Record successful call. Reset circuit if half-open."""
        key = self._get_tool_key(tool)
        with self._lock:
            state = self._circuits[key]
            if state.state == "half_open":
                state.state = "closed"
                state.failures = 0
                logger.info("circuit_breaker closed tool=%s", tool)

    def record_failure(self, tool: str) -> None:
        """Record failed call. Open circuit if threshold reached."""
        key = self._get_tool_key(tool)
        with self._lock:
            state = self._circuits[key]
            state.failures += 1
            state.last_failure_at = time.monotonic()

            if state.failures >= self.failure_threshold:
                state.state = "open"
                logger.warning(
                    "circuit_breaker open tool=%s failures=%d",
                    tool,
                    state.failures,
                )

    def check(self, tool: str) -> None:
        """
        Check if request is allowed. Raises CircuitBreakerOpenError if open.
        """
        key = self._get_tool_key(tool)
        with self._lock:
            state = self._circuits[key]

            if state.state == "closed":
                return

            if state.state == "open":
                elapsed = time.monotonic() - state.last_failure_at
                if elapsed >= self.recovery_timeout:
                    state.state = "half_open"
                    logger.info("circuit_breaker half_open tool=%s", tool)
                    return
                raise _make_circuit_error(
                    tool,
                    f"Circuit open. Retry after {self.recovery_timeout - elapsed:.0f}s",
                )

            if state.state == "half_open":
                return

    def reset(self, tool: str | None = None) -> None:
        """Reset circuit(s). If tool is None, reset all."""
        with self._lock:
            if tool:
                key = self._get_tool_key(tool)
                if key in self._circuits:
                    del self._circuits[key]
            else:
                self._circuits.clear()
