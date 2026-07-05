"""
Rate limiting: token bucket per session.

Max 15 iterations, 60s timeout, optional token budget (50k default), optional per-tool caps.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal

logger = logging.getLogger(__name__)

DEFAULT_MAX_ITERATIONS = 15
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_TOKEN_BUDGET = 50_000

RateLimitViolation = Literal["ok", "timeout", "iterations", "token_budget", "per_tool"]


@dataclass(frozen=True)
class RateLimitCheckResult:
    allowed: bool
    message: str | None = None
    violation: RateLimitViolation = "ok"


@dataclass
class SessionState:
    """Per-session rate limit state."""

    iterations: int = 0
    started_at: float = field(default_factory=time.monotonic)
    tokens_used: int = 0
    tool_iterations: dict[str, int] = field(default_factory=dict)


class TokenBucketRateLimiter:
    """Token bucket per session. Iteration cap, timeout, token budget, per-tool caps."""

    def __init__(
        self,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        token_budget: int = DEFAULT_TOKEN_BUDGET,
        max_per_tool: int = 0,
    ) -> None:
        if max_iterations < 1:
            raise ValueError("max_iterations must be >= 1")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be > 0")
        if token_budget < 1:
            raise ValueError("token_budget must be >= 1")
        if max_per_tool < 0:
            raise ValueError("max_per_tool must be >= 0")
        self.max_iterations = max_iterations
        self.timeout_seconds = timeout_seconds
        self.token_budget = token_budget
        self.max_per_tool = max_per_tool
        self._sessions: dict[str, SessionState] = defaultdict(SessionState)
        self._lock = threading.Lock()

    def _get_session_id(self, request_id: str | None, session_id: str | None) -> str:
        """Resolve session key from request or session ID."""
        return session_id or request_id or "default"

    def _cleanup_expired(self, session_key: str) -> None:
        """Remove session if it has exceeded the global timeout."""
        state = self._sessions.get(session_key)
        if state is None:
            return
        elapsed = time.monotonic() - state.started_at
        if elapsed > self.timeout_seconds:
            del self._sessions[session_key]

    def check_iteration(
        self,
        request_id: str | None = None,
        session_id: str | None = None,
        tool_name: str | None = None,
    ) -> RateLimitCheckResult:
        """
        Check if another iteration is allowed.

        Returns RateLimitCheckResult with violation kind when blocked.
        """
        key = self._get_session_id(request_id, session_id)
        with self._lock:
            self._cleanup_expired(key)

            state = self._sessions[key]
            elapsed = time.monotonic() - state.started_at

            if elapsed > self.timeout_seconds:
                del self._sessions[key]
                return RateLimitCheckResult(
                    False,
                    "Session timeout exceeded (60s limit)",
                    "timeout",
                )

            if state.iterations >= self.max_iterations:
                return RateLimitCheckResult(
                    False,
                    f"Maximum iterations exceeded ({self.max_iterations} limit)",
                    "iterations",
                )

            if state.tokens_used >= self.token_budget:
                return RateLimitCheckResult(
                    False,
                    f"Token budget exhausted ({self.token_budget} limit)",
                    "token_budget",
                )

            if self.max_per_tool > 0 and tool_name:
                tool_key = str(tool_name)
                if state.tool_iterations.get(tool_key, 0) >= self.max_per_tool:
                    return RateLimitCheckResult(
                        False,
                        f"Per-tool call limit exceeded for {tool_key!r} ({self.max_per_tool} limit)",
                        "per_tool",
                    )

            return RateLimitCheckResult(True, None, "ok")

    def consume_iteration(
        self,
        request_id: str | None = None,
        session_id: str | None = None,
        tokens: int = 0,
        tool_name: str | None = None,
    ) -> None:
        """Record one iteration and optional token consumption."""
        if tokens < 0:
            raise ValueError("tokens must be >= 0")
        key = self._get_session_id(request_id, session_id)
        with self._lock:
            state = self._sessions[key]
            state.iterations += 1
            state.tokens_used += tokens
            if tool_name:
                tool_key = str(tool_name)
                state.tool_iterations[tool_key] = state.tool_iterations.get(tool_key, 0) + 1

    def reset_session(
        self,
        request_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Reset session state (e.g., on new request)."""
        key = self._get_session_id(request_id, session_id)
        with self._lock:
            if key in self._sessions:
                del self._sessions[key]
