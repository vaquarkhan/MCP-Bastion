"""
Rate limiting: token bucket per session.

Max 15 iterations, 60s timeout, optional token budget (50k default), optional per-tool caps.
Supports pluggable StateBackend (Redis) for multi-replica deployments.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Literal

from mcp_bastion.pillars.state_backend import MemoryStateBackend, StateBackend

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

    def to_dict(self) -> dict:
        return {
            "iterations": self.iterations,
            "started_at": self.started_at,
            "tokens_used": self.tokens_used,
            "tool_iterations": dict(self.tool_iterations),
        }

    @classmethod
    def from_dict(cls, data: dict) -> SessionState:
        return cls(
            iterations=int(data.get("iterations", 0)),
            started_at=float(data.get("started_at", time.monotonic())),
            tokens_used=int(data.get("tokens_used", 0)),
            tool_iterations={
                str(k): int(v) for k, v in (data.get("tool_iterations") or {}).items()
            },
        )


class TokenBucketRateLimiter:
    """Token bucket per session. Iteration cap, timeout, token budget, per-tool caps."""

    def __init__(
        self,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        token_budget: int = DEFAULT_TOKEN_BUDGET,
        max_per_tool: int = 0,
        *,
        backend: StateBackend | None = None,
        backend_namespace: str = "ratelimit",
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
        self._backend = backend or MemoryStateBackend()
        self._backend_namespace = backend_namespace
        self._sessions: dict[str, SessionState] = defaultdict(SessionState)
        self._lock = threading.Lock()
        self._uses_shared_backend = backend is not None

    def _storage_key(self, session_key: str) -> str:
        return f"{self._backend_namespace}:{session_key}"

    def _get_session_id(self, request_id: str | None, session_id: str | None) -> str:
        """Resolve session key from request or session ID."""
        return session_id or request_id or "default"

    def _load_state(self, session_key: str) -> SessionState:
        if not self._uses_shared_backend:
            with self._lock:
                return self._sessions[session_key]
        raw = self._backend.get_json(self._storage_key(session_key))
        if raw:
            return SessionState.from_dict(raw)
        return SessionState()

    def _save_state(self, session_key: str, state: SessionState) -> None:
        if not self._uses_shared_backend:
            with self._lock:
                self._sessions[session_key] = state
            return
        self._backend.set_json(
            self._storage_key(session_key),
            state.to_dict(),
            ttl_seconds=self.timeout_seconds,
        )

    def _delete_state(self, session_key: str) -> None:
        if not self._uses_shared_backend:
            with self._lock:
                self._sessions.pop(session_key, None)
            return
        self._backend.delete(self._storage_key(session_key))

    def _cleanup_expired(self, session_key: str) -> None:
        state = self._load_state(session_key)
        elapsed = time.monotonic() - state.started_at
        if elapsed > self.timeout_seconds:
            self._delete_state(session_key)

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
        self._cleanup_expired(key)

        state = self._load_state(key)
        elapsed = time.monotonic() - state.started_at

        if elapsed > self.timeout_seconds:
            self._delete_state(key)
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
        if self._uses_shared_backend:
            with self._lock:
                state = self._load_state(key)
                state.iterations += 1
                state.tokens_used += tokens
                if tool_name:
                    tool_key = str(tool_name)
                    state.tool_iterations[tool_key] = state.tool_iterations.get(tool_key, 0) + 1
                self._save_state(key, state)
            return
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
        self._delete_state(key)


class RateLimiter:
    """Compatibility wrapper for framework integrations (pre-4.0 API).

    Older packages imported ``RateLimiter(max_requests=…, window_seconds=…)`` and
    called ``.check()``. Map that onto :class:`TokenBucketRateLimiter`.
    """

    def __init__(
        self,
        max_requests: int = 60,
        window_seconds: float = 60,
        *,
        session_id: str = "integration-default",
        backend: StateBackend | None = None,
    ) -> None:
        self._session_id = session_id
        self._inner = TokenBucketRateLimiter(
            max_iterations=max(1, int(max_requests)),
            timeout_seconds=float(window_seconds) if float(window_seconds) > 0 else 60.0,
            backend=backend,
        )

    def check(self, *, tool_name: str | None = None) -> None:
        """Raise :class:`RateLimitExceededError` when the iteration cap is hit."""
        from mcp_bastion.errors import RateLimitExceededError

        result = self._inner.check_iteration(
            session_id=self._session_id,
            tool_name=tool_name,
        )
        if not result.allowed:
            raise RateLimitExceededError(result.message or "Rate limit exceeded")
        self._inner.consume_iteration(session_id=self._session_id, tool_name=tool_name)
