"""AutoGen / agent-message guard with MCP-Bastion security."""
from __future__ import annotations
from typing import Any

from mcp_bastion.errors import PromptInjectionError, RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureAutoGen:
    """Scan agent / tool messages before they reach AutoGen handlers.

    Usage::

        from mcp_bastion_autogen import SecureAutoGen
        guard = SecureAutoGen()
        guard.check_message("user text or tool output")
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._prompt_guard = PromptGuardEngine(fail_open=True, heuristic_fallback=True)
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "autogen-default"

    def check_message(self, text: str) -> None:
        """Raise if rate-limited, content-filtered, or injection heuristics match."""
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(text)
        if self._prompt_guard.is_malicious(text):
            raise PromptInjectionError("Request blocked: suspected prompt injection")
        self._limiter.consume_iteration(session_id=self._session)

    def wrap_callable(self, fn: Any) -> Any:
        """Return a wrapper that scans the first string arg then calls ``fn``."""

        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            for a in args:
                if isinstance(a, str) and a.strip():
                    self.check_message(a)
                    break
            return fn(*args, **kwargs)

        return _wrapped
