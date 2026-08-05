"""OpenAI Agents SDK message / tool guard with MCP-Bastion security."""
from __future__ import annotations
from typing import Any, Callable

from mcp_bastion.errors import PromptInjectionError, RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureOpenAIAgents:
    """Scan agent / tool messages for the OpenAI Agents SDK."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._prompt_guard = PromptGuardEngine(fail_open=True, heuristic_fallback=True)
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "openai-agents-default"

    def check_message(self, text: str) -> None:
        if not text or not str(text).strip():
            return
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(text)
        if self._prompt_guard.is_malicious(text):
            raise PromptInjectionError("Request blocked: suspected prompt injection")
        self._limiter.consume_iteration(session_id=self._session)


_default = SecureOpenAIAgents()


def secure_tool(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator: scan string tool args, then call the tool function."""

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        for a in args:
            if isinstance(a, str):
                _default.check_message(a)
        for v in kwargs.values():
            if isinstance(v, str):
                _default.check_message(v)
        return fn(*args, **kwargs)

    wrapper.__name__ = getattr(fn, "__name__", "secure_tool")
    wrapper.__doc__ = fn.__doc__
    return wrapper
