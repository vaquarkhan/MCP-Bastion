"""LangGraph node / message guard with MCP-Bastion security."""
from __future__ import annotations
from typing import Any, Callable

from mcp_bastion.errors import PromptInjectionError, RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class BastionGraphGuard:
    """Scan text flowing through LangGraph nodes before tools / LLM hops."""

    def __init__(self, max_requests: int = 120, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._prompt_guard = PromptGuardEngine(fail_open=True, heuristic_fallback=True)
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "langgraph-default"

    def check_text(self, text: str) -> None:
        if not text or not str(text).strip():
            return
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(text)
        if self._prompt_guard.is_malicious(text):
            raise PromptInjectionError("Request blocked: suspected prompt injection")
        self._limiter.consume_iteration(session_id=self._session)

    def check_state(self, state: Any, keys: tuple[str, ...] = ("query", "input", "messages")) -> None:
        if not isinstance(state, dict):
            return
        for key in keys:
            val = state.get(key)
            if isinstance(val, str):
                self.check_text(val)
            elif isinstance(val, list):
                for item in val[-3:]:
                    content = getattr(item, "content", None)
                    if isinstance(content, str):
                        self.check_text(content)
                    elif isinstance(item, dict) and isinstance(item.get("content"), str):
                        self.check_text(item["content"])


_default_guard = BastionGraphGuard()


def secure_node(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator: scan string args / common state keys, then call the node."""

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        for a in args:
            if isinstance(a, str):
                _default_guard.check_text(a)
            elif isinstance(a, dict):
                _default_guard.check_state(a)
        for v in kwargs.values():
            if isinstance(v, str):
                _default_guard.check_text(v)
            elif isinstance(v, dict):
                _default_guard.check_state(v)
        return fn(*args, **kwargs)

    wrapper.__name__ = getattr(fn, "__name__", "secure_node")
    wrapper.__doc__ = fn.__doc__
    return wrapper
