"""LiteLLM wrapper with MCP-Bastion security."""
from __future__ import annotations
from typing import Any

import litellm

from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureLiteLLM:
    """Drop-in LiteLLM completion wrapper with MCP-Bastion security.

    Usage::

        from mcp_bastion_litellm import SecureLiteLLM
        client = SecureLiteLLM()
        print(client.chat("What is MCP?", model="gpt-4o-mini"))
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "litellm-default"

    def chat(self, prompt: str, model: str = "gpt-4o-mini", **kwargs: Any) -> str:
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(prompt)
        response = litellm.completion(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            **kwargs,
        )
        self._limiter.consume_iteration(session_id=self._session)
        choice = response.choices[0]
        msg = getattr(choice, "message", None) or choice.get("message", {})
        content = (
            getattr(msg, "content", None)
            if not isinstance(msg, dict)
            else msg.get("content")
        )
        return content or ""
