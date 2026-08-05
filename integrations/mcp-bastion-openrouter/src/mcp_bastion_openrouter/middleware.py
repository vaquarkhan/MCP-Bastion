"""OpenRouter client wrapper with MCP-Bastion security."""
from __future__ import annotations
import os
from typing import Any

from openai import OpenAI

from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureOpenRouter:
    """Drop-in wrapper around OpenRouter with MCP-Bastion security.

    Usage::

        from mcp_bastion_openrouter import SecureOpenRouter
        client = SecureOpenRouter()
        print(client.chat("What is MCP?"))
    """

    def __init__(
        self,
        api_key: str | None = None,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        key = api_key or os.environ.get("OPENROUTER_API_KEY")
        self._client = OpenAI(api_key=key, base_url="https://openrouter.ai/api/v1")
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "openrouter-default"

    def chat(self, prompt: str, model: str = "openai/gpt-4o-mini", **kwargs: Any) -> str:
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(prompt)
        response = self._client.chat.completions.create(
            model=model, messages=[{"role": "user", "content": prompt}], **kwargs
        )
        self._limiter.consume_iteration(session_id=self._session)
        return response.choices[0].message.content or ""
