"""OpenAI client wrapper with MCP-Bastion security."""

from __future__ import annotations

from typing import Any

import openai

from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureOpenAI:
    """Drop-in wrapper around ``openai.OpenAI`` that applies MCP-Bastion checks.

    Usage::

        from mcp_bastion_openai import SecureOpenAI

        client = SecureOpenAI()  # uses OPENAI_API_KEY from env
        response = client.chat("What is MCP?")
    """

    def __init__(
        self,
        api_key: str | None = None,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        self._client = openai.OpenAI(api_key=api_key)
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "openai-default"

    def chat(
        self,
        prompt: str,
        model: str = "gpt-4o",
        **kwargs: Any,
    ) -> str:
        """Send a chat completion with security scanning."""
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(prompt)
        response = self._client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            **kwargs,
        )
        self._limiter.consume_iteration(session_id=self._session)
        return response.choices[0].message.content or ""
