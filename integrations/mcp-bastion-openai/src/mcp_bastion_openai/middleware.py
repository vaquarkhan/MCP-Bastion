"""OpenAI client wrapper with MCP-Bastion security."""

from __future__ import annotations

from typing import Any

import openai

from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter


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
        self._limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def chat(
        self,
        prompt: str,
        model: str = "gpt-4o",
        **kwargs: Any,
    ) -> str:
        """Send a chat completion with security scanning."""
        self._limiter.check()
        self._filter.scan(prompt)
        response = self._client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            **kwargs,
        )
        return response.choices[0].message.content or ""
