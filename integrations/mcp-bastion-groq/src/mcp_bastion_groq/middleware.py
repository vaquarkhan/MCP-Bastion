"""Groq client wrapper with MCP-Bastion security."""
from __future__ import annotations
from typing import Any
from groq import Groq
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter


class SecureGroq:
    """Drop-in wrapper around Groq with MCP-Bastion security.

    Usage::

        from mcp_bastion_groq import SecureGroq
        client = SecureGroq()
        print(client.chat("What is MCP?"))
    """

    def __init__(self, api_key: str | None = None, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._client = Groq(api_key=api_key)
        self._filter = ContentFilter()
        self._limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def chat(self, prompt: str, model: str = "llama3-8b-8192", **kwargs: Any) -> str:
        self._limiter.check()
        self._filter.scan(prompt)
        response = self._client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            **kwargs,
        )
        return response.choices[0].message.content or ""
