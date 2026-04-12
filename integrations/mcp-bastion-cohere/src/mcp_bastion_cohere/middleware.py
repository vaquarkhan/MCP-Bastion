"""Cohere client wrapper with MCP-Bastion security."""
from __future__ import annotations
from typing import Any
import cohere
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter


class SecureCohere:
    """Drop-in wrapper around Cohere with MCP-Bastion security.

    Usage::

        from mcp_bastion_cohere import SecureCohere
        client = SecureCohere(api_key="YOUR_KEY")
        print(client.chat("What is MCP?"))
    """

    def __init__(self, api_key: str, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._client = cohere.ClientV2(api_key=api_key)
        self._filter = ContentFilter()
        self._limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def chat(self, prompt: str, model: str = "command-r-plus", **kwargs: Any) -> str:
        self._limiter.check()
        self._filter.scan(prompt)
        response = self._client.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            **kwargs,
        )
        return response.message.content[0].text
