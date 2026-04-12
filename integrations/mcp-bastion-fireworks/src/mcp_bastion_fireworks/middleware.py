"""Fireworks AI client wrapper with MCP-Bastion security."""
from __future__ import annotations
from typing import Any
import fireworks.client
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter


class SecureFireworks:
    """Drop-in wrapper around Fireworks AI with MCP-Bastion security.

    Usage::

        from mcp_bastion_fireworks import SecureFireworks
        client = SecureFireworks(api_key="YOUR_KEY")
        print(client.chat("What is MCP?"))
    """

    def __init__(self, api_key: str, max_requests: int = 60, window_seconds: int = 60) -> None:
        fireworks.client.api_key = api_key
        self._filter = ContentFilter()
        self._limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def chat(self, prompt: str, model: str = "accounts/fireworks/models/llama-v3p1-8b-instruct", **kwargs: Any) -> str:
        self._limiter.check()
        self._filter.scan(prompt)
        response = fireworks.client.ChatCompletion.create(
            model=model, messages=[{"role": "user", "content": prompt}], **kwargs)
        return response.choices[0].message.content or ""
