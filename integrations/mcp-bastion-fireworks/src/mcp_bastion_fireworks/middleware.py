"""Fireworks AI client wrapper with MCP-Bastion security."""
from __future__ import annotations
from typing import Any
import fireworks.client
from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


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
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "fireworks-default"

    def chat(self, prompt: str, model: str = "accounts/fireworks/models/llama-v3p1-8b-instruct", **kwargs: Any) -> str:
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(prompt)
        response = fireworks.client.ChatCompletion.create(
            model=model, messages=[{"role": "user", "content": prompt}], **kwargs)
        self._limiter.consume_iteration(session_id=self._session)
        return response.choices[0].message.content or ""
