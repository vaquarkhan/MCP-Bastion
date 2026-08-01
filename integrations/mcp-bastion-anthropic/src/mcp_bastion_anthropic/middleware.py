"""Anthropic Claude client wrapper with MCP-Bastion security."""

from __future__ import annotations

from typing import Any

import anthropic

from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureClaude:
    """Drop-in wrapper around ``anthropic.Anthropic`` with MCP-Bastion security.

    Usage::

        from mcp_bastion_anthropic import SecureClaude

        client = SecureClaude()  # uses ANTHROPIC_API_KEY from env
        response = client.chat("What is MCP?")
    """

    def __init__(
        self,
        api_key: str | None = None,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        self._client = anthropic.Anthropic(api_key=api_key)
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "anthropic-default"

    def chat(
        self,
        prompt: str,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> str:
        """Send a message with security scanning."""
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(prompt)
        response = self._client.messages.create(
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
            **kwargs,
        )
        self._limiter.consume_iteration(session_id=self._session)
        return response.content[0].text
