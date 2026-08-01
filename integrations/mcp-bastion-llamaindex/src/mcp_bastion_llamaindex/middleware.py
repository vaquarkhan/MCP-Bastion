"""LlamaIndex wrapper with MCP-Bastion security scanning on queries."""
from __future__ import annotations
from typing import Any
from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureLlamaIndex:
    """Security layer for LlamaIndex queries and tool calls.

    Usage::

        from mcp_bastion_llamaindex import SecureLlamaIndex
        guard = SecureLlamaIndex()
        guard.scan_query("What is the revenue for Q4?")
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "llamaindex-default"

    def scan_query(self, query: str) -> None:
        """Scan a query for security threats before sending to index."""
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(query)
        self._limiter.consume_iteration(session_id=self._session)

    def scan_response(self, response: str) -> None:
        """Scan index response for PII or sensitive content."""
        self._filter.check(response)
