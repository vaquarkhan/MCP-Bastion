"""LlamaIndex wrapper with MCP-Bastion security scanning on queries."""
from __future__ import annotations
from typing import Any
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter


class SecureLlamaIndex:
    """Security layer for LlamaIndex queries and tool calls.

    Usage::

        from mcp_bastion_llamaindex import SecureLlamaIndex
        guard = SecureLlamaIndex()
        guard.scan_query("What is the revenue for Q4?")
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def scan_query(self, query: str) -> None:
        """Scan a query for security threats before sending to index."""
        self._limiter.check()
        self._filter.scan(query)

    def scan_response(self, response: str) -> None:
        """Scan index response for PII or sensitive content."""
        self._filter.scan(response)
