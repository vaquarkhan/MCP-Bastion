"""CrewAI wrapper with MCP-Bastion security scanning on agent tasks."""
from __future__ import annotations
from typing import Any
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter


class SecureCrewAI:
    """Security layer for CrewAI agent tasks.

    Usage::

        from mcp_bastion_crewai import SecureCrewAI
        guard = SecureCrewAI()
        guard.scan_task("Summarize the quarterly report")
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def scan_task(self, task_description: str) -> None:
        """Scan a CrewAI task description for security threats."""
        self._limiter.check()
        self._filter.scan(task_description)

    def scan_output(self, output: str) -> None:
        """Scan agent output for PII or sensitive content."""
        self._filter.scan(output)
