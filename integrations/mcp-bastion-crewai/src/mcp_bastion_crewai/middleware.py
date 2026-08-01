"""CrewAI wrapper with MCP-Bastion security scanning on agent tasks."""
from __future__ import annotations
from typing import Any
from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureCrewAI:
    """Security layer for CrewAI agent tasks.

    Usage::

        from mcp_bastion_crewai import SecureCrewAI
        guard = SecureCrewAI()
        guard.scan_task("Summarize the quarterly report")
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "crewai-default"

    def scan_task(self, task_description: str) -> None:
        """Scan a CrewAI task description for security threats."""
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(task_description)
        self._limiter.consume_iteration(session_id=self._session)

    def scan_output(self, output: str) -> None:
        """Scan agent output for PII or sensitive content."""
        self._filter.check(output)
