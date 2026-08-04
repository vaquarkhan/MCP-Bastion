"""Pydantic AI prompt / tool-arg guard with MCP-Bastion security."""
from __future__ import annotations
import json
from typing import Any

from mcp_bastion.errors import PromptInjectionError, RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecurePydanticAI:
    """Scan prompts and tool arguments before Pydantic AI agents act."""

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._filter = ContentFilter()
        self._prompt_guard = PromptGuardEngine(fail_open=True, heuristic_fallback=True)
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "pydantic-ai-default"

    def _gate(self, text: str) -> None:
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(text)
        if self._prompt_guard.is_malicious(text):
            raise PromptInjectionError("Request blocked: suspected prompt injection")
        self._limiter.consume_iteration(session_id=self._session)

    def check_prompt(self, text: str) -> None:
        if text and str(text).strip():
            self._gate(str(text))

    def check_tool_args(self, arguments: Any) -> None:
        if arguments is None:
            return
        if isinstance(arguments, str):
            self._gate(arguments)
            return
        try:
            blob = json.dumps(arguments, default=str)
        except (TypeError, ValueError):
            blob = str(arguments)
        self._gate(blob)
