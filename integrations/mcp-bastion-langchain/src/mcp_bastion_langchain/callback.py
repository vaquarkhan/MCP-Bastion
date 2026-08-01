"""LangChain callback handler that applies MCP-Bastion security checks."""

from __future__ import annotations

from typing import Any

from langchain_core.callbacks import BaseCallbackHandler

from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class BastionSecurityCallback(BaseCallbackHandler):
    """LangChain callback that enforces MCP-Bastion security on every LLM call.

    Usage::

        from mcp_bastion_langchain import BastionSecurityCallback

        cb = BastionSecurityCallback()
        llm = ChatOpenAI(callbacks=[cb])
    """

    def __init__(
        self,
        enable_content_filter: bool = True,
        enable_rate_limit: bool = True,
        max_requests: int = 60,
        window_seconds: int = 60,
    ) -> None:
        super().__init__()
        self._content_filter = ContentFilter() if enable_content_filter else None
        self._rate_limiter = (
            TokenBucketRateLimiter(
                max_iterations=max_requests, timeout_seconds=float(window_seconds)
            )
            if enable_rate_limit
            else None
        )
        self._session = "langchain-default"

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        if self._rate_limiter:
            check = self._rate_limiter.check_iteration(session_id=self._session)
            if not check.allowed:
                raise RateLimitExceededError(check.message or "Rate limit exceeded")
        if self._content_filter:
            for prompt in prompts:
                self._content_filter.check(prompt)
        if self._rate_limiter:
            self._rate_limiter.consume_iteration(session_id=self._session)

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        if self._content_filter:
            self._content_filter.check(input_str)
