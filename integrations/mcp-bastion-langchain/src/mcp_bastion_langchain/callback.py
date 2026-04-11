"""LangChain callback handler that applies MCP-Bastion security checks."""

from __future__ import annotations

from typing import Any

from langchain_core.callbacks import BaseCallbackHandler

from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter


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
            RateLimiter(max_requests=max_requests, window_seconds=window_seconds)
            if enable_rate_limit
            else None
        )

    def on_llm_start(self, serialized: dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        if self._rate_limiter:
            self._rate_limiter.check()
        if self._content_filter:
            for prompt in prompts:
                self._content_filter.scan(prompt)

    def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
        if self._content_filter:
            self._content_filter.scan(input_str)
