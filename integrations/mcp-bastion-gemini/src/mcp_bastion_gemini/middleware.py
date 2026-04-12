"""Google Gemini client wrapper with MCP-Bastion security."""
from __future__ import annotations
from typing import Any
import google.generativeai as genai
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter


class SecureGemini:
    """Drop-in wrapper around Google Gemini with MCP-Bastion security.

    Usage::

        from mcp_bastion_gemini import SecureGemini
        client = SecureGemini(api_key="YOUR_KEY")
        print(client.chat("What is MCP?"))
    """

    def __init__(self, api_key: str, max_requests: int = 60, window_seconds: int = 60) -> None:
        genai.configure(api_key=api_key)
        self._model = genai.GenerativeModel("gemini-pro")
        self._filter = ContentFilter()
        self._limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def chat(self, prompt: str, **kwargs: Any) -> str:
        self._limiter.check()
        self._filter.scan(prompt)
        response = self._model.generate_content(prompt, **kwargs)
        return response.text
