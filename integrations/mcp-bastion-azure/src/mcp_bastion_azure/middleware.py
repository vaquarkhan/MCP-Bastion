"""Azure OpenAI client wrapper with MCP-Bastion security."""
from __future__ import annotations
from typing import Any
from openai import AzureOpenAI
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter


class SecureAzureOpenAI:
    """Drop-in wrapper around Azure OpenAI with MCP-Bastion security.

    Usage::

        from mcp_bastion_azure import SecureAzureOpenAI
        client = SecureAzureOpenAI(
            azure_endpoint="https://YOUR.openai.azure.com/",
            api_key="YOUR_KEY",
            api_version="2024-02-01",
        )
        print(client.chat("What is MCP?"))
    """

    def __init__(self, azure_endpoint: str, api_key: str, api_version: str = "2024-02-01",
                 max_requests: int = 60, window_seconds: int = 60) -> None:
        self._client = AzureOpenAI(azure_endpoint=azure_endpoint, api_key=api_key, api_version=api_version)
        self._filter = ContentFilter()
        self._limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def chat(self, prompt: str, model: str = "gpt-4o", **kwargs: Any) -> str:
        self._limiter.check()
        self._filter.scan(prompt)
        response = self._client.chat.completions.create(
            model=model, messages=[{"role": "user", "content": prompt}], **kwargs)
        return response.choices[0].message.content or ""
