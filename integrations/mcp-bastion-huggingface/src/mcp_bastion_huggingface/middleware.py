"""Hugging Face Inference client wrapper with MCP-Bastion security."""
from __future__ import annotations
from typing import Any
from huggingface_hub import InferenceClient
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter


class SecureHuggingFace:
    """Drop-in wrapper around Hugging Face Inference with MCP-Bastion security.

    Usage::

        from mcp_bastion_huggingface import SecureHuggingFace
        client = SecureHuggingFace(api_key="YOUR_KEY")
        print(client.chat("What is MCP?"))
    """

    def __init__(self, api_key: str, max_requests: int = 60, window_seconds: int = 60) -> None:
        self._client = InferenceClient(token=api_key)
        self._filter = ContentFilter()
        self._limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def chat(self, prompt: str, model: str = "meta-llama/Llama-3.1-8B-Instruct", **kwargs: Any) -> str:
        self._limiter.check()
        self._filter.scan(prompt)
        response = self._client.chat_completion(
            model=model, messages=[{"role": "user", "content": prompt}], **kwargs)
        return response.choices[0].message.content or ""
