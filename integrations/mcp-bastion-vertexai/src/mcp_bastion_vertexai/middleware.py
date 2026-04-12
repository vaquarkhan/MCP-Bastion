"""Google Cloud Vertex AI wrapper with MCP-Bastion security."""
from __future__ import annotations
from typing import Any
import vertexai
from vertexai.generative_models import GenerativeModel
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import RateLimiter


class SecureVertexAI:
    def __init__(self, project: str, location: str = "us-central1",
                 max_requests: int = 60, window_seconds: int = 60) -> None:
        vertexai.init(project=project, location=location)
        self._model = GenerativeModel("gemini-pro")
        self._filter = ContentFilter()
        self._limiter = RateLimiter(max_requests=max_requests, window_seconds=window_seconds)

    def chat(self, prompt: str, **kwargs: Any) -> str:
        self._limiter.check()
        self._filter.scan(prompt)
        response = self._model.generate_content(prompt, **kwargs)
        return response.text
