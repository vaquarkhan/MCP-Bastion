"""Google Cloud Vertex AI wrapper with MCP-Bastion security."""
from __future__ import annotations
from typing import Any
import vertexai
from vertexai.generative_models import GenerativeModel
from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureVertexAI:
    def __init__(self, project: str, location: str = "us-central1",
                 max_requests: int = 60, window_seconds: int = 60) -> None:
        vertexai.init(project=project, location=location)
        self._model = GenerativeModel("gemini-pro")
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "vertexai-default"

    def chat(self, prompt: str, **kwargs: Any) -> str:
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(prompt)
        response = self._model.generate_content(prompt, **kwargs)
        self._limiter.consume_iteration(session_id=self._session)
        return response.text
