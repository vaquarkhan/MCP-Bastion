"""AWS Bedrock client wrapper with MCP-Bastion security."""

from __future__ import annotations

import json
from typing import Any

import boto3

from mcp_bastion.errors import RateLimitExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


class SecureBedrock:
    """Drop-in wrapper around AWS Bedrock with MCP-Bastion security.

    Usage::

        from mcp_bastion_bedrock import SecureBedrock

        client = SecureBedrock(region_name="us-east-1")
        response = client.chat("What is MCP?")
    """

    def __init__(
        self,
        region_name: str = "us-east-1",
        max_requests: int = 60,
        window_seconds: int = 60,
        **boto_kwargs: Any,
    ) -> None:
        self._client = boto3.client(
            "bedrock-runtime", region_name=region_name, **boto_kwargs
        )
        self._filter = ContentFilter()
        self._limiter = TokenBucketRateLimiter(
            max_iterations=max_requests, timeout_seconds=float(window_seconds)
        )
        self._session = "bedrock-default"

    def chat(
        self,
        prompt: str,
        model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0",
        max_tokens: int = 1024,
        **kwargs: Any,
    ) -> str:
        """Send a Bedrock invoke with security scanning."""
        check = self._limiter.check_iteration(session_id=self._session)
        if not check.allowed:
            raise RateLimitExceededError(check.message or "Rate limit exceeded")
        self._filter.check(prompt)
        body = json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "messages": [{"role": "user", "content": prompt}],
                **kwargs,
            }
        )
        response = self._client.invoke_model(modelId=model_id, body=body)
        result = json.loads(response["body"].read())
        self._limiter.consume_iteration(session_id=self._session)
        return result["content"][0]["text"]
