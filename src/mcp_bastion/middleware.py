"""
MCP-Bastion security middleware.

Intercepts CallToolRequest and ReadResourceResult for prompt injection,
PII redaction, and rate limiting.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from mcp_bastion.base import CallNext, Middleware, MiddlewareContext
from mcp_bastion.errors import PromptInjectionError, RateLimitExceededError
from mcp_bastion.pillars.pii_redaction import PIIRedactor
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter

logger = logging.getLogger(__name__)


def _extract_text_from_value(value: Any) -> str:
    """Flatten args to string for injection check."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, dict):
        return " ".join(_extract_text_from_value(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return " ".join(_extract_text_from_value(v) for v in value)
    return str(value)


def _is_call_tool_request(message: Any) -> bool:
    """True if message is tools/call."""
    if hasattr(message, "root"):
        msg = message.root
    else:
        msg = message
    if hasattr(msg, "method") and getattr(msg, "method", None) == "tools/call":
        return True
    if isinstance(msg, dict) and msg.get("method") == "tools/call":
        return True
    return False


def _is_read_resource_result(message: Any) -> bool:
    """True if message has resource contents."""
    if message is None:
        return False
    if hasattr(message, "contents"):
        return True
    if hasattr(message, "root"):
        msg = message.root
    else:
        msg = message
    if isinstance(msg, dict):
        result = msg.get("result") or msg.get("params") or msg
        if isinstance(result, dict) and ("contents" in result or "content" in result):
            return True
        if hasattr(result, "contents"):
            return True
    return False


def _get_params(message: Any) -> dict | None:
    """Extract params from message."""
    if hasattr(message, "root"):
        msg = message.root
    else:
        msg = message
    if isinstance(msg, dict):
        return msg.get("params") or msg.get("result")
    if hasattr(msg, "params"):
        return getattr(msg.params, "__dict__", None) or {}
    return None


def _get_request_id(message: Any) -> str | None:
    """Extract request ID from message."""
    if hasattr(message, "root"):
        msg = message.root
    else:
        msg = message
    if isinstance(msg, dict):
        return str(msg.get("id", "")) or None
    if hasattr(msg, "id"):
        return str(getattr(msg, "id", "")) or None
    return None


def _get_content_from_result(result: Any) -> list[dict[str, Any]] | None:
    """Extract content list from result for PII redaction."""
    if result is None:
        return None
    payload = result
    if isinstance(result, dict) and "result" in result:
        payload = result["result"]
    if hasattr(payload, "contents"):
        items = payload.contents
    elif isinstance(payload, dict) and "contents" in payload:
        items = payload["contents"]
    elif isinstance(payload, dict) and "content" in payload:
        items = payload["content"]
    else:
        return None
    if not isinstance(items, list):
        return None
    out = []
    for item in items:
        if hasattr(item, "model_dump"):
            out.append(item.model_dump())
        elif isinstance(item, dict):
            out.append(dict(item))
        else:
            out.append({"type": "text", "text": str(item)})
    return out


def _set_content_in_result(result: Any, content: list[dict[str, Any]]) -> None:
    """Replace content in result after redaction."""
    payload = result
    if isinstance(result, dict) and "result" in result:
        payload = result["result"]
    if hasattr(payload, "contents"):
        payload.contents = content
    elif isinstance(payload, dict):
        if "contents" in payload:
            payload["contents"] = content
        if "content" in payload:
            payload["content"] = content


class MCPBastionMiddleware(Middleware[Any]):
    def __init__(
        self,
        prompt_guard: PromptGuardEngine | None = None,
        pii_redactor: PIIRedactor | None = None,
        rate_limiter: TokenBucketRateLimiter | None = None,
        enable_prompt_guard: bool = True,
        enable_pii_redaction: bool = True,
        enable_rate_limit: bool = True,
    ) -> None:
        self.prompt_guard = prompt_guard or PromptGuardEngine()
        self.pii_redactor = pii_redactor or PIIRedactor()
        self.rate_limiter = rate_limiter or TokenBucketRateLimiter()
        self.enable_prompt_guard = enable_prompt_guard
        self.enable_pii_redaction = enable_pii_redaction
        self.enable_rate_limit = enable_rate_limit

    async def __call__(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any],
    ) -> Any:
        """Run security checks, then call_next."""
        start = time.perf_counter()
        msg = context.message

        try:
            if _is_call_tool_request(msg):
                return await self._handle_call_tool(context, call_next)
            result = await call_next(context)
            if result is not None and _is_read_resource_result(result):
                result = self._redact_result_content(result)
            return result
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            context.metadata["elapsed_ms"] = round(elapsed_ms, 2)
            logger.debug("request done elapsed_ms=%.2f", elapsed_ms)

    async def _handle_call_tool(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any],
    ) -> Any:
        """Apply prompt guard and rate limit before tool execution."""
        msg = context.message
        params = _get_params(msg)
        request_id = _get_request_id(msg) or context.request_id
        session_id = context.session_id

        if self.enable_rate_limit:
            allowed, err = self.rate_limiter.check_iteration(
                request_id=request_id,
                session_id=session_id,
            )
            if not allowed:
                logger.warning("rate_limit_blocked request_id=%s session_id=%s reason=%s", request_id, session_id, err)
                raise RateLimitExceededError(err or "Rate limit exceeded")

        if self.enable_prompt_guard and params:
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            text = _extract_text_from_value(arguments)
            if text and self.prompt_guard.is_malicious(text):
                logger.warning("prompt_injection_blocked request_id=%s", request_id)
                raise PromptInjectionError()

        self.rate_limiter.consume_iteration(
            request_id=request_id,
            session_id=session_id,
        )

        result = await call_next(context)

        if self.enable_pii_redaction and result is not None:
            result = self._redact_result_content(result)

        return result

    def _redact_result_content(self, result: Any) -> Any:
        """Redact PII from result content items."""
        content = _get_content_from_result(result)
        if not content:
            return result
        redacted = self.pii_redactor.redact_content_items(content)
        _set_content_in_result(result, redacted)
        return result

