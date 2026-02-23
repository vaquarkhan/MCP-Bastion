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
from mcp_bastion.pillars.circuit_breaker import CircuitBreaker
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.pii_redaction import PIIRedactor
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.rbac import RBAC
from mcp_bastion.pillars.replay_guard import ReplayGuard
from mcp_bastion.pillars.schema_validation import SchemaValidator
from mcp_bastion.pillars.semantic_cache import SemanticCache

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


def _get_tool_name_from_params(params: dict | None) -> str:
    """Extract tool name from params."""
    if not params or not isinstance(params, dict):
        return "unknown"
    return str(params.get("name", "unknown"))


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
        circuit_breaker: CircuitBreaker | None = None,
        content_filter: ContentFilter | None = None,
        rbac: RBAC | None = None,
        schema_validator: SchemaValidator | None = None,
        replay_guard: ReplayGuard | None = None,
        cost_tracker: CostTracker | None = None,
        semantic_cache: SemanticCache | None = None,
        enable_prompt_guard: bool = True,
        enable_pii_redaction: bool = True,
        enable_rate_limit: bool = True,
        enable_circuit_breaker: bool = False,
        enable_content_filter: bool = False,
        enable_rbac: bool = False,
        enable_schema_validation: bool = False,
        enable_replay_guard: bool = False,
        enable_cost_tracker: bool = False,
        enable_semantic_cache: bool = False,
    ) -> None:
        self.prompt_guard = prompt_guard or PromptGuardEngine()
        self.pii_redactor = pii_redactor or PIIRedactor()
        self.rate_limiter = rate_limiter or TokenBucketRateLimiter()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.content_filter = content_filter or ContentFilter()
        self.rbac = rbac or RBAC({})
        self.schema_validator = schema_validator or SchemaValidator()
        self.replay_guard = replay_guard or ReplayGuard(require_nonce=False)
        self.cost_tracker = cost_tracker or CostTracker()
        self.semantic_cache = semantic_cache or SemanticCache()
        self.enable_prompt_guard = enable_prompt_guard
        self.enable_pii_redaction = enable_pii_redaction
        self.enable_rate_limit = enable_rate_limit
        self.enable_circuit_breaker = enable_circuit_breaker
        self.enable_content_filter = enable_content_filter
        self.enable_rbac = enable_rbac
        self.enable_schema_validation = enable_schema_validation
        self.enable_replay_guard = enable_replay_guard
        self.enable_cost_tracker = enable_cost_tracker
        self.enable_semantic_cache = enable_semantic_cache

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
        """Apply security checks before tool execution."""
        msg = context.message
        params = _get_params(msg)
        request_id = _get_request_id(msg) or context.request_id
        session_id = context.session_id
        tool_name = _get_tool_name_from_params(params)

        if self.enable_replay_guard:
            self.replay_guard.check(msg)

        if self.enable_rbac:
            self.rbac.check(tool_name, context)

        if self.enable_cost_tracker:
            self.cost_tracker.check(session_id=session_id, request_id=request_id)

        if self.enable_semantic_cache and params:
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            query = _extract_text_from_value(arguments)
            cached = self.semantic_cache.get(tool_name, query)
            if cached is not None:
                return cached

        if self.enable_schema_validation and params:
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {}
            if isinstance(arguments, dict):
                self.schema_validator.validate_input(tool_name, arguments)

        if self.enable_circuit_breaker:
            self.circuit_breaker.check(tool_name)

        if self.enable_rate_limit:
            allowed, err = self.rate_limiter.check_iteration(
                request_id=request_id,
                session_id=session_id,
            )
            if not allowed:
                logger.warning("rate_limit_blocked request_id=%s session_id=%s reason=%s", request_id, session_id, err)
                raise RateLimitExceededError(err or "Rate limit exceeded")

        if self.enable_content_filter and params:
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            text = _extract_text_from_value(arguments)
            self.content_filter.check(text)

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

        try:
            result = await call_next(context)
            if self.enable_circuit_breaker:
                self.circuit_breaker.record_success(tool_name)
        except Exception:
            if self.enable_circuit_breaker:
                self.circuit_breaker.record_failure(tool_name)
            raise

        if self.enable_semantic_cache and result is not None and params:
            arguments = params.get("arguments") or params
            query = _extract_text_from_value(arguments)
            self.semantic_cache.set(tool_name, query, result)

        if self.enable_cost_tracker:
            context.metadata.setdefault("cost", 0.0)
            self.cost_tracker.record(
                context.metadata.get("cost", 0.0),
                session_id=session_id,
                request_id=request_id,
            )

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

