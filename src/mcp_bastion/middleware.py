"""
MCP-Bastion security middleware.

Intercepts CallToolRequest and ReadResourceResult for prompt injection,
PII redaction, and rate limiting.
"""

from __future__ import annotations

import hmac
import json
import logging
import threading
import time
from collections import defaultdict
from typing import Any

from mcp_bastion.base import CallNext, Middleware, MiddlewareContext
from mcp_bastion.errors import (
    AuthenticationError,
    ExternalPolicyDeniedError,
    GroundingViolationError,
    PromptInjectionError,
    RateLimitExceededError,
    SensitiveContentError,
    SessionScopeExceededError,
    TokenBudgetExceededError,
    ToolMetadataPoisoningError,
    ToolNotAllowedError,
)
from mcp_bastion.pillars.circuit_breaker import CircuitBreaker
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.pii_redaction import PIIRedactor
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import RateLimitCheckResult, TokenBucketRateLimiter
from mcp_bastion.pillars.response_scanner import ResponseInjectionScanner
from mcp_bastion.pillars.output_budget import OutputBudget
from mcp_bastion.pillars.grounding_guard import GroundingGuard
from mcp_bastion.pillars.tokens import estimate_text_tokens
from mcp_bastion.pillars.rbac import RBAC
from mcp_bastion.pillars.replay_guard import ReplayGuard
from mcp_bastion.pillars.schema_validation import SchemaValidator
from mcp_bastion.pillars.metrics import MetricsStore
from mcp_bastion.pillars.pricing import estimate_llm_usd
from mcp_bastion.pillars.semantic_cache import SemanticCache
from mcp_bastion.pillars.sensitive_classifier import SensitiveContentClassifier
from mcp_bastion.pillars.semantic_firewall import SemanticFirewall
from mcp_bastion.tenant import resolve_tenant_id

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


def _tool_entry_to_dict(entry: Any) -> dict[str, Any]:
    if isinstance(entry, dict):
        return entry
    if hasattr(entry, "model_dump"):
        try:
            return entry.model_dump()
        except Exception:
            pass
    if hasattr(entry, "__dict__"):
        try:
            return dict(vars(entry))
        except Exception:
            pass
    return {"name": str(entry), "description": ""}


def _tool_metadata_scan_text(tool_dict: dict[str, Any]) -> str:
    """Flatten name, description, and input schema for policy checks."""
    parts = [
        str(tool_dict.get("name") or ""),
        str(tool_dict.get("description") or ""),
    ]
    schema = tool_dict.get("inputSchema") or tool_dict.get("input_schema")
    if schema is not None:
        try:
            parts.append(json.dumps(schema, default=str))
        except (TypeError, ValueError):
            parts.append(str(schema))
    return "\n".join(parts)


def _get_tools_list_from_result(result: Any) -> list[Any] | None:
    """Return the tools array from a tools/list style response, if present."""
    if result is None:
        return None
    if isinstance(result, dict):
        t = result.get("tools")
        if isinstance(t, list):
            return t
        inner = result.get("result")
        if isinstance(inner, dict):
            t2 = inner.get("tools")
            if isinstance(t2, list):
                return t2
    tools = getattr(result, "tools", None)
    if isinstance(tools, list):
        return tools
    inner = getattr(result, "result", None)
    if inner is not None:
        if isinstance(inner, dict):
            t3 = inner.get("tools")
            if isinstance(t3, list):
                return t3
        t4 = getattr(inner, "tools", None)
        if isinstance(t4, list):
            return t4
    return None


def _set_tools_on_result(result: Any, new_tools: list[Any]) -> Any:
    """Return a copy of result with tools replaced (dict or pydantic)."""
    if isinstance(result, dict):
        if isinstance(result.get("tools"), list):
            return {**result, "tools": new_tools}
        if "result" in result and isinstance(result["result"], dict):
            inner = {**result["result"], "tools": new_tools}
            return {**result, "result": inner}
    if hasattr(result, "model_copy"):
        try:
            return result.model_copy(update={"tools": new_tools})  # type: ignore[call-arg]
        except Exception:
            pass
    res = getattr(result, "result", None)
    if res is not None and hasattr(result, "model_copy") and hasattr(res, "model_copy"):
        try:
            new_inner = res.model_copy(update={"tools": new_tools})  # type: ignore[call-arg]
            return result.model_copy(update={"result": new_inner})  # type: ignore[call-arg]
        except Exception:
            pass
    return result


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


def _safe_forensic_value(value: Any, *, depth: int = 0) -> Any:
    """Best-effort JSON-safe value with bounded depth for forensic snapshots."""
    if depth > 4:
        return "<truncated>"
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in list(value.items())[:50]:
            out[str(k)] = _safe_forensic_value(v, depth=depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        return [_safe_forensic_value(v, depth=depth + 1) for v in list(value)[:50]]
    if hasattr(value, "model_dump"):
        try:
            return _safe_forensic_value(value.model_dump(), depth=depth + 1)
        except Exception:
            return repr(value)
    if hasattr(value, "__dict__"):
        try:
            return _safe_forensic_value(vars(value), depth=depth + 1)
        except Exception:
            return repr(value)
    return repr(value)


def _trace_append(
    trace: list[dict[str, Any]],
    *,
    pillar: str,
    status: str,
    started: float,
    detail: str | None = None,
) -> None:
    item: dict[str, Any] = {
        "pillar": pillar,
        "status": status,
        "latency_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    if detail:
        item["detail"] = detail
    trace.append(item)


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
        semantic_firewall: SemanticFirewall | None = None,
        sensitive_classifier: SensitiveContentClassifier | None = None,
        external_policy: Any = None,
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
        enable_semantic_firewall: bool = False,
        enable_sensitive_classifier: bool = False,
        enable_external_policy: bool = False,
        enable_cost_attribution: bool = True,
        sensitive_classifier_threshold: float = 0.65,
        sensitive_classifier_block_labels: set[str] | None = None,
        default_tenant_id: str = "default",
        shadow_mode: bool = False,
        enable_edge_auth: bool = False,
        edge_auth_metadata_key: str = "bastion_edge_token",
        edge_auth_secret: str | None = None,
        enable_tool_allowlist: bool = False,
        tool_allowlist: set[str] | None = None,
        session_max_unique_tools: int = 0,
        enable_tool_metadata_guard: bool = False,
        tool_metadata_guard_on_poison: str = "remove_tool",
        tool_metadata_guard_use_content_filter: bool = True,
        enable_response_scan: bool = False,
        response_scan_extra_patterns: list[str] | None = None,
        enable_discovery_filter: bool = False,
        response_scanner: ResponseInjectionScanner | None = None,
        enable_output_budget: bool = False,
        output_budget: OutputBudget | None = None,
        enable_grounding_guard: bool = False,
        grounding_guard: GroundingGuard | None = None,
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
        self.semantic_firewall = semantic_firewall or SemanticFirewall()
        self.sensitive_classifier = sensitive_classifier or SensitiveContentClassifier(
            threshold=sensitive_classifier_threshold
        )
        self.external_policy = external_policy
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
        self.enable_semantic_firewall = enable_semantic_firewall
        self.enable_sensitive_classifier = enable_sensitive_classifier
        self.enable_external_policy = enable_external_policy
        self.enable_cost_attribution = enable_cost_attribution
        self.sensitive_classifier_block_labels = {
            x.strip().lower()
            for x in (sensitive_classifier_block_labels or {"sensitive_business"})
            if str(x).strip()
        }
        self.default_tenant_id = default_tenant_id
        self.shadow_mode = shadow_mode
        self.enable_edge_auth = enable_edge_auth
        self.edge_auth_metadata_key = edge_auth_metadata_key
        self.edge_auth_secret = edge_auth_secret
        self.enable_tool_allowlist = enable_tool_allowlist
        self.tool_allowlist = frozenset(tool_allowlist or ())
        self.session_max_unique_tools = max(0, int(session_max_unique_tools))
        self._session_tools_lock = threading.Lock()
        self._session_distinct_tools: dict[str, set[str]] = defaultdict(set)
        self.enable_tool_metadata_guard = enable_tool_metadata_guard
        self.tool_metadata_guard_on_poison = (tool_metadata_guard_on_poison or "remove_tool").strip().lower()
        self.tool_metadata_guard_use_content_filter = bool(tool_metadata_guard_use_content_filter)
        self.enable_response_scan = enable_response_scan
        self.response_scanner = response_scanner or ResponseInjectionScanner(
            extra_patterns=response_scan_extra_patterns or []
        )
        self.enable_discovery_filter = enable_discovery_filter

        self.output_budget = output_budget or OutputBudget()
        self.enable_output_budget = enable_output_budget
        self.grounding_guard = grounding_guard or GroundingGuard()
        self.enable_grounding_guard = enable_grounding_guard

    @staticmethod
    def _offload_key_from_params(params: dict | None) -> str | None:
        if not params or not isinstance(params, dict):
            return None
        arguments = params.get("arguments") or params
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                return None
        if isinstance(arguments, dict):
            key = arguments.get("key")
            return str(key).strip() if key else None
        return None

    def _record_finops(self, context: MiddlewareContext[Any], section: str, data: dict[str, Any]) -> None:
        context.metadata.setdefault("finops", {}).setdefault(section, {}).update(data)

    def _apply_output_budget_to_result(
        self,
        context: MiddlewareContext[Any],
        result: Any,
        *,
        tool_name: str | None = None,
    ) -> Any:
        if not self.enable_output_budget or result is None:
            return result
        content = _get_content_from_result(result)
        if not content:
            return result
        new_content, summary = self.output_budget.process_content_items(
            content,
            session_id=context.session_id,
            tool_name=tool_name,
        )
        if summary.applied:
            self._record_finops(
                context,
                "output_budget",
                {
                    "original_tokens": summary.original_tokens,
                    "output_tokens": summary.output_tokens,
                    "tokens_saved": summary.tokens_saved,
                    "offloaded": summary.offloaded,
                    "offload_key": summary.offload_key,
                    "truncated_items": summary.truncated_items,
                },
            )
            _set_content_in_result(result, new_content)
        return result

    def _apply_grounding_to_result(
        self,
        context: MiddlewareContext[Any],
        result: Any,
        *,
        trace: list[dict[str, Any]] | None = None,
    ) -> Any:
        if not self.enable_grounding_guard or result is None:
            return result
        content = _get_content_from_result(result)
        if not content:
            return result
        started = time.perf_counter()
        try:
            new_content, check = self.grounding_guard.process_content_items(content)
            if check.violations:
                self._record_finops(
                    context,
                    "grounding_guard",
                    {"violations": check.violations[:20], "count": len(check.violations)},
                )
                if self.grounding_guard.on_violation == "warn":
                    if trace is not None:
                        _trace_append(
                            trace,
                            pillar="grounding_guard",
                            status="warn",
                            started=started,
                            detail=f"{len(check.violations)} ungrounded paths",
                        )
                else:
                    _set_content_in_result(result, new_content)
                    if trace is not None:
                        _trace_append(trace, pillar="grounding_guard", status="stripped", started=started)
            elif trace is not None:
                _trace_append(trace, pillar="grounding_guard", status="ok", started=started)
        except GroundingViolationError as e:
            if trace is not None:
                self._handle_violation(
                    context=context, trace=trace, pillar="grounding_guard", started=started, error=e
                )
            raise
        return result

    @staticmethod
    def _rate_limit_error(check: RateLimitCheckResult) -> Exception:
        if check.violation == "token_budget":
            return TokenBudgetExceededError(check.message or "Request blocked: token budget exhausted")
        return RateLimitExceededError(check.message or "Rate limit exceeded")

    def _estimate_tool_call_tokens(
        self,
        context: MiddlewareContext[Any],
        params: dict | None,
        result: Any,
    ) -> int:
        md = context.metadata
        try:
            in_tok = int(md.get("llm_input_tokens") or 0)
        except (TypeError, ValueError):
            in_tok = 0
        try:
            out_tok = int(md.get("llm_output_tokens") or 0)
        except (TypeError, ValueError):
            out_tok = 0
        if in_tok or out_tok:
            return max(0, in_tok + out_tok)
        arguments = (params or {}).get("arguments") if isinstance(params, dict) else params
        arg_text = _extract_text_from_value(arguments)
        result_text = _extract_text_from_value(result)
        return estimate_text_tokens(arg_text, result_text)

    def _scan_result_for_injection(self, result: Any) -> None:
        if not self.enable_response_scan or result is None:
            return
        content = _get_content_from_result(result)
        if content:
            self.response_scanner.check_content_items(content)

    def _apply_discovery_filter(self, context: MiddlewareContext[Any], result: Any) -> Any:
        """Strip tools from tools/list that are not on the allowlist (reduces agent context tokens)."""
        if not self.enable_discovery_filter or not self.enable_tool_allowlist:
            return result
        tools = _get_tools_list_from_result(result)
        if tools is None or not tools:
            return result
        kept: list[Any] = []
        hidden: list[str] = []
        for entry in tools:
            td = _tool_entry_to_dict(entry)
            name = str(td.get("name") or "unknown")
            if name in self.tool_allowlist:
                kept.append(entry)
            else:
                hidden.append(name)
        if hidden:
            context.metadata.setdefault("discovery_filter", {}).update(
                {
                    "hidden_tools": hidden,
                    "original_count": len(tools),
                    "kept_count": len(kept),
                }
            )
        if len(kept) == len(tools):
            return result
        return _set_tools_on_result(result, kept)

    def _enforce_session_tool_scope(
        self,
        *,
        context: MiddlewareContext[Any],
        trace: list[dict[str, Any]],
        session_id: str | None,
        tool_name: str,
    ) -> None:
        if self.session_max_unique_tools <= 0 or not session_id:
            return
        started = time.perf_counter()
        try:
            with self._session_tools_lock:
                seen = self._session_distinct_tools[session_id]
                if tool_name not in seen and len(seen) >= self.session_max_unique_tools:
                    raise SessionScopeExceededError(
                        f"Request blocked: session exceeded max distinct tools ({self.session_max_unique_tools})"
                    )
                seen.add(tool_name)
            _trace_append(trace, pillar="session_tool_scope", status="allowed", started=started)
        except Exception as e:
            self._handle_violation(context=context, trace=trace, pillar="session_tool_scope", started=started, error=e)

    def _inspect_tool_metadata_text(self, text: str) -> str | None:
        """Return a short reason if metadata should fail checks; None if acceptable."""
        if self.tool_metadata_guard_use_content_filter and self.enable_content_filter:
            try:
                self.content_filter.check(text)
            except Exception as e:
                return str(e)
        if self.enable_prompt_guard and text.strip():
            if self.prompt_guard.is_malicious(text):
                return "prompt_guard flagged tool metadata"
        return None

    def _apply_tool_metadata_guard(self, context: MiddlewareContext[Any], result: Any) -> Any:
        """
        Scan tools/list (or equivalent) responses for poisoned descriptions/schemas.

        Mitigates description-based tool poisoning when the MCP host routes list results
        through this middleware (WhatsApp-class attack path).
        """
        if not self.enable_tool_metadata_guard:
            return result
        if not self.enable_content_filter and not self.enable_prompt_guard:
            logger.warning(
                "tool_metadata_guard is enabled but both content_filter and prompt_guard are disabled; skipping"
            )
            return result

        tools = _get_tools_list_from_result(result)
        if tools is None or not tools:
            return result

        action = self.tool_metadata_guard_on_poison
        if self.shadow_mode and action == "block_all":
            action = "remove_tool"

        kept: list[Any] = []
        removed: list[str] = []
        for entry in tools:
            td = _tool_entry_to_dict(entry)
            name = str(td.get("name") or "unknown")
            if self.enable_tool_allowlist and name not in self.tool_allowlist:
                removed.append(name)
                continue
            text = _tool_metadata_scan_text(td)
            detail = self._inspect_tool_metadata_text(text)
            if detail is None:
                kept.append(entry)
                continue
            removed.append(name)
            if action == "block_all":
                raise ToolMetadataPoisoningError(
                    f"Tool list blocked: metadata failed safety checks for tool {name!r}: {detail}"
                )
            logger.warning("tool_metadata_guard removed tool=%s reason=%s", name, detail[:240])

        if removed:
            context.metadata.setdefault("tool_metadata_guard", {}).update(
                {"removed_tools": removed, "original_count": len(tools), "kept_count": len(kept)}
            )
        if not kept:
            raise ToolMetadataPoisoningError(
                "Tool list blocked: no tools remained after metadata safety checks (possible tool poisoning)"
            )
        if len(kept) == len(tools):
            return result
        return _set_tools_on_result(result, kept)

    def _handle_violation(
        self,
        *,
        context: MiddlewareContext[Any],
        trace: list[dict[str, Any]],
        pillar: str,
        started: float,
        error: Exception,
    ) -> None:
        if self.shadow_mode:
            context.metadata.setdefault("shadow_blocked", []).append(
                {
                    "pillar": pillar,
                    "reason": str(error),
                    "error_type": error.__class__.__name__,
                }
            )
            _trace_append(trace, pillar=pillar, status="would_block", started=started, detail=str(error))
            return
        _trace_append(trace, pillar=pillar, status="blocked", started=started, detail=str(error))
        raise error

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
                result = self._apply_output_budget_to_result(context, result)
                self._scan_result_for_injection(result)
                result = self._apply_grounding_to_result(context, result)
            if result is not None:
                result = self._apply_discovery_filter(context, result)
                result = self._apply_tool_metadata_guard(context, result)
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
        tenant_id = resolve_tenant_id(context, self.default_tenant_id)
        context.metadata["tenant_id"] = tenant_id
        tool_name = _get_tool_name_from_params(params)
        trace: list[dict[str, Any]] = context.metadata.setdefault("pillar_trace", [])

        safe_msg = _safe_forensic_value(msg.root if hasattr(msg, "root") else msg)
        context.metadata["forensic_request"] = {
            "request_id": request_id,
            "session_id": session_id,
            "tenant_id": tenant_id,
            "tool": tool_name,
            "message": safe_msg,
        }
        context.metadata["replay_payload"] = {
            "method": "tools/call",
            "params": _safe_forensic_value(params or {}),
            "request_id": request_id,
            "session_id": session_id,
            "tenant_id": tenant_id,
        }

        if (
            self.enable_output_budget
            and self.output_budget.retrieve_tool
            and tool_name == self.output_budget.retrieve_tool
        ):
            started = time.perf_counter()
            key = self._offload_key_from_params(params)
            if not key:
                payload = {
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": 'Missing offload key. Pass arguments: {"key": "<offload-key>"}',
                            }
                        ]
                    }
                }
            else:
                text = self.output_budget.offload_store.get(key, session_id=session_id)
                if text is None:
                    payload = {
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"Offload key not found or expired: {key}",
                                }
                            ]
                        }
                    }
                else:
                    payload = {"result": {"content": [{"type": "text", "text": text}]}}
            _trace_append(trace, pillar="output_budget_retrieve", status="ok", started=started)
            context.metadata["forensic_response"] = _safe_forensic_value(payload)
            return payload

        if self.enable_replay_guard:
            started = time.perf_counter()
            try:
                self.replay_guard.check(msg)
                _trace_append(trace, pillar="replay_guard", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(context=context, trace=trace, pillar="replay_guard", started=started, error=e)

        if self.enable_edge_auth and self.edge_auth_secret:
            started = time.perf_counter()
            raw = context.metadata.get(self.edge_auth_metadata_key)
            token = "" if raw is None else str(raw)
            try:
                a, b = token.encode("utf-8"), self.edge_auth_secret.encode("utf-8")
                if len(a) != len(b) or not hmac.compare_digest(a, b):
                    raise AuthenticationError("Request blocked: invalid edge authentication token")
                _trace_append(trace, pillar="edge_auth", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(context=context, trace=trace, pillar="edge_auth", started=started, error=e)

        if self.enable_tool_allowlist:
            started = time.perf_counter()
            try:
                if tool_name not in self.tool_allowlist:
                    raise ToolNotAllowedError(
                        f"Request blocked: tool {tool_name!r} is not on the configured allowlist"
                    )
                _trace_append(trace, pillar="tool_allowlist", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(context=context, trace=trace, pillar="tool_allowlist", started=started, error=e)

        if self.enable_rbac:
            started = time.perf_counter()
            try:
                self.rbac.check(tool_name, context)
                _trace_append(trace, pillar="rbac", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(context=context, trace=trace, pillar="rbac", started=started, error=e)

        if self.enable_external_policy and self.external_policy is not None:
            started = time.perf_counter()
            policy_input: dict[str, Any] = {
                "tool": tool_name,
                "session_id": session_id,
                "request_id": request_id,
                "params": _safe_forensic_value(params or {}),
            }
            allowed, reason = self.external_policy.evaluate(policy_input)
            if not allowed:
                self._handle_violation(
                    context=context,
                    trace=trace,
                    pillar="external_policy",
                    started=started,
                    error=ExternalPolicyDeniedError(reason or "Request blocked: external policy denied"),
                )
            _trace_append(trace, pillar="external_policy", status="allowed", started=started)

        if self.enable_cost_tracker:
            started = time.perf_counter()
            try:
                self.cost_tracker.check(session_id=session_id, request_id=request_id)
                _trace_append(trace, pillar="cost_tracker_precheck", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="cost_tracker_precheck", started=started, error=e
                )

        if self.enable_semantic_cache and params:
            started = time.perf_counter()
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            query = _extract_text_from_value(arguments)
            cached = self.semantic_cache.get(tool_name, query, scope=tenant_id)
            if cached is not None:
                _trace_append(trace, pillar="semantic_cache_get", status="cache_hit", started=started)
                self._enforce_session_tool_scope(
                    context=context, trace=trace, session_id=session_id, tool_name=tool_name
                )
                context.metadata["forensic_response"] = _safe_forensic_value(cached)
                return cached
            _trace_append(trace, pillar="semantic_cache_get", status="miss", started=started)

        if self.enable_schema_validation and params:
            started = time.perf_counter()
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {}
            if isinstance(arguments, dict):
                try:
                    self.schema_validator.validate_input(tool_name, arguments)
                    _trace_append(trace, pillar="schema_validation", status="allowed", started=started)
                except Exception as e:
                    self._handle_violation(
                        context=context, trace=trace, pillar="schema_validation", started=started, error=e
                    )

        if self.enable_circuit_breaker:
            started = time.perf_counter()
            try:
                self.circuit_breaker.check(tool_name)
                _trace_append(trace, pillar="circuit_breaker_check", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="circuit_breaker_check", started=started, error=e
                )

        if self.enable_rate_limit:
            started = time.perf_counter()
            check = self.rate_limiter.check_iteration(
                request_id=request_id,
                session_id=session_id,
                tool_name=tool_name,
            )
            if not check.allowed:
                logger.warning(
                    "rate_limit_blocked request_id=%s session_id=%s reason=%s violation=%s",
                    request_id,
                    session_id,
                    check.message,
                    check.violation,
                )
                self._handle_violation(
                    context=context,
                    trace=trace,
                    pillar="rate_limit",
                    started=started,
                    error=self._rate_limit_error(check),
                )
            else:
                _trace_append(trace, pillar="rate_limit", status="allowed", started=started)

        if self.enable_content_filter and params:
            started = time.perf_counter()
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            text = _extract_text_from_value(arguments)
            try:
                self.content_filter.check(text)
                _trace_append(trace, pillar="content_filter", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(context=context, trace=trace, pillar="content_filter", started=started, error=e)

        if self.enable_prompt_guard and params:
            started = time.perf_counter()
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            text = _extract_text_from_value(arguments)
            if text and self.prompt_guard.is_malicious(text):
                logger.warning("prompt_injection_blocked request_id=%s", request_id)
                self._handle_violation(
                    context=context,
                    trace=trace,
                    pillar="prompt_guard",
                    started=started,
                    error=PromptInjectionError(),
                )
            _trace_append(trace, pillar="prompt_guard", status="allowed", started=started)

        if self.enable_sensitive_classifier and params:
            started = time.perf_counter()
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            text = _extract_text_from_value(arguments)
            pred = self.sensitive_classifier.classify(text)
            context.metadata["sensitive_content"] = {
                "label": pred.label,
                "score": pred.score,
                "matches": pred.matches,
                "source": pred.source,
            }
            if pred.label.lower() in self.sensitive_classifier_block_labels and pred.score >= self.sensitive_classifier.threshold:
                self._handle_violation(
                    context=context,
                    trace=trace,
                    pillar="sensitive_classifier",
                    started=started,
                    error=SensitiveContentError(
                        f"Request blocked: sensitive content classifier label={pred.label} score={pred.score:.2f}"
                    ),
                )
            _trace_append(trace, pillar="sensitive_classifier", status="allowed", started=started)

        if self.enable_semantic_firewall and params:
            started = time.perf_counter()
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            try:
                self.semantic_firewall.check(tool_name, arguments, context)
                _trace_append(trace, pillar="semantic_firewall", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="semantic_firewall", started=started, error=e
                )

        self._enforce_session_tool_scope(
            context=context, trace=trace, session_id=session_id, tool_name=tool_name
        )

        result: Any = None
        try:
            started = time.perf_counter()
            result = await call_next(context)
            _trace_append(trace, pillar="handler", status="ok", started=started)
            if self.enable_circuit_breaker:
                cb_started = time.perf_counter()
                self.circuit_breaker.record_success(tool_name)
                _trace_append(trace, pillar="circuit_breaker_record", status="success", started=cb_started)
        except Exception:
            if self.enable_circuit_breaker:
                cb_started = time.perf_counter()
                self.circuit_breaker.record_failure(tool_name)
                _trace_append(trace, pillar="circuit_breaker_record", status="failure", started=cb_started)
            raise
        finally:
            if self.enable_rate_limit:
                tokens = self._estimate_tool_call_tokens(context, params, result)
                if tokens:
                    context.metadata["tokens_used"] = tokens
                started = time.perf_counter()
                self.rate_limiter.consume_iteration(
                    request_id=request_id,
                    session_id=session_id,
                    tokens=tokens,
                    tool_name=tool_name,
                )
                _trace_append(trace, pillar="rate_limit_consume", status="ok", started=started)

        if self.enable_semantic_cache and result is not None and params:
            started = time.perf_counter()
            arguments = params.get("arguments") or params
            query = _extract_text_from_value(arguments)
            self.semantic_cache.set(tool_name, query, result, scope=tenant_id)
            _trace_append(trace, pillar="semantic_cache_set", status="ok", started=started)

        if self.enable_cost_attribution:
            self._apply_cost_attribution(context, tool_name)

        if self.enable_cost_tracker:
            started = time.perf_counter()
            context.metadata.setdefault("cost", 0.0)
            self.cost_tracker.record(
                context.metadata.get("cost", 0.0),
                session_id=session_id,
                request_id=request_id,
            )
            _trace_append(trace, pillar="cost_tracker_record", status="ok", started=started)

        if self.enable_pii_redaction and result is not None:
            started = time.perf_counter()
            result = self._redact_result_content(result)
            _trace_append(trace, pillar="pii_redaction", status="ok", started=started)

        if result is not None:
            started = time.perf_counter()
            result = self._apply_output_budget_to_result(context, result, tool_name=tool_name)
            if self.enable_output_budget:
                _trace_append(trace, pillar="output_budget", status="ok", started=started)

        if result is not None:
            result = self._apply_grounding_to_result(context, result, trace=trace)

        if result is not None:
            started = time.perf_counter()
            try:
                self._scan_result_for_injection(result)
                _trace_append(trace, pillar="response_scan", status="ok", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="response_scan", started=started, error=e
                )

        context.metadata["forensic_response"] = _safe_forensic_value(result)

        return result

    def _apply_cost_attribution(self, context: MiddlewareContext[Any], tool_name: str) -> None:
        """Merge explicit cost metadata with provider/model token estimates (FinOps)."""
        md = context.metadata
        prov = md.get("llm_provider")
        model = md.get("llm_model")
        try:
            in_tok = int(md.get("llm_input_tokens") or 0)
        except (TypeError, ValueError):
            in_tok = 0
        try:
            out_tok = int(md.get("llm_output_tokens") or 0)
        except (TypeError, ValueError):
            out_tok = 0
        est = estimate_llm_usd(
            provider=str(prov) if prov is not None else None,
            model=str(model) if model is not None else None,
            input_tokens=in_tok,
            output_tokens=out_tok,
        )
        try:
            base = float(md.get("cost") or 0.0)
        except (TypeError, ValueError):
            base = 0.0
        total = max(base, est)
        md["cost"] = total
        md["cost_usd"] = total
        md["cost_dimensions"] = {
            "llm_provider": str(prov) if prov is not None else None,
            "llm_model": str(model) if model is not None else None,
            "tool": tool_name,
            "dataset": md.get("dataset"),
            "underlying_api": md.get("underlying_api"),
        }
        if total > 0:
            MetricsStore.get().record_cost(
                total,
                context.session_id,
                dimensions=md["cost_dimensions"],
                tenant=context.metadata.get("tenant_id"),
            )

    def _redact_result_content(self, result: Any) -> Any:
        """Redact PII from result content items."""
        content = _get_content_from_result(result)
        if not content:
            return result
        redacted = self.pii_redactor.redact_content_items(content)
        _set_content_in_result(result, redacted)
        return result

