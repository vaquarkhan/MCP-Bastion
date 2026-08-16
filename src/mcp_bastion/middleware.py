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
from typing import Any

from mcp_bastion.base import CallNext, Middleware, MiddlewareContext
from mcp_bastion.errors import (
    AgentAccessDeniedError,
    AgentLoopDetectedError,
    ArgumentGuardError,
    ATRRuleMatchError,
    AuthenticationError,
    BastionConfigError,
    BehaviorAnomalyError,
    CatalogDriftError,
    CanaryExfiltrationError,
    ConcurrencyLimitError,
    ExternalPolicyDeniedError,
    GroundingViolationError,
    InvalidStateHandleError,
    LLMScannerBlockedError,
    LoadShedError,
    PromptInjectionError,
    PromptGuardUnavailableError,
    ProtocolVersionError,
    RateLimitExceededError,
    SensitiveContentError,
    ServerVerificationError,
    SessionScopeExceededError,
    TokenBudgetExceededError,
    ToolMetadataPoisoningError,
    ToolNotAllowedError,
)
from mcp_bastion.pillars.circuit_breaker import CircuitBreaker
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.cost_policy import CostPolicyEngine
from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.session_governance import SessionGovernanceRecorder
from mcp_bastion.pillars.pii_redaction import PIIRedactor
from mcp_bastion.pillars.pii_vault import PiiVault
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import RateLimitCheckResult, TokenBucketRateLimiter
from mcp_bastion.pillars.response_scanner import ResponseInjectionScanner
from mcp_bastion.pillars.output_budget import OutputBudget
from mcp_bastion.pillars.grounding_guard import GroundingGuard
from mcp_bastion.pillars.identity_adapters import IdentityAdapter
from mcp_bastion.pillars.agent_iam import AgentIAM
from mcp_bastion.pillars.argument_guards import ArgumentGuardEngine
from mcp_bastion.pillars.business_rules import BusinessRuleEngine
from mcp_bastion.pillars.concurrency import ConcurrencyLimiter
from mcp_bastion.pillars.egress_allowlist import EgressAllowlist
from mcp_bastion.pillars.injection_heuristics import (
    compile_injection_patterns,
    find_injection_match,
)
from mcp_bastion.pillars.budget_principal import mark_authenticated_role, resolve_budget_principal, AUTHENTICATED_ROLE_KEY
from mcp_bastion.pillars.server_verification import ServerVerifier
from mcp_bastion.pillars.tokens import estimate_text_tokens
from mcp_bastion.pillars.rbac import RBAC
from mcp_bastion.pillars.replay_guard import ReplayGuard
from mcp_bastion.pillars.schema_validation import SchemaValidator
from mcp_bastion.pillars.metrics import MetricsStore
from mcp_bastion.pillars.pricing import estimate_llm_usd
from mcp_bastion.pillars.semantic_cache import SemanticCache
from mcp_bastion.pillars.sensitive_classifier import SensitiveContentClassifier
from mcp_bastion.pillars.semantic_firewall import SemanticFirewall
from mcp_bastion.pillars.toxic_flow import ToxicFlowTracker
from mcp_bastion.pillars.state_backend import MemoryStateBackend, StateBackend
from mcp_bastion.pillars.agent_stability import AgentStabilityMonitor
from mcp_bastion.pillars.behavior_fingerprint import BehaviorFingerprintMonitor
from mcp_bastion.pillars.atr_rules import ATRRuleLoader
from mcp_bastion.pillars.auto_repave import AutoRepaveEngine
from mcp_bastion.pillars.canary_goallock import CanaryGoalLock
from mcp_bastion.pillars.llm_scanner import LLMScanner
from mcp_bastion.pillars.secret_redaction import SecretPatternRedactor
from mcp_bastion.mcp_transport import McpTransportConfig, apply_mcp_transport
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


def _get_jsonrpc_method(message: Any) -> str | None:
    if hasattr(message, "root"):
        msg = message.root
    else:
        msg = message
    if hasattr(msg, "method"):
        m = getattr(msg, "method", None)
        return str(m) if m else None
    if isinstance(msg, dict):
        m = msg.get("method")
        return str(m) if m else None
    return None


def _is_resources_read_request(message: Any) -> bool:
    return _get_jsonrpc_method(message) == "resources/read"


GUARDED_MCP_METHODS = frozenset(
    {
        "resources/read",
        "prompts/get",
        "sampling/createMessage",
        "elicitation/create",
    }
)

_GUARDED_METHOD_ALIASES = {
    "notifications/elicitation/create": "elicitation/create",
}


def _normalize_guarded_method(method: str | None) -> str | None:
    if not method:
        return None
    m = str(method).strip()
    return _GUARDED_METHOD_ALIASES.get(m, m)


def _is_guarded_mcp_request(message: Any) -> bool:
    method = _normalize_guarded_method(_get_jsonrpc_method(message))
    return method in GUARDED_MCP_METHODS if method else False


def _extract_inbound_text_for_method(method: str, params: dict | None) -> str:
    """Flatten request params for prompt/content/PII checks on non-tools/call MCP methods."""
    if not params or not isinstance(params, dict):
        return ""
    if method == "resources/read":
        return str(params.get("uri") or "")
    if method == "prompts/get":
        return _extract_text_from_value(
            {"name": params.get("name"), "arguments": params.get("arguments")}
        )
    if method == "sampling/createMessage":
        return _extract_text_from_value(params.get("messages") or params)
    if method in ("elicitation/create",):
        return _extract_text_from_value(params)
    return _extract_text_from_value(params)


def _messages_to_content_items(messages: list[Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for message in messages:
        if hasattr(message, "model_dump"):
            try:
                message = message.model_dump()
            except Exception:
                message = {"content": str(message)}
        if not isinstance(message, dict):
            items.append({"type": "text", "text": str(message)})
            continue
        content = message.get("content")
        if isinstance(content, str):
            items.append({"type": "text", "text": content})
        elif isinstance(content, dict):
            items.append(content)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict):
                    items.append(part)
                else:
                    items.append({"type": "text", "text": str(part)})
        elif content is not None:
            items.append({"type": "text", "text": _extract_text_from_value(content)})
    return items


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
    """Extract content list from MCP result (resources, tools, prompts, etc.)."""
    if result is None:
        return None
    payload = result
    if isinstance(result, dict) and "result" in result:
        payload = result["result"]
    items = None
    if hasattr(payload, "contents"):
        items = payload.contents
    elif isinstance(payload, dict) and "contents" in payload:
        items = payload["contents"]
    elif isinstance(payload, dict) and "content" in payload:
        items = payload["content"]
    elif isinstance(payload, dict) and isinstance(payload.get("messages"), list):
        return _messages_to_content_items(payload["messages"])
    elif hasattr(payload, "messages") and isinstance(getattr(payload, "messages", None), list):
        return _messages_to_content_items(payload.messages)
    if items is None:
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


def _inject_canary_snippet_into_result(result: Any, snippet: str) -> Any:
    """Add canary as a separate text block without mutating existing resource/prompt bodies."""
    payload = result
    wrapper: dict[str, Any] | None = None
    if isinstance(result, dict) and "result" in result:
        wrapper = result
        payload = result["result"]

    if isinstance(payload, dict) and isinstance(payload.get("messages"), list):
        messages = [dict(m) if isinstance(m, dict) else {"role": "user", "content": str(m)} for m in payload["messages"]]
        messages.append({"role": "user", "content": snippet})
        updated = {**payload, "messages": messages}
        if wrapper is not None:
            return {**wrapper, "result": updated}
        payload.update(updated)
        return result

    content = _get_content_from_result(result)
    if content is None:
        content = []
    else:
        content = [dict(item) if isinstance(item, dict) else {"type": "text", "text": str(item)} for item in content]
    content.append({"type": "text", "text": snippet})
    _set_content_in_result(result, content)
    return result


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
        pii_vault: PiiVault | None = None,
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
        enable_pii_vault: bool = False,
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
        tool_metadata_guard_use_heuristics: bool = True,
        egress_allowlist: EgressAllowlist | None = None,
        enable_egress_allowlist: bool = False,
        concurrency_limiter: ConcurrencyLimiter | None = None,
        enable_concurrency: bool = False,
        business_rules: BusinessRuleEngine | None = None,
        enable_business_rules: bool = False,
        tool_action_tiers: dict[str, str] | None = None,
        enable_response_scan: bool = False,
        response_scan_extra_patterns: list[str] | None = None,
        response_scan_use_prompt_guard: bool = False,
        enable_discovery_filter: bool = False,
        discovery_filter_minimize_schemas: bool = False,
        discovery_filter_max_description_chars: int = 160,
        discovery_filter_strip_schema_descriptions: bool = True,
        live_catalog_pin: Any = None,
        enable_live_catalog_pin: bool = False,
        response_scanner: ResponseInjectionScanner | None = None,
        enable_output_budget: bool = False,
        output_budget: OutputBudget | None = None,
        enable_grounding_guard: bool = False,
        grounding_guard: GroundingGuard | None = None,
        agent_iam: AgentIAM | None = None,
        enable_agent_iam: bool = False,
        server_verifier: ServerVerifier | None = None,
        enable_server_verification: bool = False,
        state_backend: StateBackend | None = None,
        argument_guards: ArgumentGuardEngine | None = None,
        enable_argument_guards: bool = False,
        cost_policy: CostPolicyEngine | None = None,
        enable_cost_policy: bool = False,
        config_source_path: str | None = None,
        enable_governance_attestation: bool = True,
        enable_boundary_mode: bool = False,
        identity_adapter: IdentityAdapter | None = None,
        enable_identity_adapter: bool = False,
        canary_goallock: CanaryGoalLock | None = None,
        enable_canary_goallock: bool = False,
        atr_rules: ATRRuleLoader | None = None,
        enable_atr_rules: bool = False,
        llm_scanner: LLMScanner | None = None,
        enable_llm_scanner: bool = False,
        auto_repave: AutoRepaveEngine | None = None,
        enable_auto_repave: bool = False,
        secret_redactor: SecretPatternRedactor | None = None,
        enable_secret_redaction: bool = False,
        mcp_transport_config: McpTransportConfig | None = None,
        agent_stability: AgentStabilityMonitor | None = None,
        enable_agent_stability: bool = False,
        agent_stability_on_detect: str = "inject",
        behavior_fingerprint: BehaviorFingerprintMonitor | None = None,
        enable_behavior_fingerprint: bool = False,
        behavior_fingerprint_on_detect: str = "warn",
        enable_toxic_flow: bool = False,
        toxic_flow_tracker: ToxicFlowTracker | None = None,
        toxic_flow_on_violation: str = "block",
        toxic_flow_block_private_egress: bool = False,
    ) -> None:
        self.prompt_guard = prompt_guard or PromptGuardEngine()
        self.pii_redactor = pii_redactor or PIIRedactor()
        self.pii_vault = pii_vault
        self.enable_pii_vault = bool(enable_pii_vault) and pii_vault is not None
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
        self._state_backend = state_backend or MemoryStateBackend()
        self._session_tools_lock = threading.Lock()
        self.enable_tool_metadata_guard = enable_tool_metadata_guard
        self.tool_metadata_guard_on_poison = (tool_metadata_guard_on_poison or "remove_tool").strip().lower()
        self.tool_metadata_guard_use_content_filter = bool(tool_metadata_guard_use_content_filter)
        self.tool_metadata_guard_use_heuristics = bool(tool_metadata_guard_use_heuristics)
        self._tool_metadata_heuristics = compile_injection_patterns()
        self.egress_allowlist = egress_allowlist or EgressAllowlist()
        self.enable_egress_allowlist = bool(enable_egress_allowlist)
        self.concurrency_limiter = concurrency_limiter or ConcurrencyLimiter()
        self.enable_concurrency = bool(enable_concurrency)
        self.business_rules = business_rules or BusinessRuleEngine()
        self.enable_business_rules = bool(enable_business_rules)
        self.tool_action_tiers = dict(tool_action_tiers or {})
        self.enable_response_scan = enable_response_scan
        self.response_scan_use_prompt_guard = bool(response_scan_use_prompt_guard)
        self.response_scanner = response_scanner or ResponseInjectionScanner(
            extra_patterns=response_scan_extra_patterns or [],
            prompt_guard=self.prompt_guard,
            use_prompt_guard=self.response_scan_use_prompt_guard,
        )
        if response_scanner is not None and self.response_scan_use_prompt_guard:
            self.response_scanner.prompt_guard = self.prompt_guard
            self.response_scanner.use_prompt_guard = True
        self.enable_toxic_flow = bool(enable_toxic_flow)
        self.toxic_flow = toxic_flow_tracker or ToxicFlowTracker(
            enabled=self.enable_toxic_flow,
            on_violation=toxic_flow_on_violation,
            block_private_to_egress=toxic_flow_block_private_egress,
        )
        if self.enable_toxic_flow:
            self.toxic_flow.enabled = True
            self.toxic_flow.on_violation = toxic_flow_on_violation if toxic_flow_on_violation in ("block", "warn") else "block"
            self.toxic_flow.block_private_to_egress = bool(toxic_flow_block_private_egress)
        self.enable_discovery_filter = enable_discovery_filter
        self.discovery_filter_minimize_schemas = bool(discovery_filter_minimize_schemas)
        self.discovery_filter_max_description_chars = max(0, int(discovery_filter_max_description_chars))
        self.discovery_filter_strip_schema_descriptions = bool(discovery_filter_strip_schema_descriptions)
        self.live_catalog_pin = live_catalog_pin
        self.enable_live_catalog_pin = bool(enable_live_catalog_pin) and live_catalog_pin is not None

        self.output_budget = output_budget or OutputBudget()
        self.enable_output_budget = enable_output_budget
        self.grounding_guard = grounding_guard or GroundingGuard()
        self.enable_grounding_guard = enable_grounding_guard
        self.agent_iam = agent_iam
        self.enable_agent_iam = enable_agent_iam and agent_iam is not None
        self.server_verifier = server_verifier
        self.enable_server_verification = enable_server_verification and server_verifier is not None
        self.argument_guards = argument_guards
        self.enable_argument_guards = enable_argument_guards and argument_guards is not None
        self.cost_policy = cost_policy
        self.enable_cost_policy = enable_cost_policy and cost_policy is not None
        self.config_source_path = config_source_path
        self.enable_governance_attestation = enable_governance_attestation
        self.enable_boundary_mode = enable_boundary_mode
        self.identity_adapter = identity_adapter
        self.enable_identity_adapter = enable_identity_adapter and identity_adapter is not None
        self.canary_goallock = canary_goallock
        self.enable_canary_goallock = enable_canary_goallock and canary_goallock is not None
        self.atr_rules = atr_rules
        self.enable_atr_rules = enable_atr_rules and atr_rules is not None
        self.llm_scanner = llm_scanner
        self.enable_llm_scanner = enable_llm_scanner and llm_scanner is not None
        self.auto_repave = auto_repave
        self.enable_auto_repave = enable_auto_repave and auto_repave is not None
        self.secret_redactor = secret_redactor
        self.enable_secret_redaction = enable_secret_redaction and secret_redactor is not None
        self.mcp_transport_config = mcp_transport_config or McpTransportConfig()
        self.agent_stability = agent_stability
        self.enable_agent_stability = enable_agent_stability and agent_stability is not None
        self.agent_stability_on_detect = (agent_stability_on_detect or "inject").strip().lower()
        self.behavior_fingerprint = behavior_fingerprint
        self.enable_behavior_fingerprint = enable_behavior_fingerprint and behavior_fingerprint is not None
        self.behavior_fingerprint_on_detect = (behavior_fingerprint_on_detect or "warn").strip().lower()
        self._governance = SessionGovernanceRecorder.get()

        if (
            self.enable_tool_metadata_guard
            and not self.enable_content_filter
            and not self.enable_prompt_guard
            and not self.tool_metadata_guard_use_heuristics
        ):
            raise BastionConfigError(
                "tool_metadata_guard is enabled but both content_filter and prompt_guard are disabled - "
                "enable heuristics or at least one metadata scanner, or disable tool_metadata_guard"
            )

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

    def _finops_keys(self, context: MiddlewareContext[Any]) -> tuple[str, str]:
        principal_id, tenant_id = resolve_budget_principal(context, default_tenant_id=self.default_tenant_id)
        context.metadata["_budget_principal"] = principal_id
        context.metadata["_budget_tenant"] = tenant_id
        return principal_id, tenant_id

    def _vault_session_key(self, context: MiddlewareContext[Any]) -> str:
        """Stable session key for PII vault maps (tenant + session/handle)."""
        tenant = str(context.metadata.get("tenant_id") or self.default_tenant_id or "default")
        scope = (
            context.metadata.get("_mcp_transport_scope")
            or context.session_id
            or context.metadata.get("_budget_principal")
            or "anonymous"
        )
        return f"{tenant}|{scope}"

    def _hydrate_tool_arguments(
        self,
        context: MiddlewareContext[Any],
        params: dict | None,
        *,
        trace: list[dict[str, Any]],
    ) -> None:
        """Restore vault tokens in tool arguments in-place before the handler runs."""
        if not self.enable_pii_vault or self.pii_vault is None or not isinstance(params, dict):
            return
        started = time.perf_counter()
        arguments = params.get("arguments")
        if arguments is None:
            return
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                from mcp_bastion.pillars.pii_vault import count_vault_tokens

                restored = self.pii_vault.restore_text(arguments, self._vault_session_key(context))
                if restored != arguments:
                    params["arguments"] = restored
                    n = max(0, count_vault_tokens(arguments) - count_vault_tokens(restored))
                    MetricsStore.get().record_pii_vault_hydrate(n or 1)
                    _trace_append(trace, pillar="pii_vault_hydrate", status="ok", started=started)
                return
        from mcp_bastion.pillars.pii_vault import count_vault_tokens

        before = json.dumps(arguments, default=str, sort_keys=True)
        restored_args = self.pii_vault.restore_value(arguments, self._vault_session_key(context))
        if restored_args != arguments:
            params["arguments"] = restored_args
            after = json.dumps(restored_args, default=str, sort_keys=True)
            n = max(0, count_vault_tokens(before) - count_vault_tokens(after))
            MetricsStore.get().record_pii_vault_hydrate(n or 1)
            _trace_append(trace, pillar="pii_vault_hydrate", status="ok", started=started)

    def _semantic_cache_scope(self, context: MiddlewareContext[Any], tenant_id: str) -> str:
        return str(context.metadata.get("_mcp_transport_scope") or tenant_id)

    def _resolve_rate_session(
        self,
        context: MiddlewareContext[Any],
        session_id: str | None,
        agent_policy: Any,
    ) -> str:
        if agent_policy is not None and self.agent_iam is not None:
            base = f"principal:agent:{agent_policy.agent_id}"
        else:
            base = context.metadata.get("_budget_principal") or session_id or "default"
        transport_key = context.metadata.get("_mcp_rate_limit_key")
        if self.mcp_transport_config.enabled and transport_key:
            return str(transport_key)
        return str(base)

    def _apply_mcp_transport_context(
        self,
        context: MiddlewareContext[Any],
        *,
        tenant_id: str,
        trace: list[dict[str, Any]],
    ) -> None:
        if not self.mcp_transport_config.enabled:
            return
        started = time.perf_counter()
        try:
            principal_id, _ = self._finops_keys(context)
            apply_mcp_transport(
                context,
                self.mcp_transport_config,
                principal_id=principal_id,
                tenant_id=tenant_id,
            )
            _trace_append(
                trace,
                pillar="mcp_transport",
                status=str(context.metadata.get("mcp_transport_mode") or "ok"),
                started=started,
            )
        except (ProtocolVersionError, InvalidStateHandleError) as e:
            self._handle_violation(
                context=context, trace=trace, pillar="mcp_transport", started=started, error=e
            )

    def _apply_agent_stability_to_result(
        self,
        context: MiddlewareContext[Any],
        result: Any,
        *,
        trace: list[dict[str, Any]],
    ) -> Any:
        if not self.enable_agent_stability or self.agent_stability is None or result is None:
            return result
        scope = str(
            context.metadata.get("_mcp_rate_limit_key")
            or context.session_id
            or context.metadata.get("tenant_id")
            or "default"
        )
        observation = _extract_text_from_value(result)
        started = time.perf_counter()
        check = self.agent_stability.check_and_record(scope, observation)
        if not check.repetitive:
            _trace_append(trace, pillar="agent_stability", status="ok", started=started)
            return result
        detail = f"similarity={check.similarity:.2f} repeats={check.repeats}"
        mode = self.agent_stability_on_detect
        if mode == "block":
            self._handle_violation(
                context=context,
                trace=trace,
                pillar="agent_stability",
                started=started,
                error=AgentLoopDetectedError(
                    f"Repetitive agent tool loop detected ({detail})"
                ),
            )
        if mode == "inject":
            result = AgentStabilityMonitor.inject_hint_into_result(result)
            _trace_append(trace, pillar="agent_stability", status="inject", started=started, detail=detail)
        else:
            context.metadata.setdefault("agent_stability", {})["repetitive"] = True
            _trace_append(trace, pillar="agent_stability", status="warn", started=started, detail=detail)
        return result

    def _apply_behavior_fingerprint_check(
        self,
        context: MiddlewareContext[Any],
        tool_name: str,
        *,
        trace: list[dict[str, Any]],
    ) -> None:
        if not self.enable_behavior_fingerprint or self.behavior_fingerprint is None or not tool_name:
            return
        scope = str(
            context.metadata.get("_mcp_rate_limit_key")
            or context.metadata.get("_budget_principal")
            or context.session_id
            or "default"
        )
        started = time.perf_counter()
        check = self.behavior_fingerprint.check_and_record(scope, tool_name)
        if not check.anomalous:
            _trace_append(trace, pillar="behavior_fingerprint", status="ok", started=started)
            return
        detail = check.message or check.kind or "anomaly"
        context.metadata.setdefault("behavior_fingerprint", {})["anomaly"] = {
            "kind": check.kind,
            "message": detail,
            "overlap": check.overlap,
        }
        try:
            from mcp_bastion.pillars.metrics import MetricsStore

            MetricsStore.get().record_behavior_anomaly(
                kind=str(check.kind or "behavior_anomaly"),
                tool=tool_name,
                message=str(detail),
                value=float(check.overlap or check.current_rate or 0.0),
                baseline=float(check.baseline_rate or 1.0),
            )
        except Exception:
            pass
        mode = self.behavior_fingerprint_on_detect
        if mode == "block":
            self._handle_violation(
                context=context,
                trace=trace,
                pillar="behavior_fingerprint",
                started=started,
                error=BehaviorAnomalyError(f"Behavioral anomaly: {detail}"),
            )
        _trace_append(trace, pillar="behavior_fingerprint", status="warn", started=started, detail=detail)

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
            if summary.tokens_saved > 0:
                try:
                    from mcp_bastion.pillars.metrics import MetricsStore

                    dims = context.metadata.get("cost_dimensions") or {}
                    MetricsStore.get().record_tokens_saved(
                        int(summary.tokens_saved),
                        source="output_budget",
                        provider=(dims.get("llm_provider") if isinstance(dims, dict) else None),
                        model=(dims.get("llm_model") if isinstance(dims, dict) else None),
                        as_output=True,
                    )
                except Exception:
                    pass
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

    def _record_governance(
        self,
        context: MiddlewareContext[Any],
        *,
        method: str,
        tool: str | None,
        pillar: str,
        status: str,
    ) -> None:
        if not self.enable_governance_attestation:
            return
        try:
            cost = float(context.metadata.get("cost") or context.metadata.get("cost_usd") or 0.0)
        except (TypeError, ValueError):
            cost = 0.0
        self._governance.record(
            session_id=context.session_id or "default",
            request_id=context.request_id,
            method=method,
            tool=tool,
            pillar=pillar,
            status=status,
            cost_usd=cost,
            metadata={
                "tenant_id": context.metadata.get("tenant_id"),
                "principal_id": context.metadata.get("_budget_principal"),
                "cost_policy_actions": context.metadata.get("cost_policy_actions"),
            },
        )

    def _apply_discovery_filter(self, context: MiddlewareContext[Any], result: Any) -> Any:
        """Strip tools from tools/list that are not on the allowlist (reduces agent context tokens)."""
        force = bool(context.metadata.get("_cost_policy_force_discovery_filter"))
        if not force and (not self.enable_discovery_filter or not self.enable_tool_allowlist):
            return result
        if force and not self.enable_tool_allowlist:
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
            # Rough catalog-token savings from tools not advertised to the agent.
            tokens_saved = 0
            try:
                import json

                from mcp_bastion.pillars.tokens import count_text_tokens

                hidden_payload = []
                for entry in tools:
                    td = _tool_entry_to_dict(entry)
                    if str(td.get("name") or "") in hidden:
                        hidden_payload.append(td)
                if hidden_payload:
                    tokens_saved = max(0, count_text_tokens(json.dumps(hidden_payload)))
            except Exception:
                tokens_saved = max(0, len(hidden) * 80)
            context.metadata.setdefault("discovery_filter", {}).update(
                {
                    "hidden_tools": hidden,
                    "original_count": len(tools),
                    "kept_count": len(kept),
                    "tokens_saved": tokens_saved,
                }
            )
            if tokens_saved > 0:
                try:
                    from mcp_bastion.pillars.metrics import MetricsStore

                    MetricsStore.get().record_tokens_saved(
                        tokens_saved,
                        source="discovery_filter",
                        as_output=False,
                    )
                except Exception:
                    pass
        if len(kept) == len(tools):
            return result
        return _set_tools_on_result(result, kept)

    def _apply_schema_minimize(self, context: MiddlewareContext[Any], result: Any) -> Any:
        """Truncate tool descriptions / strip schema descriptions on tools/list (opt-in)."""
        if not self.discovery_filter_minimize_schemas:
            return result
        tools = _get_tools_list_from_result(result)
        if tools is None or not tools:
            return result
        from mcp_bastion.pillars.schema_minimize import minimize_tools

        minimized, tokens_saved = minimize_tools(
            tools,
            max_description_chars=self.discovery_filter_max_description_chars,
            strip_schema_descriptions=self.discovery_filter_strip_schema_descriptions,
            to_dict=_tool_entry_to_dict,
        )
        context.metadata.setdefault("schema_minimize", {}).update(
            {
                "tool_count": len(minimized),
                "max_description_chars": self.discovery_filter_max_description_chars,
                "strip_schema_descriptions": self.discovery_filter_strip_schema_descriptions,
                "tokens_saved": tokens_saved,
            }
        )
        if tokens_saved > 0:
            try:
                from mcp_bastion.pillars.metrics import MetricsStore

                MetricsStore.get().record_tokens_saved(
                    tokens_saved,
                    source="schema_minimize",
                    as_output=False,
                )
            except Exception:
                pass
        return _set_tools_on_result(result, minimized)

    def _apply_live_catalog_pin(self, context: MiddlewareContext[Any], result: Any) -> Any:
        """Pin tools/list fingerprint on first sight; warn or block on drift."""
        if not self.enable_live_catalog_pin or self.live_catalog_pin is None:
            return result
        tools = _get_tools_list_from_result(result)
        if tools is None or not tools:
            return result
        tool_dicts = [_tool_entry_to_dict(t) for t in tools]
        tenant = str(context.metadata.get("tenant_id") or self.default_tenant_id or "default")
        scope = f"{tenant}|{context.session_id or 'global'}"
        outcome = self.live_catalog_pin.check(tool_dicts, scope=scope)
        context.metadata.setdefault("live_catalog_pin", {}).update(outcome)
        if outcome.get("status") == "drift":
            detail = str(outcome.get("detail") or "catalog fingerprint drift")
            err = CatalogDriftError(
                f"Tool catalog drift detected: {detail} "
                f"(got {str(outcome.get('fingerprint') or '')[:16]}…)"
            )
            if self.live_catalog_pin.on_drift == "block" and not self.shadow_mode:
                raise err
            bucket = "shadow_blocked" if self.shadow_mode else "catalog_drift_warnings"
            context.metadata.setdefault(bucket, []).append(
                {"pillar": "live_catalog_pin", "reason": str(err), "outcome": outcome}
            )
            logger.warning("live_catalog_pin drift scope=%s detail=%s", scope, detail)
        return result

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
                allowed = self._state_backend.set_add(
                    f"session_tools:{session_id}",
                    tool_name,
                    max_size=self.session_max_unique_tools,
                )
                if not allowed:
                    raise SessionScopeExceededError(
                        f"Request blocked: session exceeded max distinct tools ({self.session_max_unique_tools})"
                    )
            _trace_append(trace, pillar="session_tool_scope", status="allowed", started=started)
        except Exception as e:
            self._handle_violation(context=context, trace=trace, pillar="session_tool_scope", started=started, error=e)

    def _inspect_tool_metadata_text(self, text: str) -> str | None:
        """Return a short reason if metadata should fail checks; None if acceptable."""
        if self.tool_metadata_guard_use_heuristics:
            matched = find_injection_match(text, self._tool_metadata_heuristics)
            if matched:
                return f"injection heuristic matched tool metadata: {matched}"
        if self.tool_metadata_guard_use_content_filter and self.enable_content_filter:
            try:
                self.content_filter.check(text)
            except Exception as e:
                return str(e)
        if self.enable_prompt_guard and text.strip():
            try:
                if self.prompt_guard.is_malicious(text):
                    return "prompt_guard flagged tool metadata"
            except PromptGuardUnavailableError as e:
                return str(e)
        return None

    def _apply_tool_metadata_guard(self, context: MiddlewareContext[Any], result: Any) -> Any:
        """
        Scan tools/list (or equivalent) responses for poisoned descriptions/schemas.

        Mitigates description-based tool poisoning when the MCP host routes list results
        through this middleware (WhatsApp-class attack path).
        """
        if not self.enable_tool_metadata_guard:
            return result
        if (
            not self.enable_content_filter
            and not self.enable_prompt_guard
            and not self.tool_metadata_guard_use_heuristics
        ):
            raise BastionConfigError(
                "tool_metadata_guard is enabled but both content_filter and prompt_guard are disabled"
            )

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

    def _maybe_auto_repave(self, error: Exception, context: MiddlewareContext[Any]) -> None:
        if not self.enable_auto_repave or self.auto_repave is None:
            return
        event: str | None = None
        if isinstance(error, CanaryExfiltrationError):
            event = "canary_detections"
        elif isinstance(error, LLMScannerBlockedError):
            event = "llm_scanner_blocks"
        elif isinstance(error, ATRRuleMatchError):
            event = "atr_rule_matches"
        if not event:
            return
        fired = self.auto_repave.record_detection(event)
        if fired:
            context.metadata.setdefault("auto_repave", {})["actions"] = fired

    def _handle_violation(
        self,
        *,
        context: MiddlewareContext[Any],
        trace: list[dict[str, Any]],
        pillar: str,
        started: float,
        error: Exception,
    ) -> None:
        self._maybe_auto_repave(error, context)
        if self.shadow_mode:
            context.metadata.setdefault("shadow_blocked", []).append(
                {
                    "pillar": pillar,
                    "reason": str(error),
                    "error_type": error.__class__.__name__,
                }
            )
            _trace_append(trace, pillar=pillar, status="would_block", started=started, detail=str(error))
            try:
                from mcp_bastion.pillars.metrics import MetricsStore

                tool = None
                params = (context.message or {}).get("params") if isinstance(context.message, dict) else None
                if isinstance(params, dict):
                    tool = params.get("name")
                MetricsStore.get().record_shadow_would_block(
                    pillar=pillar,
                    reason=str(error),
                    tool=str(tool) if tool else None,
                )
            except Exception:
                pass
            return
        _trace_append(trace, pillar=pillar, status="blocked", started=started, detail=str(error))
        method = str((context.message or {}).get("method") or "unknown")
        tool = None
        params = (context.message or {}).get("params") if isinstance(context.message, dict) else None
        if isinstance(params, dict):
            tool = params.get("name")
        self._record_governance(context, method=method, tool=str(tool) if tool else None, pillar=pillar, status="blocked")
        raise error

    async def _gate_agent_iam_for_request(
        self,
        context: MiddlewareContext[Any],
        *,
        method: str,
        tool_name: str | None = None,
        resource_uri: str | None = None,
    ) -> None:
        """Authenticate agent and enforce method/tool/resource policy."""
        if not self.enable_agent_iam or self.agent_iam is None:
            return
        trace: list[dict[str, Any]] = context.metadata.setdefault("pillar_trace", [])
        started = time.perf_counter()
        raw_token = context.metadata.get(self.agent_iam.token_metadata_key)
        agent_policy = self.agent_iam.authenticate(None if raw_token is None else str(raw_token))
        self.agent_iam.apply_to_context(context, agent_policy)
        if agent_policy is not None:
            self.agent_iam.check_method(agent_policy, method)
            if tool_name is not None:
                self.agent_iam.check_tool(agent_policy, tool_name)
            if resource_uri is not None:
                self.agent_iam.check_resource(agent_policy, resource_uri)
            isolated = self.agent_iam.isolated_session_id(agent_policy, context.session_id)
            if isolated != context.session_id:
                context.session_id = isolated
        context.metadata["_agent_policy"] = agent_policy
        _trace_append(trace, pillar="agent_iam", status="allowed", started=started)

    def _record_prompt_guard_scan(self, context: MiddlewareContext[Any], text: str) -> tuple[bool, bool]:
        """Run PromptGuard once and cache heuristic/ML results for LLM scanner reuse."""
        heuristic_hit = bool(self.prompt_guard.heuristic_match(text))
        malicious = False
        if text.strip():
            malicious = self.prompt_guard.is_malicious(text)
        context.metadata["bastion_prompt_guard_scan"] = {
            "heuristic_hit": heuristic_hit,
            "malicious": malicious,
        }
        return heuristic_hit, malicious

    def _apply_inbound_text_guards(
        self,
        *,
        context: MiddlewareContext[Any],
        trace: list[dict[str, Any]],
        text: str,
        request_id: str | None,
    ) -> None:
        """Prompt, content, and sensitive-classifier checks on arbitrary inbound MCP text."""
        if self.enable_content_filter and text.strip():
            started = time.perf_counter()
            try:
                self.content_filter.check(text)
                _trace_append(trace, pillar="content_filter", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(context=context, trace=trace, pillar="content_filter", started=started, error=e)

        if self.enable_prompt_guard and text.strip():
            started = time.perf_counter()
            try:
                _heuristic_hit, malicious = self._record_prompt_guard_scan(context, text)
            except PromptGuardUnavailableError as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="prompt_guard", started=started, error=e
                )
            if malicious:
                logger.warning("prompt_injection_blocked request_id=%s (mcp_surface)", request_id)
                self._handle_violation(
                    context=context,
                    trace=trace,
                    pillar="prompt_guard",
                    started=started,
                    error=PromptInjectionError(),
                )
            _trace_append(trace, pillar="prompt_guard", status="allowed", started=started)

        if self.enable_sensitive_classifier and text.strip():
            started = time.perf_counter()
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

    def _process_guarded_response(
        self,
        context: MiddlewareContext[Any],
        result: Any,
        *,
        trace: list[dict[str, Any]],
        method: str,
        surface_key: str | None = None,
    ) -> Any:
        """Outbound PII redaction, output budget, grounding, and response scan for MCP surface calls."""
        if result is None:
            return result
        if self.enable_pii_redaction:
            started = time.perf_counter()
            result = self._redact_result_content(result, context=context)
            pillar = "pii_vault_abstract" if self.enable_pii_vault else "pii_redaction"
            _trace_append(trace, pillar=pillar, status="ok", started=started)
            if self.enable_toxic_flow:
                kinds = context.metadata.pop("_bastion_taint_kinds", None) or []
                if kinds:
                    self.toxic_flow.mark(
                        context.session_id, kinds=kinds, tool=surface_key or method
                    )
        result = self._apply_output_budget_to_result(context, result, tool_name=surface_key or method)
        result = self._apply_grounding_to_result(context, result, trace=trace)
        if self.enable_response_scan:
            started = time.perf_counter()
            try:
                self._scan_result_for_injection(result)
                _trace_append(trace, pillar="response_scan", status="ok", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="response_scan", started=started, error=e
                )
        if (
            self.enable_canary_goallock
            and self.canary_goallock is not None
            and method in ("prompts/get", "resources/read")
        ):
            snippet = self.canary_goallock.context_snippet()
            context.metadata["bastion_canary_snippet"] = snippet
            started = time.perf_counter()
            result = _inject_canary_snippet_into_result(result, snippet)
            _trace_append(trace, pillar="canary_goallock", status="injected", started=started)
        return result

    async def _handle_guarded_surface(
        self,
        context: MiddlewareContext[Any],
        call_next: CallNext[Any],
        *,
        method: str,
    ) -> Any:
        """Apply security pillars to resources/read, prompts/get, sampling, and elicitation."""
        msg = context.message
        params = _get_params(msg)
        request_id = _get_request_id(msg) or context.request_id
        session_id = context.session_id
        tenant_id = resolve_tenant_id(context, self.default_tenant_id)
        context.metadata["tenant_id"] = tenant_id
        trace: list[dict[str, Any]] = context.metadata.setdefault("pillar_trace", [])
        self._apply_mcp_transport_context(context, tenant_id=tenant_id, trace=trace)
        session_id = context.session_id or session_id
        surface_key = method.replace("/", "_")

        context.metadata["forensic_request"] = {
            "request_id": request_id,
            "session_id": session_id,
            "tenant_id": tenant_id,
            "method": method,
            "params": _safe_forensic_value(params or {}),
        }
        context.metadata["replay_payload"] = {
            "method": method,
            "params": _safe_forensic_value(params or {}),
            "request_id": request_id,
            "session_id": session_id,
            "tenant_id": tenant_id,
        }

        if self.enable_replay_guard:
            started = time.perf_counter()
            try:
                self.replay_guard.check(msg)
                _trace_append(trace, pillar="replay_guard", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(context=context, trace=trace, pillar="replay_guard", started=started, error=e)

        resource_uri = None
        if method == "resources/read" and isinstance(params, dict):
            resource_uri = str(params.get("uri") or "") or None

        agent_policy = None
        self._apply_identity_adapter(context, trace)
        if self.enable_agent_iam and self.agent_iam is not None:
            started = time.perf_counter()
            try:
                await self._gate_agent_iam_for_request(
                    context,
                    method=method,
                    resource_uri=resource_uri,
                )
                agent_policy = context.metadata.get("_agent_policy")
            except Exception as e:
                self._handle_violation(context=context, trace=trace, pillar="agent_iam", started=started, error=e)

        if agent_policy is not None and self.agent_iam is not None:
            isolated = self.agent_iam.isolated_session_id(agent_policy, session_id)
            if isolated and isolated != session_id:
                session_id = isolated
                context.session_id = isolated

        if self.enable_cost_tracker:
            started = time.perf_counter()
            try:
                budget_principal, budget_tenant = self._finops_keys(context)
                self.cost_tracker.check(
                    session_id=session_id,
                    request_id=request_id,
                    principal_id=budget_principal,
                    tenant_id=budget_tenant,
                )
                _trace_append(trace, pillar="cost_tracker_precheck", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="cost_tracker_precheck", started=started, error=e
                )

        if self.enable_rate_limit:
            started = time.perf_counter()
            limiter = self.rate_limiter
            rate_session = self._resolve_rate_session(context, session_id, agent_policy)
            if agent_policy is not None and self.agent_iam is not None:
                agent_limiter = self.agent_iam.rate_limiter_for(agent_policy)
                if agent_limiter is not None:
                    limiter = agent_limiter
            check = limiter.check_and_consume(
                request_id=request_id,
                session_id=rate_session,
                tool_name=surface_key,
            )
            if not check.allowed:
                self._handle_violation(
                    context=context,
                    trace=trace,
                    pillar="rate_limit",
                    started=started,
                    error=self._rate_limit_error(check),
                )
            _trace_append(trace, pillar="rate_limit", status="allowed", started=started)
            context.metadata["_rate_limiter"] = limiter
            context.metadata["_rate_session"] = rate_session

        inbound_text = _extract_inbound_text_for_method(method, params if isinstance(params, dict) else None)
        self._apply_inbound_text_guards(
            context=context,
            trace=trace,
            text=inbound_text,
            request_id=request_id,
        )

        result = await call_next(context)

        if self.enable_rate_limit:
            tokens = estimate_text_tokens(inbound_text, _extract_text_from_value(result))
            consume_limiter = context.metadata.get("_rate_limiter") or self.rate_limiter
            consume_session = context.metadata.get("_rate_session") or session_id
            consume_limiter.add_tokens(
                request_id=request_id,
                session_id=consume_session,
                tokens=tokens,
            )

        if self.enable_cost_tracker:
            context.metadata.setdefault("cost", 0.0)
            budget_principal = context.metadata.get("_budget_principal")
            budget_tenant = context.metadata.get("_budget_tenant")
            if budget_principal is None or budget_tenant is None:
                budget_principal, budget_tenant = self._finops_keys(context)
            self.cost_tracker.record(
                context.metadata.get("cost", 0.0),
                session_id=session_id,
                request_id=request_id,
                principal_id=budget_principal,
                tenant_id=budget_tenant,
            )

        result = self._process_guarded_response(
            context, result, trace=trace, method=method, surface_key=surface_key
        )
        context.metadata["forensic_response"] = _safe_forensic_value(result)
        return result

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
                if not self.enable_concurrency:
                    return await self._handle_call_tool(context, call_next)
                params = _get_params(msg)
                tool_name = _get_tool_name_from_params(params)
                tenant_id = resolve_tenant_id(context, self.default_tenant_id)
                caller_id = str(
                    context.metadata.get("principal_id")
                    or context.metadata.get("agent_id")
                    or context.metadata.get("caller_id")
                    or context.session_id
                    or "anonymous"
                )
                trace = context.metadata.setdefault("pillar_trace", [])
                admitted = False
                started = time.perf_counter()
                try:
                    outcome = self.concurrency_limiter.try_acquire(caller_id, tenant_id)
                    if outcome == "concurrency_limit":
                        self._handle_violation(
                            context=context,
                            trace=trace,
                            pillar="concurrency",
                            started=started,
                            error=ConcurrencyLimitError(
                                f"Request blocked: concurrency limit reached for caller {caller_id!r} or tenant {tenant_id!r}"
                            ),
                        )
                    if outcome == "load_shed":
                        self._handle_violation(
                            context=context,
                            trace=trace,
                            pillar="concurrency",
                            started=started,
                            error=LoadShedError(
                                f"Request blocked: admission capacity exhausted for tenant {tenant_id!r}"
                            ),
                        )
                    admitted = outcome == "admit"
                    _trace_append(trace, pillar="concurrency", status="allowed", started=started)
                    return await self._handle_call_tool(context, call_next)
                finally:
                    if admitted:
                        self.concurrency_limiter.release(caller_id, tenant_id)
            guarded_method = _normalize_guarded_method(_get_jsonrpc_method(msg))
            if guarded_method in GUARDED_MCP_METHODS:
                return await self._handle_guarded_surface(context, call_next, method=guarded_method)
            result = await call_next(context)
            if result is not None and _is_read_resource_result(result):
                trace = context.metadata.setdefault("pillar_trace", [])
                result = self._process_guarded_response(
                    context,
                    result,
                    trace=trace,
                    method="resources/read",
                    surface_key="resources_read",
                )
            if result is not None:
                result = self._apply_discovery_filter(context, result)
                result = self._apply_live_catalog_pin(context, result)
                result = self._apply_schema_minimize(context, result)
                result = self._apply_tool_metadata_guard(context, result)
            return result
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000
            context.metadata["elapsed_ms"] = round(elapsed_ms, 2)
            logger.debug("request done elapsed_ms=%.2f", elapsed_ms)

    def _apply_identity_adapter(self, context: MiddlewareContext[Any], trace: list[Any]) -> None:
        if not self.enable_identity_adapter or self.identity_adapter is None:
            return
        started = time.perf_counter()
        try:
            self.identity_adapter.stamp(context)
            _trace_append(trace, pillar="identity_adapter", status="allowed", started=started)
        except Exception as e:
            self._handle_violation(
                context=context, trace=trace, pillar="identity_adapter", started=started, error=e
            )

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
        action_tier = self.tool_action_tiers.get(tool_name)
        if action_tier:
            context.metadata["action_tier"] = action_tier
            context.metadata.setdefault("tool_catalog", {})["action_tier"] = action_tier
        trace: list[dict[str, Any]] = context.metadata.setdefault("pillar_trace", [])
        if action_tier:
            _trace_append(
                trace,
                pillar="tool_action_tier",
                status="metadata",
                started=time.perf_counter(),
                detail=action_tier,
            )
        self._apply_mcp_transport_context(context, tenant_id=tenant_id, trace=trace)
        session_id = context.session_id or session_id

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

        if self.enable_canary_goallock and self.canary_goallock is not None:
            context.metadata["bastion_canary_snippet"] = self.canary_goallock.context_snippet()

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

        if self.enable_server_verification and self.server_verifier is not None:
            started = time.perf_counter()
            try:
                self.server_verifier.ensure_ok(force=True)
                _trace_append(trace, pillar="server_verification", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="server_verification", started=started, error=e
                )

        agent_policy = None
        self._apply_identity_adapter(context, trace)
        if self.enable_agent_iam and self.agent_iam is not None:
            started = time.perf_counter()
            try:
                await self._gate_agent_iam_for_request(
                    context,
                    method="tools/call",
                    tool_name=tool_name or "",
                )
                agent_policy = context.metadata.get("_agent_policy")
            except Exception as e:
                self._handle_violation(context=context, trace=trace, pillar="agent_iam", started=started, error=e)
        else:
            context.metadata["_agent_policy"] = agent_policy

        if agent_policy is not None and self.agent_iam is not None:
            isolated = self.agent_iam.isolated_session_id(agent_policy, session_id)
            if isolated and isolated != session_id:
                session_id = isolated
                context.session_id = isolated

        if self.enable_edge_auth and self.edge_auth_secret and not self.enable_agent_iam:
            started = time.perf_counter()
            raw = context.metadata.get(self.edge_auth_metadata_key)
            token = "" if raw is None else str(raw)
            try:
                a, b = token.encode("utf-8"), self.edge_auth_secret.encode("utf-8")
                if len(a) != len(b) or not hmac.compare_digest(a, b):
                    raise AuthenticationError("Request blocked: invalid edge authentication token")
                mark_authenticated_role(context, role=str(context.metadata.get("role") or "edge"))
                _trace_append(trace, pillar="edge_auth", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(context=context, trace=trace, pillar="edge_auth", started=started, error=e)

        if self.enable_boundary_mode:
            started = time.perf_counter()
            try:
                if not context.metadata.get(AUTHENTICATED_ROLE_KEY) and not context.metadata.get("agent_id"):
                    raise AuthenticationError(
                        "Request blocked: boundary mode requires edge_auth or agent_iam authentication"
                    )
                _trace_append(trace, pillar="boundary_mode", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="boundary_mode", started=started, error=e
                )

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

        self._apply_behavior_fingerprint_check(context, tool_name, trace=trace)

        arguments: Any = params.get("arguments") if isinstance(params, dict) else {}
        if arguments is None:
            arguments = params if isinstance(params, dict) else {}
        if isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except json.JSONDecodeError:
                arguments = {"raw": arguments}
        if not isinstance(arguments, dict):
            arguments = {"raw": arguments}

        if self.enable_egress_allowlist:
            started = time.perf_counter()
            try:
                hosts = self.egress_allowlist.check(tool_name, arguments)
                if hosts:
                    context.metadata.setdefault("egress_allowlist", {})["hosts"] = sorted(hosts)
                _trace_append(trace, pillar="egress_allowlist", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="egress_allowlist", started=started, error=e
                )

        if self.enable_business_rules:
            started = time.perf_counter()
            try:
                self.business_rules.check(tool_name, arguments, context.metadata)
                _trace_append(trace, pillar="business_rules", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="business_rules", started=started, error=e
                )

        if self.enable_argument_guards and self.argument_guards and params and tool_name:
            started = time.perf_counter()
            arguments = params.get("arguments") if isinstance(params, dict) else None
            if arguments is None:
                arguments = params if isinstance(params, dict) else {}
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            if not isinstance(arguments, dict):
                arguments = {"raw": arguments}
            try:
                allowed, reason = self.argument_guards.check_blocking(tool_name, arguments)
                if not allowed:
                    raise ArgumentGuardError(reason or "Request blocked: argument guard policy violation")
                redacted = self.argument_guards.redact(tool_name, arguments)
                if redacted != arguments and isinstance(params, dict):
                    params["arguments"] = redacted
                _trace_append(trace, pillar="argument_guards", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="argument_guards", started=started, error=e
                )

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
                budget_principal, budget_tenant = self._finops_keys(context)
                self.cost_tracker.check(
                    session_id=session_id,
                    request_id=request_id,
                    principal_id=budget_principal,
                    tenant_id=budget_tenant,
                )
                _trace_append(trace, pillar="cost_tracker_precheck", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="cost_tracker_precheck", started=started, error=e
                )

        if self.enable_cost_policy and self.cost_policy is not None and self.enable_cost_tracker:
            started = time.perf_counter()
            try:
                budget_principal, budget_tenant = self._finops_keys(context)
                projected = self.cost_policy.tool_projected_cost(tool_name, context.metadata)
                self.cost_policy.check_expensive_chain(session_id or "default", tool_name, projected)
                self.cost_policy.apply_rules(
                    self.cost_tracker,
                    context.metadata,
                    session_id=session_id,
                    request_id=request_id,
                    principal_id=budget_principal,
                )
                _trace_append(trace, pillar="cost_policy", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="cost_policy", started=started, error=e
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
            cached = self.semantic_cache.get(tool_name, query, scope=self._semantic_cache_scope(context, tenant_id))
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
            limiter = self.rate_limiter
            rate_session = self._resolve_rate_session(context, session_id, agent_policy)
            if agent_policy is not None and self.agent_iam is not None:
                agent_limiter = self.agent_iam.rate_limiter_for(agent_policy)
                if agent_limiter is not None:
                    limiter = agent_limiter
            check = limiter.check_and_consume(
                request_id=request_id,
                session_id=rate_session,
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
            context.metadata["_rate_limiter"] = limiter
            context.metadata["_rate_session"] = rate_session

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
            malicious = False
            if text:
                try:
                    _heuristic_hit, malicious = self._record_prompt_guard_scan(context, text)
                except PromptGuardUnavailableError as e:
                    self._handle_violation(
                        context=context, trace=trace, pillar="prompt_guard", started=started, error=e
                    )
                if malicious:
                    logger.warning("prompt_injection_blocked request_id=%s", request_id)
                    self._handle_violation(
                        context=context,
                        trace=trace,
                        pillar="prompt_guard",
                        started=started,
                        error=PromptInjectionError(),
                    )
            _trace_append(trace, pillar="prompt_guard", status="allowed", started=started)

        if self.enable_canary_goallock and params and self.canary_goallock is not None:
            started = time.perf_counter()
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            try:
                self.canary_goallock.check_outbound_arguments(arguments)
                _trace_append(trace, pillar="canary_goallock", status="allowed", started=started)
            except CanaryExfiltrationError as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="canary_goallock", started=started, error=e
                )

        if self.enable_atr_rules and params and self.atr_rules is not None:
            started = time.perf_counter()
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            text = _extract_text_from_value(arguments)
            if text:
                matched = self.atr_rules.match(text)
                if matched is not None:
                    self._handle_violation(
                        context=context,
                        trace=trace,
                        pillar="atr_rules",
                        started=started,
                        error=ATRRuleMatchError(
                            f"Request blocked: ATR rule {matched.rule_id} matched ({matched.title})"
                        ),
                    )
            _trace_append(trace, pillar="atr_rules", status="allowed", started=started)

        if self.enable_llm_scanner and params and self.llm_scanner is not None:
            started = time.perf_counter()
            arguments = params.get("arguments") or params
            if isinstance(arguments, str):
                try:
                    arguments = json.loads(arguments)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments}
            text = _extract_text_from_value(arguments)
            if text:
                scan = context.metadata.get("bastion_prompt_guard_scan") or {}
                heuristic_hit = bool(scan.get("heuristic_hit")) if self.enable_prompt_guard else False
                malicious_pg = bool(scan.get("malicious")) if self.enable_prompt_guard else False
                heuristics_uncertain = not heuristic_hit and not malicious_pg
                try:
                    self.llm_scanner.scan(text, heuristics_uncertain=heuristics_uncertain)
                    _trace_append(trace, pillar="llm_scanner", status="allowed", started=started)
                except LLMScannerBlockedError as e:
                    self._handle_violation(
                        context=context, trace=trace, pillar="llm_scanner", started=started, error=e
                    )

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

        if self.enable_toxic_flow and params:
            started = time.perf_counter()
            try:
                arguments = params.get("arguments") or params
                if isinstance(arguments, str):
                    try:
                        arguments = json.loads(arguments)
                    except json.JSONDecodeError:
                        arguments = {"raw": arguments}
                self.toxic_flow.check_egress(tool_name, arguments, context.session_id)
                _trace_append(trace, pillar="toxic_flow", status="allowed", started=started)
            except Exception as e:
                self._handle_violation(
                    context=context, trace=trace, pillar="toxic_flow", started=started, error=e
                )

        self._enforce_session_tool_scope(
            context=context, trace=trace, session_id=session_id, tool_name=tool_name
        )

        # Hydrate vault tokens in args so MCP tools receive plaintext (opt-in vault only).
        if isinstance(params, dict):
            self._hydrate_tool_arguments(context, params, trace=trace)

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
                consume_limiter = context.metadata.get("_rate_limiter") or self.rate_limiter
                consume_session = context.metadata.get("_rate_session") or session_id
                consume_limiter.add_tokens(
                    request_id=request_id,
                    session_id=consume_session,
                    tokens=tokens,
                )
                _trace_append(trace, pillar="rate_limit_consume", status="ok", started=started)

        if self.enable_semantic_cache and result is not None and params:
            started = time.perf_counter()
            arguments = params.get("arguments") or params
            query = _extract_text_from_value(arguments)
            self.semantic_cache.set(tool_name, query, result, scope=self._semantic_cache_scope(context, tenant_id))
            _trace_append(trace, pillar="semantic_cache_set", status="ok", started=started)

        if self.enable_cost_attribution:
            self._apply_cost_attribution(context, tool_name)

        if self.enable_cost_tracker:
            started = time.perf_counter()
            context.metadata.setdefault("cost", 0.0)
            budget_principal = context.metadata.get("_budget_principal")
            budget_tenant = context.metadata.get("_budget_tenant")
            if budget_principal is None or budget_tenant is None:
                budget_principal, budget_tenant = self._finops_keys(context)
            self.cost_tracker.record(
                context.metadata.get("cost", 0.0),
                session_id=session_id,
                request_id=request_id,
                principal_id=budget_principal,
                tenant_id=budget_tenant,
            )
            _trace_append(trace, pillar="cost_tracker_record", status="ok", started=started)

        if self.enable_pii_redaction and result is not None:
            started = time.perf_counter()
            result = self._redact_result_content(result, context=context)
            pillar = "pii_vault_abstract" if self.enable_pii_vault else "pii_redaction"
            _trace_append(trace, pillar=pillar, status="ok", started=started)
            if self.enable_toxic_flow and context is not None:
                kinds = context.metadata.pop("_bastion_taint_kinds", None) or []
                if kinds:
                    self.toxic_flow.mark(context.session_id, kinds=kinds, tool=tool_name)

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

        result = self._apply_agent_stability_to_result(context, result, trace=trace)

        context.metadata["forensic_response"] = _safe_forensic_value(result)

        if self.enable_cost_policy and self.cost_policy is not None:
            self.cost_policy.record_tool(session_id or "default", tool_name)

        self._record_governance(
            context, method="tools/call", tool=tool_name, pillar="handler", status="allowed"
        )

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

    def _redact_result_content(
        self,
        result: Any,
        *,
        context: MiddlewareContext[Any] | None = None,
    ) -> Any:
        """Redact or vault-abstract PII (and optional secrets) from result content items."""
        content = _get_content_from_result(result)
        if not content:
            return result
        taint_kinds: list[str] = []
        if self.enable_pii_vault and self.pii_vault is not None and context is not None:
            from mcp_bastion.pillars.pii_vault import count_vault_tokens

            session_key = self._vault_session_key(context)
            before = " ".join(
                str(i.get("text", "")) for i in content if isinstance(i, dict) and i.get("type") == "text"
            )
            redacted = self.pii_redactor.vault_content_items(content, self.pii_vault, session_key)
            after = " ".join(
                str(i.get("text", "")) for i in redacted if isinstance(i, dict) and i.get("type") == "text"
            )
            n = max(0, count_vault_tokens(after) - count_vault_tokens(before))
            if n:
                MetricsStore.get().record_pii_vault_abstract(n)
                taint_kinds.append("pii")
        else:
            before_txt = " ".join(
                str(i.get("text", "")) for i in content if isinstance(i, dict) and i.get("type") == "text"
            )
            redacted = self.pii_redactor.redact_content_items(content)
            after_txt = " ".join(
                str(i.get("text", "")) for i in redacted if isinstance(i, dict) and i.get("type") == "text"
            )
            if before_txt != after_txt:
                taint_kinds.append("pii")
        if self.enable_secret_redaction and self.secret_redactor is not None:
            out = []
            changed = False
            for item in redacted:
                if isinstance(item, dict) and item.get("type") == "text" and "text" in item:
                    new_t = self.secret_redactor.redact_text(str(item["text"]))
                    if new_t != item["text"]:
                        changed = True
                    out.append({**item, "text": new_t})
                else:
                    out.append(item)
            redacted = out
            if changed:
                taint_kinds.append("secret")
        if context is not None and taint_kinds:
            context.metadata["_bastion_taint_kinds"] = list(dict.fromkeys(taint_kinds))
        _set_content_in_result(result, redacted)
        return result
