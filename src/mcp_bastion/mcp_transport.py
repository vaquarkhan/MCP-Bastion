"""
Hybrid MCP transport: stateful sessions and stateless explicit state handles.

Opt-in via bastion.yaml `mcp_transport`. When disabled (default), Bastion behaves
exactly as before. When enabled, the middleware resolves identity from either:

- Legacy stateful: MCP-Session-Id / host session_id
- Stateless (SEP-2575 / state handles): explicit handle in tool args or headers

Deterministic rate-limit and cost keys work across load-balanced replicas when
combined with `state_backend: redis`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import InvalidStateHandleError, ProtocolVersionError

STATEFUL_INIT_METHODS = frozenset({"initialize", "notifications/initialized"})

DEFAULT_STATE_HANDLE_PARAMS = (
    "state_handle",
    "mcp_state_handle",
    "stateHandle",
    "mcpStateHandle",
)
DEFAULT_STATE_HANDLE_HEADERS = (
    "mcp-state-handle",
    "x-mcp-state-handle",
)
DEFAULT_STATE_HANDLE_METADATA_KEYS = (
    "state_handle",
    "mcp_state_handle",
    "stateHandle",
)

_HANDLE_PATTERN = re.compile(r"^[A-Za-z0-9_\-:.]{16,256}$")


@dataclass
class McpTransportConfig:
    """Policy for hybrid stateful / stateless MCP transport."""

    enabled: bool = False
    mode: str = "auto"  # auto | stateful | stateless
    state_handle_param_names: list[str] = field(default_factory=lambda: list(DEFAULT_STATE_HANDLE_PARAMS))
    state_handle_header_names: list[str] = field(default_factory=lambda: list(DEFAULT_STATE_HANDLE_HEADERS))
    state_handle_metadata_keys: list[str] = field(default_factory=lambda: list(DEFAULT_STATE_HANDLE_METADATA_KEYS))
    require_state_handle_in_stateless: bool = False
    state_handle_min_length: int = 16
    protocol_version_enabled: bool = False
    protocol_version_header: str = "MCP-Protocol-Version"
    allowed_protocol_versions: list[str] = field(default_factory=lambda: ["2024-11-05", "2025-03-26"])
    default_protocol_version: str = "2024-11-05"
    discovery_enabled: bool = False
    discovery_card: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TransportResolution:
    """Resolved transport identity for a single request."""

    mode: str  # stateful | stateless
    session_id: str | None
    state_handle: str | None
    protocol_version: str | None
    rate_limit_key: str


def mcp_transport_config_from_bastion(config: Any) -> McpTransportConfig:
    """Build McpTransportConfig from BastionConfig."""
    params = list(getattr(config, "mcp_transport_state_handle_params", []) or [])
    headers = list(getattr(config, "mcp_transport_state_handle_headers", []) or [])
    meta_keys = list(getattr(config, "mcp_transport_state_handle_metadata_keys", []) or [])
    versions = list(getattr(config, "mcp_transport_allowed_versions", []) or [])
    return McpTransportConfig(
        enabled=bool(getattr(config, "mcp_transport_enabled", False)),
        mode=str(getattr(config, "mcp_transport_mode", "auto")),
        state_handle_param_names=params or list(DEFAULT_STATE_HANDLE_PARAMS),
        state_handle_header_names=headers or list(DEFAULT_STATE_HANDLE_HEADERS),
        state_handle_metadata_keys=meta_keys or list(DEFAULT_STATE_HANDLE_METADATA_KEYS),
        require_state_handle_in_stateless=bool(getattr(config, "mcp_transport_require_handle", False)),
        state_handle_min_length=int(getattr(config, "mcp_transport_handle_min_length", 16)),
        protocol_version_enabled=bool(getattr(config, "mcp_transport_protocol_enabled", False)),
        protocol_version_header=str(getattr(config, "mcp_transport_protocol_header", "MCP-Protocol-Version")),
        allowed_protocol_versions=versions or ["2024-11-05", "2025-03-26"],
        default_protocol_version=str(getattr(config, "mcp_transport_default_version", "2024-11-05")),
        discovery_enabled=bool(getattr(config, "mcp_transport_discovery_enabled", False)),
        discovery_card=dict(getattr(config, "mcp_transport_discovery_card", {}) or {}),
    )


def _normalize_header_map(metadata: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in metadata.items():
        if isinstance(k, str) and isinstance(v, str):
            out[k.lower()] = v
    return out


def _get_message_dict(context: MiddlewareContext[Any]) -> dict[str, Any] | None:
    msg = context.message
    if hasattr(msg, "root"):
        msg = msg.root
    return msg if isinstance(msg, dict) else None


def _get_params(context: MiddlewareContext[Any]) -> dict[str, Any]:
    msg = _get_message_dict(context)
    if not msg:
        return {}
    params = msg.get("params")
    return params if isinstance(params, dict) else {}


def _jsonrpc_method(context: MiddlewareContext[Any]) -> str | None:
    msg = _get_message_dict(context)
    if not msg:
        return None
    method = msg.get("method")
    return str(method) if method else None


def _dig_arguments(params: dict[str, Any]) -> dict[str, Any]:
    arguments = params.get("arguments")
    if isinstance(arguments, dict):
        return arguments
    if isinstance(arguments, str):
        import json

        try:
            parsed = json.loads(arguments)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return params


def extract_state_handle(context: MiddlewareContext[Any], config: McpTransportConfig) -> str | None:
    """Extract explicit state handle from headers, metadata, or tool arguments."""
    headers = _normalize_header_map(context.metadata)
    for name in config.state_handle_header_names:
        value = headers.get(name.lower())
        if isinstance(value, str) and value.strip():
            return value.strip()

    for key in config.state_handle_metadata_keys:
        value = context.metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    params = _get_params(context)
    meta = params.get("_meta") or params.get("metadata")
    if isinstance(meta, dict):
        for key in config.state_handle_metadata_keys:
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    arguments = _dig_arguments(params)
    for name in config.state_handle_param_names:
        value = arguments.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def extract_protocol_version(context: MiddlewareContext[Any], config: McpTransportConfig) -> str | None:
    """Read protocol version from HTTP header mirror or JSON-RPC metadata."""
    header_key = config.protocol_version_header.lower()
    headers = _normalize_header_map(context.metadata)
    if header_key in headers:
        return headers[header_key].strip()

    params = _get_params(context)
    for container_key in ("_meta", "metadata"):
        meta = params.get(container_key)
        if isinstance(meta, dict):
            for vk in ("protocolVersion", "protocol_version", "mcp_protocol_version"):
                value = meta.get(vk)
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def validate_state_handle(handle: str, config: McpTransportConfig) -> None:
    """Raise InvalidStateHandleError when handle fails entropy/charset policy."""
    if len(handle) < config.state_handle_min_length:
        raise InvalidStateHandleError(
            f"State handle too short (min {config.state_handle_min_length} characters)"
        )
    if not _HANDLE_PATTERN.match(handle):
        raise InvalidStateHandleError("State handle must be 16-256 URL-safe characters")


def validate_protocol_version(version: str | None, config: McpTransportConfig) -> str:
    """Validate declared protocol version; return effective version."""
    effective = (version or config.default_protocol_version).strip()
    allowed = {v.strip() for v in config.allowed_protocol_versions if str(v).strip()}
    if allowed and effective not in allowed:
        raise ProtocolVersionError(
            f"Unsupported MCP protocol version: {effective!r} (allowed: {sorted(allowed)})"
        )
    return effective


def detect_transport_mode(
    context: MiddlewareContext[Any],
    config: McpTransportConfig,
    *,
    state_handle: str | None = None,
) -> str:
    """
    Return ``stateful`` or ``stateless``.

    ``auto`` prefers explicit stateless signals (handle, protocol header, non-init
    without session) over legacy session coupling.
    """
    forced = (config.mode or "auto").strip().lower()
    if forced in ("stateful", "stateless"):
        return forced

    method = (_jsonrpc_method(context) or "").lower()
    if method in STATEFUL_INIT_METHODS:
        return "stateful"

    handle = state_handle if state_handle is not None else extract_state_handle(context, config)
    if handle:
        return "stateless"

    if extract_protocol_version(context, config):
        return "stateless"

    session = (context.session_id or "").strip()
    placeholder_sessions = {"", "proxy-session", "default", "stdio-session"}
    if session and session not in placeholder_sessions:
        return "stateful"

    return "stateless"


def build_rate_limit_key(
    *,
    principal_id: str,
    mode: str,
    session_id: str | None,
    state_handle: str | None,
    tenant_id: str,
) -> str:
    """Deterministic FinOps / rate-limit key for distributed backends."""
    if mode == "stateless" and state_handle:
        return f"tenant:{tenant_id}|principal:{principal_id}|handle:{state_handle}"
    if session_id:
        return f"tenant:{tenant_id}|principal:{principal_id}|session:{session_id}"
    return f"tenant:{tenant_id}|principal:{principal_id}|anonymous"


def resolve_transport_context(
    context: MiddlewareContext[Any],
    config: McpTransportConfig,
    *,
    principal_id: str,
    tenant_id: str,
) -> TransportResolution:
    """Resolve hybrid transport identity and composite rate-limit key."""
    state_handle = extract_state_handle(context, config)
    mode = detect_transport_mode(context, config, state_handle=state_handle)

    if mode == "stateless":
        if config.require_state_handle_in_stateless and not state_handle:
            raise InvalidStateHandleError("Stateless MCP request missing required state_handle")
        if state_handle:
            validate_state_handle(state_handle, config)

    protocol_version: str | None = None
    if config.protocol_version_enabled:
        raw_version = extract_protocol_version(context, config)
        protocol_version = validate_protocol_version(raw_version, config)

    effective_session = context.session_id
    if mode == "stateless" and state_handle:
        effective_session = f"handle:{state_handle}"

    rate_key = build_rate_limit_key(
        principal_id=principal_id,
        mode=mode,
        session_id=effective_session,
        state_handle=state_handle,
        tenant_id=tenant_id,
    )

    return TransportResolution(
        mode=mode,
        session_id=effective_session,
        state_handle=state_handle,
        protocol_version=protocol_version,
        rate_limit_key=rate_key,
    )


def apply_mcp_transport(
    context: MiddlewareContext[Any],
    config: McpTransportConfig,
    *,
    principal_id: str,
    tenant_id: str,
) -> TransportResolution | None:
    """
    Stamp context metadata with transport resolution. No-op when disabled.

    Updates ``context.session_id`` for stateless handle-scoped session limits.
    """
    if not config.enabled:
        return None

    resolution = resolve_transport_context(
        context, config, principal_id=principal_id, tenant_id=tenant_id
    )
    context.metadata["mcp_transport_mode"] = resolution.mode
    context.metadata["mcp_state_handle"] = resolution.state_handle
    context.metadata["mcp_protocol_version"] = resolution.protocol_version
    context.metadata["_mcp_rate_limit_key"] = resolution.rate_limit_key
    context.metadata["_mcp_transport_scope"] = resolution.state_handle or resolution.session_id or tenant_id

    if resolution.session_id and resolution.mode == "stateless":
        context.session_id = resolution.session_id

    return resolution


def ingest_http_headers(context: MiddlewareContext[Any], headers: list[tuple[str, str]]) -> None:
    """Mirror HTTP headers into context.metadata for transport sniffing."""
    for name, value in headers:
        if not name or value is None:
            continue
        key = name.lower()
        context.metadata[key] = value
        if key == "mcp-session-id" and not context.session_id:
            context.session_id = value
        if key == "x-request-id" and not context.request_id:
            context.request_id = value
