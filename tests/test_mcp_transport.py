"""Tests for hybrid stateful / stateless MCP transport identity."""

from __future__ import annotations

import json

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.config import BastionConfig, load_config
from mcp_bastion.errors import InvalidStateHandleError, ProtocolVersionError
from mcp_bastion.mcp_transport import (
    McpTransportConfig,
    apply_mcp_transport,
    build_rate_limit_key,
    detect_transport_mode,
    extract_protocol_version,
    extract_state_handle,
    ingest_http_headers,
    mcp_transport_config_from_bastion,
    validate_protocol_version,
    validate_state_handle,
)


def _ctx(
    message: dict | None = None,
    *,
    session_id: str | None = None,
    metadata: dict | None = None,
) -> MiddlewareContext[dict]:
    return MiddlewareContext(
        message=message or {"method": "tools/call", "params": {"name": "search", "arguments": {}}},
        session_id=session_id,
        metadata=dict(metadata or {}),
    )


def test_defaults_disabled_no_op():
    cfg = McpTransportConfig(enabled=False)
    ctx = _ctx(session_id="sess-abc1234567890123")
    assert apply_mcp_transport(ctx, cfg, principal_id="anonymous:default", tenant_id="default") is None
    assert "_mcp_rate_limit_key" not in ctx.metadata


def test_extract_state_handle_from_arguments():
    cfg = McpTransportConfig(enabled=True)
    ctx = _ctx(
        message={
            "method": "tools/call",
            "params": {
                "name": "search",
                "arguments": {"query": "hello", "state_handle": "sh-" + "a" * 20},
            },
        }
    )
    assert extract_state_handle(ctx, cfg) == "sh-" + "a" * 20
    assert detect_transport_mode(ctx, cfg) == "stateless"


def test_extract_state_handle_from_header_metadata():
    cfg = McpTransportConfig(enabled=True)
    ctx = _ctx(metadata={"mcp-state-handle": "hdr-" + "b" * 20})
    assert extract_state_handle(ctx, cfg) == "hdr-" + "b" * 20


def test_stateful_mode_with_session_id():
    cfg = McpTransportConfig(enabled=True, mode="auto")
    ctx = _ctx(session_id="real-session-id-1234567890")
    assert detect_transport_mode(ctx, cfg) == "stateful"


def test_forced_stateful_mode_ignores_handle():
    cfg = McpTransportConfig(enabled=True, mode="stateful")
    ctx = _ctx(
        message={
            "method": "tools/call",
            "params": {"arguments": {"state_handle": "sh-" + "c" * 20}},
        }
    )
    assert detect_transport_mode(ctx, cfg) == "stateful"


def test_validate_state_handle_rejects_short():
    cfg = McpTransportConfig(state_handle_min_length=16)
    with pytest.raises(InvalidStateHandleError):
        validate_state_handle("too-short", cfg)


def test_validate_protocol_version_allowed():
    cfg = McpTransportConfig(
        protocol_version_enabled=True,
        allowed_protocol_versions=["2024-11-05", "2025-03-26"],
        default_protocol_version="2024-11-05",
    )
    assert validate_protocol_version("2025-03-26", cfg) == "2025-03-26"
    assert validate_protocol_version(None, cfg) == "2024-11-05"


def test_validate_protocol_version_rejects_unknown():
    cfg = McpTransportConfig(
        protocol_version_enabled=True,
        allowed_protocol_versions=["2024-11-05"],
    )
    with pytest.raises(ProtocolVersionError):
        validate_protocol_version("2099-01-01", cfg)


def test_build_rate_limit_key_stateless_handle():
    key = build_rate_limit_key(
        principal_id="agent:bot",
        mode="stateless",
        session_id=None,
        state_handle="handle-" + "x" * 20,
        tenant_id="acme",
    )
    assert "handle:" in key
    assert "agent:bot" in key
    assert "tenant:acme" in key


def test_apply_mcp_transport_stamps_metadata():
    cfg = McpTransportConfig(enabled=True, mode="stateless")
    handle = "explicit-" + "d" * 20
    ctx = _ctx(
        message={
            "method": "tools/call",
            "params": {"arguments": {"state_handle": handle}},
        },
        session_id="proxy-session",
    )
    resolution = apply_mcp_transport(ctx, cfg, principal_id="anonymous:t1", tenant_id="t1")
    assert resolution is not None
    assert resolution.mode == "stateless"
    assert ctx.metadata["mcp_transport_mode"] == "stateless"
    assert ctx.metadata["mcp_state_handle"] == handle
    assert ctx.session_id == f"handle:{handle}"
    assert ctx.metadata["_mcp_rate_limit_key"].startswith("tenant:t1|")


def test_require_state_handle_in_stateless_raises():
    cfg = McpTransportConfig(enabled=True, mode="stateless", require_state_handle_in_stateless=True)
    ctx = _ctx(session_id="proxy-session")
    with pytest.raises(InvalidStateHandleError):
        apply_mcp_transport(ctx, cfg, principal_id="anonymous:t1", tenant_id="t1")


def test_protocol_version_from_metadata():
    cfg = McpTransportConfig(enabled=True, protocol_version_enabled=True)
    ctx = _ctx(
        message={
            "method": "tools/call",
            "params": {"_meta": {"protocolVersion": "2025-03-26"}, "arguments": {}},
        }
    )
    assert extract_protocol_version(ctx, cfg) == "2025-03-26"


def test_ingest_http_headers_sets_session():
    ctx = _ctx()
    ingest_http_headers(ctx, [("MCP-Session-Id", "sess-from-header-1234567890")])
    assert ctx.session_id == "sess-from-header-1234567890"
    assert ctx.metadata["mcp-session-id"] == "sess-from-header-1234567890"


def test_load_config_mcp_transport_section(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
mcp_transport:
  enabled: true
  mode: auto
  state_handle:
    param_names: ["my_handle"]
    required_in_stateless: true
  protocol:
    enabled: true
    allowed_versions: ["2025-03-26"]
  discovery:
    enabled: true
    card:
      name: test-server
  stability:
    enabled: true
    on_detect: block
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    cfg = load_config(str(yaml_path))
    assert cfg.mcp_transport_enabled is True
    assert cfg.mcp_transport_state_handle_params == ["my_handle"]
    assert cfg.mcp_transport_require_handle is True
    assert cfg.mcp_transport_protocol_enabled is True
    assert cfg.mcp_transport_allowed_versions == ["2025-03-26"]
    assert cfg.mcp_transport_discovery_enabled is True
    assert cfg.mcp_transport_discovery_card.get("name") == "test-server"
    assert cfg.agent_stability_enabled is True
    assert cfg.agent_stability_on_detect == "block"


def test_mcp_transport_config_from_bastion_uses_defaults():
    cfg = BastionConfig(mcp_transport_enabled=True)
    transport = mcp_transport_config_from_bastion(cfg)
    assert transport.enabled is True
    assert "state_handle" in transport.state_handle_param_names


def test_initialize_method_is_stateful():
    cfg = McpTransportConfig(enabled=True, mode="auto")
    ctx = _ctx(message={"method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
    assert detect_transport_mode(ctx, cfg) == "stateful"


def test_protocol_header_implies_stateless_without_session():
    cfg = McpTransportConfig(enabled=True, protocol_version_enabled=True)
    ctx = _ctx(
        metadata={"mcp-protocol-version": "2025-03-26"},
        session_id="proxy-session",
    )
    assert detect_transport_mode(ctx, cfg) == "stateless"


def test_build_rate_limit_key_session_fallback():
    key = build_rate_limit_key(
        principal_id="agent:x",
        mode="stateful",
        session_id="sess-123",
        state_handle=None,
        tenant_id="default",
    )
    assert key.endswith("|session:sess-123")


def test_validate_state_handle_rejects_invalid_charset():
    cfg = McpTransportConfig(state_handle_min_length=16)
    bad = "invalid handle with spaces!!"
    with pytest.raises(InvalidStateHandleError):
        validate_state_handle(bad, cfg)


def test_validate_state_handle_rejects_too_long():
    cfg = McpTransportConfig(state_handle_min_length=16)
    too_long = "a" * 257
    with pytest.raises(InvalidStateHandleError):
        validate_state_handle(too_long, cfg)


def test_extract_state_handle_from_params_meta():
    cfg = McpTransportConfig(enabled=True)
    ctx = _ctx(
        message={
            "method": "tools/call",
            "params": {
                "_meta": {"state_handle": "meta-" + "e" * 20},
                "arguments": {},
            },
        }
    )
    assert extract_state_handle(ctx, cfg) == "meta-" + "e" * 20


def test_extract_state_handle_from_json_string_arguments():
    cfg = McpTransportConfig(enabled=True)
    handle = "jsonarg-" + "f" * 20
    ctx = _ctx(
        message={
            "method": "tools/call",
            "params": {
                "arguments": json.dumps({"state_handle": handle}),
            },
        }
    )
    assert extract_state_handle(ctx, cfg) == handle


def test_extract_protocol_version_from_header():
    cfg = McpTransportConfig(enabled=True, protocol_version_enabled=True)
    ctx = _ctx(metadata={"mcp-protocol-version": "2025-03-26"})
    assert extract_protocol_version(ctx, cfg) == "2025-03-26"


def test_resolve_transport_context_returns_resolution():
    cfg = McpTransportConfig(enabled=True)
    handle = "resolve-" + "g" * 20
    ctx = _ctx(
        message={
            "method": "tools/call",
            "params": {"arguments": {"state_handle": handle}},
        }
    )
    from mcp_bastion.mcp_transport import resolve_transport_context

    resolution = resolve_transport_context(ctx, cfg, principal_id="p1", tenant_id="t1")
    assert resolution.mode == "stateless"
    assert resolution.state_handle == handle
    assert "handle:" in resolution.rate_limit_key


def test_build_rate_limit_key_anonymous_fallback():
    key = build_rate_limit_key(
        principal_id="agent:x",
        mode="stateless",
        session_id=None,
        state_handle=None,
        tenant_id="default",
    )
    assert key.endswith("|anonymous")


def test_forced_stateless_mode_without_handle():
    cfg = McpTransportConfig(enabled=True, mode="stateless")
    ctx = _ctx(session_id="real-session-id-1234567890")
    assert detect_transport_mode(ctx, cfg) == "stateless"


def test_ingest_http_headers_sets_request_id():
    ctx = _ctx()
    ingest_http_headers(ctx, [("X-Request-Id", "req-from-header-1")])
    assert ctx.request_id == "req-from-header-1"


def test_apply_mcp_transport_stamps_protocol_version():
    cfg = McpTransportConfig(
        enabled=True,
        protocol_version_enabled=True,
        allowed_protocol_versions=["2025-03-26"],
    )
    ctx = _ctx(
        message={
            "method": "tools/call",
            "params": {"_meta": {"protocolVersion": "2025-03-26"}, "arguments": {}},
        }
    )
    apply_mcp_transport(ctx, cfg, principal_id="p", tenant_id="t")
    assert ctx.metadata["mcp_protocol_version"] == "2025-03-26"
