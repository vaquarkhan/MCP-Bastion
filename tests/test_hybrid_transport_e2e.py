"""
End-to-end tests: hybrid stateful / stateless MCP transport.

Verifies bastion.yaml → build_middleware_from_config → tools/call without
breaking legacy sessions or stateless state-handle clients.
"""

from __future__ import annotations

import json

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.config import build_middleware_from_config, load_config
from mcp_bastion.errors import AgentLoopDetectedError, InvalidStateHandleError, ProtocolVersionError


def _require_yaml():
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")


def _tool_ctx(
    *,
    session_id: str = "legacy-session-id-1234567890",
    arguments: dict | None = None,
    metadata: dict | None = None,
) -> MiddlewareContext:
    return MiddlewareContext(
        message={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "search", "arguments": arguments or {"q": "hello"}},
        },
        request_id="hybrid-req",
        session_id=session_id,
        metadata=dict(metadata or {}),
    )


@pytest.fixture
def hybrid_workspace(tmp_path):
    _require_yaml()
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
audit:
  enabled: false
prompt_guard:
  enabled: false
pii:
  enabled: false
rate_limit:
  enabled: false
mcp_transport:
  enabled: true
  mode: auto
  protocol:
    enabled: true
    allowed_versions: ["2024-11-05", "2025-03-26"]
  stability:
    enabled: true
    repeat_threshold: 2
    on_detect: inject
""",
        encoding="utf-8",
    )
    cfg = load_config(str(yaml_path))
    return {"config": cfg, "middleware": build_middleware_from_config(cfg), "yaml_path": yaml_path}


@pytest.mark.asyncio
async def test_e2e_stateful_session_unchanged(hybrid_workspace):
    mw = hybrid_workspace["middleware"]
    ctx = _tool_ctx(session_id="real-legacy-session-abcdefghij")

    async def handler(c):
        return {"content": [{"type": "text", "text": "stateful ok"}]}

    result = await mw(ctx, handler)
    assert result["content"][0]["text"] == "stateful ok"
    assert ctx.metadata.get("mcp_transport_mode") == "stateful"
    assert "session:real-legacy-session-abcdefghij" in ctx.metadata.get("_mcp_rate_limit_key", "")


@pytest.mark.asyncio
async def test_e2e_stateless_handle_scopes_session(hybrid_workspace):
    mw = hybrid_workspace["middleware"]
    handle = "stateless-handle-" + "x" * 20
    ctx = _tool_ctx(
        session_id="proxy-session",
        arguments={"q": "hello", "state_handle": handle},
    )

    async def handler(c):
        return {"content": [{"type": "text", "text": "stateless ok"}]}

    result = await mw(ctx, handler)
    assert result["content"][0]["text"] == "stateless ok"
    assert ctx.metadata.get("mcp_transport_mode") == "stateless"
    assert ctx.metadata.get("mcp_state_handle") == handle
    assert ctx.session_id == f"handle:{handle}"
    assert f"handle:{handle}" in ctx.metadata.get("_mcp_rate_limit_key", "")


@pytest.mark.asyncio
async def test_e2e_invalid_protocol_version_blocked(hybrid_workspace):
    mw = hybrid_workspace["middleware"]
    ctx = _tool_ctx(
        metadata={"mcp-protocol-version": "2099-01-01"},
        session_id="proxy-session",
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(ProtocolVersionError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_e2e_invalid_state_handle_blocked(tmp_path):
    _require_yaml()
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
audit: {enabled: false}
prompt_guard: {enabled: false}
pii: {enabled: false}
rate_limit: {enabled: false}
mcp_transport:
  enabled: true
  mode: stateless
  state_handle:
    required_in_stateless: true
""",
        encoding="utf-8",
    )
    mw = build_middleware_from_config(load_config(str(yaml_path)))
    ctx = _tool_ctx(session_id="proxy-session", arguments={"q": "x"})

    async def handler(c):
        return {"ok": True}

    with pytest.raises(InvalidStateHandleError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_e2e_stability_inject_on_repeated_output(hybrid_workspace):
    mw = hybrid_workspace["middleware"]
    handle = "stability-scope-" + "y" * 20
    ctx = _tool_ctx(arguments={"state_handle": handle})
    err_text = "Error: connection refused port 443"

    async def handler(c):
        return {"content": [{"type": "text", "text": err_text}]}

    await mw(ctx, handler)
    result = await mw(ctx, handler)
    assert len(result["content"]) == 2
    assert "stability monitor" in result["content"][-1]["text"].lower()


@pytest.mark.asyncio
async def test_e2e_stability_block_mode(tmp_path):
    _require_yaml()
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
audit: {enabled: false}
prompt_guard: {enabled: false}
pii: {enabled: false}
rate_limit: {enabled: false}
mcp_transport:
  enabled: true
  stability:
    enabled: true
    repeat_threshold: 2
    on_detect: block
""",
        encoding="utf-8",
    )
    mw = build_middleware_from_config(load_config(str(yaml_path)))
    ctx = _tool_ctx(session_id="stability-block-session-1234567890")
    msg = "identical failure message from upstream"

    async def handler(c):
        return {"content": [{"type": "text", "text": msg}]}

    await mw(ctx, handler)
    with pytest.raises(AgentLoopDetectedError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_e2e_transport_disabled_no_metadata_stamp(tmp_path):
    _require_yaml()
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
audit: {enabled: false}
prompt_guard: {enabled: false}
pii: {enabled: false}
rate_limit: {enabled: false}
mcp_transport:
  enabled: false
""",
        encoding="utf-8",
    )
    mw = build_middleware_from_config(load_config(str(yaml_path)))
    ctx = _tool_ctx()

    async def handler(c):
        return {"content": [{"type": "text", "text": "legacy"}]}

    await mw(ctx, handler)
    assert "mcp_transport_mode" not in ctx.metadata


@pytest.mark.asyncio
async def test_e2e_both_modes_same_middleware_stack(hybrid_workspace):
    """Stateful and stateless requests through the same stack must both succeed."""
    mw = hybrid_workspace["middleware"]

    async def handler(c):
        mode = c.metadata.get("mcp_transport_mode")
        return {"content": [{"type": "text", "text": mode}]}

    stateful_ctx = _tool_ctx(session_id="coexist-stateful-session-123456789")
    stateful_result = await mw(stateful_ctx, handler)
    assert stateful_result["content"][0]["text"] == "stateful"

    handle = "coexist-handle-" + "z" * 20
    stateless_ctx = _tool_ctx(
        session_id="proxy-session",
        arguments={"state_handle": handle},
    )
    stateless_result = await mw(stateless_ctx, handler)
    assert stateless_result["content"][0]["text"] == "stateless"


def test_build_middleware_wires_transport_and_stability(hybrid_workspace):
    mw = hybrid_workspace["middleware"]
    assert mw.mcp_transport_config.enabled is True
    assert mw.enable_agent_stability is True
    assert mw.agent_stability is not None
