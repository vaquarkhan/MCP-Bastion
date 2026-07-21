"""E2E: behavior_fingerprint pillar via middleware."""

from __future__ import annotations

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.config import build_middleware_from_config, load_config
from mcp_bastion.errors import BehaviorAnomalyError


def _require_yaml():
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")


@pytest.mark.asyncio
async def test_e2e_behavior_fingerprint_warn_mode(tmp_path):
    _require_yaml()
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
audit: {enabled: false}
prompt_guard: {enabled: false}
pii: {enabled: false}
rate_limit: {enabled: false}
behavior_fingerprint:
  enabled: true
  learn_min_calls: 3
  freeze_after_calls: 4
  drift_window: 3
  on_detect: warn
""",
        encoding="utf-8",
    )
    mw = build_middleware_from_config(load_config(str(yaml_path)))
    assert mw.enable_behavior_fingerprint is True

    async def handler(c):
        return {"content": [{"type": "text", "text": "ok"}]}

    scope = "e2e-behavior-session-1234567890"
    for _ in range(8):
        ctx = MiddlewareContext(
            message={"method": "tools/call", "params": {"name": "read_docs", "arguments": {}}},
            request_id="bf-1",
            session_id=scope,
            metadata={},
        )
        await mw(ctx, handler)

    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "delete_all", "arguments": {}}},
        request_id="bf-2",
        session_id=scope,
        metadata={},
    )
    await mw(ctx, handler)
    ctx2 = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "delete_all", "arguments": {}}},
        request_id="bf-3",
        session_id=scope,
        metadata={},
    )
    await mw(ctx2, handler)
    ctx3 = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "delete_all", "arguments": {}}},
        request_id="bf-4",
        session_id=scope,
        metadata={},
    )
    await mw(ctx3, handler)
    assert ctx3.metadata.get("behavior_fingerprint", {}).get("anomaly") is not None


@pytest.mark.asyncio
async def test_e2e_behavior_fingerprint_block_mode(tmp_path):
    _require_yaml()
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
audit: {enabled: false}
prompt_guard: {enabled: false}
pii: {enabled: false}
rate_limit: {enabled: false}
behavior_fingerprint:
  enabled: true
  learn_min_calls: 2
  freeze_after_calls: 3
  drift_window: 2
  on_detect: block
""",
        encoding="utf-8",
    )
    mw = build_middleware_from_config(load_config(str(yaml_path)))

    async def handler(c):
        return {"ok": True}

    scope = "block-scope-session-1234567890"
    for _ in range(10):
        ctx = MiddlewareContext(
            message={"method": "tools/call", "params": {"name": "read_docs", "arguments": {}}},
            request_id="x",
            session_id=scope,
            metadata={},
        )
        await mw(ctx, handler)

    for i in range(2):
        ctx = MiddlewareContext(
            message={"method": "tools/call", "params": {"name": "totally_new_tool", "arguments": {}}},
            request_id=f"y{i}",
            session_id=scope,
            metadata={},
        )
        await mw(ctx, handler)

    ctx_block = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "totally_new_tool", "arguments": {}}},
        request_id="z",
        session_id=scope,
        metadata={},
    )
    with pytest.raises(BehaviorAnomalyError):
        await mw(ctx_block, handler)
