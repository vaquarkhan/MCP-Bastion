"""Tests for proxy boundary mode enforcement."""

from __future__ import annotations

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import AuthenticationError
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


@pytest.mark.asyncio
async def test_boundary_mode_blocks_unauthenticated():
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        enable_boundary_mode=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_governance_attestation=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "search", "arguments": {}}},
        request_id="r1",
        session_id="s1",
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(AuthenticationError, match="boundary mode"):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_boundary_mode_allows_edge_auth(monkeypatch):
    secret = "edge-secret-test"
    monkeypatch.setenv("BASTION_EDGE_SECRET", secret)
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        enable_boundary_mode=True,
        enable_edge_auth=True,
        edge_auth_secret=secret,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_governance_attestation=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "search", "arguments": {}}},
        request_id="r1",
        session_id="s1",
        metadata={"bastion_edge_token": secret},
    )

    async def handler(c):
        return {"ok": True}

    assert await mw(ctx, handler) == {"ok": True}


def test_config_boundary_mode_requires_auth(tmp_path):
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")

    from mcp_bastion.config import load_config, validate_bastion_config
    from mcp_bastion.errors import BastionConfigError

    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "boundary_mode:\n  enabled: true\nprompt_guard:\n  enabled: false\n",
        encoding="utf-8",
    )
    cfg = load_config(bad)
    with pytest.raises(BastionConfigError, match="boundary_mode"):
        validate_bastion_config(cfg)
