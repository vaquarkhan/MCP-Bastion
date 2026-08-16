import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.config import load_config
from mcp_bastion.errors import EgressDeniedError
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.egress_allowlist import EgressAllowlist


def test_exact_wildcard_and_host_key_extraction():
    guard = EgressAllowlist(["api.example.com", "*.trusted.test"])
    assert guard.check("post_http", {"url": "https://api.example.com/v1"}) == {"api.example.com"}
    assert guard.check("send_webhook", {"endpoint": "child.trusted.test:443"}) == {
        "child.trusted.test"
    }
    with pytest.raises(EgressDeniedError) as exc:
        guard.check("fetch_url", {"body": "go to https://evil.test/x"})
    assert exc.value.code == -32043


def test_non_egress_tool_does_not_apply_destination_policy():
    guard = EgressAllowlist([])
    assert guard.check("summarize", {"url": "https://evil.test"}) == set()


def test_config_loads_egress_allowlist(tmp_path):
    path = tmp_path / "bastion.yaml"
    path.write_text(
        "egress_allowlist:\n  enabled: true\n  hosts: ['*.example.com']\n  tool_hints: [deliver]\n",
        encoding="utf-8",
    )
    cfg = load_config(path)
    assert cfg.egress_allowlist_enabled is True
    assert cfg.egress_allowlist_hosts == ["*.example.com"]
    assert cfg.egress_allowlist_tool_hints == ["deliver"]


@pytest.mark.asyncio
async def test_middleware_blocks_denied_egress_before_handler():
    called = False
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_egress_allowlist=True,
        egress_allowlist=EgressAllowlist(["safe.test"]),
    )
    ctx = MiddlewareContext(
        message={
            "method": "tools/call",
            "params": {"name": "send_webhook", "arguments": {"url": "https://evil.test/x"}},
        },
        metadata={},
    )

    async def handler(_ctx):
        nonlocal called
        called = True
        return {}

    with pytest.raises(EgressDeniedError):
        await mw(ctx, handler)
    assert called is False
