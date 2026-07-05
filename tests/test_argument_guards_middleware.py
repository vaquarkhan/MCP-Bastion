"""Middleware integration tests for argument guards."""

import pytest

jsonpath_ng = pytest.importorskip("jsonpath_ng")

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import ArgumentGuardError
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.argument_guards import ArgumentGuardEngine, GuardRule


@pytest.mark.asyncio
async def test_middleware_blocks_argument_guard_violation():
    guards = ArgumentGuardEngine(
        [
            GuardRule(
                name="no_rm",
                match="*",
                arg="$.cmd",
                pattern="rm\\s+-rf",
                action="block",
            )
        ]
    )
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_argument_guards=True,
        argument_guards=guards,
    )
    msg = {
        "method": "tools/call",
        "id": "1",
        "params": {"name": "run_shell", "arguments": {"cmd": "rm -rf /"}},
    }
    ctx = MiddlewareContext(message=msg, request_id="1", session_id="s1", metadata={})

    async def handler(_ctx):
        return {"result": "ok"}

    with pytest.raises(ArgumentGuardError, match="no_rm"):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_middleware_redacts_before_handler():
    guards = ArgumentGuardEngine(
        [
            GuardRule(
                name="redact_key",
                match="*",
                arg="$.secret",
                pattern="sk-[A-Za-z0-9]{6,}",
                action="redact",
            )
        ]
    )
    mw = MCPBastionMiddleware(
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_argument_guards=True,
        argument_guards=guards,
    )
    captured: dict = {}

    async def handler(ctx):
        params = ctx.message.get("params", {})
        captured["arguments"] = params.get("arguments")
        return {"result": "ok"}

    msg = {
        "method": "tools/call",
        "id": "2",
        "params": {"name": "save", "arguments": {"secret": "sk-abcdefghij"}},
    }
    ctx = MiddlewareContext(message=msg, request_id="2", session_id="s2", metadata={})
    await mw(ctx, handler)
    assert captured["arguments"]["secret"] == "***"
