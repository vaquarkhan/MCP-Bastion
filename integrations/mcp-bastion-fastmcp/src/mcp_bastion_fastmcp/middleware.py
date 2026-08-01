"""FastMCP server wrapper with MCP-Bastion security."""
from __future__ import annotations

import logging
import uuid
from typing import Any

from mcp_bastion import MCPBastionMiddleware, compose_middleware
from mcp_bastion.base import MiddlewareContext

logger = logging.getLogger(__name__)

# FastMCP versions this wrapper was validated against (private API may change).
_SUPPORTED_FASTMCP_HINT = "mcp[cli] / mcp.server.fastmcp (call_tool on ToolManager)"


def secure_fastmcp(
    mcp: Any,
    enable_prompt_guard: bool = True,
    enable_pii_redaction: bool = True,
    enable_rate_limit: bool = True,
) -> Any:
    """Wire :class:`MCPBastionMiddleware` into a :class:`mcp.server.fastmcp.FastMCP` server.

    The official FastMCP API does not expose a generic JSON-RPC middleware hook, so this
    function patches ``mcp._tool_manager.call_tool`` to run each ``tools/call`` through
    the same composed chain used by the low-level MCP server examples.

    Call **immediately after** ``FastMCP(...)`` and **before** tools are invoked (e.g. before
    ``mcp.run()``)::

        from mcp.server.fastmcp import FastMCP
        from mcp_bastion_fastmcp import secure_fastmcp

        mcp = FastMCP("My Server")
        secure_fastmcp(mcp)

        @mcp.tool()
        def f(x: int) -> int:
            return x

    For **full** policy-as-code (``bastion.yaml``) including semantic firewall, external
    policy, allowlists, etc., use :func:`mcp_bastion.build_middleware_from_config` with
    the low-level MCP server or a transport you control; see **docs/QUICK_START.md** path B.

    Args:
        mcp: A :class:`mcp.server.fastmcp.FastMCP` instance.
        enable_prompt_guard: Pass-through to :class:`MCPBastionMiddleware`.
        enable_pii_redaction: Pass-through to :class:`MCPBastionMiddleware`.
        enable_rate_limit: Pass-through to :class:`MCPBastionMiddleware`.

    Returns:
        The same ``mcp`` instance (for call chaining).
    """
    if not hasattr(mcp, "_tool_manager"):
        raise RuntimeError(
            "secure_fastmcp requires FastMCP._tool_manager (private API). "
            f"Supported shape: {_SUPPORTED_FASTMCP_HINT}. "
            "Use build_middleware_from_config with a low-level MCP server instead."
        )
    tm = mcp._tool_manager
    if not hasattr(tm, "call_tool") or not callable(getattr(tm, "call_tool", None)):
        raise RuntimeError(
            "secure_fastmcp: ToolManager has no callable call_tool — "
            "FastMCP internals may have changed; pin a known mcp package version."
        )
    logger.warning(
        "secure_fastmcp patches FastMCP._tool_manager.call_tool (private API). "
        "Pin your mcp/FastMCP version and re-test after upgrades. Prefer "
        "build_middleware_from_config when you control the transport."
    )

    bastion = MCPBastionMiddleware(
        enable_prompt_guard=enable_prompt_guard,
        enable_pii_redaction=enable_pii_redaction,
        enable_rate_limit=enable_rate_limit,
    )
    chain = compose_middleware(bastion)

    _orig = tm.call_tool

    async def _guarded_call_tool(
        name: str,
        arguments: dict[str, Any],
        context: Any = None,
        convert_result: bool = False,
    ) -> Any:
        session_id = "fastmcp"
        if context is not None:
            try:
                rc = getattr(context, "request_context", None)
                if rc is not None:
                    session_id = f"ses:{id(rc)}"
            except Exception:
                pass
        req_id = str(uuid.uuid4())
        msg: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
        mw_ctx = MiddlewareContext(
            message=msg,
            request_id=req_id,
            session_id=session_id,
            metadata={},
        )

        async def call_next(_ctx: MiddlewareContext[Any]) -> Any:
            return await _orig(name, arguments, context=context, convert_result=convert_result)

        return await chain(mw_ctx, call_next)

    tm.call_tool = _guarded_call_tool  # type: ignore[method-assign]
    return mcp
