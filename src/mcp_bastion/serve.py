"""Hardened HTTP serve helpers for MCP-Bastion."""

from __future__ import annotations

import logging
from typing import Any

from mcp_bastion.transport_hardening import run_hardened_streamable_http

__all__ = [
    "configure_fastmcp_http",
    "run_streamable_http",
    "run_hardened_streamable_http",
]

logger = logging.getLogger(__name__)


def configure_fastmcp_http(mcp: Any, *, host: str, port: int) -> None:
    """Set bind host/port for FastMCP streamable-http.

    FastMCP >= 1.2 ``run()`` no longer accepts ``host``/``port``; they live on ``settings``
    (or the ``FastMCP(..., host=, port=)`` constructor).
    """
    settings = getattr(mcp, "settings", None)
    if settings is None:
        raise TypeError("FastMCP instance has no settings; pass host/port to FastMCP(...) instead")
    settings.host = host
    settings.port = port


def run_streamable_http(
    mcp: Any,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    config: Any | None = None,
) -> None:
    """Run streamable HTTP - hardened uvicorn path or ``mcp.run(transport=...)`` with settings."""
    from mcp_bastion.config import load_config

    cfg = config or load_config(None)
    if bool(getattr(cfg, "transport_hardening_enabled", True)):
        run_hardened_streamable_http(mcp, host=host, port=port, config=cfg)
        return
    configure_fastmcp_http(mcp, host=host, port=port)
    logger.info("MCP streamable-http on http://%s:%s/mcp", host, port)
    mcp.run(transport="streamable-http")
