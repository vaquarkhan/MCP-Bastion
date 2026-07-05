"""
HTTP transport hardening for local MCP servers (CSRF / DNS rebind mitigation).

Wraps the MCP streamable-HTTP ASGI app with Host / Origin checks before JSON-RPC
reaches middleware. Pair with bind_host=127.0.0.1 and edge_auth or agent_iam.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

logger = logging.getLogger(__name__)

ASGIApp = Callable[..., Any]


@dataclass(frozen=True)
class TransportHardeningConfig:
    enabled: bool = True
    allowed_hosts: frozenset[str] = frozenset({"127.0.0.1", "localhost", "[::1]"})
    block_browser_origin: bool = True
    require_loopback_host: bool = True


def transport_config_from_bastion(cfg: Any) -> TransportHardeningConfig:
    """Build config from BastionConfig transport_hardening fields."""
    hosts = getattr(cfg, "transport_hardening_allowed_hosts", None) or [
        "127.0.0.1",
        "localhost",
        "[::1]",
    ]
    return TransportHardeningConfig(
        enabled=bool(getattr(cfg, "transport_hardening_enabled", True)),
        allowed_hosts=frozenset(str(h).lower() for h in hosts),
        block_browser_origin=bool(getattr(cfg, "transport_hardening_block_browser_origin", True)),
        require_loopback_host=bool(getattr(cfg, "transport_hardening_require_loopback", True)),
    )


def _header(headers: list[tuple[bytes, bytes]], name: str) -> str | None:
    key = name.lower().encode("ascii")
    for k, v in headers:
        if k.lower() == key:
            return v.decode("latin-1", errors="replace")
    return None


def _host_only(host_header: str | None) -> str:
    if not host_header:
        return ""
    return host_header.split(":")[0].strip().lower()


def _is_loopback_host(host: str) -> bool:
    return host in ("127.0.0.1", "localhost", "[::1]", "::1")


def _is_browser_origin(origin: str) -> bool:
    o = origin.strip().lower()
    return o.startswith("http://") or o.startswith("https://")


class TransportHardeningMiddleware:
    """ASGI middleware: reject cross-origin browser requests to localhost MCP."""

    def __init__(self, app: ASGIApp, config: TransportHardeningConfig | None = None) -> None:
        self.app = app
        self.config = config or TransportHardeningConfig()

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or not self.config.enabled:
            await self.app(scope, receive, send)
            return

        headers = scope.get("headers") or []
        host = _host_only(_header(headers, "host"))
        origin = _header(headers, "origin") or ""
        client = scope.get("client")
        client_host = client[0] if client else ""

        if self.config.require_loopback_host and host and not _is_loopback_host(host):
            logger.warning("transport_hardening blocked non-loopback Host: %s", host)
            await _send_json_error(send, 403, "Forbidden: MCP HTTP must bind to loopback")
            return

        if host and self.config.allowed_hosts and host not in self.config.allowed_hosts:
            logger.warning("transport_hardening blocked Host not in allowlist: %s", host)
            await _send_json_error(send, 403, "Forbidden: Host not allowed")
            return

        if (
            self.config.block_browser_origin
            and origin
            and _is_browser_origin(origin)
            and (_is_loopback_host(host) or _is_loopback_host(client_host))
        ):
            logger.warning(
                "transport_hardening blocked browser Origin=%s to Host=%s (CSRF/rebind)",
                origin,
                host or client_host,
            )
            await _send_json_error(send, 403, "Forbidden: browser cross-origin request to local MCP")
            return

        await self.app(scope, receive, send)


async def _send_json_error(send: Any, status: int, detail: str) -> None:
    body = (
        '{"jsonrpc":"2.0","error":{"code":-32021,"message":'
        + __import__("json").dumps(detail)
        + '},"id":null}'
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def wrap_asgi_app(app: ASGIApp, config: TransportHardeningConfig | None = None) -> ASGIApp:
    """Return app wrapped with transport hardening middleware."""
    return TransportHardeningMiddleware(app, config)


def run_hardened_streamable_http(
    mcp: Any,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    config: Any | None = None,
) -> None:
    """Run FastMCP streamable HTTP with transport hardening and uvicorn."""
    import uvicorn

    from mcp_bastion.config import load_config

    cfg = config or load_config(None)
    th = transport_config_from_bastion(cfg)
    app = mcp.streamable_http_app()
    if th.enabled:
        app = wrap_asgi_app(app, th)
    logger.info("MCP streamable-http on http://%s:%s/mcp (transport_hardening=%s)", host, port, th.enabled)
    uvicorn.run(app, host=host, port=port, log_level="info")
