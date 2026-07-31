"""
MCP HTTP proxy - same bastion.yaml enforcement, boundary deployment shape.

Forwards streamable-HTTP MCP to an upstream URL while running configured middleware
on guarded JSON-RPC methods (tools/call, resources/read, etc.).

Phase 2: when PII (and optional vault) is enabled, mutates wire bodies:
- hydrate vault tokens in inbound ``tools/call`` arguments before upstream
- abstract/redact PII in upstream JSON-RPC ``result`` content before the client sees it
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request
from typing import Any

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.config import build_middleware_from_config, load_config, resolve_bastion_middleware
from mcp_bastion.discovery_card import card_from_config, discovery_response_body, is_discovery_path
from mcp_bastion.mcp_transport import ingest_http_headers
from mcp_bastion.transport_hardening import TransportHardeningMiddleware, transport_config_from_bastion

logger = logging.getLogger(__name__)

GUARDED_METHODS = frozenset(
    {
        "tools/call",
        "tools/list",
        "resources/read",
        "prompts/get",
        "sampling/createMessage",
        "elicitation/create",
    }
)

# Methods whose upstream results typically carry text content worth PII treatment.
_RESPONSE_MUTATE_METHODS = frozenset(
    {
        "tools/call",
        "resources/read",
        "prompts/get",
        "sampling/createMessage",
        "elicitation/create",
    }
)


def _jsonrpc_method(body: bytes) -> str | None:
    try:
        msg = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if isinstance(msg, dict):
        m = str(msg.get("method") or "")
        return m or None
    return None


async def _read_body(receive: Any) -> bytes:
    chunks: list[bytes] = []
    while True:
        event = await receive()
        if event.get("type") == "http.request":
            chunks.append(event.get("body") or b"")
            if not event.get("more_body"):
                break
        elif event.get("type") == "http.disconnect":
            break
    return b"".join(chunks)


def _upstream_request(
    upstream: str,
    *,
    method: str,
    headers: list[tuple[str, str]],
    body: bytes,
    timeout: float = 120.0,
) -> tuple[int, list[tuple[str, str]], bytes]:
    req = urllib.request.Request(
        upstream,
        data=body if method.upper() in ("POST", "PUT", "PATCH") else None,
        method=method.upper(),
    )
    skip = frozenset({"host", "content-length", "transfer-encoding"})
    for k, v in headers:
        if k.lower() not in skip:
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = int(getattr(resp, "status", 200) or 200)
            resp_headers = list(resp.headers.items())
            data = resp.read()
            return status, resp_headers, data
    except urllib.error.HTTPError as e:
        return e.code, list(e.headers.items()) if e.headers else [], e.read()


def _proxy_context(
    msg: dict[str, Any],
    *,
    session_id: str | None,
    request_id: str | None,
    metadata: dict[str, Any],
    headers: list[tuple[str, str]] | None = None,
) -> MiddlewareContext[Any]:
    ctx = MiddlewareContext(
        message=msg,
        request_id=request_id or str(msg.get("id") or "proxy"),
        session_id=session_id or "proxy-session",
        metadata=dict(metadata),
    )
    ingest_http_headers(ctx, headers or [])
    return ctx


async def _guard_request(
    middleware_stack: Any,
    body: bytes,
    *,
    session_id: str | None,
    request_id: str | None,
    metadata: dict[str, Any],
    headers: list[tuple[str, str]] | None = None,
) -> bytes | None:
    """Return JSON-RPC error body if middleware blocks; None if allowed (forward upstream)."""
    try:
        msg = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(msg, dict):
        return None
    method = str(msg.get("method") or "")
    if method not in GUARDED_METHODS:
        return None

    ctx = _proxy_context(
        msg, session_id=session_id, request_id=request_id, metadata=metadata, headers=headers
    )

    async def _noop_handler(c: MiddlewareContext[Any]) -> Any:
        if method == "tools/call":
            return {"content": [{"type": "text", "text": "proxy-allowed"}]}
        if method == "tools/list":
            return {"tools": []}
        return {}

    try:
        await middleware_stack(ctx, _noop_handler)
    except Exception as e:
        code = getattr(e, "code", -32000)
        return json.dumps(
            {"jsonrpc": "2.0", "error": {"code": code, "message": str(e)}, "id": msg.get("id")}
        ).encode("utf-8")
    return None


def _hydrate_proxy_request(
    bastion: Any,
    body: bytes,
    *,
    session_id: str | None,
    request_id: str | None,
    metadata: dict[str, Any],
    headers: list[tuple[str, str]] | None = None,
) -> tuple[bytes, MiddlewareContext[Any] | None]:
    """
    Restore vault tokens in tools/call arguments before forwarding upstream.

    Returns (possibly mutated body, context for response mutation).
    """
    try:
        msg = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return body, None
    if not isinstance(msg, dict):
        return body, None
    method = str(msg.get("method") or "")
    if method not in GUARDED_METHODS:
        return body, None

    ctx = _proxy_context(
        msg, session_id=session_id, request_id=request_id, metadata=metadata, headers=headers
    )
    if (
        method == "tools/call"
        and getattr(bastion, "enable_pii_vault", False)
        and getattr(bastion, "pii_vault", None) is not None
    ):
        params = msg.get("params")
        if isinstance(params, dict):
            bastion._hydrate_tool_arguments(ctx, params, trace=[])  # noqa: SLF001
            msg["params"] = params
            try:
                body = json.dumps(msg, separators=(",", ":")).encode("utf-8")
            except (TypeError, ValueError):
                pass
    return body, ctx


def _mutate_proxy_response(
    bastion: Any,
    resp_body: bytes,
    *,
    ctx: MiddlewareContext[Any] | None,
    method: str | None,
) -> bytes:
    """Apply outbound PII redaction / vault abstract to JSON-RPC result content."""
    if ctx is None or not method or method not in _RESPONSE_MUTATE_METHODS:
        return resp_body
    if not getattr(bastion, "enable_pii_redaction", False):
        return resp_body
    try:
        msg = json.loads(resp_body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return resp_body
    if not isinstance(msg, dict) or "result" not in msg or msg.get("error"):
        return resp_body
    try:
        mutated = bastion._redact_result_content(msg, context=ctx)  # noqa: SLF001
        return json.dumps(mutated, separators=(",", ":")).encode("utf-8")
    except Exception as exc:
        logger.debug("proxy response PII mutate skipped: %s", exc)
        return resp_body


def build_proxy_asgi_app(
    upstream_url: str,
    *,
    config_path: str | None = None,
    config: Any | None = None,
) -> Any:
    """Build ASGI app: hardened transport + guarded forward to upstream_url."""
    cfg = config or load_config(config_path)
    middleware_stack = build_middleware_from_config(cfg)
    bastion = resolve_bastion_middleware(middleware_stack)
    upstream = upstream_url.rstrip("/")
    th = transport_config_from_bastion(cfg)

    async def proxy_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await send({"type": "http.response.start", "status": 400, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return

        method = scope.get("method", "GET")
        headers_raw = scope.get("headers") or []
        headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in headers_raw]
        query = scope.get("query_string", b"").decode("latin-1")
        path = scope.get("path", "/mcp")
        if getattr(cfg, "mcp_transport_discovery_enabled", False) and is_discovery_path(path):
            if method.upper() == "GET":
                body = discovery_response_body(card_from_config(cfg))
                await send(
                    {
                        "type": "http.response.start",
                        "status": 200,
                        "headers": [
                            (b"content-type", b"application/json"),
                            (b"cache-control", b"public, max-age=300"),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": body})
                return
            await send({"type": "http.response.start", "status": 405, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return

        base = upstream.rsplit("/mcp", 1)[0] if "/mcp" in upstream else upstream
        url = upstream if path == "/mcp" else f"{base}{path}"
        if query:
            url = f"{url}?{query}"

        metadata: dict[str, Any] = {}
        session_id = None
        request_id = None
        for k, v in headers:
            kl = k.lower()
            metadata[kl] = v
            if kl == "mcp-session-id":
                session_id = v
            if kl == "x-request-id":
                request_id = v
            if kl.startswith("x-bastion-") or kl == "authorization":
                metadata[k] = v

        body = b""
        rpc_method: str | None = None
        proxy_ctx: MiddlewareContext[Any] | None = None
        if method.upper() in ("POST", "PUT", "PATCH"):
            body = await _read_body(receive)
            rpc_method = _jsonrpc_method(body)
            if rpc_method in GUARDED_METHODS:
                blocked = await _guard_request(
                    middleware_stack,
                    body,
                    session_id=session_id,
                    request_id=request_id,
                    metadata=metadata,
                    headers=headers,
                )
                if blocked is not None:
                    await send(
                        {
                            "type": "http.response.start",
                            "status": 403,
                            "headers": [(b"content-type", b"application/json")],
                        }
                    )
                    await send({"type": "http.response.body", "body": blocked})
                    return
                if bastion is not None:
                    body, proxy_ctx = _hydrate_proxy_request(
                        bastion,
                        body,
                        session_id=session_id,
                        request_id=request_id,
                        metadata=metadata,
                        headers=headers,
                    )

        status, resp_headers, resp_body = await asyncio.to_thread(
            _upstream_request, url, method=method, headers=headers, body=body
        )
        if bastion is not None and proxy_ctx is not None:
            resp_body = _mutate_proxy_response(
                bastion, resp_body, ctx=proxy_ctx, method=rpc_method
            )
        out_headers = [
            (k.encode("latin-1"), v.encode("latin-1"))
            for k, v in resp_headers
            if k.lower() not in ("transfer-encoding", "connection", "content-length")
        ]
        # Recompute length after possible mutation.
        out_headers.append((b"content-length", str(len(resp_body)).encode("latin-1")))
        await send({"type": "http.response.start", "status": status, "headers": out_headers})
        await send({"type": "http.response.body", "body": resp_body})

    if th.enabled:
        return TransportHardeningMiddleware(proxy_app, th)
    return proxy_app


def run_proxy_http(
    upstream_url: str,
    *,
    host: str = "127.0.0.1",
    port: int = 8080,
    config_path: str | None = None,
) -> None:
    """Run MCP HTTP proxy with uvicorn."""
    import uvicorn

    cfg = load_config(config_path)
    app = build_proxy_asgi_app(upstream_url, config=cfg)
    logger.info(
        "MCP-Bastion proxy on http://%s:%s/mcp → %s (boundary_mode=%s)",
        host,
        port,
        upstream_url,
        getattr(cfg, "boundary_mode_enabled", False),
    )
    uvicorn.run(app, host=host, port=port, log_level="info")
