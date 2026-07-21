"""
Lightweight MCP server discovery card (.well-known/mcp.json).

Optional opt-in for HTTP proxy / boundary deployments. Serves a cacheable JSON
schema so orchestrators can discover capabilities without an initialize handshake.
"""

from __future__ import annotations

import json
from typing import Any


DEFAULT_DISCOVERY_PATHS = (
    "/.well-known/mcp.json",
    "/.well-known/mcp",
)


def build_server_card(
    *,
    name: str = "mcp-bastion-protected",
    version: str = "1.0.0",
    protocol_versions: list[str] | None = None,
    transport_modes: list[str] | None = None,
    tools: list[dict[str, Any]] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a minimal MCP server discovery card."""
    card: dict[str, Any] = {
        "name": name,
        "version": version,
        "protocolVersions": protocol_versions or ["2024-11-05", "2025-03-26"],
        "transport": {
            "streamableHttp": {"path": "/mcp"},
            "modes": transport_modes or ["stateful", "stateless"],
        },
        "capabilities": {
            "tools": {"listChanged": False},
            "resources": {"subscribe": False, "listChanged": False},
            "prompts": {"listChanged": False},
        },
    }
    if tools:
        card["tools"] = tools
    if extra:
        card.update(extra)
    return card


def card_from_config(config: Any) -> dict[str, Any]:
    """Merge bastion.yaml discovery overrides with sensible defaults."""
    inline = dict(getattr(config, "mcp_transport_discovery_card", {}) or {})
    versions = list(getattr(config, "mcp_transport_allowed_versions", []) or [])
    if not versions:
        versions = ["2024-11-05", "2025-03-26"]
    base = build_server_card(
        name=str(inline.get("name", "mcp-bastion-protected")),
        version=str(inline.get("version", "1.0.0")),
        protocol_versions=list(inline.get("protocolVersions", versions)),
        transport_modes=list(inline.get("transport", {}).get("modes", ["stateful", "stateless"]))
        if isinstance(inline.get("transport"), dict)
        else ["stateful", "stateless"],
        tools=inline.get("tools") if isinstance(inline.get("tools"), list) else None,
    )
    for k, v in inline.items():
        if k not in base:
            base[k] = v
    base.setdefault("bastion", {"hybridTransport": True, "discovery": "edge-cacheable"})
    return base


def discovery_response_body(card: dict[str, Any]) -> bytes:
    return json.dumps(card, separators=(",", ":")).encode("utf-8")


def is_discovery_path(path: str) -> bool:
    normalized = (path or "/").rstrip("/") or "/"
    return normalized in DEFAULT_DISCOVERY_PATHS
