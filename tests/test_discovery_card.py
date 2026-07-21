"""Tests for MCP server discovery card (.well-known/mcp.json)."""

from __future__ import annotations

import json

from mcp_bastion.config import BastionConfig
from mcp_bastion.discovery_card import (
    DEFAULT_DISCOVERY_PATHS,
    build_server_card,
    card_from_config,
    discovery_response_body,
    is_discovery_path,
)


def test_build_server_card_defaults():
    card = build_server_card()
    assert card["name"] == "mcp-bastion-protected"
    assert "2024-11-05" in card["protocolVersions"]
    assert card["transport"]["modes"] == ["stateful", "stateless"]


def test_build_server_card_custom_tools():
    card = build_server_card(name="demo", tools=[{"name": "search"}])
    assert card["name"] == "demo"
    assert card["tools"] == [{"name": "search"}]


def test_card_from_config_merges_inline_overrides():
    cfg = BastionConfig(
        mcp_transport_enabled=True,
        mcp_transport_allowed_versions=["2025-03-26"],
        mcp_transport_discovery_card={
            "name": "acme-mcp",
            "version": "2.0.0",
            "extraField": True,
        },
    )
    card = card_from_config(cfg)
    assert card["name"] == "acme-mcp"
    assert card["version"] == "2.0.0"
    assert card["protocolVersions"] == ["2025-03-26"]
    assert card["bastion"]["hybridTransport"] is True
    assert card["extraField"] is True


def test_discovery_response_body_compact_json():
    body = discovery_response_body({"name": "x", "version": "1"})
    parsed = json.loads(body.decode("utf-8"))
    assert parsed["name"] == "x"
    assert b" " not in body


def test_is_discovery_path():
    assert is_discovery_path("/.well-known/mcp.json") is True
    assert is_discovery_path("/.well-known/mcp") is True
    assert is_discovery_path("/.well-known/mcp.json/") is True
    assert is_discovery_path("/mcp") is False
    assert DEFAULT_DISCOVERY_PATHS == ("/.well-known/mcp.json", "/.well-known/mcp")


def test_build_server_card_extra_merge():
    card = build_server_card(extra={"customField": True})
    assert card["customField"] is True
    assert card["name"] == "mcp-bastion-protected"


def test_card_from_config_transport_modes_override():
    cfg = BastionConfig(
        mcp_transport_discovery_card={
            "transport": {"modes": ["stateless"]},
        }
    )
    card = card_from_config(cfg)
    assert card["transport"]["modes"] == ["stateless"]


def test_card_from_config_empty_versions_uses_defaults():
    cfg = BastionConfig(mcp_transport_allowed_versions=[])
    card = card_from_config(cfg)
    assert "2024-11-05" in card["protocolVersions"]
