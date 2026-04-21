"""Tests for MCP-Bastion error types."""

import pytest

from mcp_bastion.errors import (
    AuthenticationError,
    CircuitBreakerOpenError,
    ContentFilterError,
    CostBudgetExceededError,
    ExternalPolicyDeniedError,
    MCPBastionError,
    PromptInjectionError,
    RBACError,
    RateLimitExceededError,
    ReplayAttackError,
    SchemaValidationError,
    SemanticFirewallError,
    SensitiveContentError,
    SessionScopeExceededError,
    TokenBudgetExceededError,
    ToolMetadataPoisoningError,
    ToolNotAllowedError,
)


def test_prompt_injection_error_default():
    """PromptInjectionError uses default message when not provided."""
    err = PromptInjectionError()
    assert err.code == -32001
    assert "prompt injection" in err.message.lower()


def test_token_budget_exceeded_error_default():
    """TokenBudgetExceededError uses default message when not provided."""
    err = TokenBudgetExceededError()
    assert err.code == -32003
    assert "token budget" in err.message.lower()


def test_content_filter_error_matched_pattern():
    """ContentFilterError stores matched_pattern."""
    err = ContentFilterError("blocked", matched_pattern="password")
    assert err.matched_pattern == "password"


def test_all_errors_to_mcp_error():
    """All error types produce valid MCP error structure."""
    errors = [
        MCPBastionError("base", code=-32000),
        PromptInjectionError("injection"),
        RateLimitExceededError("rate"),
        TokenBudgetExceededError("tokens"),
        CircuitBreakerOpenError("circuit"),
        ContentFilterError("content"),
        RBACError("rbac"),
        SchemaValidationError("schema"),
        ReplayAttackError("replay"),
        CostBudgetExceededError("cost"),
        SemanticFirewallError("semantic"),
        ExternalPolicyDeniedError("opa"),
        SensitiveContentError("sensitive"),
        AuthenticationError("auth"),
        ToolNotAllowedError("allowlist"),
        SessionScopeExceededError("session"),
        ToolMetadataPoisoningError("metadata"),
    ]
    for err in errors:
        obj = err.to_mcp_error()
        assert "code" in obj
        assert "message" in obj
        assert isinstance(obj["code"], int)
        assert isinstance(obj["message"], str)


def test_json_rpc_error_codes_sequential_policy_exceptions():
    """Documented codes -32001..-32016 match default constructor for each policy exception."""
    pairs = [
        (-32001, PromptInjectionError),
        (-32002, RateLimitExceededError),
        (-32003, TokenBudgetExceededError),
        (-32004, CircuitBreakerOpenError),
        (-32005, ContentFilterError),
        (-32006, RBACError),
        (-32007, SchemaValidationError),
        (-32008, ReplayAttackError),
        (-32009, CostBudgetExceededError),
        (-32010, SemanticFirewallError),
        (-32011, ExternalPolicyDeniedError),
        (-32012, SensitiveContentError),
        (-32013, AuthenticationError),
        (-32014, ToolNotAllowedError),
        (-32015, SessionScopeExceededError),
        (-32016, ToolMetadataPoisoningError),
    ]
    for expected_code, cls in pairs:
        err = cls()
        assert err.code == expected_code, cls.__name__
        assert err.to_mcp_error()["code"] == expected_code
