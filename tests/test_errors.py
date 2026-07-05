"""Tests for MCP-Bastion error types."""

import pytest

from mcp_bastion.errors import (
    CircuitBreakerOpenError,
    ContentFilterError,
    CostBudgetExceededError,
    GroundingViolationError,
    MCPBastionError,
    PromptInjectionError,
    RBACError,
    RateLimitExceededError,
    ReplayAttackError,
    SchemaValidationError,
    TokenBudgetExceededError,
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


def test_grounding_violation_error_default():
    err = GroundingViolationError()
    assert err.code == -32017


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
        GroundingViolationError("grounding"),
    ]
    for err in errors:
        obj = err.to_mcp_error()
        assert "code" in obj
        assert "message" in obj
        assert isinstance(obj["code"], int)
        assert isinstance(obj["message"], str)
