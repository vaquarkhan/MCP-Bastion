"""
MCP-compliant error types for security policy violations.
"""

from __future__ import annotations


class MCPBastionError(Exception):
    """Base exception for MCP-Bastion security violations."""

    def __init__(self, message: str, code: int = -32000) -> None:
        super().__init__(message)
        self.message = message
        self.code = code

    def to_mcp_error(self) -> dict:
        """Format as MCP/JSON-RPC error object."""
        return {
            "code": self.code,
            "message": self.message,
        }


class PromptInjectionError(MCPBastionError):
    """Raised when prompt injection or jailbreak is detected."""

    def __init__(self, message: str = "Request blocked: potential prompt injection detected") -> None:
        super().__init__(message, code=-32001)


class RateLimitExceededError(MCPBastionError):
    """Raised when rate limit or iteration cap is exceeded."""

    def __init__(self, message: str = "Request blocked: rate limit exceeded") -> None:
        super().__init__(message, code=-32002)


class TokenBudgetExceededError(MCPBastionError):
    """Raised when FinOps token budget is exhausted."""

    def __init__(self, message: str = "Request blocked: token budget exhausted") -> None:
        super().__init__(message, code=-32003)
