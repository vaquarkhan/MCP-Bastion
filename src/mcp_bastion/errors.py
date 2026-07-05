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


class CircuitBreakerOpenError(MCPBastionError):
    """Raised when circuit breaker is open for a tool."""

    def __init__(self, message: str = "Request blocked: circuit breaker open") -> None:
        super().__init__(message, code=-32004)


class ContentFilterError(MCPBastionError):
    """Raised when content filter blocks a request."""

    def __init__(self, message: str = "Request blocked: content filter", matched_pattern: str | None = None) -> None:
        super().__init__(message, code=-32005)
        self.matched_pattern = matched_pattern


class RBACError(MCPBastionError):
    """Raised when user lacks permission for tool."""

    def __init__(self, message: str = "Request blocked: unauthorized tool access") -> None:
        super().__init__(message, code=-32006)


class SchemaValidationError(MCPBastionError):
    """Raised when schema validation fails."""

    def __init__(self, message: str = "Request blocked: schema validation failed") -> None:
        super().__init__(message, code=-32007)


class ReplayAttackError(MCPBastionError):
    """Raised when replay attack detected."""

    def __init__(self, message: str = "Request blocked: replay attack detected") -> None:
        super().__init__(message, code=-32008)


class CostBudgetExceededError(MCPBastionError):
    """Raised when cost budget exceeded."""

    def __init__(self, message: str = "Request blocked: cost budget exceeded") -> None:
        super().__init__(message, code=-32009)


class SemanticFirewallError(MCPBastionError):
    """Raised when semantic firewall detects suspicious tool intent or chain."""

    def __init__(self, message: str = "Request blocked: semantic firewall policy violation") -> None:
        super().__init__(message, code=-32010)


class ExternalPolicyDeniedError(MCPBastionError):
    """Raised when OPA/Cedar external policy engine denies the request."""

    def __init__(self, message: str = "Request blocked: external policy denied") -> None:
        super().__init__(message, code=-32011)


class SensitiveContentError(MCPBastionError):
    """Raised when model-based sensitive content classifier flags a request."""

    def __init__(self, message: str = "Request blocked: sensitive business content detected") -> None:
        super().__init__(message, code=-32012)


class AuthenticationError(MCPBastionError):
    """Raised when optional edge authentication (metadata token) is missing or invalid."""

    def __init__(self, message: str = "Request blocked: authentication required") -> None:
        super().__init__(message, code=-32013)


class ToolNotAllowedError(MCPBastionError):
    """Raised when tool name is not on the configured allowlist (tool inventory / poisoning guard)."""

    def __init__(self, message: str = "Request blocked: tool not on allowlist") -> None:
        super().__init__(message, code=-32014)


class SessionScopeExceededError(MCPBastionError):
    """Raised when a session exceeds distinct-tool limits (scope creep / agent sprawl)."""

    def __init__(self, message: str = "Request blocked: session tool scope exceeded") -> None:
        super().__init__(message, code=-32015)


class ToolMetadataPoisoningError(MCPBastionError):
    """Raised when tools/list (or equivalent) exposes tool metadata that fails safety checks."""

    def __init__(self, message: str = "Response blocked: suspicious tool metadata (possible tool poisoning)") -> None:
        super().__init__(message, code=-32016)


class GroundingViolationError(MCPBastionError):
    """Raised when outbound text references paths/symbols not grounded in the workspace."""

    def __init__(self, message: str = "Response blocked: ungrounded file reference in tool output") -> None:
        super().__init__(message, code=-32017)
