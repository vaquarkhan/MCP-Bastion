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


class BastionConfigError(ValueError):
    """Invalid bastion.yaml or incompatible pillar combination at startup."""


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


class PromptGuardUnavailableError(MCPBastionError):
    """Raised when PromptGuard ML is required but unavailable (gated model, auth, runtime error)."""

    def __init__(
        self,
        message: str = (
            "Request blocked: PromptGuard ML model unavailable. "
            "Install transformers/torch for ProtectAI/deberta-v3-base-prompt-injection-v2 "
            "(default ungated model), or configure Hugging Face access for the gated Llama model."
        ),
    ) -> None:
        super().__init__(message, code=-32018)


class AgentAccessDeniedError(MCPBastionError):
    """Raised when an authenticated agent attempts a tool outside its IAM policy."""

    def __init__(
        self,
        message: str = "Request blocked: agent is not permitted to call this tool",
    ) -> None:
        super().__init__(message, code=-32019)


class ServerVerificationError(MCPBastionError):
    """Raised when MCP server artifact checksums do not match the trusted manifest."""

    def __init__(
        self,
        message: str = "Request blocked: MCP server failed cryptographic verification",
    ) -> None:
        super().__init__(message, code=-32020)


class TransportBlockedError(MCPBastionError):
    """Raised when HTTP transport hardening blocks a cross-origin or non-loopback request."""

    def __init__(
        self,
        message: str = "Request blocked: HTTP transport hardening rejected this request",
    ) -> None:
        super().__init__(message, code=-32021)


class ArgumentGuardError(MCPBastionError):
    """Raised when a JSONPath argument guard blocks a tool call."""

    def __init__(self, message: str = "Request blocked: argument guard policy violation") -> None:
        super().__init__(message, code=-32022)


class CostPolicyApprovalRequiredError(MCPBastionError):
    """Raised when spend threshold requires explicit approval metadata."""

    def __init__(self, message: str = "Request blocked: cost policy approval required") -> None:
        super().__init__(message, code=-32023)


class ExpensiveChainError(MCPBastionError):
    """Raised when projected tool-sequence cost exceeds policy limit."""

    def __init__(self, message: str = "Request blocked: expensive tool chain") -> None:
        super().__init__(message, code=-32024)


class ToxicFlowError(MCPBastionError):
    """Raised when sensitive session taint flows into an external-write tool call."""

    def __init__(
        self,
        message: str = "Request blocked: toxic data-flow (sensitive read → external write)",
    ) -> None:
        super().__init__(message, code=-32042)


class EgressDeniedError(MCPBastionError):
    """Raised when an MCP-mediated outbound destination is not allowlisted."""

    def __init__(self, message: str = "Request blocked: egress destination denied") -> None:
        super().__init__(message, code=-32043)


class ConcurrencyLimitError(MCPBastionError):
    """Raised when a caller or tenant in-flight cap is reached."""

    def __init__(self, message: str = "Request blocked: concurrency limit exceeded") -> None:
        super().__init__(message, code=-32044)


class LoadShedError(MCPBastionError):
    """Raised when bounded admission capacity is exhausted."""

    def __init__(self, message: str = "Request blocked: load shed admission denied") -> None:
        super().__init__(message, code=-32045)


class BusinessRuleDeniedError(MCPBastionError):
    """Raised when a configured per-parameter business rule denies a call."""

    def __init__(self, message: str = "Request blocked: business rule denied") -> None:
        super().__init__(message, code=-32047)


class CanaryExfiltrationError(MCPBastionError):
    """Raised when runtime canary token appears in outbound tool arguments."""

    def __init__(
        self,
        message: str = "Request blocked: runtime canary exfiltration detected",
    ) -> None:
        super().__init__(message, code=-32025)


class LLMScannerBlockedError(MCPBastionError):
    """Raised when optional local LLM scanner flags injection above threshold."""

    def __init__(
        self,
        message: str = "Request blocked: local LLM scanner flagged injection",
    ) -> None:
        super().__init__(message, code=-32026)


class ATRRuleMatchError(MCPBastionError):
    """Raised when an ATR community rule matches inbound content."""

    def __init__(self, message: str = "Request blocked: ATR threat rule matched") -> None:
        super().__init__(message, code=-32027)


class ProtocolVersionError(MCPBastionError):
    """Raised when a stateless request declares an unsupported MCP protocol version."""

    def __init__(self, message: str = "Request blocked: unsupported MCP protocol version") -> None:
        super().__init__(message, code=-32028)


class InvalidStateHandleError(MCPBastionError):
    """Raised when an explicit state handle is missing or fails validation."""

    def __init__(self, message: str = "Request blocked: invalid MCP state handle") -> None:
        super().__init__(message, code=-32029)


class AgentLoopDetectedError(MCPBastionError):
    """Raised when agent stability monitor detects a repetitive tool-output loop."""

    def __init__(
        self,
        message: str = "Request blocked: repetitive agent tool loop detected",
    ) -> None:
        super().__init__(message, code=-32030)


class BehaviorAnomalyError(MCPBastionError):
    """Raised when behavioral fingerprint detects anomalous agent activity."""

    def __init__(
        self,
        message: str = "Request blocked: behavioral anomaly detected",
    ) -> None:
        super().__init__(message, code=-32031)


class CatalogDriftError(MCPBastionError):
    """Raised when tools/list catalog fingerprint drifts from pin or expected hash."""

    def __init__(
        self,
        message: str = "Response blocked: tool catalog fingerprint drift (possible tool poisoning)",
    ) -> None:
        super().__init__(message, code=-32032)
