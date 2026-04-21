"""
MCP-aware semantic firewall.

Detect suspicious intent mismatches and dangerous multi-tool chains.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from typing import Any

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import SemanticFirewallError

_SQL_TOKENS = re.compile(r"(drop\s+table|union\s+select|;\s*--|insert\s+into|delete\s+from)", re.IGNORECASE)
_SHELL_TOKENS = re.compile(r"(\brm\s+-rf\b|\bcurl\s+https?://|wget\s+https?://|\bchmod\s+\+x\b)", re.IGNORECASE)


class SemanticFirewall:
    """Heuristic semantic policy checks for MCP tool calls."""

    def __init__(self, *, history_limit: int = 50) -> None:
        self._history_limit = max(5, int(history_limit))
        self._session_tools: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=self._history_limit))

    @staticmethod
    def _flatten_text(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float, bool)):
            return str(value)
        if isinstance(value, dict):
            return " ".join(SemanticFirewall._flatten_text(v) for v in value.values())
        if isinstance(value, (list, tuple)):
            return " ".join(SemanticFirewall._flatten_text(v) for v in value)
        return str(value)

    @staticmethod
    def _is_external_write_tool(tool: str) -> bool:
        t = tool.lower()
        return any(x in t for x in ["webhook", "http", "api", "post", "send", "publish", "email", "upload"])

    @staticmethod
    def _is_sensitive_read_tool(tool: str) -> bool:
        t = tool.lower()
        return any(x in t for x in ["secret", "credential", "token", "key", "vault", "password"])

    def check(self, tool: str, arguments: Any, context: MiddlewareContext[Any]) -> None:
        """Raise SemanticFirewallError on suspicious intent or call chain."""
        session = context.session_id or "default"
        arg_text = self._flatten_text(arguments)
        tool_lower = (tool or "unknown").lower()

        if "weather" in tool_lower and (_SQL_TOKENS.search(arg_text) or _SHELL_TOKENS.search(arg_text)):
            raise SemanticFirewallError("Tool intent mismatch: weather tool received command/injection-like arguments")

        if _SHELL_TOKENS.search(arg_text) and "exec" not in tool_lower and "shell" not in tool_lower:
            raise SemanticFirewallError("Tool intent mismatch: non-exec tool received shell-like payload")

        history = self._session_tools[session]
        if history:
            prev = history[-1]
            if self._is_sensitive_read_tool(prev) and self._is_external_write_tool(tool):
                raise SemanticFirewallError(
                    f"Dangerous tool chain detected: {prev} -> {tool}. Review for data exfiltration risk"
                )

        history.append(tool)
