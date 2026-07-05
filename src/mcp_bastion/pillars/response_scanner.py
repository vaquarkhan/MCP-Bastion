"""
Scan outbound MCP tool/resource text for prompt-injection patterns.

Mitigates compromised or malicious MCP servers embedding jailbreak instructions
in tool results before they reach the agent (MCP03 / MCP06 / MCP10).
"""

from __future__ import annotations

from typing import Iterable

from mcp_bastion.errors import PromptInjectionError
from mcp_bastion.pillars.injection_heuristics import (
    DEFAULT_INJECTION_PATTERNS,
    compile_injection_patterns,
    find_injection_match,
)

DEFAULT_RESPONSE_INJECTION_PATTERNS = DEFAULT_INJECTION_PATTERNS


class ResponseInjectionScanner:
    """Regex-based scan of outbound text content for injection markers."""

    def __init__(
        self,
        *,
        extra_patterns: Iterable[str] | None = None,
    ) -> None:
        self._regexes = compile_injection_patterns(extra_patterns)

    def find_match(self, text: str) -> str | None:
        """Return matched pattern source if text is suspicious."""
        return find_injection_match(text, self._regexes)

    def check_text(self, text: str) -> None:
        """Raise PromptInjectionError if injection pattern found."""
        matched = self.find_match(text)
        if matched:
            raise PromptInjectionError(
                "Response blocked: suspected prompt injection in tool/resource output"
            )

    def check_content_items(self, content: list[dict]) -> None:
        """Scan MCP text content items."""
        for item in content:
            if not isinstance(item, dict):
                continue
            if item.get("type") == "text" and "text" in item:
                self.check_text(str(item["text"]))
