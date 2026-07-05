"""
Scan outbound MCP tool/resource text for prompt-injection patterns.

Mitigates compromised or malicious MCP servers embedding jailbreak instructions
in tool results before they reach the agent (MCP03 / MCP06 / MCP10).
"""

from __future__ import annotations

import re
from typing import Iterable

from mcp_bastion.errors import PromptInjectionError

DEFAULT_RESPONSE_INJECTION_PATTERNS = [
    r"(?i)ignore\s+(?:all\s+)?previous\s+instructions",
    r"(?i)disregard\s+(?:all\s+)?(?:prior|previous|above)\s+instructions",
    r"(?i)you\s+are\s+now\s+(?:in\s+)?(?:developer|admin|god)\s+mode",
    r"(?i)<\s*system\s*>",
    r"(?i)\[INST\]",
    r"(?i)<!--\s*hidden",
    r"(?i)do\s+not\s+tell\s+the\s+user",
]


class ResponseInjectionScanner:
    """Regex-based scan of outbound text content for injection markers."""

    def __init__(
        self,
        *,
        extra_patterns: Iterable[str] | None = None,
    ) -> None:
        patterns = list(DEFAULT_RESPONSE_INJECTION_PATTERNS)
        if extra_patterns:
            patterns.extend(str(p) for p in extra_patterns if str(p).strip())
        self._regexes = [re.compile(p) for p in patterns]

    def find_match(self, text: str) -> str | None:
        """Return matched pattern source if text is suspicious."""
        if not text or not isinstance(text, str):
            return None
        for rx in self._regexes:
            if rx.search(text):
                return rx.pattern
        return None

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
