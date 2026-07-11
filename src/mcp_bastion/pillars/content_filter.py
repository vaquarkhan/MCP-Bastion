"""
Content filtering beyond PII for MCP-Bastion.

Block/flag code execution, file paths, URLs, and custom patterns.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from mcp_bastion.errors import ContentFilterError
from mcp_bastion.pillars.content_normalize import normalize_for_scan

logger = logging.getLogger(__name__)

# Default patterns
DEFAULT_CODE_PATTERNS = [
    r"```[\s\S]*?```",  # Markdown code blocks
    r"`[^`]+`",  # Inline code
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__\s*\(",
    r"subprocess\.(run|call|Popen)",
    r"os\.system\s*\(",
    r"shell\s*=\s*True",
    r"(?i)\brm\s+-rf\b",
    r"(?i)\bcurl\s+[^\n|]*\|\s*(?:ba)?sh\b",
    r"(?i)\bwget\s+[^\n|]*\|\s*(?:ba)?sh\b",
    r"(?i)\bchmod\s+\+x\b",
    r"(?i)base64\s+-d[^\n|]*\|\s*(?:ba)?sh\b",
    r"(?i)\|\s*(?:ba)?sh\s*$",
]

DEFAULT_PATH_PATTERNS = [
    r"(?:^|[\s/\\])(?:/etc/|/var/|/usr/|C:\\|/root/|~/)",
    r"(?:^|[\s/\\])\.\./",  # Path traversal
    r"(?:^|[\s/\\])\.\.\\",
    r"/etc/passwd",
    r"/etc/shadow",
    r"\.env",
]

DEFAULT_URL_PATTERN = r"https?://[^\s]+"

# High-confidence credential / key material (MCP01). Enable via block_secrets=True.
DEFAULT_SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",  # AWS access key id
    r"ASIA[0-9A-Z]{16}",  # AWS STS temporary key id
    r"sk-(?:live|proj|ant|test)-[A-Za-z0-9]{20,}",  # common LLM / API key prefixes
    r"AIza[0-9A-Za-z\-_]{35}",  # Google API key shape
    r"xox[baprs]-[0-9A-Za-z\-]+",  # Slack tokens
    r"gh[pousr]_[A-Za-z0-9_]{36,}",  # GitHub PAT
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
]


class ContentFilter:
    """
    Block/flag specific content types in tool arguments.

    Use for preventing code injection, path traversal, URL exfiltration.
    """

    def __init__(
        self,
        *,
        block_code_execution: bool = True,
        block_file_paths: bool = True,
        block_urls: bool = False,
        block_secrets: bool = False,
        allowlist_patterns: list[str] | None = None,
        denylist_patterns: list[str] | None = None,
        custom_patterns: list[str] | None = None,
    ) -> None:
        self.block_code_execution = block_code_execution
        self.block_file_paths = block_file_paths
        self.block_urls = block_urls
        self.block_secrets = block_secrets
        self.allowlist_patterns = allowlist_patterns or []
        self.denylist_patterns = denylist_patterns or custom_patterns or []
        # Backward compatible alias retained for callers that still use custom_patterns.
        self.custom_patterns = self.denylist_patterns

        self._code_regexes = [re.compile(p, re.IGNORECASE) for p in DEFAULT_CODE_PATTERNS]
        self._path_regexes = [re.compile(p) for p in DEFAULT_PATH_PATTERNS]
        self._url_regex = re.compile(DEFAULT_URL_PATTERN)
        self._secret_regexes = [re.compile(p) for p in DEFAULT_SECRET_PATTERNS]

        def _compile_patterns(patterns: list[str], label: str) -> list[re.Pattern[str]]:
            compiled: list[re.Pattern[str]] = []
            for p in patterns:
                try:
                    compiled.append(re.compile(p))
                except re.error as e:
                    raise ValueError(f"Invalid {label} regex pattern: {e}") from e
            return compiled

        self._allowlist_regexes = _compile_patterns(self.allowlist_patterns, "allowlist")
        self._denylist_regexes = _compile_patterns(self.denylist_patterns, "custom")

    def update_denylist_patterns(self, patterns: list[str]) -> None:
        """Replace custom/denylist patterns and recompile (e.g. after threat-feed refresh)."""
        self.denylist_patterns = list(patterns)
        self.custom_patterns = self.denylist_patterns
        compiled: list[re.Pattern[str]] = []
        for p in self.denylist_patterns:
            try:
                compiled.append(re.compile(p))
            except re.error as e:
                logger.warning("content_filter: skip invalid denylist pattern: %s", e)
        self._denylist_regexes = compiled

    @property
    def _custom_regexes(self) -> list[re.Pattern[str]]:
        """Alias for denylist regexes (backward compatible with older tests)."""
        return self._denylist_regexes

    def _extract_text(self, value: Any) -> str:
        """Flatten value to string for scanning."""
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float, bool)):
            return str(value)
        if isinstance(value, dict):
            return " ".join(self._extract_text(v) for v in value.values())
        if isinstance(value, (list, tuple)):
            return " ".join(self._extract_text(v) for v in value)
        return str(value)

    def check(self, text: str | dict | list | None) -> None:
        """
        Check content. Raises ContentFilterError if blocked.
        Accepts string or nested structure (flattened for scanning).
        """
        flat = self._extract_text(text)
        if not flat or not flat.strip():
            return
        text = normalize_for_scan(flat)

        for rx in self._allowlist_regexes:
            if rx.search(text):
                logger.debug("content_filter allowlisted pattern=%s", rx.pattern)
                return

        if self.block_secrets:
            for rx in self._secret_regexes:
                if rx.search(text):
                    logger.warning("content_filter blocked secret-like material pattern=%s", rx.pattern)
                    raise ContentFilterError(
                        "Content blocked: possible credential or API key material in payload",
                        matched_pattern=rx.pattern,
                    )

        for rx in self._denylist_regexes:
            if rx.search(text):
                logger.warning("content_filter blocked denylist pattern=%s", rx.pattern)
                raise ContentFilterError(
                    "Content blocked: denylist pattern matched",
                    matched_pattern=rx.pattern,
                )

        if self.block_code_execution:
            for rx in self._code_regexes:
                if rx.search(text):
                    logger.warning("content_filter blocked code_execution pattern=%s", rx.pattern)
                    raise ContentFilterError(
                        "Content blocked: potential code execution",
                        matched_pattern=rx.pattern,
                    )

        if self.block_file_paths:
            for rx in self._path_regexes:
                if rx.search(text):
                    logger.warning("content_filter blocked file_path pattern=%s", rx.pattern)
                    raise ContentFilterError(
                        "Content blocked: suspicious file path",
                        matched_pattern=rx.pattern,
                    )

        if self.block_urls:
            if self._url_regex.search(text):
                logger.warning("content_filter blocked url")
                raise ContentFilterError(
                    "Content blocked: URL not allowed",
                    matched_pattern=DEFAULT_URL_PATTERN,
                )

