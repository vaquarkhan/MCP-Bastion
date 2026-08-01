"""
Grounding guard: verify file-path references in outbound MCP text against a workspace root.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from mcp_bastion.errors import GroundingViolationError

GroundingAction = Literal["warn", "block", "strip"]

_EXTENSIONS = (
    "py|ts|tsx|js|jsx|go|rs|java|kt|rb|php|cs|cpp|c|h|"
    "yaml|yml|json|toml|md|txt|sql|sh|ps1|vue|svelte|dart|swift|scala|r"
)

# Strong path signals only (B-3): do NOT match slash idioms like 24/7, TCP/IP, read/write, and/or.
_PATH_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:"
    # Relative / absolute / drive prefixes with at least one more segment
    r"(?:\.\.?[\\/]|[A-Za-z]:[\\/]|/(?:etc|var|usr|home|tmp|opt|root|Users|windows|Windows|mnt|data)[\\/])"
    r"[A-Za-z0-9_./\\-]+"
    r"|"
    # Multi-segment path that ends with a known source/config extension
    r"[A-Za-z0-9_.-]+(?:[\\/][A-Za-z0-9_.-]+)+\.(?:" + _EXTENSIONS + r")"
    r"|"
    # Bare filename with a known extension (src/app.py still matched via multi-segment)
    r"[A-Za-z0-9_.-]+\.(?:" + _EXTENSIONS + r")"
    r")"
)

# Explicit non-paths (defense in depth if regex drifts).
_SLASH_IDIOM = re.compile(
    r"(?ix)^(?:"
    r"\d+\s*/\s*\d+"  # 24/7
    r"|and/or|read/write|input/output|i/o|tcp/ip|udp/ip|http/https|os/2"
    r"|he/she|his/her|yes/no|on/off|up/down|in/out"
    r")$"
)


@dataclass
class GroundingCheckResult:
    """Result of scanning text for ungrounded path references."""

    violations: list[str] = field(default_factory=list)
    stripped_text: str | None = None


class GroundingGuard:
    """
    Check outbound text for file paths that do not exist under workspace_root.

    Modes:
    - warn: record violations only (caller handles metadata)
    - block: raise GroundingViolationError
    - strip: redact ungrounded path strings from text
    """

    def __init__(
        self,
        *,
        workspace_root: str | Path = ".",
        on_violation: GroundingAction = "warn",
        allow_absolute: bool = False,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        if on_violation not in ("warn", "block", "strip"):
            raise ValueError("on_violation must be warn, block, or strip")
        self.on_violation = on_violation
        self.allow_absolute = allow_absolute

    def extract_paths(self, text: str) -> list[str]:
        """Return unique path-like tokens found in text."""
        if not text:
            return []
        seen: set[str] = set()
        out: list[str] = []
        for match in _PATH_PATTERN.finditer(text):
            token = match.group(0).strip().strip("'\"`,;:")
            if len(token) < 3 or token in seen:
                continue
            if _SLASH_IDIOM.match(token):
                continue
            # Reject pure slash-idioms captured as a larger token (e.g. "TCP/IP.")
            core = token.rstrip(".,;:)")
            if _SLASH_IDIOM.match(core):
                continue
            seen.add(token)
            out.append(token)
        return out

    def _path_exists(self, token: str) -> bool:
        p = Path(token)
        if p.is_absolute():
            if not self.allow_absolute:
                try:
                    p.relative_to(self.workspace_root)
                except ValueError:
                    return False
            candidate = p
        else:
            candidate = (self.workspace_root / token).resolve()
            try:
                candidate.relative_to(self.workspace_root)
            except ValueError:
                return False
        return candidate.exists()

    def check_text(self, text: str) -> GroundingCheckResult:
        """Scan text; apply on_violation policy."""
        violations: list[str] = []
        for token in self.extract_paths(text):
            if not self._path_exists(token):
                violations.append(token)

        result = GroundingCheckResult(violations=violations)
        if not violations:
            return result

        if self.on_violation == "block":
            sample = ", ".join(violations[:5])
            extra = f" (+{len(violations) - 5} more)" if len(violations) > 5 else ""
            raise GroundingViolationError(
                f"Response blocked: ungrounded file references: {sample}{extra}"
            )

        if self.on_violation == "strip":
            stripped = text
            for token in violations:
                stripped = stripped.replace(token, "[ungrounded-path-removed]")
            result.stripped_text = stripped

        return result

    def process_content_items(
        self, content: list[dict]
    ) -> tuple[list[dict], GroundingCheckResult]:
        """Scan MCP text content items; return updated content and summary."""
        merged = GroundingCheckResult()
        out: list[dict] = []
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "text" or "text" not in item:
                out.append(item)
                continue
            text = str(item["text"])
            partial = self.check_text(text)
            merged.violations.extend(partial.violations)
            if partial.stripped_text is not None:
                out.append({**item, "text": partial.stripped_text})
            else:
                out.append(item)
        return out, merged
