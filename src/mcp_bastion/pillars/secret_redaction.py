"""
Secret pattern redaction with replace | hash | mask | remove strategies.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any


def apply_redaction_strategy(
    value: str,
    *,
    strategy: str = "replace",
    placeholder: str = "<REDACTED>",
    mask_prefix: int = 4,
    mask_suffix: int = 4,
) -> str:
    s = str(strategy or "replace").lower()
    if s == "remove":
        return ""
    if s == "hash":
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
        return f"<HASH:{digest}>"
    if s == "mask":
        if len(value) <= mask_prefix + mask_suffix:
            return "*" * len(value)
        return value[:mask_prefix] + "*" * (len(value) - mask_prefix - mask_suffix) + value[-mask_suffix:]
    return placeholder


class SecretPatternRedactor:
    """Apply per-rule regex redaction strategies to text."""

    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None:
        self._rules: list[tuple[re.Pattern[str], dict[str, Any]]] = []
        for raw in rules or []:
            pattern = raw.get("rule") or raw.get("pattern")
            if not pattern:
                continue
            try:
                compiled = re.compile(str(pattern))
            except re.error:
                continue
            self._rules.append((compiled, raw))

    def redact_text(self, text: str) -> str:
        if not text or not self._rules:
            return text
        out = text
        for pattern, cfg in self._rules:
            strategy = str(cfg.get("strategy", "replace"))

            def _sub(m: re.Match[str]) -> str:
                return apply_redaction_strategy(
                    m.group(0),
                    strategy=strategy,
                    placeholder=str(cfg.get("placeholder", "<REDACTED>")),
                    mask_prefix=int(cfg.get("mask_prefix", 4)),
                    mask_suffix=int(cfg.get("mask_suffix", 4)),
                )

            out = pattern.sub(_sub, out)
        return out
