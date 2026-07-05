"""
Shared regex heuristics for prompt-injection patterns.

Used by PromptGuard (when the ML model is unavailable) and ResponseInjectionScanner.
No ML dependencies — blocks obvious jailbreak strings out of the box.
"""

from __future__ import annotations

import re
from typing import Iterable

DEFAULT_INJECTION_PATTERNS = [
    r"(?i)ignore\s+(?:all\s+)?previous\s+instructions",
    r"(?i)disregard\s+(?:all\s+)?(?:prior|previous|above)\s+instructions",
    r"(?i)forget\s+(?:everything|what)\s+you\s+(?:were|are)\s+(?:told|instructed)",
    r"(?i)(?:stop|cease)\s+following\s+(?:your|the)\s+(?:rules|guidelines|instructions)",
    r"(?i)from\s+now\s+on\s+(?:you\s+)?(?:will|must|should)\s+(?:ignore|disregard|override)",
    r"(?i)override\s+(?:your|the)\s+(?:system|initial|original)\s+(?:prompt|instructions)",
    r"(?i)pretend\s+(?:you\s+)?(?:are|have)\s+no\s+(?:rules|guidelines|limits|restrictions)",
    r"(?i)you\s+are\s+now\s+(?:in\s+)?(?:developer|admin|god|DAN)\s+mode",
    r"(?i)<\s*system\s*>",
    r"(?i)\[INST\]",
    r"(?i)<!--\s*hidden",
    r"(?i)do\s+not\s+tell\s+the\s+user",
    r"(?i)reveal\s+(?:your\s+)?system\s+prompt",
    r"(?i)output\s+(?:your\s+)?system\s+prompt",
    r"(?i)\bDAN\s+mode\b",
    r"(?i)jailbreak",
    r"(?i)act\s+as\s+(?:if\s+you\s+have\s+)?no\s+(?:restrictions|rules|limits)",
    r"(?i)role[\s-]*play\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered)",
]


def compile_injection_patterns(extra: Iterable[str] | None = None) -> list[re.Pattern[str]]:
    """Compile default + optional extra injection regex patterns."""
    patterns = list(DEFAULT_INJECTION_PATTERNS)
    if extra:
        patterns.extend(str(p) for p in extra if str(p).strip())
    return [re.compile(p) for p in patterns]


def find_injection_match(text: str, regexes: list[re.Pattern[str]]) -> str | None:
    """Return matched pattern source if text looks like an injection attempt."""
    if not text or not isinstance(text, str):
        return None
    from mcp_bastion.pillars.content_normalize import normalize_for_scan

    normalized = normalize_for_scan(text)
    for rx in regexes:
        if rx.search(normalized):
            return rx.pattern
    return None
