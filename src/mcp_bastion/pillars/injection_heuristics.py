"""
Shared regex heuristics for prompt-injection patterns.

Used by PromptGuard (when the ML model is unavailable) and ResponseInjectionScanner.
No ML dependencies - blocks obvious jailbreak strings out of the box.
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
    # Role-play / social-engineering jailbreaks (C-2)
    r"(?i)grandma(?:ma)?\s+(?:used\s+to|would)\b",
    r"(?i)(?:my\s+)?(?:deceased|late|dead)\s+grandm(?:a|other)\b",
    r"(?i)grandm(?:a|other).{0,120}\b(?:used\s+to|would|taught|told)\b.{0,80}\b(?:napalm|bomb|hack|password|secret|bypass|exploit|weapon)",
    r"(?i)for\s+(?:a\s+|the\s+|my\s+)?novel\b.{0,80}\b(?:bypass|villain|filter|jailbreak|how\s+to|weapon|bomb|hack|ignore\s+previous)",
    r"(?i)(?:write|tell|explain|describe|act|role[\s-]*play).{0,60}\b(?:for|as|in)\s+(?:a\s+|the\s+|my\s+)?(?:novel|fiction|story|screenplay)\b.{0,80}\b(?:bypass|villain|hack|weapon|bomb|password|exploit|jailbreak|how\s+to)",
    r"(?i)(?:write|tell|explain).{0,40}\bfor\s+(?:a\s+|the\s+|my\s+)?novel\b",
    r"(?i)let'?s\s+play\s+a\s+game\b.{0,80}\b(?:no\s+restrictions|unrestricted|FreeGPT|DAN)",
    r"(?i)\bSYSTEM\s*:\s*(?:from\s+this\s+point|you\s+are\s+now|ignore)",
    r"(?i)act\s+as\s+an?\s+unrestricted\s+assistant",
    r"(?i)no\s+restrictions\s*\((?:FreeGPT|DAN|Jailbreak)",
]

# ProtectAI over-scores some short business phrases (B-2 / N-2). Allowlist before ML.
BENIGN_ALLOWLIST_PATTERNS = [
    r"(?i)^repeat$",
    r"(?i)^repeat\s+(?:order|the\s+search|customer|that)$",
    r"(?i)^please\s+repeat\s+that$",
    r"(?i)^override$",
    r"(?i)^ignore\s+case(?:\s+in\s+search)?$",
    r"(?i)^show\s+previous\s+orders$",
    r"(?i)^forget\s+password\s+link$",
    r"(?i)^act\s+on\s+this\s+ticket$",
    r"(?i)^catalog\s+lookup$",
    r"(?i)^please\s+summarize\s+this\s+document$",
    r"(?i)^what\s+is\s+the\s+weather(?:\s+today)?$",
]

# Sentence-level business markers (N-2): allow when these dominate and no jailbreak.
_BENIGN_BUSINESS_MARKERS = [
    re.compile(r"(?i)\b(?:please|refund|invoice|order|ticket|customer|hold|search|catalog)\b"),
    re.compile(r"(?i)\brepeat\s+(?:the\s+)?(?:refund|search|order|that)\b"),
    re.compile(r"(?i)\boverride\s+(?:the\s+)?(?:hold|limit|cap|flag)\b"),
    re.compile(r"(?i)\bignore\s+case\b"),
    re.compile(r"(?i)\brepeat\s+the\s+search\b"),
]

_JAILBREAK_MARKERS = [
    re.compile(r"(?i)\b(?:jailbreak|DAN\s+mode|system\s+prompt|ignore\s+previous\s+instructions)\b"),
    re.compile(r"(?i)\bno\s+restrictions\b|\bunrestricted\s+assistant\b|\bFreeGPT\b"),
    re.compile(r"(?i)\b(?:deceased|late)\s+grandm"),
    re.compile(r"(?i)\bfor\s+(?:a\s+)?novel\b.{0,40}\b(?:bypass|hack|weapon)"),
]


def is_benign_allowlisted(text: str) -> bool:
    """True for short phrases / business sentences that ProtectAI often false-positives."""
    if not text or not isinstance(text, str):
        return False
    from mcp_bastion.pillars.content_normalize import normalize_for_scan

    normalized = normalize_for_scan(text).strip()
    if not normalized:
        return False
    # Exact / short allowlist (original B-2)
    if len(normalized) <= 120:
        for rx in _BENIGN_COMPILED:
            if rx.search(normalized):
                return True
    # Sentence-level (N-2): business ops wording without jailbreak markers
    if len(normalized) > 280:
        return False
    for bad in _JAILBREAK_MARKERS:
        if bad.search(normalized):
            return False
    marker_hits = sum(1 for rx in _BENIGN_BUSINESS_MARKERS if rx.search(normalized))
    if marker_hits >= 2:
        return True
    # Single strong business construction
    if re.search(
        r"(?i)please\s+.*\b(?:repeat|override|ignore\s+case)\b.*\b(?:refund|hold|search|invoice|order)\b",
        normalized,
    ):
        return True
    if re.search(
        r"(?i)\bignore\s+case\b.*\brepeat\s+the\s+search\b",
        normalized,
    ):
        return True
    if re.search(
        r"(?i)\brepeat\s+the\s+refund\b.*\boverride\s+the\s+hold\b",
        normalized,
    ):
        return True
    return False


_BENIGN_COMPILED = [re.compile(p) for p in BENIGN_ALLOWLIST_PATTERNS]


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
    if is_benign_allowlisted(normalized):
        return None
    for rx in regexes:
        if rx.search(normalized):
            return rx.pattern
    return None
