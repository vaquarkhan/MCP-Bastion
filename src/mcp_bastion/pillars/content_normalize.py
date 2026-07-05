"""Normalize untrusted text before content-filter / heuristic matching."""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import unquote


_ZERO_WIDTH = re.compile(r"[\u200b-\u200d\ufeff]")
_COLLAPSE_SPACES = re.compile(r"\s+")


def _collapse_word_segment(segment: str) -> str:
    """Collapse a leading run of single-letter tokens: ``i g n o r e previous`` → ``ignore previous``."""
    tokens = segment.split()
    if not tokens:
        return segment
    idx = 0
    while idx < len(tokens) and len(tokens[idx]) == 1 and tokens[idx].isalpha():
        idx += 1
    if idx >= 2:
        prefix = "".join(tokens[:idx])
        rest = " ".join(tokens[idx:])
        return f"{prefix} {rest}".strip() if rest else prefix
    if idx == len(tokens) and idx >= 2:
        return "".join(tokens)
    return segment


def _collapse_spaced_letters(text: str) -> str:
    """Collapse obfuscated spellings while preserving real word boundaries."""
    segments = re.split(r"\s{2,}", text)
    if len(segments) == 1:
        return _collapse_word_segment(text)
    return " ".join(_collapse_word_segment(s.strip()) for s in segments if s.strip())


def normalize_for_scan(text: str) -> str:
    """URL-decode, unicode-normalize, and strip common obfuscations."""
    if not text:
        return ""
    out = text
    for _ in range(2):
        out = unquote(out)
    out = unicodedata.normalize("NFKC", out)
    out = _ZERO_WIDTH.sub("", out)
    out = out.replace("\x00", "")
    # Shell empty-string joins: r''m -> rm, ba""sh -> bash
    out = re.sub(r"(?<=[a-zA-Z])''(?=[a-zA-Z])", "", out)
    out = re.sub(r'(?<=[a-zA-Z])""(?=[a-zA-Z])', "", out)
    out = _collapse_spaced_letters(out)
    out = _COLLAPSE_SPACES.sub(" ", out)
    return out.strip()
