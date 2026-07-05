"""Normalize untrusted text before content-filter / heuristic matching."""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import unquote


_ZERO_WIDTH = re.compile(r"[\u200b-\u200d\ufeff]")
_LETTER_SPACED = re.compile(r"(?<=\b)([a-zA-Z])(?:\s+(?=[a-zA-Z]\b))+")
_COLLAPSE_SPACES = re.compile(r"\s+")


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
    # Light de-spacing: "r m - r f" -> "rm - rf" (not full homoglyph defense)
    out = _LETTER_SPACED.sub(r"\1", out)
    out = _COLLAPSE_SPACES.sub(" ", out)
    return out.strip()
