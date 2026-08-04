"""Normalize untrusted text before content-filter / heuristic matching."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from urllib.parse import unquote


_ZERO_WIDTH = re.compile(r"[\u200b-\u200d\ufeff]")
_COLLAPSE_SPACES = re.compile(r"\s+")
# Long base64-looking runs (min ~18 decoded bytes).
_B64_CHUNK = re.compile(r"(?<![A-Za-z0-9+/_=])([A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/_=])")
_HEX_ESCAPE_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
_HEX_BLOB = re.compile(r"(?<![0-9a-fA-F])([0-9a-fA-F]{24,})(?![0-9a-fA-F])")


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


def _printable_ratio(raw: bytes) -> float:
    if not raw:
        return 0.0
    ok = sum(1 for b in raw if 9 <= b <= 13 or 32 <= b <= 126)
    return ok / len(raw)


def _safe_b64_decode(chunk: str) -> str | None:
    try:
        pad = "=" * (-len(chunk) % 4)
        raw = base64.b64decode(chunk + pad, validate=False)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 8 or _printable_ratio(raw) < 0.85:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except UnicodeDecodeError:
            return None


def _safe_hex_decode(chunk: str) -> str | None:
    if len(chunk) % 2:
        return None
    try:
        raw = binascii.unhexlify(chunk)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 8 or _printable_ratio(raw) < 0.85:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _decode_hex_escapes(segment: str) -> str:
    return re.sub(
        r"\\x([0-9a-fA-F]{2})",
        lambda m: chr(int(m.group(1), 16)),
        segment,
    )


def _append_decoded_payloads(text: str) -> str:
    """Decode base64 / hex / \\xNN runs and append plaintext for re-scan."""
    extras: list[str] = []
    for m in _B64_CHUNK.finditer(text):
        decoded = _safe_b64_decode(m.group(1))
        if decoded and decoded not in text:
            extras.append(decoded)
    for m in _HEX_ESCAPE_RUN.finditer(text):
        decoded = _decode_hex_escapes(m.group(0))
        if decoded and decoded not in text:
            extras.append(decoded)
    for m in _HEX_BLOB.finditer(text):
        decoded = _safe_hex_decode(m.group(1))
        if decoded and decoded not in text:
            extras.append(decoded)
    if not extras:
        return text
    return text + " " + " ".join(extras)


def normalize_for_scan(text: str) -> str:
    """URL-decode, unicode-normalize, strip obfuscations, and decode embedded payloads."""
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
    out = _append_decoded_payloads(out)
    out = _COLLAPSE_SPACES.sub(" ", out)
    return out.strip()
