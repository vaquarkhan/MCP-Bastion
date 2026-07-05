"""Token estimation helpers for FinOps rate limiting and output budgeting."""

from __future__ import annotations

from typing import Any, Callable

_CHARS_PER_TOKEN = 4
_tiktoken_encoder: Any | None = None
_tiktoken_checked = False


def _get_tiktoken_encoder() -> Any | None:
    """Lazy-load tiktoken when installed (optional, no hard dependency)."""
    global _tiktoken_encoder, _tiktoken_checked
    if _tiktoken_checked:
        return _tiktoken_encoder
    _tiktoken_checked = True
    try:
        import tiktoken

        _tiktoken_encoder = tiktoken.get_encoding("cl100k_base")
    except Exception:
        _tiktoken_encoder = None
    return _tiktoken_encoder


def count_text_tokens(text: str) -> int:
    """
    Count tokens in text.

    Uses tiktoken (cl100k_base) when available; otherwise ≈4 characters per token.
    Returns 0 for empty input.
    """
    if not text:
        return 0
    enc = _get_tiktoken_encoder()
    if enc is not None:
        try:
            return len(enc.encode(text))
        except Exception:
            pass
    return max(1, len(text) // _CHARS_PER_TOKEN)


def estimate_text_tokens(*parts: Any) -> int:
    """
    Rough token estimate from one or more text parts.

    Used when explicit llm_input_tokens / llm_output_tokens metadata is absent.
    """
    combined = "".join(part if isinstance(part, str) else str(part) for part in parts if part is not None)
    return count_text_tokens(combined)


def truncate_text_to_token_budget(
    text: str,
    max_tokens: int,
    *,
    head_ratio: float = 0.7,
    token_counter: Callable[[str], int] | None = None,
) -> str:
    """
    Truncate text to approximately max_tokens, preserving head and tail.

    Uses binary search on character length against token_counter for accuracy.
    """
    if not text or max_tokens < 1:
        return text
    counter = token_counter or count_text_tokens
    if counter(text) <= max_tokens:
        return text

    head_ratio = min(max(head_ratio, 0.1), 0.9)
    tail_ratio = 1.0 - head_ratio
    head_budget = max(1, int(max_tokens * head_ratio))
    tail_budget = max(1, max_tokens - head_budget)

    def _fit_prefix(s: str, budget: int) -> str:
        if counter(s) <= budget:
            return s
        lo, hi = 0, len(s)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if counter(s[:mid]) <= budget:
                lo = mid
            else:
                hi = mid - 1
        return s[:lo]

    def _fit_suffix(s: str, budget: int) -> str:
        if counter(s) <= budget:
            return s
        lo, hi = 0, len(s)
        while lo < hi:
            mid = (lo + hi) // 2
            if counter(s[mid:]) <= budget:
                hi = mid
            else:
                lo = mid + 1
        return s[lo:]

    head = _fit_prefix(text, head_budget)
    tail = _fit_suffix(text, tail_budget)
    omitted = max(0, len(text) - len(head) - len(tail))
    return f"{head}\n\n… [{omitted:,} chars omitted] …\n\n{tail}"
