"""Token estimation helpers for FinOps rate limiting."""

from __future__ import annotations

from typing import Any


def estimate_text_tokens(*parts: Any) -> int:
    """
    Rough token estimate from text (≈4 characters per token).

    Used when explicit llm_input_tokens / llm_output_tokens metadata is absent.
    Returns 0 for empty input.
    """
    total_chars = 0
    for part in parts:
        if part is None:
            continue
        text = part if isinstance(part, str) else str(part)
        total_chars += len(text)
    if total_chars <= 0:
        return 0
    return max(1, total_chars // 4)
