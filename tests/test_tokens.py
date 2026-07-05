"""Tests for token estimation helper."""

from unittest import mock

from mcp_bastion.pillars import tokens as tokens_mod
from mcp_bastion.pillars.tokens import count_text_tokens, estimate_text_tokens, truncate_text_to_token_budget


def test_estimate_text_tokens_empty():
    assert estimate_text_tokens() == 0
    assert estimate_text_tokens("") == 0


def test_estimate_text_tokens_nonzero():
    assert estimate_text_tokens("hello world") >= 1


def test_count_text_tokens_chars_fallback():
    with mock.patch.object(tokens_mod, "_get_tiktoken_encoder", return_value=None):
        assert count_text_tokens("abcd") == 1
        assert count_text_tokens("a" * 100) == 25


def test_truncate_text_to_token_budget():
    text = "line\n" * 500
    with mock.patch.object(tokens_mod, "_get_tiktoken_encoder", return_value=None):
        out = truncate_text_to_token_budget(text, 20)
    assert len(out) < len(text)
    assert "omitted" in out

