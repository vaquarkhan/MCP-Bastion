"""Tests for token estimation helper."""

from mcp_bastion.pillars.tokens import estimate_text_tokens


def test_estimate_text_tokens_empty():
    assert estimate_text_tokens() == 0
    assert estimate_text_tokens("") == 0


def test_estimate_text_tokens_nonzero():
    assert estimate_text_tokens("hello world") >= 1
