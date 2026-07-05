"""Tests for response injection scanner."""

import pytest

from mcp_bastion.errors import PromptInjectionError
from mcp_bastion.pillars.response_scanner import ResponseInjectionScanner


def test_response_scanner_allows_benign_text():
    ResponseInjectionScanner().check_text("Weather is sunny today.")


def test_response_scanner_custom_pattern():
    scanner = ResponseInjectionScanner(extra_patterns=[r"CUSTOM_MARKER"])
    with pytest.raises(PromptInjectionError):
        scanner.check_text("data CUSTOM_MARKER here")
