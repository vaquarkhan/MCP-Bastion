"""Tests for content filter."""

import pytest

from mcp_bastion.errors import ContentFilterError
from mcp_bastion.pillars.content_filter import ContentFilter


def test_content_filter_empty_passthrough():
    cf = ContentFilter()
    cf.check("")
    cf.check("   ")
    cf.check(None)  # type: ignore[arg-type]


def test_content_filter_blocks_code():
    cf = ContentFilter(block_code_execution=True)
    with pytest.raises(ContentFilterError) as exc:
        cf.check("run eval('bad')")
    assert exc.value.matched_pattern


def test_content_filter_blocks_file_path():
    cf = ContentFilter(block_file_paths=True)
    with pytest.raises(ContentFilterError):
        cf.check("path /etc/passwd")
    with pytest.raises(ContentFilterError):
        cf.check("read ../secret")


def test_content_filter_blocks_urls_when_enabled():
    cf = ContentFilter(block_urls=True)
    with pytest.raises(ContentFilterError):
        cf.check("visit https://example.com")


def test_content_filter_allows_urls_when_disabled():
    cf = ContentFilter(block_urls=False)
    cf.check("visit https://example.com")


def test_content_filter_custom_patterns():
    cf = ContentFilter(
        block_code_execution=False,
        block_file_paths=False,
        custom_patterns=[r"password", r"api[_-]?key"],
    )
    with pytest.raises(ContentFilterError):
        cf.check("secret password here")
    with pytest.raises(ContentFilterError):
        cf.check("api_key=123")


def test_content_filter_safe_content():
    cf = ContentFilter()
    cf.check("hello world")
    cf.check("add 2 and 3")


def test_content_filter_extract_text_from_nested():
    """ContentFilter.check with dict extracts and scans."""
    cf = ContentFilter(
        block_code_execution=False,
        block_file_paths=True,
        custom_patterns=[],
    )
    with pytest.raises(ContentFilterError):
        cf.check({"path": "/etc/passwd"})


def test_content_filter_extract_text_from_list():
    """ContentFilter.check with list extracts and scans."""
    cf = ContentFilter(
        block_code_execution=False,
        block_file_paths=True,
        custom_patterns=[],
    )
    with pytest.raises(ContentFilterError):
        cf.check(["safe", "/etc/passwd", "other"])


def test_content_filter_extract_text_from_primitive():
    """ContentFilter.check with int/float/bool passes or blocks."""
    cf = ContentFilter(
        block_code_execution=False,
        block_file_paths=False,
        custom_patterns=[],
    )
    cf.check(42)
    cf.check(3.14)
    cf.check(True)


def test_content_filter_extract_text_fallback():
    """ContentFilter.check with non-standard type uses str()."""
    cf = ContentFilter(
        block_code_execution=False,
        block_file_paths=False,
        custom_patterns=[],
    )
    cf.check(object())
