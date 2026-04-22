"""Deterministic SSN-format redaction (supplement to Presidio)."""

from mcp_bastion.pillars.pii_redaction import _redact_dashed_ssn_patterns


def test_redact_dashed_ssn_replaces_placeholder():
    s = "SSN 123-45-6789 here"
    out = _redact_dashed_ssn_patterns(s)
    assert "123-45-6789" not in out
    assert "<US_SSN>" in out


def test_redact_multiple_ssn():
    out = _redact_dashed_ssn_patterns("a 111-22-3333 b 444-55-6666")
    assert "111-22-3333" not in out
    assert "444-55-6666" not in out
    assert out.count("<US_SSN>") == 2
