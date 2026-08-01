"""Tests for schema strict mode, optional args, PDF reports, and grade helpers."""

from __future__ import annotations

import pytest

from mcp_bastion.errors import SchemaValidationError
from mcp_bastion.pillars.compliance_report import generate_report_markdown, generate_report_pdf
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.schema_validation import SchemaValidator, parse_tool_schemas


def test_parse_tool_schemas_tuple_and_optional():
    schemas, optional = parse_tool_schemas(
        {
            "transfer": {
                "amount": "number",
                "to": "string",
                "memo": "string?",
                "note": {"type": "string", "required": False},
            }
        }
    )
    assert schemas["transfer"]["amount"] is float
    assert "memo" in optional["transfer"]
    assert "note" in optional["transfer"]
    assert "to" not in optional["transfer"]


def test_schema_strict_rejects_extra_args():
    sv = SchemaValidator({"transfer": {"amount": float, "to": str}}, strict=True)
    with pytest.raises(SchemaValidationError, match="Unexpected argument"):
        sv.validate_input("transfer", {"amount": 10.0, "to": "bob", "evil": "DROP"})


def test_schema_non_strict_allows_extra_args():
    sv = SchemaValidator({"transfer": {"amount": float, "to": str}}, strict=False)
    sv.validate_input("transfer", {"amount": 10.0, "to": "bob", "evil": "DROP"})


def test_schema_optional_arg_may_be_omitted():
    sv = SchemaValidator(
        {"transfer": {"amount": float, "to": str, "memo": str}},
        optional_args={"transfer": {"memo"}},
    )
    sv.validate_input("transfer", {"amount": 10.0, "to": "bob"})


def test_content_filter_block_secrets_default_on():
    cf = ContentFilter(block_code_execution=False, block_file_paths=False)
    assert cf.block_secrets is True
    with pytest.raises(Exception):
        cf.check("key=AKIAIOSFODNN7EXAMPLE")


def test_generate_report_pdf_header(tmp_path):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        '{"timestamp":"2026-01-01T00:00:00Z","action":"BLOCKED","kind":"prompt_guard"}\n',
        encoding="utf-8",
    )
    md = generate_report_markdown(framework="soc2", audit_path=audit, version="test")
    assert "Compliance Evidence" in md
    pdf = generate_report_pdf(framework="soc2", audit_path=audit, version="test")
    assert pdf.startswith(b"%PDF")
    assert b"endobj" in pdf
