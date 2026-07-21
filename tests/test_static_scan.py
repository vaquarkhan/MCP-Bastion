"""Tests for mcp-bastion scan static tool-definition scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_bastion.cli import cmd_scan
from mcp_bastion.pillars.tool_metadata_fingerprint import build_fingerprint_document
from mcp_bastion.static_scan import format_report_text, scan_tools, scan_tools_file

FIXTURES = Path(__file__).resolve().parent.parent / "examples" / "fixtures"


def test_scan_clean_catalog():
    tools = json.loads((FIXTURES / "tools-clean.json").read_text(encoding="utf-8"))["tools"]
    report = scan_tools(tools)
    assert report.tool_count == 2
    assert report.grade == "A"
    assert report.findings == []


def test_scan_poisoned_catalog_flags_injection_homoglyph_and_secrets():
    tools = json.loads((FIXTURES / "tools-poisoned.json").read_text(encoding="utf-8"))["tools"]
    report = scan_tools(tools)
    checks = {f.check for f in report.findings}
    assert "injection_heuristic" in checks
    assert "homoglyph" in checks
    assert "content_filter" in checks
    assert report.grade in ("D", "F")


def test_scan_fingerprint_drift(tmp_path):
    clean = json.loads((FIXTURES / "tools-clean.json").read_text(encoding="utf-8"))["tools"]
    baseline_doc = build_fingerprint_document(clean)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline_doc), encoding="utf-8")

    poisoned = json.loads((FIXTURES / "tools-poisoned.json").read_text(encoding="utf-8"))["tools"]
    report = scan_tools(poisoned, baseline_fingerprint=baseline_doc["fingerprint"])
    assert report.baseline_match is False
    assert any(f.check == "fingerprint_drift" for f in report.findings)


def test_scan_tools_file_and_format_text():
    report = scan_tools_file(str(FIXTURES / "tools-clean.json"))
    text = format_report_text(report)
    assert "Grade: A" in text
    assert "No findings" in text
    assert "schema" in text.lower()


def test_scan_json_includes_taxonomy():
    tools = [
        {
            "name": "run_shell",
            "description": "Run a command.",
            "inputSchema": {
                "type": "object",
                "properties": {"cmd": {"type": "string"}},
                "required": ["cmd"],
            },
        }
    ]
    report = scan_tools(tools)
    data = report.to_dict()
    hit = next(f for f in data["findings"] if f["check"] == "unbounded_string")
    assert "ASI02" in hit["taxonomy"]["asi"]


def test_scan_report_text_is_ascii():
    """Console-safe: no em-dash/ellipsis that mojibake on Windows cp1252."""
    tools = json.loads((FIXTURES / "tools-poisoned.json").read_text(encoding="utf-8"))["tools"]
    report = scan_tools(tools)
    text = format_report_text(report)
    text.encode("ascii")
    assert "\u2014" not in text  # em dash
    assert "\u2013" not in text  # en dash
    assert "\u2026" not in text  # ellipsis


def test_cmd_scan_clean_exits_zero(tmp_path, capsys):
    path = FIXTURES / "tools-clean.json"
    assert cmd_scan(str(path), fail_on="high") == 0


def test_cmd_scan_poisoned_exits_one(tmp_path, capsys):
    path = FIXTURES / "tools-poisoned.json"
    assert cmd_scan(str(path), fail_on="high") == 1


def test_cmd_scan_json_output(tmp_path):
    out = tmp_path / "report.json"
    path = FIXTURES / "tools-poisoned.json"
    assert cmd_scan(str(path), output=str(out), output_format="json", fail_on="none") == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["finding_count"] >= 3
    assert "grade" in data


def test_cmd_scan_missing_file():
    assert cmd_scan("/nonexistent/tools.json") == 1


def test_schema_risky_unbounded_string_is_high():
    tools = [
        {
            "name": "run_shell",
            "description": "Run a command.",
            "inputSchema": {
                "type": "object",
                "properties": {"cmd": {"type": "string"}},
                "required": ["cmd"],
            },
        }
    ]
    report = scan_tools(tools)
    hits = [f for f in report.findings if f.check == "unbounded_string"]
    assert hits
    assert hits[0].severity == "high"
    assert "cmd" in hits[0].message


def test_schema_bounded_string_is_clean():
    tools = [
        {
            "name": "run_shell",
            "description": "Run a command.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "cmd": {"type": "string", "maxLength": 128, "pattern": "^[a-z0-9 _-]+$"}
                },
                "required": ["cmd"],
            },
        }
    ]
    report = scan_tools(tools)
    assert not any(f.check.startswith(("unbounded", "weak_schema", "missing")) for f in report.findings)


def test_schema_additional_properties_false_with_props_clean_for_weak():
    tools = [
        {
            "name": "echo",
            "description": "Echo text.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"text": {"type": "string", "maxLength": 64}},
                "required": ["text"],
            },
        }
    ]
    report = scan_tools(tools)
    assert not any(f.check == "weak_schema" for f in report.findings)


def test_schema_checks_can_be_disabled():
    tools = [
        {
            "name": "run_shell",
            "description": "Run a command.",
            "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}},
        }
    ]
    assert any(f.check == "unbounded_string" for f in scan_tools(tools).findings)
    assert not any(
        f.check == "unbounded_string" for f in scan_tools(tools, schema_checks=False).findings
    )
