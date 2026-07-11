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
