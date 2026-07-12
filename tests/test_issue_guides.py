"""Tests for PMD-style issue guides and posture enrichment."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_bastion.dashboard_local import load_posture
from mcp_bastion.issue_guides import (
    enrich_finding_with_guide,
    guide_for_check,
    guide_for_framework_id,
)


def test_guide_for_check_weak_schema():
    g = guide_for_check("weak_schema")
    assert g is not None
    assert g["check"] == "weak_schema"
    assert g["fix"]
    assert g["style"] == "pmd-rule-card"
    assert any(f.get("id") == "ASI02" for f in g.get("frameworks") or [])


def test_guide_for_framework_asi02():
    g = guide_for_framework_id("ASI02")
    assert g is not None
    assert g["id"] == "ASI02"
    assert "Tool" in (g.get("title") or "") or g.get("summary")
    assert g.get("refs")


def test_enrich_finding_attaches_guide():
    out = enrich_finding_with_guide(
        {"check": "weak_schema", "severity": "medium", "message": "unbounded"}
    )
    assert "guide" in out
    assert out["guide"]["name"]
    assert out["taxonomy"]


def test_load_posture_findings_include_guide(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "catalog.json").write_text(
        json.dumps(
            {
                "grade": "C",
                "findings": [
                    {
                        "check": "weak_schema",
                        "severity": "medium",
                        "message": "unbounded string",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("MCP_BASTION_SCAN_DIR", str(scan))
    posture = load_posture(demo=False)
    findings = posture["checks"]["catalog"]["findings"]
    assert findings
    assert findings[0].get("guide", {}).get("fix")
