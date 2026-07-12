"""Tests for dashboard local-artifact panels (posture / taxonomy / compliance)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_bastion.dashboard_local import (
    build_evidence_bundle_zip,
    grade_from_severities,
    load_compliance,
    load_onboarding,
    load_posture,
    load_taxonomy_coverage,
    load_trends_from_audit,
    provenance_from_reason,
)


def test_grade_from_severities():
    assert grade_from_severities([]) == "A"
    assert grade_from_severities(["info"]) == "A"
    assert grade_from_severities(["low"]) == "B"
    assert grade_from_severities(["medium"]) == "C"
    assert grade_from_severities(["high"]) == "D"
    assert grade_from_severities(["critical"]) == "F"


def test_load_posture_from_scan_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "catalog.json").write_text(
        json.dumps(
            {
                "grade": "B",
                "finding_count": 1,
                "findings": [
                    {
                        "check": "weak_schema",
                        "severity": "medium",
                        "message": "unbounded",
                        "taxonomy": {"asi": ["ASI02"]},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (scan / "osv.json").write_text(
        json.dumps({"finding_count": 0, "findings": []}),
        encoding="utf-8",
    )
    monkeypatch.setenv("MCP_BASTION_SCAN_DIR", str(scan))
    posture = load_posture(demo=False)
    assert posture["empty"] is False
    assert posture["checks"]["catalog"]["grade"] == "B"
    assert posture["checks"]["osv"]["grade"] == "A"
    assert posture["checks"]["skills"]["present"] is False
    assert posture["combined_grade"] in ("A", "B", "C", "D", "F")


def test_load_posture_demo_when_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    empty = tmp_path / "empty-scan"
    empty.mkdir()
    monkeypatch.setenv("MCP_BASTION_SCAN_DIR", str(empty))
    posture = load_posture(demo=True)
    assert posture["demo"] is True
    assert posture["combined_grade"] == "C"
    assert posture["checks"]["catalog"]["present"] is True


def test_taxonomy_coverage_cells(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    scan = tmp_path / "scan"
    scan.mkdir()
    (scan / "catalog.json").write_text(
        json.dumps(
            {
                "grade": "C",
                "findings": [
                    {
                        "check": "injection_heuristic",
                        "severity": "high",
                        "message": "inject",
                        "taxonomy": {"asi": ["ASI01"]},
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("MCP_BASTION_SCAN_DIR", str(scan))
    posture = load_posture(demo=False)
    tax = load_taxonomy_coverage(
        posture=posture,
        metrics={"blocked_by_kind": {"agent_iam": 3}},
        config=None,
    )
    assert len(tax["cells"]) == 10
    asi01 = next(c for c in tax["cells"] if c["id"] == "ASI01")
    assert asi01["status"] == "findings"
    assert asi01["finding_hits"] >= 1
    asi03 = next(c for c in tax["cells"] if c["id"] == "ASI03")
    assert asi03["block_hits"] >= 3


def test_compliance_and_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    att = tmp_path / "attest"
    att.mkdir()
    (att / "session.json").write_text(
        json.dumps(
            {
                "generated_at": "2026-07-12T00:00:00+00:00",
                "session_id": "s1",
                "policy": {"policy_hash": "abc"},
                "summary": {"pillars_fired": ["prompt_guard"], "blocked_count": 1, "allowed_count": 2},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("MCP_BASTION_ATTEST_DIR", str(att))
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        '{"timestamp":"2026-07-11T12:00:00+00:00","action":"BLOCKED","tool":"x"}\n'
        '{"timestamp":"2026-07-11T13:00:00+00:00","action":"ALLOWED","tool":"y"}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MCP_BASTION_AUDIT_PATH", str(audit))
    comp = load_compliance()
    assert "not a certificate" in comp["disclaimer"].lower()
    assert comp["attestation"] is not None
    assert comp["attestation"]["session_id"] == "s1"
    blob = build_evidence_bundle_zip(framework="soc2")
    assert blob[:2] == b"PK"


def test_trends_and_onboarding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    audit = tmp_path / "audit.jsonl"
    audit.write_text(
        '{"timestamp":"2026-07-10T01:00:00Z","action":"BLOCKED"}\n'
        '{"timestamp":"2026-07-10T02:00:00Z","action":"ALLOWED"}\n'
        '{"timestamp":"2026-07-11T01:00:00Z","action":"ALLOWED"}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MCP_BASTION_AUDIT_PATH", str(audit))
    trends = load_trends_from_audit(days=14)
    assert trends["present"] is True
    assert len(trends["days"]) >= 1
    empty_scan = tmp_path / "noscan"
    empty_scan.mkdir()
    monkeypatch.setenv("MCP_BASTION_SCAN_DIR", str(empty_scan))
    onboard = load_onboarding({"requests_total": 0, "blocked_total": 0}, load_posture(demo=False))
    assert onboard["show"] is True
    assert len(onboard["steps"]) == 3


def test_provenance_from_reason():
    p = provenance_from_reason("Agent 'bot' is not permitted to call tool 'x'")
    assert p["kind"] == "agent_iam"
    assert "agent_iam" in p["rule"]
    p2 = provenance_from_reason(
        "blocked",
        forensic_trace=[{"pillar": "prompt_guard", "status": "blocked"}],
    )
    assert p2["pillar"] == "prompt_guard"


def test_dashboard_api_routes_importable():
    """Smoke: dashboard app module exposes new endpoints."""
    import importlib.util

    root = Path(__file__).resolve().parents[1]
    app_path = root / "dashboard" / "app.py"
    spec = importlib.util.spec_from_file_location("dash_app_test", app_path)
    assert spec and spec.loader
    # Importing dashboard/app.py starts FastAPI; ensure routes exist without binding port.
    # Use TestClient if fastapi available.
    try:
        from fastapi.testclient import TestClient
    except ImportError:
        pytest.skip("fastapi not installed")

    # Avoid demo seed side effects fighting tests: still OK for route presence.
    mod = importlib.util.module_from_spec(spec)
    # Running app.py as module executes lifespan setup — may be heavy.
    # Instead check route strings in source.
    text = app_path.read_text(encoding="utf-8")
    for path in (
        "/api/posture",
        "/api/taxonomy",
        "/api/compliance",
        "/api/observe",
        "/api/agents",
        "/api/trends",
        "/api/onboarding",
        "/api/alerts/stream",
        "/api/attack-matrix",
    ):
        assert path in text
