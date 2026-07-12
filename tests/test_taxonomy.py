"""Tests for finding taxonomy (ASI / MCP / LLM tags)."""

from __future__ import annotations

from mcp_bastion.pillars.compliance_report import FRAMEWORK_CONTROLS
from mcp_bastion.taxonomy import ASI_TITLES, TAXONOMY, enrich_finding, tags_for_check


def test_asi_titles_cover_01_to_10():
    for i in range(1, 11):
        key = f"ASI{i:02d}"
        assert key in ASI_TITLES
        assert ASI_TITLES[key]


def test_verified_injection_maps_to_asi01():
    tags = tags_for_check("injection_heuristic")
    assert "ASI01" in tags.get("asi", [])


def test_unbounded_string_maps_to_asi():
    tags = tags_for_check("unbounded_string")
    assert "ASI02" in tags["asi"]


def test_enrich_finding_attaches_taxonomy():
    out = enrich_finding({"check": "homoglyph", "severity": "high"})
    assert out["taxonomy"]["asi"] == ["ASI04"]


def test_compliance_asi_framework_present():
    assert "asi" in FRAMEWORK_CONTROLS
    assert "ASI01" in FRAMEWORK_CONTROLS["asi"]
    assert "ASI10" in FRAMEWORK_CONTROLS["asi"]


def test_taxonomy_covers_all_emitted_checks():
    """Every check id we emit must have a taxonomy row (no silent stubs)."""
    required = {
        "injection_heuristic",
        "homoglyph",
        "unbounded_string",
        "weak_schema",
        "missing_input_schema",
        "invalid_input_schema",
        "unconstrained_numeric",
        "risky_arg_optional",
        "content_filter",
        "fingerprint_drift",
        "hidden_unicode",
        "empty_description",
        "skill_over_broad_grant",
        "skill_credential_ref",
        "skill_name_mismatch",
        "skill_read_error",
        "standing_credential",
        "credential_env_ref",
        "standing_env_secret",
        "over_permissioned_tools",
        "broad_tool_surface",
        "shell_launcher",
        "filesystem_server",
        "no_mcp_configs",
        "config_parse_error",
        "empty_servers",
    }
    assert required <= set(TAXONOMY.keys())


def test_severity_from_osv_metadata():
    from mcp_bastion.pillars.osv_scan import _severity_from_vuln

    assert _severity_from_vuln({"database_specific": {"severity": "CRITICAL"}}) == "critical"
    assert _severity_from_vuln({"severity": [{"type": "CVSS_V3", "score": "9.8"}]}) == "critical"
    assert _severity_from_vuln({"severity": [{"type": "CVSS_V3", "score": "5.0"}]}) == "medium"
