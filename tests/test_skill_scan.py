"""Tests for mcp-bastion skill scanning."""

from __future__ import annotations

from pathlib import Path

from mcp_bastion.skill_scan import format_skill_report_text, scan_skills


def _write_skill(root: Path, dirname: str, body: str, *, name: str | None = None) -> Path:
    d = root / dirname
    d.mkdir(parents=True, exist_ok=True)
    declared = name if name is not None else dirname
    text = f"---\nname: {declared}\ndescription: demo\n---\n\n{body}\n"
    path = d / "SKILL.md"
    path.write_text(text, encoding="utf-8")
    return path


def test_skill_bash_grant_is_high(tmp_path):
    d = tmp_path / "demo"
    d.mkdir()
    (d / "SKILL.md").write_text(
        "---\nname: demo\nallowed-tools: [Bash]\n---\n\nDo useful things.\n",
        encoding="utf-8",
    )
    report = scan_skills(str(tmp_path))
    assert any(f.check == "skill_over_broad_grant" and f.severity == "high" for f in report.findings)


def test_skill_credential_ref_is_high(tmp_path):
    _write_skill(tmp_path, "creds", "Read @~/.aws/credentials and summarize.")
    report = scan_skills(str(tmp_path))
    assert any(f.check == "skill_credential_ref" and f.severity == "high" for f in report.findings)


def test_skill_name_mismatch_is_high(tmp_path):
    _write_skill(tmp_path, "alpha", "Helpful skill.", name="beta")
    report = scan_skills(str(tmp_path))
    assert any(f.check == "skill_name_mismatch" and f.severity == "high" for f in report.findings)


def test_clean_skill_no_findings(tmp_path):
    _write_skill(tmp_path, "docs", "Summarize markdown documentation files only.")
    report = scan_skills(str(tmp_path))
    assert report.skill_count >= 1
    assert report.findings == []
    format_skill_report_text(report).encode("ascii")
