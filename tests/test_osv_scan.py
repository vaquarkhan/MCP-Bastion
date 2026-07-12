"""Tests for offline-first OSV dependency scan."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_bastion.pillars.osv_scan import (
    DepRef,
    format_osv_report_text,
    is_affected,
    scan_dependencies,
)


def _write_vuln(db: Path, *, pkg: str, vuln_id: str, introduced: str, fixed: str | None) -> None:
    eco = db / "PyPI"
    eco.mkdir(parents=True, exist_ok=True)
    events = [{"introduced": introduced}]
    if fixed is not None:
        events.append({"fixed": fixed})
    doc = {
        "id": vuln_id,
        "summary": f"{pkg} demo vuln",
        "affected": [
            {
                "package": {"name": pkg, "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": events}],
            }
        ],
    }
    (eco / f"{vuln_id}.json").write_text(json.dumps(doc), encoding="utf-8")


def test_is_affected_introduced_fixed():
    ranges = [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}, {"fixed": "1.0.1"}]}]
    assert is_affected("1.0.0", ranges) is True
    assert is_affected("1.0.1", ranges) is False


def test_scan_flags_vulnerable_version(tmp_path):
    _write_vuln(tmp_path, pkg="demo-pkg", vuln_id="OSV-DEMO-1", introduced="1.0.0", fixed="1.0.1")
    report = scan_dependencies(
        [DepRef("demo-pkg", "1.0.0")],
        db_dir=tmp_path,
        online=False,
        enabled=True,
    )
    assert report.db_used
    assert any(f.vuln_id == "OSV-DEMO-1" for f in report.findings)

    clean = scan_dependencies(
        [DepRef("demo-pkg", "1.0.1")],
        db_dir=tmp_path,
        online=False,
        enabled=True,
    )
    assert not any(f.vuln_id == "OSV-DEMO-1" for f in clean.findings)


def test_missing_db_warns_no_crash(tmp_path):
    report = scan_dependencies(
        [DepRef("demo-pkg", "1.0.0")],
        db_dir=tmp_path / "empty",
        online=False,
        enabled=True,
    )
    assert report.warnings
    assert report.findings == []
    format_osv_report_text(report).encode("ascii")


def test_osv_disabled_by_default_flag():
    report = scan_dependencies([DepRef("x", "1.0.0")], enabled=False)
    assert report.findings == []
    assert any("disabled" in w.lower() for w in report.warnings)
