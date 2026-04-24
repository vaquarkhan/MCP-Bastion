"""Release metadata: version strings stay aligned across packaging files."""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r"(?m)^version\s*=\s*\"([^\"]+)\"", text)
    assert m, "version field missing in pyproject.toml"
    return m.group(1)


def test_package_version_matches_pyproject():
    import mcp_bastion

    assert mcp_bastion.__version__ == _pyproject_version()


def test_server_json_version_matches_pyproject():
    raw = (REPO_ROOT / "server.json").read_text(encoding="utf-8")
    data = json.loads(raw)
    assert data.get("version") == _pyproject_version()
    pkgs = data.get("packages") or []
    for p in pkgs:
        assert p.get("version") == _pyproject_version(), f"package version mismatch: {p}"


def test_citation_cff_version_matches_pyproject():
    text = (REPO_ROOT / "CITATION.cff").read_text(encoding="utf-8")
    m = re.search(r"(?m)^version:\s*([0-9]+(?:\.[0-9]+)*)", text)
    assert m, "version field in CITATION.cff"
    assert m.group(1) == _pyproject_version()
