"""Tests for scripts/generate_sbom.py (CRA CycloneDX SBOM helper)."""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_sbom.py"


def _load_mod():
    spec = importlib.util.spec_from_file_location("generate_sbom", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["generate_sbom"] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def sbom():
    return _load_mod()


def test_parse_pep508_name_variants(sbom):
    assert sbom.parse_pep508_name("mcp>=1.2.0") == "mcp"
    assert sbom.parse_pep508_name("torch>=2.0.0") == "torch"
    assert sbom.parse_pep508_name("Requests[security]>=2.0") == "Requests"
    assert sbom.parse_pep508_name('foo>=1; python_version<"3.12"') == "foo"


def test_parse_pep508_rejects_empty(sbom):
    with pytest.raises(ValueError):
        sbom.parse_pep508_name("")
    with pytest.raises(ValueError):
        sbom.parse_pep508_name("   ")


def test_build_cyclonedx_from_pyproject_shape(sbom):
    pyproject = {
        "project": {
            "name": "mcp-bastion-python",
            "version": "3.3.0",
            "dependencies": ["mcp>=1.2.0", "presidio-analyzer>=2.2.0", "mcp>=1.2.0"],
        }
    }
    doc = sbom.build_cyclonedx_from_pyproject(
        pyproject,
        serial="urn:uuid:00000000-0000-4000-8000-000000000001",
        timestamp=datetime(2026, 7, 23, 12, 0, 0, tzinfo=timezone.utc),
    )
    errs = sbom.validate_bom_shape(doc)
    assert errs == []
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["metadata"]["component"]["name"] == "mcp-bastion-python"
    assert doc["metadata"]["component"]["version"] == "3.3.0"
    assert doc["metadata"]["component"]["purl"].startswith("pkg:pypi/mcp-bastion-python@")
    names = {c["name"] for c in doc["components"]}
    assert names == {"mcp", "presidio-analyzer"}  # de-duped
    root_dep = doc["dependencies"][0]
    assert root_dep["ref"].endswith("@3.3.0")
    assert len(root_dep["dependsOn"]) == 2


def test_build_cyclonedx_from_package_json(sbom):
    package = {
        "name": "@mcp-bastion/core",
        "version": "3.3.0",
        "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"},
    }
    doc = sbom.build_cyclonedx_from_package_json(
        package,
        serial="urn:uuid:00000000-0000-4000-8000-000000000002",
        timestamp=datetime(2026, 7, 23, 12, 0, 0, tzinfo=timezone.utc),
    )
    assert sbom.validate_bom_shape(doc) == []
    assert doc["metadata"]["component"]["name"] == "@mcp-bastion/core"
    assert "%40mcp-bastion" in doc["metadata"]["component"]["purl"]
    assert doc["components"][0]["name"] == "@modelcontextprotocol/sdk"


def test_write_bom_and_main_cli(sbom, tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "demo-pkg"
version = "1.2.3"
dependencies = ["alpha>=1.0", "beta"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "out" / "bom.json"
    # Call builder + write directly
    data = sbom.load_pyproject(pyproject)
    doc = sbom.build_cyclonedx_from_pyproject(data, serial="urn:uuid:11111111-1111-4111-8111-111111111111")
    sbom.write_bom(doc, out)
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["metadata"]["component"]["name"] == "demo-pkg"
    assert loaded["metadata"]["component"]["version"] == "1.2.3"


def test_main_writes_repo_pyproject(sbom, tmp_path, monkeypatch):
    out = tmp_path / "bom.json"
    rc = sbom.main(
        [
            "--pyproject",
            str(ROOT / "pyproject.toml"),
            "--output",
            str(out),
            "--serial",
            "urn:uuid:22222222-2222-4222-8222-222222222222",
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["metadata"]["component"]["name"] == "mcp-bastion-python"
    assert doc["components"], "expected declared runtime dependencies"
    assert sbom.validate_bom_shape(doc) == []


def test_main_npm_path(sbom, tmp_path):
    pkg = ROOT / "packages" / "core" / "package.json"
    if not pkg.is_file():
        pytest.skip("packages/core/package.json missing")
    out = tmp_path / "bom-npm.json"
    rc = sbom.main(["--npm", str(pkg), "--output", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["bomFormat"] == "CycloneDX"
    assert "@mcp-bastion" in doc["metadata"]["component"]["name"] or "mcp-bastion" in doc[
        "metadata"
    ]["component"]["name"]


def test_validate_bom_shape_errors(sbom):
    assert sbom.validate_bom_shape({})  # non-empty errors
    assert "bomFormat" in " ".join(sbom.validate_bom_shape({"bomFormat": "x"}))


def test_main_missing_file_returns_nonzero(sbom, tmp_path):
    rc = sbom.main(["--pyproject", str(tmp_path / "missing.toml"), "--output", str(tmp_path / "x.json")])
    assert rc == 1
