"""Tests for mcp_bastion.doctor."""

import json
from unittest import mock

import pytest

from mcp_bastion.doctor import _package_version, run_doctor


def test_package_version_returns_string():
    v = _package_version()
    assert isinstance(v, str) and len(v) > 0


def test_package_version_unknown_when_metadata_missing():
    with mock.patch("importlib.metadata.version", side_effect=Exception("no pkg")):
        assert _package_version() == "unknown"


def test_run_doctor_config_ok(tmp_path):
    p = tmp_path / "bastion.yaml"
    p.write_text("audit:\n  enabled: true\n", encoding="utf-8")
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    r = run_doctor(config_path=str(p), repo_root=tmp_path)
    assert r["ok"] is True
    assert any(c["id"] == "config_load" and c["ok"] for c in r["checks"])
    assert any(c["id"] == "manifests" for c in r["checks"])
    assert "bastion_version" in r and "python" in r


def test_run_doctor_config_invalid(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("{ invalid", encoding="utf-8")
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    r = run_doctor(config_path=str(p), repo_root=tmp_path)
    assert r["ok"] is False


def test_run_doctor_pip_audit_skipped(tmp_path):
    (tmp_path / "bastion.yaml").write_text("audit:\n  enabled: true\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    with mock.patch("mcp_bastion.doctor.shutil.which", return_value=None):
        r = run_doctor(config_path=str(tmp_path / "bastion.yaml"), repo_root=tmp_path)
    pa = next(c for c in r["checks"] if c["id"] == "pip_audit")
    assert pa.get("skipped") is True


def test_run_doctor_pip_audit_bad_json_stdout(tmp_path):
    (tmp_path / "bastion.yaml").write_text("audit:\n  enabled: true\n", encoding="utf-8")
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    with mock.patch("mcp_bastion.doctor.shutil.which", return_value="pip-audit"):
        with mock.patch("mcp_bastion.doctor.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="not-json")
            r = run_doctor(config_path=str(tmp_path / "bastion.yaml"), repo_root=tmp_path)
    pa = next(c for c in r["checks"] if c["id"] == "pip_audit")
    assert pa.get("ok") is True


def test_run_doctor_pip_audit_subprocess_error(tmp_path):
    (tmp_path / "bastion.yaml").write_text("audit:\n  enabled: true\n", encoding="utf-8")
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    with mock.patch("mcp_bastion.doctor.shutil.which", return_value="pip-audit"):
        with mock.patch("mcp_bastion.doctor.subprocess.run", side_effect=OSError("nope")):
            r = run_doctor(config_path=str(tmp_path / "bastion.yaml"), repo_root=tmp_path)
    assert r["ok"] is False


def test_run_doctor_pip_audit_runs(tmp_path):
    (tmp_path / "bastion.yaml").write_text("audit:\n  enabled: true\n", encoding="utf-8")
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    with mock.patch("mcp_bastion.doctor.shutil.which", return_value="pip-audit"):
        with mock.patch("mcp_bastion.doctor.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0, stdout=json.dumps([]))
            r = run_doctor(config_path=str(tmp_path / "bastion.yaml"), repo_root=tmp_path)
    pa = next(c for c in r["checks"] if c["id"] == "pip_audit")
    assert pa.get("returncode") == 0
