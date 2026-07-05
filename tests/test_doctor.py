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
    # pip-audit on PATH may report local vulns (returncode != 0); isolate config check.
    with mock.patch("mcp_bastion.doctor.shutil.which", return_value=None):
        with mock.patch("mcp_bastion.pillars.prompt_guard.PromptGuardEngine.score", return_value=0.0):
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
        with mock.patch("mcp_bastion.pillars.prompt_guard.PromptGuardEngine.score", return_value=0.0):
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
        with mock.patch("mcp_bastion.pillars.prompt_guard.PromptGuardEngine.score", return_value=0.0):
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
        with mock.patch("mcp_bastion.pillars.prompt_guard.PromptGuardEngine.score", return_value=0.0):
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
        with mock.patch("mcp_bastion.pillars.prompt_guard.PromptGuardEngine.score", return_value=0.0):
            with mock.patch("mcp_bastion.doctor.subprocess.run") as run:
                run.return_value = mock.Mock(returncode=0, stdout=json.dumps([]))
                r = run_doctor(config_path=str(tmp_path / "bastion.yaml"), repo_root=tmp_path)
    pa = next(c for c in r["checks"] if c["id"] == "pip_audit")
    assert pa.get("returncode") == 0


def test_run_doctor_schema_validation_warns_when_enabled_without_schemas(tmp_path):
    (tmp_path / "bastion.yaml").write_text(
        "schema_validation:\n  enabled: true\naudit:\n  enabled: true\n",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    with mock.patch("mcp_bastion.doctor.shutil.which", return_value=None):
        with mock.patch("mcp_bastion.pillars.prompt_guard.PromptGuardEngine.score", return_value=0.0):
            r = run_doctor(config_path=str(tmp_path / "bastion.yaml"), repo_root=tmp_path)
    sv = next(c for c in r["checks"] if c["id"] == "schema_validation")
    assert sv["ok"] is False
    assert "empty" in sv["detail"].lower()


def test_run_doctor_state_backend_memory_skipped(tmp_path):
    (tmp_path / "bastion.yaml").write_text(
        "state_backend:\n  type: memory\naudit:\n  enabled: true\n",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    with mock.patch("mcp_bastion.doctor.shutil.which", return_value=None):
        with mock.patch("mcp_bastion.pillars.prompt_guard.PromptGuardEngine.score", return_value=0.0):
            r = run_doctor(config_path=str(tmp_path / "bastion.yaml"), repo_root=tmp_path)
    sb = next(c for c in r["checks"] if c["id"] == "state_backend_redis")
    assert sb.get("skipped") is True
    assert "memory" in sb["detail"]


def test_run_doctor_state_backend_redis_ping(tmp_path):
    (tmp_path / "bastion.yaml").write_text(
        "state_backend:\n  type: redis\n  redis_url: redis://127.0.0.1:6379/0\naudit:\n  enabled: true\n",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    fake_client = mock.Mock()
    fake_client.ping.return_value = True
    fake_mod = mock.Mock()
    fake_mod.Redis.from_url = mock.Mock(return_value=fake_client)
    with mock.patch("mcp_bastion.doctor.shutil.which", return_value=None):
        with mock.patch("mcp_bastion.pillars.prompt_guard.PromptGuardEngine.score", return_value=0.0):
            with mock.patch.dict("sys.modules", {"redis": fake_mod}):
                r = run_doctor(config_path=str(tmp_path / "bastion.yaml"), repo_root=tmp_path)
    sb = next(c for c in r["checks"] if c["id"] == "state_backend_redis")
    assert sb["ok"] is True
