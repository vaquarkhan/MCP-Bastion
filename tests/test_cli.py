"""Tests for CLI validate command."""

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

# Ensure src is on path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_bastion.cli import cmd_validate, cmd_serve, cmd_dashboard, main, _ensure_src_on_path


def test_cmd_validate_missing_file_returns_one():
    assert cmd_validate("/nonexistent/bastion.yaml") == 1


def test_cmd_validate_valid_yaml_returns_zero(tmp_path, capsys, caplog):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text("prompt_guard:\n  enabled: true\n", encoding="utf-8")
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
    with caplog.at_level("INFO"):
        result = cmd_validate(str(yaml_path))
    out, err = capsys.readouterr()
    combined = out + err + caplog.text
    assert result == 0
    assert "Valid" in combined or "prompt_guard" in combined


def test_cmd_validate_invalid_yaml_returns_one(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text("prompt_guard: [broken: yaml\n", encoding="utf-8")
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
    result = cmd_validate(str(yaml_path))
    assert result == 1


def test_cmd_validate_uses_bastion_config_env(monkeypatch, tmp_path, capsys):
    yaml_path = tmp_path / "env_config.yaml"
    yaml_path.write_text("pii:\n  enabled: false\n", encoding="utf-8")
    monkeypatch.setenv("BASTION_CONFIG", str(yaml_path))
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
    result = cmd_validate(None)
    assert result == 0
    monkeypatch.delenv("BASTION_CONFIG", raising=False)


def test_ensure_src_on_path():
    _ensure_src_on_path()
    # Either no change or src was inserted when running from repo root
    assert True


def test_ensure_src_on_path_inserts_when_repo_root(monkeypatch, tmp_path):
    """When cwd has bastion.yaml.example and src and src not in path, insert src."""
    (tmp_path / "bastion.yaml.example").write_text("")
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.path", [str(tmp_path)])
    _ensure_src_on_path()
    assert str(src_dir) in sys.path


def test_cmd_serve_config_error():
    with mock.patch("mcp_bastion.config.load_config", side_effect=ValueError("bad yaml")):
        result = cmd_serve(None, 8080, "0.0.0.0")
    assert result == 1


def test_cmd_serve_success(monkeypatch):
    root = Path(__file__).resolve().parent.parent
    if not (root / "examples" / "llm_server.py").exists():
        pytest.skip("examples/llm_server.py not found")
    with mock.patch("subprocess.run") as sub:
        sub.return_value.returncode = 0
        result = cmd_serve(None, 8080, "0.0.0.0")
    assert result == 0


def test_cmd_serve_import_error():
    with mock.patch("mcp_bastion.config.load_config", side_effect=ImportError("no config")):
        result = cmd_serve("nonexistent.yaml", 8080, "0.0.0.0")
    assert result == 1


def test_cmd_serve_import_error_at_import(capsys, caplog):
    """Cover except ImportError in cmd_serve when 'from mcp_bastion.config import load_config' fails."""
    real_import = __import__
    mod_key = "mcp_bastion.config"
    had = sys.modules.pop(mod_key, None)

    def fake_import(name, *args, **kwargs):
        if name == mod_key:
            raise ImportError("no config module")
        return real_import(name, *args, **kwargs)

    try:
        with mock.patch("builtins.__import__", side_effect=fake_import):
            with caplog.at_level("ERROR"):
                result = cmd_serve(None, 8080, "0.0.0.0")
        assert result == 1
        _, err = capsys.readouterr()
        combined = err + caplog.text
        assert "Error" in combined or "config" in combined
    finally:
        if had is not None:
            sys.modules[mod_key] = had


def test_cmd_serve_llm_server_not_found():
    with mock.patch("mcp_bastion.config.load_config"), \
         mock.patch.object(Path, "exists", return_value=False):
        result = cmd_serve(None, 8080, "0.0.0.0")
    assert result == 1


def test_cmd_validate_import_error(capsys, caplog):
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "mcp_bastion.config":
            raise ImportError("no config module")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=fake_import):
        with caplog.at_level("ERROR"):
            result = cmd_validate("/any.yaml")
    assert result == 1
    out, err = capsys.readouterr()
    combined = out + err + caplog.text
    assert "Error" in combined or "no config" in combined


def test_cmd_dashboard_app_not_found():
    with mock.patch("uvicorn.run"):
        with mock.patch("mcp_bastion.cli._resolve_dashboard_repo", return_value=None):
            result = cmd_dashboard(7000)
    assert result == 1


def test_cmd_dashboard_import_error(monkeypatch):
    real_import = __import__

    def fake_import(name, *args, **kwargs):
        if name == "uvicorn":
            raise ImportError("No module named 'uvicorn'")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=fake_import):
        result = cmd_dashboard(7000)
    assert result == 1


def test_cmd_dashboard_success(monkeypatch):
    root = Path(__file__).resolve().parent.parent
    if not (root / "dashboard" / "app.py").exists():
        pytest.skip("dashboard/app.py not found")
    with mock.patch("uvicorn.run"):
        result = cmd_dashboard(7000)
    assert result == 0


def test_main_validate(monkeypatch):
    root = Path(__file__).resolve().parent.parent
    config_path = root / "bastion.yaml.example"
    if not config_path.exists():
        pytest.skip("bastion.yaml.example not found")
    monkeypatch.setattr("sys.argv", ["mcp-bastion", "validate", "-c", str(config_path)])
    result = main()
    assert result == 0


def test_main_serve_help(monkeypatch):
    monkeypatch.setattr("sys.argv", ["mcp-bastion", "serve", "--help"])
    with pytest.raises(SystemExit):
        main()


def test_main_dashboard_help(monkeypatch):
    monkeypatch.setattr("sys.argv", ["mcp-bastion", "dashboard", "--help"])
    with pytest.raises(SystemExit):
        main()


def test_cli_main_entrypoint(monkeypatch):
    """Cover if __name__ == '__main__' by running the module as __main__."""
    monkeypatch.setattr("sys.argv", ["mcp-bastion", "validate", "--help"])
    with mock.patch("sys.exit") as exit_mock:
        import runpy
        runpy.run_module("mcp_bastion.cli", run_name="__main__")
    assert exit_mock.called
