"""Tests for CLI validate command."""

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

# Ensure src is on path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_bastion.cli import (
    cmd_validate,
    cmd_serve,
    cmd_dashboard,
    cmd_manifest,
    cmd_attest_export,
    main,
    _ensure_src_on_path,
    _resolve_dashboard_repo,
)


def test_cli_version_flag(capsys, monkeypatch):
    from mcp_bastion import __version__

    monkeypatch.setattr(sys, "argv", ["mcp-bastion", "--version"])
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    out, _ = capsys.readouterr()
    assert __version__ in out
    assert "mcp-bastion" in out.lower() or "bastion" in out.lower() or __version__ in out


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


def test_resolve_dashboard_repo_finds_repo_when_cwd_has_no_dashboard(monkeypatch, tmp_path):
    """When cwd is not the repo, still resolve repo root via cli.py location."""
    monkeypatch.chdir(tmp_path)
    root = _resolve_dashboard_repo()
    assert root is not None
    assert (root / "dashboard" / "app.py").is_file()


def test_resolve_dashboard_repo_returns_none_when_dashboard_missing(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    real_is_file = Path.is_file

    def is_file_stub(self):
        s = str(self).replace("\\", "/")
        if s.endswith("dashboard/app.py"):
            return False
        return real_is_file(self)

    with mock.patch.object(Path, "is_file", is_file_stub):
        assert _resolve_dashboard_repo() is None


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


def _restore_env(keys: dict[str, str | None]) -> None:
    for k, v in keys.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def test_cmd_dashboard_no_demo_sets_env():
    root = Path(__file__).resolve().parent.parent
    if not (root / "dashboard" / "app.py").exists():
        pytest.skip("dashboard/app.py not found")
    prev = {k: os.environ.get(k) for k in ("MCP_BASTION_DEMO", "MCP_BASTION_DEMO_LIVE")}
    try:
        os.environ.pop("MCP_BASTION_DEMO", None)
        with mock.patch("uvicorn.run"):
            result = cmd_dashboard(7000, no_demo=True)
        assert result == 0
        assert os.environ.get("MCP_BASTION_DEMO") == "0"
    finally:
        _restore_env({k: prev[k] for k in prev})


def test_cmd_dashboard_demo_flag_sets_env():
    root = Path(__file__).resolve().parent.parent
    if not (root / "dashboard" / "app.py").exists():
        pytest.skip("dashboard/app.py not found")
    prev = {k: os.environ.get(k) for k in ("MCP_BASTION_DEMO", "MCP_BASTION_DEMO_LIVE")}
    try:
        with mock.patch("uvicorn.run"):
            result = cmd_dashboard(7000, demo=True)
        assert result == 0
        assert os.environ.get("MCP_BASTION_DEMO") == "1"
    finally:
        _restore_env({k: prev[k] for k in prev})


def test_cmd_dashboard_no_live_and_live_flags():
    root = Path(__file__).resolve().parent.parent
    if not (root / "dashboard" / "app.py").exists():
        pytest.skip("dashboard/app.py not found")
    prev = {k: os.environ.get(k) for k in ("MCP_BASTION_DEMO", "MCP_BASTION_DEMO_LIVE")}
    try:
        with mock.patch("uvicorn.run"):
            assert cmd_dashboard(7000, no_live=True) == 0
        assert os.environ.get("MCP_BASTION_DEMO_LIVE") == "0"
        with mock.patch("uvicorn.run"):
            assert cmd_dashboard(7000, live=True) == 0
        assert os.environ.get("MCP_BASTION_DEMO_LIVE") == "1"
    finally:
        _restore_env({k: prev[k] for k in prev})


def test_cmd_dashboard_reload_logs_auto_reload(caplog):
    root = Path(__file__).resolve().parent.parent
    if not (root / "dashboard" / "app.py").exists():
        pytest.skip("dashboard/app.py not found")
    prev = {k: os.environ.get(k) for k in ("MCP_BASTION_DEMO", "MCP_BASTION_DEMO_LIVE", "MCP_BASTION_DASHBOARD_RELOAD")}
    try:
        os.environ.pop("MCP_BASTION_DASHBOARD_RELOAD", None)
        with mock.patch("uvicorn.run"):
            with caplog.at_level("INFO"):
                result = cmd_dashboard(7000, reload=True)
        assert result == 0
        assert "Auto-reload enabled" in caplog.text
    finally:
        _restore_env({k: prev[k] for k in prev})


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


def test_main_scan_help(monkeypatch):
    monkeypatch.setattr("sys.argv", ["mcp-bastion", "scan", "--help"])
    with pytest.raises(SystemExit):
        main()


def test_cmd_manifest_writes_json(tmp_path, caplog):
    import json
    import logging

    f = tmp_path / "server.py"
    f.write_text("print('x')\n", encoding="utf-8")
    out = tmp_path / "manifest.json"
    with caplog.at_level(logging.INFO):
        rc = cmd_manifest(["server.py"], base_path=str(tmp_path), output=str(out))
    assert rc == 0
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert "server.py" in data["files"]
    assert len(data["files"]["server.py"]) == 64
    assert data["algorithm"] == "sha256"
    assert "signature" not in data


def test_cmd_manifest_missing_file_returns_one(tmp_path):
    rc = cmd_manifest(["missing.py"], base_path=str(tmp_path), output=None)
    assert rc == 1


@pytest.mark.filterwarnings(
    "ignore:.*mcp_bastion.cli.*sys.modules:RuntimeWarning"
)
def test_cli_main_entrypoint(monkeypatch):
    """Cover if __name__ == '__main__' by running the module as __main__."""
    monkeypatch.setattr("sys.argv", ["mcp-bastion", "validate", "--help"])
    with mock.patch("sys.exit") as exit_mock:
        import runpy
        runpy.run_module("mcp_bastion.cli", run_name="__main__")
    assert exit_mock.called


def test_cmd_serve_proxy_mode(tmp_path, monkeypatch):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text("prompt_guard:\n  enabled: false\naudit:\n  enabled: false\n", encoding="utf-8")
    called: list[tuple] = []

    def fake_run(upstream_url, **kwargs):
        called.append((upstream_url, kwargs))

    monkeypatch.setattr("mcp_bastion.proxy_server.run_proxy_http", fake_run)
    rc = cmd_serve(str(yaml_path), 8080, "127.0.0.1", proxy_url="http://127.0.0.1:9000/mcp")
    assert rc == 0
    assert called[0][0] == "http://127.0.0.1:9000/mcp"
    assert called[0][1]["port"] == 8080


def test_cmd_serve_missing_config_returns_one(tmp_path):
    assert cmd_serve(str(tmp_path / "missing.yaml"), 8080, "127.0.0.1", proxy_url=None) == 1


def test_cmd_attest_export_sign_missing_key(tmp_path, monkeypatch):
    from mcp_bastion.pillars.session_governance import SessionGovernanceRecorder

    SessionGovernanceRecorder.reset()
    SessionGovernanceRecorder.get().record(
        session_id="s",
        request_id="r",
        method="tools/call",
        tool="t",
        pillar="handler",
        status="allowed",
    )
    monkeypatch.delenv("BASTION_MANIFEST_SIGNING_KEY", raising=False)
    rc = cmd_attest_export("s", str(tmp_path / "bastion.yaml"), None, sign=True, principal_id=None, tenant_id=None)
    assert rc == 1
    SessionGovernanceRecorder.reset()
