"""Tests for config load and build_middleware_from_config."""

import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from mcp_bastion.config import BastionConfig, build_middleware_from_config, load_config


def test_bastion_config_defaults():
    c = BastionConfig()
    assert c.prompt_guard is True
    assert c.pii is True
    assert c.rate_limit is True
    assert c.audit is True
    assert c.rate_limit_max_iterations == 15
    assert c.rbac is False
    assert c.alerts_on == ["injection", "rate_limit", "cost"]


def test_load_config_missing_file_returns_defaults():
    result = load_config(Path("/nonexistent/bastion.yaml"))
    assert isinstance(result, BastionConfig)
    assert result.prompt_guard is True


def test_load_config_with_yaml(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text("""
prompt_guard:
  enabled: false
rate_limit:
  enabled: true
  max_iterations: 5
rbac:
  enabled: true
  permissions:
    default: ["read"]
audit:
  enabled: false
""", encoding="utf-8")
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
    result = load_config(str(yaml_path))
    assert result.prompt_guard is False
    assert result.rate_limit_max_iterations == 5
    assert result.rbac is True
    assert result.rbac_permissions.get("default") == ["read"]
    assert result.audit is False


def test_load_config_uses_bastion_config_env(monkeypatch, tmp_path):
    yaml_path = tmp_path / "custom.yaml"
    yaml_path.write_text("rate_limit:\n  enabled: false\n", encoding="utf-8")
    monkeypatch.setenv("BASTION_CONFIG", str(yaml_path))
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
    result = load_config(None)
    assert result.rate_limit is False
    monkeypatch.delenv("BASTION_CONFIG", raising=False)


def test_build_middleware_from_config_none():
    mw = build_middleware_from_config(None)
    assert mw is not None
    assert callable(getattr(mw, "__call__", None)) or hasattr(mw, "on_message")


def test_build_middleware_from_config_explicit_config():
    config = BastionConfig(audit=False, prompt_guard=False)
    mw = build_middleware_from_config(config)
    assert mw is not None


def test_build_middleware_from_config_with_slack_webhook():
    config = BastionConfig(
        audit=True,
        alerts_slack_webhook="https://hooks.slack.com/fake",
    )
    mw = build_middleware_from_config(config)
    assert mw is not None


def test_build_middleware_from_config_with_webhook_url():
    config = BastionConfig(
        audit=True,
        alerts_webhook_url="https://example.com/webhook",
    )
    mw = build_middleware_from_config(config)
    assert mw is not None


def test_build_middleware_from_config_with_webhooks_list():
    config = BastionConfig(
        audit=True,
        alerts_webhooks=["https://a.com", "https://b.com"],
    )
    mw = build_middleware_from_config(config)
    assert mw is not None


def test_load_config_yaml_import_error(tmp_path):
    """Cover _load_yaml when yaml module is not available."""
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text("prompt_guard:\n  enabled: true\n", encoding="utf-8")
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("No module named 'yaml'")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=fake_import):
        with pytest.raises(ImportError, match="PyYAML"):
            load_config(str(yaml_path))
