"""Tests for config load and build_middleware_from_config."""

import asyncio
import logging
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from mcp_bastion.config import (
    BastionConfig,
    _HotReloadingMiddleware,
    build_middleware_from_config,
    load_config,
)
from mcp_bastion.base import MiddlewareContext


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


def test_load_config_content_filter_and_alert_and_hot_reload_fields(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
content_filter:
  enabled: true
  block_code_execution: false
  block_file_paths: true
  block_urls: true
  allowlist_patterns:
    - '^safe$'
  denylist_patterns:
    - secret
alerts:
  retry_attempts: 4
  retry_backoff_seconds: 0.1
  retry_backoff_max_seconds: 0.5
  timeout_seconds: 7
hot_reload:
  enabled: true
  poll_seconds: 1.5
""",
        encoding="utf-8",
    )
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
    result = load_config(str(yaml_path))
    assert result.content_filter is True
    assert result.content_filter_block_code_execution is False
    assert result.content_filter_block_urls is True
    assert result.content_filter_allowlist_patterns == ["^safe$"]
    assert result.content_filter_denylist_patterns == ["secret"]
    assert result.alerts_retry_attempts == 4
    assert result.alerts_timeout_seconds == 7.0
    assert result.hot_reload is True
    assert result.hot_reload_poll_seconds == 1.5


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


@pytest.mark.asyncio
async def test_build_middleware_hot_reload_invalid_update_keeps_running(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        "hot_reload:\n  enabled: true\n  poll_seconds: 0.1\nprompt_guard:\n  enabled: false\n",
        encoding="utf-8",
    )
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")

    config = load_config(str(yaml_path))
    mw = build_middleware_from_config(config)

    async def call_next(ctx):
        return {"ok": True}

    ctx = MiddlewareContext(message={"method": "ping"}, request_id="r1", session_id="s1")
    first = await mw(ctx, call_next)
    assert first == {"ok": True}

    yaml_path.write_text("prompt_guard: [broken\n", encoding="utf-8")
    os.utime(yaml_path, None)
    await asyncio.sleep(0.35)
    second = await mw(ctx, call_next)
    assert second == {"ok": True}


def test_hot_reload_mtime_oserror(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        "hot_reload:\n  enabled: true\n  poll_seconds: 1.0\nprompt_guard:\n  enabled: false\n",
        encoding="utf-8",
    )
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
    cfg = load_config(str(yaml_path))
    h = _HotReloadingMiddleware(config_path=yaml_path, initial_config=cfg, poll_seconds=1.0)

    real_stat = Path.stat

    def stat_stub(self):
        if self is yaml_path:
            raise OSError("stat failed")
        return real_stat(self)

    with mock.patch.object(Path, "stat", stat_stub):
        assert h._mtime() is None


def test_hot_reload_maybe_skips_when_poll_interval_not_elapsed(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        "hot_reload:\n  enabled: true\n  poll_seconds: 1.0\nprompt_guard:\n  enabled: false\n",
        encoding="utf-8",
    )
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
    cfg = load_config(str(yaml_path))
    h = _HotReloadingMiddleware(config_path=yaml_path, initial_config=cfg, poll_seconds=1.0)
    h._maybe_reload()
    h._maybe_reload()


@pytest.mark.asyncio
async def test_build_middleware_hot_reload_valid_update_logs_reload(tmp_path, caplog):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        "hot_reload:\n  enabled: true\n  poll_seconds: 0.05\nprompt_guard:\n  enabled: false\naudit:\n  enabled: false\n",
        encoding="utf-8",
    )
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")

    config = load_config(str(yaml_path))
    mw = build_middleware_from_config(config)

    async def call_next(ctx):
        return {"ok": True}

    ctx = MiddlewareContext(message={"method": "ping"}, request_id="r1", session_id="s1")
    await mw(ctx, call_next)

    yaml_path.write_text(
        "hot_reload:\n  enabled: true\n  poll_seconds: 0.05\nprompt_guard:\n  enabled: false\naudit:\n  enabled: true\n",
        encoding="utf-8",
    )
    os.utime(yaml_path, None)
    await asyncio.sleep(0.35)
    with caplog.at_level(logging.INFO, logger="mcp_bastion.config"):
        await mw(ctx, call_next)
    assert "Reloaded bastion config" in caplog.text


def test_load_config_schema_validation_schemas(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
schema_validation:
  enabled: true
  schemas:
    create_report:
      year: integer
      amount: number
prompt_guard:
  enabled: false
pii:
  enabled: false
rate_limit:
  enabled: false
audit:
  enabled: false
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    cfg = load_config(str(yaml_path))
    assert cfg.schema_validation is True
    assert cfg.schema_validation_schemas["create_report"]["year"] is int
    assert cfg.schema_validation_schemas["create_report"]["amount"] is float


@pytest.mark.asyncio
async def test_build_middleware_enforces_schema_from_yaml(tmp_path):
    from mcp_bastion.errors import SchemaValidationError

    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
schema_validation:
  enabled: true
  schemas:
    add:
      a: integer
      b: integer
prompt_guard:
  enabled: false
pii:
  enabled: false
rate_limit:
  enabled: false
audit:
  enabled: false
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    mw = build_middleware_from_config(load_config(str(yaml_path)))
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "add", "arguments": {"a": 1, "b": "x"}}},
        request_id="r1",
    )

    async def handler(_ctx):
        return {"ok": True}

    with pytest.raises(SchemaValidationError, match="expected int"):
        await mw(ctx, handler)


def test_load_config_state_backend(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
state_backend:
  type: redis
  redis_url: redis://redis.example:6379/1
  key_prefix: my-bastion
prompt_guard:
  enabled: false
audit:
  enabled: false
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    cfg = load_config(str(yaml_path))
    assert cfg.state_backend == "redis"
    assert cfg.state_backend_redis_url == "redis://redis.example:6379/1"
    assert cfg.state_backend_key_prefix == "my-bastion"


def test_bastion_config_state_backend_defaults():
    cfg = BastionConfig()
    assert cfg.state_backend == "memory"
    assert "6379" in cfg.state_backend_redis_url
    assert cfg.state_backend_key_prefix == "mcp-bastion"


def test_build_middleware_wires_shared_backend_for_redis(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
state_backend:
  type: redis
  redis_url: redis://127.0.0.1:6379/0
prompt_guard:
  enabled: false
pii:
  enabled: false
rate_limit:
  enabled: true
replay_guard:
  enabled: true
cost_tracker:
  enabled: true
audit:
  enabled: false
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    with mock.patch("mcp_bastion.config.build_state_backend") as build_sb:
        from mcp_bastion.pillars.state_backend import MemoryStateBackend

        fake = MemoryStateBackend()
        build_sb.return_value = fake
        mw = build_middleware_from_config(load_config(str(yaml_path)))
        build_sb.assert_called_once()
        # Inner bastion middleware is second in compose when audit disabled — unwrap composed chain
        assert mw is not None


def test_load_config_adopted_features(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
argument_guards:
  enabled: true
  rules:
    - name: block_x
      match: "*"
      arg: "$.x"
      pattern: "bad"
      action: block
audit:
  enabled: false
  jsonl_path: /var/log/bastion.jsonl
cost_tracker:
  enabled: true
  checkpoint_path: /tmp/cost.json
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    cfg = load_config(str(yaml_path))
    assert cfg.argument_guards_enabled is True
    assert len(cfg.argument_guards_rules) == 1
    assert cfg.audit_jsonl_path == "/var/log/bastion.jsonl"
    assert cfg.cost_checkpoint_path == "/tmp/cost.json"


def test_build_middleware_argument_guards_enabled_no_rules(tmp_path, caplog):
    import logging

    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
argument_guards:
  enabled: true
  rules: []
audit:
  enabled: false
prompt_guard:
  enabled: false
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    from mcp_bastion.config import build_middleware_from_config, load_config

    with caplog.at_level(logging.WARNING):
        mw = build_middleware_from_config(load_config(str(yaml_path)))
    assert mw is not None
    assert "argument_guards" in caplog.text.lower()
