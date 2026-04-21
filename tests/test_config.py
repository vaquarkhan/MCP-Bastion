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
    _bastion_distribution_version,
    _HotReloadingMiddleware,
    build_middleware_from_config,
    load_config,
)
from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import ContentFilterError


def test_bastion_config_defaults():
    c = BastionConfig()
    assert c.telemetry_export_mode == "all"
    assert c.telemetry_sinks == []
    assert c.tool_metadata_guard_enabled is False
    assert c.prompt_guard is True
    assert c.pii is True
    assert c.rate_limit is True
    assert c.audit is True
    assert c.rate_limit_max_iterations == 15
    assert c.rbac is False
    assert c.semantic_firewall is False
    assert c.alerts_on == ["injection", "rate_limit", "cost"]
    assert c.policy_engine_type == "none"
    assert c.behavior_fingerprint is True
    assert c.cost_attribution is True
    assert c.audit_hash_chain_anchor_every == 0


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
semantic_firewall:
  enabled: true
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
    assert result.semantic_firewall is True


def test_load_config_policy_engine_and_audit_hash(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
audit_hash_chain:
  anchor_every: 10
  anchor_webhook_url: https://example.com/anchor
behavior_fingerprint:
  enabled: false
cost_attribution:
  enabled: false
policy_engine:
  type: opa
  opa:
    policy_dir: /policies
    query: data.test.allow
""",
        encoding="utf-8",
    )
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
    result = load_config(str(yaml_path))
    assert result.audit_hash_chain_anchor_every == 10
    assert result.audit_anchor_webhook_url == "https://example.com/anchor"
    assert result.behavior_fingerprint is False
    assert result.cost_attribution is False
    assert result.policy_engine_type == "opa"
    assert result.opa_policy_dir == "/policies"
    assert result.opa_query == "data.test.allow"


def test_load_config_multi_tenant_and_sensitive_classifier(tmp_path):
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
multi_tenant:
  enabled: true
  config_dir: ./tenants
  default_tenant: global
sensitive_classifier:
  enabled: true
  threshold: 0.4
  block_labels: [sensitive_business]
""",
        encoding="utf-8",
    )
    try:
        import yaml
    except ImportError:
        pytest.skip("pyyaml not installed")
    result = load_config(str(yaml_path))
    assert result.multi_tenant_enabled is True
    assert result.multi_tenant_config_dir == "./tenants"
    assert result.multi_tenant_default_tenant == "global"
    assert result.sensitive_classifier is True
    assert result.sensitive_classifier_threshold == 0.4
    assert result.sensitive_classifier_block_labels == ["sensitive_business"]


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
        assert h._file_sig() is None


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


@pytest.mark.asyncio
async def test_build_middleware_multi_tenant_uses_tenant_specific_file(tmp_path):
    tenant_dir = tmp_path / "tenants"
    tenant_dir.mkdir()
    (tenant_dir / "acme.yaml").write_text(
        "content_filter:\n  enabled: true\n  block_file_paths: true\nprompt_guard:\n  enabled: false\n",
        encoding="utf-8",
    )
    base = BastionConfig(
        prompt_guard=False,
        content_filter=False,
        audit=False,
        multi_tenant_enabled=True,
        multi_tenant_config_dir=str(tenant_dir),
    )
    mw = build_middleware_from_config(base)

    async def call_next(ctx):
        return {"ok": True}

    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "read", "arguments": {"path": "/etc/passwd"}}},
        request_id="r1",
        session_id="tenant:acme|s-1",
    )
    with pytest.raises(ContentFilterError):
        await mw(ctx, call_next)


def test_bastion_distribution_version_unknown_on_metadata_error():
    with mock.patch("importlib.metadata.version", side_effect=Exception("no distribution")):
        assert _bastion_distribution_version() == "unknown"


def test_build_middleware_schedules_governance_beacon(tmp_path):
    from mcp_bastion.governance_beacon import reset_registry_beacon_for_tests

    reset_registry_beacon_for_tests()
    p = tmp_path / "b.yaml"
    p.write_text(
        """
governance:
  registry_url: http://127.0.0.1:9/nope
  service_id: unit-test
hot_reload:
  enabled: false
multi_tenant:
  enabled: false
audit:
  enabled: false
prompt_guard:
  enabled: false
pii:
  enabled: false
rate_limit:
  enabled: false
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    with mock.patch("mcp_bastion.config.schedule_registry_beacon") as sb:
        cfg = load_config(str(p))
        build_middleware_from_config(cfg)
    assert sb.called


@pytest.mark.asyncio
async def test_multi_tenant_missing_tenant_yaml_uses_base_chain(tmp_path):
    tenant_dir = tmp_path / "tenants"
    tenant_dir.mkdir()
    base = BastionConfig(
        prompt_guard=False,
        content_filter=False,
        audit=False,
        multi_tenant_enabled=True,
        multi_tenant_config_dir=str(tenant_dir),
    )
    mw = build_middleware_from_config(base)

    async def call_next(ctx):
        return {"ok": True}

    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "read", "arguments": {"path": "/etc/passwd"}}},
        request_id="r1",
        session_id="tenant:unknowncorp|s-1",
    )
    assert await mw(ctx, call_next) == {"ok": True}


@pytest.mark.asyncio
async def test_multi_tenant_reuses_cached_chain(tmp_path):
    tenant_dir = tmp_path / "tenants"
    tenant_dir.mkdir()
    (tenant_dir / "acme.yaml").write_text(
        "content_filter:\n  enabled: false\nprompt_guard:\n  enabled: false\n",
        encoding="utf-8",
    )
    base = BastionConfig(
        prompt_guard=False,
        content_filter=False,
        audit=False,
        multi_tenant_enabled=True,
        multi_tenant_config_dir=str(tenant_dir),
    )
    mw = build_middleware_from_config(base)

    async def call_next(ctx):
        return {"ok": True}

    ctx = MiddlewareContext(
        message={"method": "ping"},
        request_id="r1",
        session_id="tenant:acme|s1",
    )
    assert await mw(ctx, call_next) == {"ok": True}
    assert await mw(ctx, call_next) == {"ok": True}


def test_build_middleware_edge_auth_without_secret_warns(monkeypatch, caplog):
    monkeypatch.delenv("BASTION_EDGE_SECRET", raising=False)
    cfg = BastionConfig(
        prompt_guard=False,
        pii=False,
        rate_limit=False,
        audit=False,
        edge_auth_enabled=True,
    )
    with caplog.at_level("WARNING", logger="mcp_bastion.config"):
        build_middleware_from_config(cfg)
    assert "edge_auth" in caplog.text.lower()
