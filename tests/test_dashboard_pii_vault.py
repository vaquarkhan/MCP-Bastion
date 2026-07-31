"""Dashboard governance / Prometheus exposure for PII vault Phase 3."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

_root = Path(__file__).resolve().parents[1]
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))


def test_governance_snapshot_includes_pii_vault(tmp_path, monkeypatch):
    from mcp_bastion.config import load_config
    from dashboard import app as dash

    cfg_path = tmp_path / "bastion.yaml"
    cfg_path.write_text(
        "pii:\n  enabled: true\n"
        "pii_vault:\n  enabled: true\n  token_style: low_entropy\n  ttl_seconds: 120\n",
        encoding="utf-8",
    )
    cfg = load_config(str(cfg_path))
    with mock.patch.object(dash, "_load_demo_bastion_config", return_value=cfg):
        snap = dash._governance_config_snapshot()
    vault = snap["features"]["pii_vault"]
    assert vault["enabled"] is True
    assert vault["token_style"] == "low_entropy"
    assert vault["ttl_seconds"] == 120.0


def test_prometheus_includes_vault_counters():
    from mcp_bastion.pillars.metrics import MetricsStore
    from dashboard import app as dash

    store = MetricsStore.get()
    before_a = store.get_metrics().get("pii_vault_abstract_total", 0)
    before_h = store.get_metrics().get("pii_vault_hydrate_total", 0)
    store.record_pii_vault_abstract(2)
    store.record_pii_vault_hydrate(1)
    resp = dash.prometheus_metrics()
    text = resp.body.decode()
    assert "mcp_bastion_pii_vault_abstract_total" in text
    assert "mcp_bastion_pii_vault_hydrate_total" in text
    assert f"mcp_bastion_pii_vault_abstract_total {before_a + 2}" in text
    assert f"mcp_bastion_pii_vault_hydrate_total {before_h + 1}" in text


def test_governance_vault_off_when_disabled(tmp_path):
    from mcp_bastion.config import load_config
    from dashboard import app as dash

    cfg_path = tmp_path / "bastion.yaml"
    cfg_path.write_text("pii:\n  enabled: true\n", encoding="utf-8")
    cfg = load_config(str(cfg_path))
    with mock.patch.object(dash, "_load_demo_bastion_config", return_value=cfg):
        snap = dash._governance_config_snapshot()
    assert snap["features"]["pii_vault"]["enabled"] is False
