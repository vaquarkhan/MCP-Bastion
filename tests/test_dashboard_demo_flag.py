"""Dashboard demo env: default OFF (live); opt-in via MCP_BASTION_DEMO=1."""

import sys
from pathlib import Path

import pytest

_root = Path(__file__).resolve().parents[1]
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))


def test_demo_metrics_enabled_treats_unset_as_false(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_BASTION_DEMO", raising=False)
    monkeypatch.delenv("MCP_BASTION_DEMO_LIVE", raising=False)
    monkeypatch.setattr(
        "mcp_bastion.config.load_config",
        lambda *a, **k: __import__("mcp_bastion.config", fromlist=["BastionConfig"]).BastionConfig(),
    )
    # Re-import app after clearing module-level applied flag if needed
    import dashboard.app as dash

    dash._dashboard_defaults_applied = False
    assert dash._demo_metrics_enabled() is False


def test_demo_metrics_enabled_explicit_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_BASTION_DEMO", "1")
    import dashboard.app as dash

    dash._dashboard_defaults_applied = True
    assert dash._demo_metrics_enabled() is True


def test_demo_metrics_enabled_explicit_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_BASTION_DEMO", "0")
    import dashboard.app as dash

    dash._dashboard_defaults_applied = True
    assert dash._demo_metrics_enabled() is False
