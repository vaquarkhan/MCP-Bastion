"""Dashboard demo env: unset MCP_BASTION_DEMO must mean demo ON (seed), not off."""

import sys
from pathlib import Path

import pytest

_root = Path(__file__).resolve().parents[1]
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))


def test_demo_metrics_enabled_treats_unset_as_true(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MCP_BASTION_DEMO", raising=False)
    from dashboard import app as dash

    assert dash._demo_metrics_enabled() is True


def test_demo_metrics_enabled_explicit_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_BASTION_DEMO", "0")
    from dashboard import app as dash

    assert dash._demo_metrics_enabled() is False
