"""Tests for FastMCP streamable-http serve helpers."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from mcp_bastion.config import BastionConfig
from mcp_bastion.serve import configure_fastmcp_http, run_streamable_http


class _FakeSettings:
    host = "127.0.0.1"
    port = 8000


class FakeMcp:
    def __init__(self) -> None:
        self.settings = _FakeSettings()
        self.run_calls: list[dict] = []

    def streamable_http_app(self):
        async def app(scope, receive, send):
            return None

        return app

    def run(self, transport: str = "stdio", mount_path=None) -> None:
        self.run_calls.append({"transport": transport, "mount_path": mount_path})


def test_configure_fastmcp_http_sets_settings():
    mcp = FakeMcp()
    configure_fastmcp_http(mcp, host="0.0.0.0", port=9090)
    assert mcp.settings.host == "0.0.0.0"
    assert mcp.settings.port == 9090


def test_run_streamable_http_without_hardening_uses_settings_not_run_kwargs(monkeypatch):
    mcp = FakeMcp()
    cfg = BastionConfig(transport_hardening_enabled=False)

    run_streamable_http(mcp, host="127.0.0.1", port=4242, config=cfg)

    assert mcp.settings.port == 4242
    assert len(mcp.run_calls) == 1
    assert mcp.run_calls[0]["transport"] == "streamable-http"
    assert "host" not in mcp.run_calls[0]
    assert "port" not in mcp.run_calls[0]


def test_run_streamable_http_with_hardening_uses_uvicorn(monkeypatch):
    mcp = FakeMcp()
    cfg = BastionConfig(transport_hardening_enabled=True)
    seen: dict = {}

    def fake_run(app, host, port, log_level):
        seen.update({"host": host, "port": port, "log_level": log_level})

    monkeypatch.setattr("uvicorn.run", fake_run)
    run_streamable_http(mcp, host="127.0.0.1", port=8888, config=cfg)
    assert seen["port"] == 8888
    assert mcp.run_calls == []


def test_configure_fastmcp_http_raises_without_settings():
    with pytest.raises(TypeError, match="no settings"):
        configure_fastmcp_http(object(), host="127.0.0.1", port=8000)


def test_llm_server_does_not_pass_host_to_fastmcp_run():
    """Regression: FastMCP.run() no longer accepts host/port (Bug A)."""
    root = Path(__file__).resolve().parent.parent
    src = (root / "examples" / "llm_server.py").read_text(encoding="utf-8")
    assert "mcp.run(transport=\"streamable-http\", host=" not in src
    assert "run_streamable_http" in src
