"""Tests for mcp-bastion tail CLI."""

import logging
from pathlib import Path

from mcp_bastion.cli import cmd_tail, logger


def _reset_cli_logger() -> None:
    logger.handlers.clear()


def test_cmd_tail_reads_path(tmp_path: Path, caplog):
    _reset_cli_logger()
    audit = tmp_path / "audit.jsonl"
    audit.write_text('{"tool":"a","action":"ALLOWED"}\n', encoding="utf-8")
    with caplog.at_level(logging.INFO, logger="mcp_bastion.cli"):
        rc = cmd_tail(str(audit), lines=5, config_path=None)
    assert rc == 0
    assert "a" in caplog.text


def test_cmd_tail_missing_path_returns_error(caplog):
    _reset_cli_logger()
    with caplog.at_level(logging.ERROR, logger="mcp_bastion.cli"):
        rc = cmd_tail(None, lines=5, config_path=None)
    assert rc == 1
    assert caplog.text
