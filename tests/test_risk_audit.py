"""Tests for mcp-bastion audit (local MCP risk audit) and filesystem guards demo."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_bastion.cli import cmd_audit
from mcp_bastion.config import build_middleware_from_config, load_config
from mcp_bastion.errors import ArgumentGuardError, ContentFilterError, MCPBastionError
from mcp_bastion.base import MiddlewareContext
from mcp_bastion.risk_audit import format_risk_audit_text, run_risk_audit


def test_risk_audit_flags_standing_secret_and_wildcard_tools(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
                        "allowedTools": "*",
                        "env": {"OPENAI_API_KEY": "sk-proj-abcdefghijklmnopqrstuvwxyz"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    report = run_risk_audit(tmp_path, extra_config_paths=[str(cfg)])
    checks = {f.check for f in report.findings}
    assert "standing_credential" in checks
    assert "over_permissioned_tools" in checks
    assert "filesystem_server" in checks
    text = format_risk_audit_text(report)
    text.encode("ascii")
    assert "Grade:" in text


def test_risk_audit_clean_config_is_grade_a_or_info_only(tmp_path):
    cfg = tmp_path / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "docs": {
                        "command": "node",
                        "args": ["server.js"],
                        "env": {"API_TOKEN": "${DOCS_TOKEN}"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    report = run_risk_audit(tmp_path)
    assert report.server_count == 1
    assert not any(f.severity in ("critical", "high") for f in report.findings)


def test_cmd_audit_json_output(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"a": {"command": "echo"}}}), encoding="utf-8")
    out = tmp_path / "report.json"
    assert cmd_audit(str(tmp_path), output=str(out), output_format="json", fail_on="none") == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["server_count"] >= 1
    assert "grade" in data


@pytest.mark.asyncio
async def test_filesystem_guards_allow_readme_deny_env():
    root = Path(__file__).resolve().parent.parent
    cfg = load_config(str(root / "examples" / "bastion-filesystem-guards.yaml"))
    mw = build_middleware_from_config(cfg)
    assert mw is not None

    async def handler(c):
        return {"ok": True}

    async def call(path: str):
        ctx = MiddlewareContext(
            message={
                "method": "tools/call",
                "params": {"name": "read_text_file", "arguments": {"path": path}},
            },
            request_id="t",
            session_id="s",
            metadata={},
        )
        return await mw(ctx, handler)

    await call("project/README.md")
    with pytest.raises((ArgumentGuardError, ContentFilterError, MCPBastionError)):
        await call("project/.env")
    with pytest.raises((ArgumentGuardError, ContentFilterError, MCPBastionError)):
        await call("project/.git/config")
