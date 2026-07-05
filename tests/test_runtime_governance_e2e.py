"""
End-to-end tests: bastion.yaml → build_middleware_from_config → tools/call
for Agent IAM and server cryptographic verification.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.cli import cmd_manifest
from mcp_bastion.config import build_middleware_from_config, load_config
from mcp_bastion.errors import AgentAccessDeniedError, AuthenticationError, ServerVerificationError
from mcp_bastion.pillars.server_verification import sha256_file


def _require_yaml():
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")


def _tool_call_ctx(*, tool: str, token: str | None, session: str = "e2e-session") -> MiddlewareContext:
    meta: dict = {}
    if token is not None:
        meta["bastion_agent_token"] = token
    return MiddlewareContext(
        message={"method": "tools/call", "params": {"name": tool, "arguments": {}}},
        request_id="e2e-req",
        session_id=session,
        metadata=meta,
    )


@pytest.fixture
def governance_workspace(tmp_path, monkeypatch):
    """Minimal MCP server artifact + manifest + bastion.yaml for E2E."""
    _require_yaml()

    server_py = tmp_path / "server.py"
    server_py.write_text("print('trusted build v1')\n", encoding="utf-8")
    digest = sha256_file(server_py)

    manifest_path = tmp_path / "mcp-server.manifest.json"
    manifest_path.write_text(json.dumps({"files": {"server.py": digest}}), encoding="utf-8")

    monkeypatch.setenv("BASTION_TOKEN_SUPPORT", "support-secret-e2e")
    monkeypatch.setenv("BASTION_TOKEN_ADMIN", "admin-secret-e2e")

    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        f"""
audit:
  enabled: false
prompt_guard:
  enabled: false
pii:
  enabled: false
rate_limit:
  enabled: false
agent_iam:
  enabled: true
  token_metadata_key: bastion_agent_token
  require_token: true
  agents:
    - id: customer_support_bot
      token_env: BASTION_TOKEN_SUPPORT
      allowed_tools: ["search_docs", "get_ticket_status"]
      blocked_tools: ["execute_sql", "delete_user"]
      rate_limit:
        max_iterations: 5
    - id: admin_bot
      token_env: BASTION_TOKEN_ADMIN
      allowed_tools: ["*"]
      blocked_tools: []
server_verification:
  enabled: true
  on_mismatch: block
  base_path: {json.dumps(str(tmp_path).replace(chr(92), "/"))}
  manifest_path: {json.dumps(str(manifest_path).replace(chr(92), "/"))}
""",
        encoding="utf-8",
    )

    cfg = load_config(yaml_path)
    mw = build_middleware_from_config(cfg)
    return {
        "tmp_path": tmp_path,
        "server_py": server_py,
        "manifest_path": manifest_path,
        "yaml_path": yaml_path,
        "config": cfg,
        "middleware": mw,
    }


@pytest.mark.asyncio
async def test_e2e_support_bot_allowed_tool(governance_workspace):
    mw = governance_workspace["middleware"]
    ctx = _tool_call_ctx(tool="search_docs", token="support-secret-e2e")

    async def handler(c):
        return {"content": [{"type": "text", "text": "doc hit"}]}

    result = await mw(ctx, handler)
    assert result["content"][0]["text"] == "doc hit"
    assert ctx.metadata.get("agent_id") == "customer_support_bot"


@pytest.mark.asyncio
async def test_e2e_support_bot_blocked_destructive_tool(governance_workspace):
    mw = governance_workspace["middleware"]
    ctx = _tool_call_ctx(tool="delete_user", token="support-secret-e2e")

    async def handler(c):
        return {"ok": True}

    with pytest.raises(AgentAccessDeniedError, match="delete_user"):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_e2e_support_bot_not_on_allow_list(governance_workspace):
    mw = governance_workspace["middleware"]
    ctx = _tool_call_ctx(tool="execute_sql", token="support-secret-e2e")

    async def handler(c):
        return {"ok": True}

    with pytest.raises(AgentAccessDeniedError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_e2e_admin_bot_unrestricted_tool(governance_workspace):
    mw = governance_workspace["middleware"]
    ctx = _tool_call_ctx(tool="delete_user", token="admin-secret-e2e")

    async def handler(c):
        return {"deleted": True}

    result = await mw(ctx, handler)
    assert result["deleted"] is True
    assert ctx.metadata.get("agent_id") == "admin_bot"


@pytest.mark.asyncio
async def test_e2e_missing_agent_token_rejected(governance_workspace):
    mw = governance_workspace["middleware"]
    ctx = _tool_call_ctx(tool="search_docs", token=None)

    async def handler(c):
        return {"ok": True}

    with pytest.raises(AuthenticationError, match="agent identity token"):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_e2e_tampered_server_blocked_on_tool_call(governance_workspace):
    mw = governance_workspace["middleware"]
    governance_workspace["server_py"].write_text("print('tampered')\n", encoding="utf-8")
    ctx = _tool_call_ctx(tool="search_docs", token="support-secret-e2e")

    async def handler(c):
        return {"ok": True}

    with pytest.raises(ServerVerificationError):
        await mw(ctx, handler)


@pytest.mark.asyncio
async def test_e2e_manifest_cli_then_config_verify(governance_workspace, monkeypatch, caplog):
    """CLI manifest generation feeds server_verification in a fresh config load."""
    _require_yaml()
    import logging

    tmp_path: Path = governance_workspace["tmp_path"]
    server_py: Path = governance_workspace["server_py"]
    out_manifest = tmp_path / "cli.manifest.json"

    with caplog.at_level(logging.INFO):
        rc = cmd_manifest(["server.py"], base_path=str(tmp_path), output=str(out_manifest))
    assert rc == 0
    assert out_manifest.is_file()
    payload = json.loads(out_manifest.read_text(encoding="utf-8"))
    assert "server.py" in payload["files"]

    yaml_path = tmp_path / "bastion-cli.yaml"
    yaml_path.write_text(
        f"""
audit:
  enabled: false
prompt_guard:
  enabled: false
pii:
  enabled: false
rate_limit:
  enabled: false
server_verification:
  enabled: true
  on_mismatch: block
  base_path: {json.dumps(str(tmp_path).replace(chr(92), "/"))}
  manifest_path: {json.dumps(str(out_manifest).replace(chr(92), "/"))}
""",
        encoding="utf-8",
    )
    cfg = load_config(yaml_path)
    mw = build_middleware_from_config(cfg)
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "ping", "arguments": {}}},
        request_id="r-cli",
        session_id="s-cli",
        metadata={},
    )

    async def handler(c):
        return {"pong": True}

    result = await mw(ctx, handler)
    assert result == {"pong": True}

    server_py.write_text("# mutated\n", encoding="utf-8")
    with pytest.raises(ServerVerificationError):
        await mw(ctx, handler)


def test_load_config_parses_runtime_governance_fields(tmp_path, monkeypatch):
    _require_yaml()
    monkeypatch.setenv("BASTION_TOKEN_SUPPORT", "tok")
    yaml_path = tmp_path / "bastion.yaml"
    yaml_path.write_text(
        """
agent_iam:
  enabled: true
  token_metadata_key: my_agent_token
  require_token: false
  agents:
    - id: bot_a
      token_env: BASTION_TOKEN_SUPPORT
      allowed_tools: ["read"]
server_verification:
  enabled: true
  on_mismatch: warn
  base_path: /srv/mcp
  manifest_path: manifest.json
""",
        encoding="utf-8",
    )
    cfg = load_config(yaml_path)
    assert cfg.agent_iam_enabled is True
    assert cfg.agent_iam_token_metadata_key == "my_agent_token"
    assert cfg.agent_iam_require_token is False
    assert len(cfg.agent_iam_agents) == 1
    assert cfg.server_verification_enabled is True
    assert cfg.server_verification_on_mismatch == "warn"
    assert cfg.server_verification_base_path == "/srv/mcp"
    assert cfg.server_verification_manifest_path == "manifest.json"
