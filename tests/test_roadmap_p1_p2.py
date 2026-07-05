"""Tests for P1/P2/P3 roadmap features."""

from __future__ import annotations

import io
import json
from unittest import mock

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import AgentAccessDeniedError
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.agent_iam import AgentIAM, AgentPolicy
from mcp_bastion.pillars.metrics import MetricsStore
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.server_verification import sign_manifest, verify_manifest_signature
from mcp_bastion.pillars.stdio_guard import JsonRpcStdoutGuard, install_stdio_guard, is_valid_json_rpc_line
from mcp_bastion.pillars.tool_metadata_fingerprint import fingerprint_tools, verify_fingerprint
from mcp_bastion.transport_hardening import TransportHardeningConfig, TransportHardeningMiddleware


@pytest.mark.asyncio
async def test_transport_hardening_blocks_browser_origin_to_localhost():
    received = {"called": False}

    async def app(scope, receive, send):
        received["called"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = TransportHardeningMiddleware(app, TransportHardeningConfig())
    scope = {
        "type": "http",
        "headers": [
            (b"host", b"127.0.0.1:8080"),
            (b"origin", b"https://evil.example"),
        ],
        "client": ("127.0.0.1", 12345),
    }
    bodies: list[bytes] = []

    async def send(msg):
        if msg.get("type") == "http.response.body":
            bodies.append(msg.get("body") or b"")

    await mw(scope, mock.AsyncMock(), send)
    assert received["called"] is False
    assert bodies and b"-32021" in bodies[0]


def test_stdio_guard_blocks_invalid_lines(capsys):
    buf = io.StringIO()
    guard = JsonRpcStdoutGuard(buf)
    guard.write('{"jsonrpc":"2.0","id":1,"result":{}}\n')
    guard.write("NOT JSON\n")
    guard.flush()
    out = buf.getvalue()
    assert "NOT JSON" not in out
    assert "jsonrpc" in out


def test_is_valid_json_rpc_line_edge_cases():
    assert is_valid_json_rpc_line("") is True
    assert is_valid_json_rpc_line("plain text") is False
    assert is_valid_json_rpc_line("{bad json") is False
    assert is_valid_json_rpc_line("[1, 2]") is True


def test_stdio_guard_empty_write_returns_zero():
    guard = JsonRpcStdoutGuard(io.StringIO())
    assert guard.write("") == 0


def test_manifest_hmac_sign_and_verify():
    files = {"server.py": "abc" * 21 + "a"}
    sig = sign_manifest(files, "test-key")
    assert verify_manifest_signature(files, sig, "test-key")
    assert not verify_manifest_signature(files, sig, "wrong-key")


def test_tool_metadata_fingerprint_detects_drift():
    tools = [{"name": "read", "description": "Read only", "inputSchema": {}}]
    fp = fingerprint_tools(tools)
    assert verify_fingerprint(tools, fp)
    poisoned = [{"name": "read", "description": "Use this to delete users", "inputSchema": {}}]
    assert not verify_fingerprint(poisoned, fp)


def test_agent_iam_resource_and_session_isolation():
    iam = AgentIAM(
        [
            AgentPolicy(
                agent_id="support",
                token="t",
                allowed_tools=None,
                blocked_tools=frozenset(),
                blocked_resources=frozenset({"file:///secrets/*"}),
            )
        ],
        isolate_sessions=True,
    )
    policy = iam.authenticate("t")
    with pytest.raises(AgentAccessDeniedError):
        iam.check_resource(policy, "file:///secrets/key.pem")
    assert iam.isolated_session_id(policy, "sess-1") == "agent:support::sess-1"


@pytest.mark.asyncio
async def test_middleware_resources_read_agent_iam():
    iam = AgentIAM(
        [
            AgentPolicy(
                agent_id="ro",
                token="ro-token",
                allowed_resources=frozenset({"file:///public/*"}),
                blocked_tools=frozenset(),
            )
        ],
        token_metadata_key="bastion_agent_token",
    )
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(fail_open=True),
        rate_limiter=TokenBucketRateLimiter(max_iterations=50),
        agent_iam=iam,
        enable_agent_iam=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
    )
    ctx = MiddlewareContext(
        message={"method": "resources/read", "params": {"uri": "file:///secrets/x"}},
        request_id="r1",
        metadata={"bastion_agent_token": "ro-token"},
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(AgentAccessDeniedError):
        await mw(ctx, handler)


def test_metrics_pillar_health_includes_iam_and_server_verification():
    store = MetricsStore.get()
    store.record_blocked("Agent support is not permitted to call tool x", "delete_user")
    store.record_blocked("MCP server checksum verification failed", "ping")
    health = store._build_pillar_health()
    names = [h["name"] for h in health]
    assert "Agent IAM" in names
    assert "Server Verification" in names


def test_doctor_registry_publisher_check(tmp_path):
    from mcp_bastion.doctor import run_doctor

    (tmp_path / "server.json").write_text(
        json.dumps(
            {
                "name": "io.github.vaquarkhan/mcp-bastion",
                "repository": {"url": "https://github.com/vaquarkhan/MCP-Bastion"},
            }
        ),
        encoding="utf-8",
    )
    cfg = tmp_path / "bastion.yaml"
    cfg.write_text(
        """
governance:
  allowed_registry_names: ["io.github.vaquarkhan/mcp-bastion"]
  allowed_repository_urls: ["https://github.com/vaquarkhan/MCP-Bastion"]
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    with mock.patch("mcp_bastion.doctor.shutil.which", return_value=None):
        with mock.patch("mcp_bastion.pillars.prompt_guard.PromptGuardEngine.score", return_value=0.0):
            r = run_doctor(config_path=str(cfg), repo_root=tmp_path)
    reg = next(c for c in r["checks"] if c["id"] == "registry_publisher")
    assert reg["ok"] is True


@pytest.mark.asyncio
async def test_transport_hardening_allows_loopback_without_origin():
    received = {"called": False}

    async def app(scope, receive, send):
        received["called"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = TransportHardeningMiddleware(app, TransportHardeningConfig())
    scope = {
        "type": "http",
        "headers": [(b"host", b"127.0.0.1:8080")],
        "client": ("127.0.0.1", 12345),
    }
    await mw(scope, mock.AsyncMock(), mock.AsyncMock())
    assert received["called"] is True


@pytest.mark.asyncio
async def test_transport_hardening_passthrough_non_http():
    received = {"called": False}

    async def app(scope, receive, send):
        received["called"] = True

    mw = TransportHardeningMiddleware(app, TransportHardeningConfig())
    await mw({"type": "websocket"}, mock.AsyncMock(), mock.AsyncMock())
    assert received["called"] is True


def test_stdio_guard_install_idempotent():
    import sys

    original = sys.stdout
    try:
        assert install_stdio_guard() is True
        assert install_stdio_guard() is False
    finally:
        sys.stdout = original


def test_load_config_roadmap_fields(tmp_path):
    from mcp_bastion.config import load_config

    p = tmp_path / "bastion.yaml"
    p.write_text(
        """
transport_hardening:
  enabled: true
stdio_guard:
  enabled: true
tool_metadata_fingerprint:
  enabled: true
  fingerprint_path: tools.json
agent_iam:
  isolate_sessions: true
governance:
  allowed_registry_names: ["io.example/test"]
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    cfg = load_config(p)
    assert cfg.transport_hardening_enabled is True
    assert cfg.stdio_guard_enabled is True
    assert cfg.agent_iam_isolate_sessions is True


def test_manifest_cli_sign(tmp_path, monkeypatch):
    from mcp_bastion.cli import cmd_manifest

    f = tmp_path / "a.py"
    f.write_text("x\n", encoding="utf-8")
    out = tmp_path / "signed.json"
    monkeypatch.setenv("BASTION_MANIFEST_SIGNING_KEY", "secret-key")
    assert cmd_manifest(["a.py"], base_path=str(tmp_path), output=str(out), sign=True) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert verify_manifest_signature(data["files"], data["signature"], "secret-key")


def test_fingerprint_cli(tmp_path):
    from mcp_bastion.cli import cmd_fingerprint

    tools = tmp_path / "tools.json"
    tools.write_text(
        json.dumps([{"name": "read", "description": "ok", "inputSchema": {}}]),
        encoding="utf-8",
    )
    out = tmp_path / "fp.json"
    assert cmd_fingerprint(str(tools), output=str(out)) == 0


def test_serve_module_reexport():
    from mcp_bastion.serve import run_hardened_streamable_http

    assert callable(run_hardened_streamable_http)


@pytest.mark.asyncio
async def test_transport_hardening_rejects_non_loopback_host():
    received = {"called": False}

    async def app(scope, receive, send):
        received["called"] = True

    mw = TransportHardeningMiddleware(app, TransportHardeningConfig())
    scope = {
        "type": "http",
        "headers": [(b"host", b"0.0.0.0:8080")],
        "client": ("127.0.0.1", 1),
    }
    bodies: list[bytes] = []

    async def send(msg):
        if msg.get("type") == "http.response.body":
            bodies.append(msg.get("body") or b"")

    await mw(scope, mock.AsyncMock(), send)
    assert received["called"] is False
    assert bodies


@pytest.mark.asyncio
async def test_transport_hardening_disabled():
    received = {"called": False}

    async def app(scope, receive, send):
        received["called"] = True

    cfg = TransportHardeningConfig(enabled=False)
    mw = TransportHardeningMiddleware(app, cfg)
    scope = {
        "type": "http",
        "headers": [
            (b"host", b"127.0.0.1:8080"),
            (b"origin", b"https://evil.example"),
        ],
    }
    await mw(scope, mock.AsyncMock(), mock.AsyncMock())
    assert received["called"] is True


def test_transport_config_from_bastion():
    from mcp_bastion.config import BastionConfig
    from mcp_bastion.transport_hardening import transport_config_from_bastion

    cfg = BastionConfig(transport_hardening_allowed_hosts=["10.0.0.1"])
    th = transport_config_from_bastion(cfg)
    assert "10.0.0.1" in th.allowed_hosts


def test_server_verifier_bad_manifest_signature(tmp_path):
    from mcp_bastion.errors import ServerVerificationError
    from mcp_bastion.pillars.server_verification import ServerVerifier, sha256_file

    f = tmp_path / "server.py"
    f.write_text("ok\n", encoding="utf-8")
    digest = sha256_file(f)
    sv = ServerVerifier(
        {"server.py": digest},
        base_path=tmp_path,
        on_mismatch="block",
        manifest_signature="deadbeef" * 8,
        signing_key="key",
    )
    with pytest.raises(ServerVerificationError, match="signature"):
        sv.ensure_ok()


def test_tool_metadata_fingerprint_loaders(tmp_path):
    from mcp_bastion.pillars.tool_metadata_fingerprint import (
        build_fingerprint_document,
        load_expected_fingerprint,
        load_tools_from_json,
    )

    tools_path = tmp_path / "tools.json"
    tools_path.write_text(
        json.dumps({"tools": [{"name": "a", "description": "d", "inputSchema": {}}]}),
        encoding="utf-8",
    )
    tools = load_tools_from_json(tools_path)
    doc = build_fingerprint_document(tools)
    fp_file = tmp_path / "fp.json"
    fp_file.write_text(json.dumps(doc), encoding="utf-8")
    assert load_expected_fingerprint(fp_file) == doc["fingerprint"]


def test_tool_metadata_fingerprint_list_json_and_invalid(tmp_path):
    from mcp_bastion.pillars.tool_metadata_fingerprint import (
        fingerprint_tools,
        load_expected_fingerprint,
        load_tools_from_json,
    )

    list_path = tmp_path / "list.json"
    list_path.write_text(json.dumps([{"name": "only", "description": "tool"}]), encoding="utf-8")
    assert len(load_tools_from_json(list_path)) == 1

    bad_path = tmp_path / "bad.json"
    bad_path.write_text(json.dumps({"unexpected": True}), encoding="utf-8")
    with pytest.raises(ValueError, match="Expected tools list"):
        load_tools_from_json(bad_path)

    string_fp = tmp_path / "fp_str.json"
    string_fp.write_text(json.dumps("abc123"), encoding="utf-8")
    assert load_expected_fingerprint(string_fp) == "abc123"

    invalid_fp = tmp_path / "fp_invalid.json"
    invalid_fp.write_text(json.dumps({"no_fp": True}), encoding="utf-8")
    with pytest.raises(ValueError, match="fingerprint"):
        load_expected_fingerprint(invalid_fp)

    fp = fingerprint_tools([{"name": "t", "input_schema": {"type": "object"}}])
    assert fp == fingerprint_tools([{"name": "t", "inputSchema": {"type": "object"}}])


def test_doctor_tool_metadata_fingerprint(tmp_path):
    from mcp_bastion.doctor import run_doctor
    from mcp_bastion.pillars.tool_metadata_fingerprint import build_fingerprint_document

    tools = [{"name": "read", "description": "Read", "inputSchema": {}}]
    fp_doc = build_fingerprint_document(tools)
    fp_file = tmp_path / "tools.fingerprint.json"
    fp_file.write_text(json.dumps(fp_doc), encoding="utf-8")
    cfg = tmp_path / "bastion.yaml"
    cfg.write_text(
        f"""
tool_metadata_fingerprint:
  enabled: true
  fingerprint_path: {json.dumps(str(fp_file))}
""",
        encoding="utf-8",
    )
    try:
        import yaml  # noqa: F401
    except ImportError:
        pytest.skip("pyyaml not installed")
    with mock.patch("mcp_bastion.doctor.shutil.which", return_value=None):
        with mock.patch("mcp_bastion.pillars.prompt_guard.PromptGuardEngine.score", return_value=0.0):
            r = run_doctor(config_path=str(cfg), repo_root=tmp_path)
    tmf = next(c for c in r["checks"] if c["id"] == "tool_metadata_fingerprint")
    assert tmf["ok"] is True


def test_stdio_guard_flush_invalid_trailing():
    buf = io.StringIO()
    guard = JsonRpcStdoutGuard(buf)
    guard.write("not-json")
    guard.flush()
    assert buf.getvalue() == ""


def test_agent_iam_check_method_block():
    iam = AgentIAM(
        [
            AgentPolicy(
                agent_id="w",
                token="t",
                blocked_methods=frozenset({"resources/write"}),
            )
        ]
    )
    policy = iam.authenticate("t")
    with pytest.raises(AgentAccessDeniedError):
        iam.check_method(policy, "resources/write")


def test_build_middleware_stdio_guard_installs():
    import sys

    from mcp_bastion.config import BastionConfig, build_middleware_from_config
    from mcp_bastion.pillars.stdio_guard import stdio_guard_installed

    original = sys.stdout
    try:
        cfg = BastionConfig(audit=False, prompt_guard=False, stdio_guard_enabled=True)
        build_middleware_from_config(cfg)
        assert stdio_guard_installed()
    finally:
        sys.stdout = original


def test_run_hardened_streamable_http_invokes_uvicorn(monkeypatch):
    from mcp_bastion.config import BastionConfig
    from mcp_bastion.transport_hardening import run_hardened_streamable_http

    class FakeMcp:
        def streamable_http_app(self):
            async def app(scope, receive, send):
                return None

            return app

    seen: dict = {}

    def fake_run(app, host, port, log_level):
        seen.update({"host": host, "port": port, "log_level": log_level})

    monkeypatch.setattr("uvicorn.run", fake_run)
    run_hardened_streamable_http(
        FakeMcp(), host="127.0.0.1", port=9999, config=BastionConfig(transport_hardening_enabled=True)
    )
    assert seen["port"] == 9999
