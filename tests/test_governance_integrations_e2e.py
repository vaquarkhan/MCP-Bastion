"""Live integration-style tests for OPA, OTLP, and Slack alert paths."""

from __future__ import annotations

import json
import logging
from unittest import mock

import pytest

from mcp_bastion import otel
from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import ExternalPolicyDeniedError
from mcp_bastion.middleware import MCPBastionMiddleware
from mcp_bastion.pillars.alerts import SlackAlertSink
from mcp_bastion.pillars.external_policy import ExternalPolicyConfig, ExternalPolicyEvaluator
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter


@pytest.fixture(autouse=True)
def _reset_otel():
    otel._tracer = None
    otel._meter = None
    otel._cw_client = None
    otel._observability_target = None
    otel._otel_init_attempted = False
    yield
    otel._tracer = None
    otel._meter = None
    otel._cw_client = None
    otel._observability_target = None
    otel._otel_init_attempted = False


def test_opa_subprocess_allow_and_deny(tmp_path):
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "bastion.rego").write_text(
        'package bastion\n\ndefault allow = false\n\nallow { input.tool == "safe_tool" }\n',
        encoding="utf-8",
    )
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="opa",
            opa_policy_dir=str(policy_dir),
            opa_query="data.bastion.allow",
            fail_closed=True,
        )
    )
    allow = mock.Mock(returncode=0, stdout="true", stderr="")
    deny = mock.Mock(returncode=0, stdout="false", stderr="")
    with mock.patch("subprocess.run", side_effect=[allow, deny]):
        ok, _ = ev.evaluate({"tool": "safe_tool"})
        assert ok is True
        ok2, reason = ev.evaluate({"tool": "danger"})
        assert ok2 is False
        assert reason


@pytest.mark.asyncio
async def test_middleware_external_policy_opa_blocks_tool(tmp_path):
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    (policy_dir / "bastion.rego").write_text(
        'package bastion\n\ndefault allow = false\n\nallow { input.tool == "allowed" }\n',
        encoding="utf-8",
    )
    ev = ExternalPolicyEvaluator(
        ExternalPolicyConfig(
            engine="opa",
            opa_policy_dir=str(policy_dir),
            opa_query="data.bastion.allow",
            fail_closed=True,
        )
    )
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        external_policy=ev,
        enable_external_policy=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_governance_attestation=False,
    )
    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "blocked_tool", "arguments": {}}},
        request_id="r1",
        session_id="s1",
    )

    async def handler(c):
        return {"ok": True}

    with mock.patch("subprocess.run", return_value=mock.Mock(returncode=0, stdout="false", stderr="")):
        with pytest.raises(ExternalPolicyDeniedError):
            await mw(ctx, handler)


def test_otel_span_recorded_with_mock_tracer():
    class FakeSpan:
        def __init__(self):
            self.attrs = {}

        def set_attribute(self, key, value):
            self.attrs[key] = value

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class FakeTracer:
        def __init__(self):
            self.last_span = None

        def start_as_current_span(self, name):
            self.last_span = FakeSpan()
            return self.last_span

    tracer = FakeTracer()
    otel._tracer = tracer
    otel._otel_init_attempted = True
    otel.record_tool_span("search", "ALLOWED", 12.5, None)
    assert tracer.last_span is not None
    assert tracer.last_span.attrs.get("mcp.tool") == "search"
    assert tracer.last_span.attrs.get("mcp.action") == "ALLOWED"


def test_slack_alert_sink_posts_json(caplog):
    caplog.set_level(logging.INFO)
    captured = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b"ok"

    def fake_urlopen(req, timeout=5):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return FakeResponse()

    with mock.patch("urllib.request.urlopen", fake_urlopen):
        sink = SlackAlertSink("https://hooks.slack.com/services/T/B/x")
        sink.send("cost", "Budget threshold", "warning", {"session": "s1"})

    assert "hooks.slack.com" in captured["url"]
    body = captured["body"]
    assert body.get("attachments") or body.get("text")
    attachment_text = body["attachments"][0]["text"] if body.get("attachments") else body.get("text", "")
    assert "Budget threshold" in attachment_text or "cost" in str(body).lower()
