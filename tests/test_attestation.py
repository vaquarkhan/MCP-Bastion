"""Tests for governance attestation export and CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.cli import cmd_attest_export, main
from mcp_bastion.errors import CostPolicyApprovalRequiredError
from mcp_bastion.pillars.cost_policy import CostPolicyEngine, CostPolicyRule
from mcp_bastion.pillars.cost_tracker import CostTracker
from mcp_bastion.pillars.governance_attestation import (
    build_session_attestation,
    export_session_attestation,
    policy_version_hash,
    sign_attestation,
)
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.session_governance import SessionGovernanceRecorder
from mcp_bastion.middleware import MCPBastionMiddleware


@pytest.fixture(autouse=True)
def _reset_governance():
    SessionGovernanceRecorder.reset()
    yield
    SessionGovernanceRecorder.reset()


def test_policy_version_hash_from_config_file(tmp_path):
    cfg = tmp_path / "bastion.yaml"
    cfg.write_text("prompt_guard:\n  enabled: true\n", encoding="utf-8")
    h1 = policy_version_hash(cfg)
    h2 = policy_version_hash(cfg)
    assert len(h1) == 64
    assert h1 == h2


def test_build_session_attestation_includes_events():
    rec = SessionGovernanceRecorder.get()
    rec.record(
        session_id="sess-1",
        request_id="r1",
        method="tools/call",
        tool="search",
        pillar="handler",
        status="allowed",
        cost_usd=0.05,
    )
    rec.record(
        session_id="sess-1",
        request_id="r2",
        method="tools/call",
        tool="delete",
        pillar="rbac",
        status="blocked",
        cost_usd=0.0,
    )
    doc = build_session_attestation("sess-1", principal_id="agent:bot", tenant_id="t1")
    assert doc["session_id"] == "sess-1"
    assert doc["summary"]["total_events"] == 2
    assert doc["summary"]["blocked_count"] == 1
    assert doc["summary"]["allowed_count"] == 1
    assert "rbac" in doc["summary"]["pillars_fired"]
    assert doc["attestation_version"] == "1.0.0"


def test_sign_attestation_hmac():
    payload = {"session_id": "s", "summary": {"total_events": 0}}
    sig = sign_attestation(payload, "test-secret")
    assert isinstance(sig, str) and len(sig) == 64


def test_export_session_attestation_sign_requires_key(monkeypatch):
    monkeypatch.delenv("BASTION_MANIFEST_SIGNING_KEY", raising=False)
    with pytest.raises(ValueError, match="BASTION_MANIFEST_SIGNING_KEY"):
        export_session_attestation("s1", sign=True)


def test_export_session_attestation_signed(monkeypatch):
    monkeypatch.setenv("BASTION_MANIFEST_SIGNING_KEY", "attest-key")
    doc = export_session_attestation("s1", sign=True)
    assert doc["signature_algorithm"] == "hmac-sha256"
    assert doc["signature"]


@pytest.mark.asyncio
async def test_middleware_records_governance_for_attestation():
    ct = CostTracker(max_cost_per_session=1.0)
    policy = CostPolicyEngine(rules=[CostPolicyRule(session_spend_pct_gte=99, action="require_approval")])
    mw = MCPBastionMiddleware(
        prompt_guard=PromptGuardEngine(),
        rate_limiter=TokenBucketRateLimiter(max_iterations=100),
        cost_tracker=ct,
        cost_policy=policy,
        enable_cost_tracker=True,
        enable_cost_policy=True,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_governance_attestation=True,
    )
    ct.record(0.99, session_id="gov-s", principal_id="anonymous:default", tenant_id="default")

    ctx = MiddlewareContext(
        message={"method": "tools/call", "params": {"name": "x", "arguments": {}}},
        request_id="r-block",
        session_id="gov-s",
        metadata={"cost": 0.01},
    )

    async def handler(c):
        return {"ok": True}

    with pytest.raises(CostPolicyApprovalRequiredError):
        await mw(ctx, handler)

    events = SessionGovernanceRecorder.get().events_for_session("gov-s")
    assert len(events) >= 1
    assert any(e["status"] == "blocked" and e["pillar"] == "cost_policy" for e in events)


def test_cli_attest_export_stdout(tmp_path, caplog, monkeypatch):
    rec = SessionGovernanceRecorder.get()
    rec.record(
        session_id="cli-s",
        request_id="r1",
        method="tools/call",
        tool="t",
        pillar="handler",
        status="allowed",
        cost_usd=0.1,
    )
    cfg = tmp_path / "bastion.yaml"
    cfg.write_text("prompt_guard:\n  enabled: false\n", encoding="utf-8")
    import logging

    caplog.set_level(logging.INFO)
    rc = cmd_attest_export(
        session_id="cli-s",
        config_path=str(cfg),
        output=None,
        sign=False,
        principal_id=None,
        tenant_id=None,
    )
    assert rc == 0
    assert "cli-s" in caplog.text


def test_cli_attest_export_writes_file(tmp_path):
    SessionGovernanceRecorder.get().record(
        session_id="out-s",
        request_id="r1",
        method="tools/call",
        tool="t",
        pillar="handler",
        status="allowed",
    )
    out = tmp_path / "attest.json"
    rc = cmd_attest_export(
        session_id="out-s",
        config_path=None,
        output=str(out),
        sign=False,
        principal_id=None,
        tenant_id=None,
    )
    assert rc == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["session_id"] == "out-s"


def test_cli_attest_subcommand_parses(monkeypatch, caplog):
    SessionGovernanceRecorder.get().record(
        session_id="parse-s",
        request_id="r1",
        method="tools/call",
        tool="t",
        pillar="handler",
        status="allowed",
    )
    monkeypatch.setattr(sys, "argv", ["mcp-bastion", "attest", "export", "--session", "parse-s"])
    import logging

    caplog.set_level(logging.INFO)
    rc = main()
    assert rc == 0
    assert "parse-s" in caplog.text
