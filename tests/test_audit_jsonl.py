"""Tests for JSONL audit sink and CLI tail helper."""

import json
from pathlib import Path

from mcp_bastion.audit_jsonl import AuditJsonlSink
from mcp_bastion.pillars.audit_log import AuditEntry
from mcp_bastion.pillars.alerts import make_audit_export_callback


def test_audit_jsonl_sink_writes_and_tails(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    sink = AuditJsonlSink(path)
    entry = AuditEntry(
        timestamp="2026-01-01T00:00:00Z",
        session_id="s1",
        request_id="r1",
        tool="read_file",
        action="ALLOWED",
        reason=None,
        latency_ms=1.0,
    )
    sink.write(entry)
    sink.write(
        AuditEntry(
            timestamp="2026-01-01T00:00:01Z",
            session_id="s2",
            request_id="r2",
            tool="write_file",
            action="BLOCKED",
            reason="rbac",
            latency_ms=2.0,
        )
    )
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    tailed = AuditJsonlSink.tail(path, lines=1)
    assert len(tailed) == 1
    assert tailed[0]["tool"] == "write_file"


def test_make_audit_export_callback_writes_jsonl(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    sink = AuditJsonlSink(path)
    cb = make_audit_export_callback(audit_jsonl_sink=sink)
    cb(
        AuditEntry(
            timestamp="2026-01-01T00:00:00Z",
            session_id="s1",
            request_id="r1",
            tool="t",
            action="ALLOWED",
            reason=None,
            latency_ms=0.5,
        )
    )
    data = json.loads(path.read_text(encoding="utf-8").strip())
    assert data["tool"] == "t"


def test_make_audit_export_callback_jsonl_sink_error(tmp_path: Path):
    class FailingSink:
        def write(self, _entry):
            raise OSError("disk full")

    cb = make_audit_export_callback(audit_jsonl_sink=FailingSink())
    cb(
        AuditEntry(
            timestamp="2026-01-01T00:00:00Z",
            session_id="s1",
            request_id="r1",
            tool="t",
            action="ALLOWED",
            reason=None,
            latency_ms=0.5,
        )
    )


def test_audit_jsonl_tail_missing_file():
    assert AuditJsonlSink.tail("/nonexistent/audit.jsonl") == []


def test_audit_jsonl_tail_skips_blank_and_bad_json(tmp_path: Path):
    path = tmp_path / "audit.jsonl"
    path.write_text('\n{"tool":"ok"}\n{bad json}\n', encoding="utf-8")
    rows = AuditJsonlSink.tail(path, lines=5)
    assert len(rows) == 2
    assert rows[0]["tool"] == "ok"
    assert "raw" in rows[1]
