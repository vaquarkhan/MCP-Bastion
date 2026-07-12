"""
Compliance evidence report generator (framework-mapped audit summaries).
Does NOT claim certification - evidence to support audits only.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DISCLAIMER = (
    "This report is compliance evidence generated from MCP-Bastion audit logs. "
    "It does not constitute certification, attestation, or legal advice."
)

# Pillar names align with forensic_trace[].pillar values written by middleware.
# Use _total_events for controls that map to overall audit coverage.
# Aliases: audit/simulators may emit short names (e.g. "pii") vs middleware "pii_redaction".
PILLAR_ALIASES: dict[str, frozenset[str]] = {
    "pii_redaction": frozenset({"pii_redaction", "pii"}),
    "pii": frozenset({"pii_redaction", "pii"}),
}

FRAMEWORK_CONTROLS: dict[str, dict[str, list[str]]] = {
    "soc2": {
        "CC6.1": ["rbac", "agent_iam", "edge_auth", "tool_allowlist"],
        "CC6.6": ["prompt_guard", "content_filter", "argument_guards", "pii_redaction"],
        "CC7.2": ["_total_events", "cost_tracker"],
    },
    "iso27001": {
        "A.9.2": ["rbac", "agent_iam"],
        "A.12.4": ["_total_events"],
        "A.14.2": ["server_verification", "prompt_guard"],
    },
    "gdpr": {
        "Art32": ["pii_redaction", "_total_events", "edge_auth"],
        "Art25": ["pii_redaction", "content_filter", "output_budget"],
    },
    "nist_ai_rmf": {
        "MAP-1": ["prompt_guard", "semantic_firewall", "sensitive_classifier"],
        "MANAGE-2": ["cost_tracker", "rate_limit", "auto_repave"],
    },
}


def _parse_jsonl_line(line: str) -> dict[str, Any] | None:
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def _parse_utc_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _in_date_range(ts: str, start: str | None, end: str | None) -> bool:
    dt = _parse_utc_datetime(ts)
    if dt is None:
        return True
    if start:
        start_dt = _parse_utc_datetime(start)
        if start_dt is not None and dt < start_dt:
            return False
    if end:
        end_dt = _parse_utc_datetime(end)
        if end_dt is not None and dt > end_dt:
            return False
    return True


def _pillars_from_entry(entry: dict[str, Any]) -> list[str]:
    names: list[str] = []
    trace = entry.get("forensic_trace")
    if isinstance(trace, list):
        for item in trace:
            if isinstance(item, dict) and item.get("pillar"):
                names.append(str(item["pillar"]))
    if names:
        return names
    legacy = entry.get("pillar")
    if legacy:
        return [str(legacy)]
    return [str(entry.get("kind", entry.get("reason", "other")))]


def summarize_audit_log(
    path: str | Path,
    *,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict[str, Any]:
    p = Path(path)
    kinds: Counter[str] = Counter()
    pillars: Counter[str] = Counter()
    total = 0
    blocked = 0
    if p.is_file():
        for line in p.read_text(encoding="utf-8").splitlines():
            entry = _parse_jsonl_line(line)
            if not entry:
                continue
            ts = str(entry.get("timestamp", entry.get("ts", "")))
            if not _in_date_range(ts, date_from, date_to):
                continue
            total += 1
            action = str(entry.get("action", "")).upper()
            if action == "BLOCKED":
                blocked += 1
            kind = str(entry.get("kind", entry.get("reason", "other")))
            kinds[kind] += 1
            for pname in _pillars_from_entry(entry):
                pillars[pname] += 1
    return {
        "total_events": total,
        "blocked_events": blocked,
        "kinds": dict(kinds),
        "pillars": dict(pillars),
    }


def _pillar_event_count(summary: dict[str, Any], pillar_name: str) -> int:
    if pillar_name == "_total_events":
        return int(summary["total_events"])
    aliases = PILLAR_ALIASES.get(pillar_name, frozenset({pillar_name}))
    pillars = summary.get("pillars") or {}
    return sum(int(pillars.get(alias, 0)) for alias in aliases)


def generate_report_markdown(
    *,
    framework: str,
    audit_path: str | Path,
    date_from: str | None = None,
    date_to: str | None = None,
    version: str = "unknown",
) -> str:
    fw = framework.lower().replace(" ", "_").replace("-", "_")
    controls = FRAMEWORK_CONTROLS.get(fw, {})
    summary = summarize_audit_log(audit_path, date_from=date_from, date_to=date_to)
    lines = [
        "# MCP-Bastion Compliance Evidence Report",
        "",
        f"**Framework:** {framework.upper()}",
        f"**Package version:** {version}",
        f"**Period:** {date_from or 'start'} to {date_to or 'end'}",
        "",
        f"> {DISCLAIMER}",
        "",
        "## Audit summary",
        "",
        f"- Total events: {summary['total_events']}",
        f"- Blocked events: {summary['blocked_events']}",
        "",
        "### Events by kind",
        "",
    ]
    for k, v in sorted(summary["kinds"].items()):
        lines.append(f"- {k}: {v}")
    lines.extend(["", "## Control mapping", ""])
    for control_id, pillar_names in controls.items():
        lines.append(f"### {control_id}")
        for pname in pillar_names:
            count = _pillar_event_count(summary, pname)
            label = "all audit events" if pname == "_total_events" else pname
            lines.append(f"- **{label}**: {count} related audit events")
        lines.append("")
    return "\n".join(lines)
