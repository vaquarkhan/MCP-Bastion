"""
Compliance evidence report generator (framework-mapped audit summaries).
Does NOT claim certification - evidence to support audits only.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

DISCLAIMER = (
    "This report is compliance evidence generated from MCP-Bastion audit logs. "
    "It does not constitute certification, attestation, or legal advice."
)

# Pillar to framework control mapping (starter set)
FRAMEWORK_CONTROLS: dict[str, dict[str, list[str]]] = {
    "soc2": {
        "CC6.1": ["rbac", "agent_iam", "edge_auth", "tool_allowlist"],
        "CC6.6": ["prompt_guard", "content_filter", "argument_guards", "pii"],
        "CC7.2": ["audit", "audit_hash_chain", "telemetry"],
    },
    "iso27001": {
        "A.9.2": ["rbac", "agent_iam"],
        "A.12.4": ["audit", "audit_hash_chain"],
        "A.14.2": ["server_verification", "prompt_guard"],
    },
    "gdpr": {
        "Art32": ["pii", "audit", "edge_auth"],
        "Art25": ["pii", "content_filter", "output_budget"],
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


def _in_date_range(ts: str, start: str | None, end: str | None) -> bool:
    if not ts:
        return True
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return True
    if start:
        try:
            if dt < datetime.fromisoformat(start):
                return False
        except ValueError:
            pass
    if end:
        try:
            if dt > datetime.fromisoformat(end):
                return False
        except ValueError:
            pass
    return True


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
            pillar = str(entry.get("pillar", kind))
            pillars[pillar] += 1
    return {
        "total_events": total,
        "blocked_events": blocked,
        "kinds": dict(kinds),
        "pillars": dict(pillars),
    }


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
        f"# MCP-Bastion Compliance Evidence Report",
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
            count = summary["pillars"].get(pname, 0)
            lines.append(f"- **{pname}**: {count} related audit events")
        lines.append("")
    return "\n".join(lines)
