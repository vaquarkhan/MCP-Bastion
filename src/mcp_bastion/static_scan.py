"""
Static MCP tool-definition scanner (mcp-bastion scan).

Client-side CLI: no infra, no cloud. Reuses Bastion pillars already used at runtime
(content_filter, prompt_guard heuristics, tool_metadata_fingerprint).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.pillars.tool_metadata_fingerprint import (
    fingerprint_tools,
    load_expected_fingerprint,
    load_tools_from_json,
    verify_fingerprint,
)

Severity = Literal["critical", "high", "medium", "low", "info"]

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_HIDDEN_UNICODE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")

# Confusable normalization for homoglyph / typosquat pairs (l/1/I, o/0, etc.)
_CONFUSABLE_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "I": "l",
        "|": "l",
        "Ο": "o",
        "о": "o",
        "а": "a",
        "е": "e",
        "і": "i",
        "ρ": "p",
    }
)


def tool_metadata_scan_text(tool_dict: dict[str, Any]) -> str:
    """Flatten name, description, and input schema for static checks."""
    parts = [
        str(tool_dict.get("name") or ""),
        str(tool_dict.get("description") or ""),
    ]
    schema = tool_dict.get("inputSchema") or tool_dict.get("input_schema")
    if schema is not None:
        try:
            parts.append(json.dumps(schema, default=str))
        except (TypeError, ValueError):
            parts.append(str(schema))
    return "\n".join(parts)


def _normalize_confusable(name: str) -> str:
    return name.translate(_CONFUSABLE_TRANSLATION).casefold()


@dataclass
class ScanFinding:
    tool: str
    check: str
    severity: Severity
    message: str
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "tool": self.tool,
            "check": self.check,
            "severity": self.severity,
            "message": self.message,
        }
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class ScanReport:
    tool_count: int
    fingerprint: str
    findings: list[ScanFinding] = field(default_factory=list)
    baseline_match: bool | None = None

    @property
    def grade(self) -> str:
        """Letter grade A–F from worst finding severity."""
        if not self.findings:
            return "A"
        worst = max(_SEVERITY_RANK[f.severity] for f in self.findings)
        if worst >= _SEVERITY_RANK["critical"]:
            return "F"
        if worst >= _SEVERITY_RANK["high"]:
            return "D"
        if worst >= _SEVERITY_RANK["medium"]:
            return "C"
        if worst >= _SEVERITY_RANK["low"]:
            return "B"
        return "A"

    def findings_at_or_above(self, min_severity: Severity) -> list[ScanFinding]:
        threshold = _SEVERITY_RANK[min_severity]
        return [f for f in self.findings if _SEVERITY_RANK[f.severity] >= threshold]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_count": self.tool_count,
            "fingerprint": self.fingerprint,
            "grade": self.grade,
            "finding_count": len(self.findings),
            "baseline_match": self.baseline_match,
            "findings": [f.to_dict() for f in self.findings],
        }


def _find_homoglyph_pairs(tools: list[dict[str, Any]]) -> list[ScanFinding]:
    """Flag tool names that normalize to the same confusable form but differ literally."""
    by_norm: dict[str, list[str]] = {}
    for entry in tools:
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        norm = _normalize_confusable(name)
        by_norm.setdefault(norm, []).append(name)

    findings: list[ScanFinding] = []
    for norm, names in by_norm.items():
        unique = sorted(set(names))
        if len(unique) < 2:
            continue
        findings.append(
            ScanFinding(
                tool=unique[0],
                check="homoglyph",
                severity="high",
                message="Confusable tool name pair (possible typosquat / rug-pull)",
                detail=f"names={unique!r} normalize_to={norm!r}",
            )
        )
    return findings


def _scan_tool_entry(
    entry: dict[str, Any],
    *,
    content_filter: ContentFilter,
    prompt_guard: PromptGuardEngine,
) -> list[ScanFinding]:
    name = str(entry.get("name") or "unknown").strip() or "unknown"
    text = tool_metadata_scan_text(entry)
    findings: list[ScanFinding] = []

    if _HIDDEN_UNICODE.search(text):
        findings.append(
            ScanFinding(
                tool=name,
                check="hidden_unicode",
                severity="high",
                message="Hidden Unicode characters in tool metadata",
                detail="zero-width or bidi override characters detected",
            )
        )

    matched = prompt_guard.heuristic_match(text)
    if matched:
        findings.append(
            ScanFinding(
                tool=name,
                check="injection_heuristic",
                severity="critical",
                message="Prompt-injection pattern in tool metadata",
                detail=matched[:200],
            )
        )

    try:
        content_filter.check(text)
    except Exception as e:
        severity: Severity = "high"
        msg = str(e)
        if "credential" in msg.lower() or "api key" in msg.lower():
            severity = "critical"
        elif "file path" in msg.lower():
            severity = "medium"
        findings.append(
            ScanFinding(
                tool=name,
                check="content_filter",
                severity=severity,
                message=msg,
            )
        )

    description = str(entry.get("description") or "").strip()
    schema = entry.get("inputSchema") or entry.get("input_schema")
    if not description and schema:
        findings.append(
            ScanFinding(
                tool=name,
                check="empty_description",
                severity="low",
                message="Tool has input schema but no description (review for rug-pull)",
            )
        )

    return findings


def scan_tools(
    tools: list[dict[str, Any]],
    *,
    baseline_fingerprint: str | None = None,
    extra_heuristic_patterns: list[str] | None = None,
    denylist_patterns: list[str] | None = None,
) -> ScanReport:
    """
    Scan a tools/list-style catalog offline.

    Uses heuristic injection detection and content_filter only (no ML, no network).
    """
    fp = fingerprint_tools(tools)
    baseline_match: bool | None = None
    findings: list[ScanFinding] = []

    if baseline_fingerprint:
        baseline_match = verify_fingerprint(tools, baseline_fingerprint)
        if not baseline_match:
            findings.append(
                ScanFinding(
                    tool="*",
                    check="fingerprint_drift",
                    severity="high",
                    message="Tool catalog fingerprint does not match baseline",
                    detail=f"expected={baseline_fingerprint[:16]}… actual={fp[:16]}…",
                )
            )

    content_filter = ContentFilter(
        block_code_execution=True,
        block_file_paths=True,
        block_urls=False,
        block_secrets=True,
        denylist_patterns=denylist_patterns or [],
    )
    prompt_guard = PromptGuardEngine(
        fail_open=True,
        heuristic_fallback=True,
        heuristic_extra_patterns=extra_heuristic_patterns,
    )
    # Static scan never loads ML — heuristics only.
    prompt_guard._model = None  # type: ignore[attr-defined]

    for entry in tools:
        if not isinstance(entry, dict):
            continue
        findings.extend(
            _scan_tool_entry(entry, content_filter=content_filter, prompt_guard=prompt_guard)
        )

    findings.extend(_find_homoglyph_pairs(tools))
    findings.sort(key=lambda f: (-_SEVERITY_RANK[f.severity], f.tool, f.check))
    return ScanReport(tool_count=len(tools), fingerprint=fp, findings=findings, baseline_match=baseline_match)


def scan_tools_file(
    path: str,
    *,
    baseline_path: str | None = None,
    extra_heuristic_patterns: list[str] | None = None,
    denylist_patterns: list[str] | None = None,
) -> ScanReport:
    tools = load_tools_from_json(path)
    baseline: str | None = None
    if baseline_path:
        baseline = load_expected_fingerprint(baseline_path)
    return scan_tools(
        tools,
        baseline_fingerprint=baseline,
        extra_heuristic_patterns=extra_heuristic_patterns,
        denylist_patterns=denylist_patterns,
    )


def format_report_text(report: ScanReport) -> str:
    lines = [
        "MCP-Bastion static tool scan",
        f"Tools: {report.tool_count}",
        f"Fingerprint (sha256): {report.fingerprint}",
        f"Grade: {report.grade}",
    ]
    if report.baseline_match is not None:
        lines.append(f"Baseline match: {'yes' if report.baseline_match else 'NO'}")
    lines.append("")
    if not report.findings:
        lines.append("No findings — catalog looks clean under heuristic + content checks.")
        return "\n".join(lines)
    lines.append(f"Findings ({len(report.findings)}):")
    for f in report.findings:
        lines.append(f"  [{f.severity.upper()}] {f.tool} — {f.check}: {f.message}")
        if f.detail:
            lines.append(f"           {f.detail}")
    return "\n".join(lines)
