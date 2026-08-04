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
        from mcp_bastion.taxonomy import tags_for_check

        tags = tags_for_check(self.check)
        if tags:
            out["taxonomy"] = tags
        return out


@dataclass
class ScanReport:
    tool_count: int
    fingerprint: str
    findings: list[ScanFinding] = field(default_factory=list)
    baseline_match: bool | None = None

    @property
    def grade(self) -> str:
        """Letter grade A-F from worst finding severity."""
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


def _tool_server_label(entry: dict[str, Any]) -> str | None:
    for key in ("server", "serverName", "server_name", "source"):
        val = entry.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    meta = entry.get("_meta")
    if isinstance(meta, dict):
        for key in ("server", "serverName", "server_name"):
            val = meta.get(key)
            if val is not None and str(val).strip():
                return str(val).strip()
    return None


def _find_shadow_tools(tools: list[dict[str, Any]]) -> list[ScanFinding]:
    """Flag duplicate / cross-server shadow tools (same name from 2+ sources)."""
    by_key: dict[str, list[tuple[str, str | None]]] = {}
    for entry in tools:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        key = name.casefold()
        by_key.setdefault(key, []).append((name, _tool_server_label(entry)))

    findings: list[ScanFinding] = []
    for _key, items in by_key.items():
        if len(items) < 2:
            continue
        display = items[0][0]
        servers = sorted({s for _, s in items if s})
        if len(servers) >= 2:
            detail = f"name={display!r} servers={servers!r}"
            msg = "Shadow tool: same name exposed by multiple servers"
        else:
            detail = f"name={display!r} occurrences={len(items)}"
            msg = "Duplicate tool name in catalog (possible shadow / merge conflict)"
        findings.append(
            ScanFinding(
                tool=display,
                check="shadow_tool",
                severity="high",
                message=msg,
                detail=detail,
            )
        )
    return findings


def _scan_tool_entry(
    entry: dict[str, Any],
    *,
    content_filter: ContentFilter,
    prompt_guard: PromptGuardEngine,
    schema_checks: bool = True,
    risky_names: tuple[str, ...] | list[str] | None = None,
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

    if schema_checks:
        findings.extend(_scan_input_schema(entry, name, risky_names=risky_names))

    return findings


_DEFAULT_RISKY_NAMES = ("cmd", "command", "path", "file", "url", "query", "sql", "script", "code")
_SIZE_NAMES = ("limit", "count", "n", "size", "max", "offset", "timeout")
_STRING_CONSTRAINTS = ("maxLength", "enum", "pattern", "const", "format")
_NUMBER_CONSTRAINTS = ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "enum", "const")


def _scan_props_recursive(
    props: dict[str, Any],
    *,
    tool_name: str,
    path_prefix: str,
    risky: tuple[str, ...],
    required: set[str],
    findings: list[ScanFinding],
    depth: int = 0,
) -> None:
    """Walk nested object/array schemas for weak/unbounded shapes."""
    if depth > 8:
        return
    for pname, spec in props.items():
        if not isinstance(spec, dict):
            continue
        path = f"{path_prefix}{pname}"
        pl = str(pname).lower()
        is_risky = pl in risky
        ptype = spec.get("type")

        if ptype == "string" and not any(k in spec for k in _STRING_CONSTRAINTS):
            findings.append(
                ScanFinding(
                    tool=tool_name,
                    check="unbounded_string",
                    severity="high" if is_risky else "medium",
                    message=(
                        f"Unbounded string parameter '{path}' "
                        "(no maxLength/enum/pattern)"
                    ),
                )
            )

        if ptype in ("number", "integer") and pl in _SIZE_NAMES:
            if not any(k in spec for k in _NUMBER_CONSTRAINTS):
                findings.append(
                    ScanFinding(
                        tool=tool_name,
                        check="unconstrained_numeric",
                        severity="medium",
                        message=(
                            f"Unconstrained numeric parameter '{path}' "
                            "(no minimum/maximum/enum)"
                        ),
                    )
                )

        if isinstance(ptype, str) and ptype == "object":
            nested_props = spec.get("properties")
            nested_add = spec.get("additionalProperties", True)
            if (not isinstance(nested_props, dict) or not nested_props) and nested_add is not False:
                findings.append(
                    ScanFinding(
                        tool=tool_name,
                        check="weak_schema",
                        severity="medium",
                        message=f"Object parameter '{path}' is free-form (no properties)",
                    )
                )
            elif isinstance(nested_props, dict) and nested_props:
                nested_req_raw = spec.get("required") or []
                nested_req = (
                    {str(x) for x in nested_req_raw} if isinstance(nested_req_raw, list) else set()
                )
                _scan_props_recursive(
                    nested_props,
                    tool_name=tool_name,
                    path_prefix=f"{path}.",
                    risky=risky,
                    required=nested_req,
                    findings=findings,
                    depth=depth + 1,
                )

        if isinstance(ptype, str) and ptype == "array":
            items = spec.get("items")
            if isinstance(items, dict):
                item_type = items.get("type")
                if item_type == "object":
                    item_props = items.get("properties")
                    item_add = items.get("additionalProperties", True)
                    if (not isinstance(item_props, dict) or not item_props) and item_add is not False:
                        findings.append(
                            ScanFinding(
                                tool=tool_name,
                                check="weak_schema",
                                severity="medium",
                                message=f"Array items at '{path}' are free-form objects",
                            )
                        )
                    elif isinstance(item_props, dict) and item_props:
                        item_req_raw = items.get("required") or []
                        item_req = (
                            {str(x) for x in item_req_raw}
                            if isinstance(item_req_raw, list)
                            else set()
                        )
                        _scan_props_recursive(
                            item_props,
                            tool_name=tool_name,
                            path_prefix=f"{path}[].",
                            risky=risky,
                            required=item_req,
                            findings=findings,
                            depth=depth + 1,
                        )
                elif item_type == "string" and not any(k in items for k in _STRING_CONSTRAINTS):
                    findings.append(
                        ScanFinding(
                            tool=tool_name,
                            check="unbounded_string",
                            severity="medium",
                            message=f"Unbounded string array items at '{path}'",
                        )
                    )

        # Only flag optional risky args at the top-level path segment match
        if depth == 0 and is_risky and pname not in required and str(pname) not in required:
            findings.append(
                ScanFinding(
                    tool=tool_name,
                    check="risky_arg_optional",
                    severity="low",
                    message=f"Security-relevant parameter '{pname}' is not in required[]",
                )
            )


def _scan_input_schema(
    entry: dict[str, Any],
    name: str,
    *,
    risky_names: tuple[str, ...] | list[str] | None = None,
) -> list[ScanFinding]:
    """Flag schema shapes that precede RCE-class issues (static, offline)."""
    findings: list[ScanFinding] = []
    risky = tuple(n.lower() for n in (risky_names if risky_names is not None else _DEFAULT_RISKY_NAMES))
    schema = entry.get("inputSchema") or entry.get("input_schema")

    if schema is None:
        findings.append(
            ScanFinding(
                tool=name,
                check="missing_input_schema",
                severity="medium",
                message="Tool has no inputSchema (arguments unconstrained)",
            )
        )
        return findings

    if not isinstance(schema, dict):
        findings.append(
            ScanFinding(
                tool=name,
                check="invalid_input_schema",
                severity="medium",
                message="inputSchema is not a JSON object",
            )
        )
        return findings

    props = schema.get("properties")
    if not isinstance(props, dict):
        props = {}
    required_raw = schema.get("required") or []
    required = {str(x) for x in required_raw} if isinstance(required_raw, list) else set()
    additional = schema.get("additionalProperties", True)

    if not props and additional is not False:
        findings.append(
            ScanFinding(
                tool=name,
                check="weak_schema",
                severity="medium",
                message="Tool accepts free-form arguments (no properties, additionalProperties open)",
            )
        )

    if props:
        _scan_props_recursive(
            props,
            tool_name=name,
            path_prefix="",
            risky=risky,
            required=required,
            findings=findings,
        )

    return findings


def scan_tools(
    tools: list[dict[str, Any]],
    *,
    baseline_fingerprint: str | None = None,
    extra_heuristic_patterns: list[str] | None = None,
    denylist_patterns: list[str] | None = None,
    schema_checks: bool = True,
    risky_names: tuple[str, ...] | list[str] | None = None,
) -> ScanReport:
    """
    Scan a tools/list-style catalog offline.

    Uses heuristic injection detection and content_filter only (no ML, no network).
    Schema precondition checks are on by default within scan (disable with schema_checks=False).
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
                    detail=f"expected={baseline_fingerprint[:16]}... actual={fp[:16]}...",
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
    # Static scan never loads ML - heuristics only.
    prompt_guard._model = None  # type: ignore[attr-defined]

    for entry in tools:
        if not isinstance(entry, dict):
            continue
        findings.extend(
            _scan_tool_entry(
                entry,
                content_filter=content_filter,
                prompt_guard=prompt_guard,
                schema_checks=schema_checks,
                risky_names=risky_names,
            )
        )

    findings.extend(_find_homoglyph_pairs(tools))
    findings.extend(_find_shadow_tools(tools))
    findings.sort(key=lambda f: (-_SEVERITY_RANK[f.severity], f.tool, f.check))
    return ScanReport(tool_count=len(tools), fingerprint=fp, findings=findings, baseline_match=baseline_match)


def scan_tools_file(
    path: str,
    *,
    baseline_path: str | None = None,
    extra_heuristic_patterns: list[str] | None = None,
    denylist_patterns: list[str] | None = None,
    schema_checks: bool = True,
    risky_names: tuple[str, ...] | list[str] | None = None,
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
        schema_checks=schema_checks,
        risky_names=risky_names,
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
        lines.append("No findings - catalog looks clean under heuristic, content, and schema checks.")
        return "\n".join(lines)
    lines.append(f"Findings ({len(report.findings)}):")
    for f in report.findings:
        tax = ""
        try:
            from mcp_bastion.taxonomy import tags_for_check

            tags = tags_for_check(f.check)
            if tags.get("asi"):
                tax = f" [{', '.join(tags['asi'])}]"
        except Exception:
            tax = ""
        lines.append(f"  [{f.severity.upper()}] {f.tool} - {f.check}: {f.message}{tax}")
        if f.detail:
            lines.append(f"           {f.detail}")
    return "\n".join(lines)
