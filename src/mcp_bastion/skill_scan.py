"""
Static scan of agent skill files (Markdown / SKILL.md style).

Offline, opt-in via mcp-bastion scan --skills. Reuses prompt_guard heuristics
and content_filter. No network, no ML download.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.prompt_guard import PromptGuardEngine
from mcp_bastion.static_scan import ScanFinding, _SEVERITY_RANK

Severity = Literal["critical", "high", "medium", "low", "info"]

_GRANT_RISK = {"bash", "exec", "shell", "*"}
_CRED_REF = re.compile(
    r"@[~/][\w./\\-]*(\.env|\.aws[/\\]credentials|\.ssh[/\\]|id_rsa|id_ed25519)",
    re.IGNORECASE,
)
_FRONT_MATTER = re.compile(r"\A---\s*\n(.*?)\n---\s*\n?", re.DOTALL)
_SKILL_GLOBS = ("**/SKILL.md", "**/*.skill.md", "**/skill.md")


@dataclass
class SkillScanReport:
    skill_count: int = 0
    findings: list[ScanFinding] = field(default_factory=list)

    @property
    def grade(self) -> str:
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
            "skill_count": self.skill_count,
            "grade": self.grade,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _parse_front_matter(text: str) -> tuple[dict[str, Any], str]:
    m = _FRONT_MATTER.match(text)
    if not m:
        return {}, text
    raw = m.group(1)
    body = text[m.end() :]
    meta: dict[str, Any] = {}
    # Minimal YAML-ish: key: value / key: [a, b]
    for line in raw.splitlines():
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if not key:
            continue
        if val.startswith("[") and val.endswith("]"):
            inner = val[1:-1].strip()
            items = [x.strip().strip("'\"") for x in inner.split(",") if x.strip()]
            meta[key] = items
        else:
            meta[key] = val.strip("'\"")
    return meta, body


def _allowed_tools(meta: dict[str, Any]) -> list[str]:
    for key in ("allowed-tools", "allowed_tools", "tools"):
        v = meta.get(key)
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str) and v:
            return [x.strip() for x in v.split(",") if x.strip()]
    return []


def discover_skill_files(root: str | Path) -> list[Path]:
    base = Path(root)
    if base.is_file():
        return [base]
    found: list[Path] = []
    for pattern in _SKILL_GLOBS:
        found.extend(base.glob(pattern))
    seen: set[str] = set()
    out: list[Path] = []
    for p in sorted(found):
        key = str(p.resolve())
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _scan_skill_file(
    path: Path,
    *,
    content_filter: ContentFilter,
    prompt_guard: PromptGuardEngine,
    root: Path,
) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        findings.append(
            ScanFinding(
                tool=str(path),
                check="skill_read_error",
                severity="medium",
                message=f"Could not read skill file: {e}",
            )
        )
        return findings

    meta, body = _parse_front_matter(text)
    try:
        label = str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        label = path.parent.name + "/" + path.name

    declared = str(meta.get("name") or "").strip()

    # Name-vs-directory deception
    expected = path.parent.name if path.name.lower() in ("skill.md",) else path.stem
    if expected.endswith(".skill"):
        expected = expected[: -len(".skill")]
    if declared and declared.casefold() != expected.casefold():
        findings.append(
            ScanFinding(
                tool=label,
                check="skill_name_mismatch",
                severity="high",
                message=f"Declared skill name {declared!r} does not match path {expected!r}",
            )
        )

    # Over-broad grants
    for tool in _allowed_tools(meta):
        t = tool.strip().lower()
        base = t.split("(")[0].strip()
        if base in _GRANT_RISK or any(g in t for g in ("bash", "shell", "exec")) or t.endswith("/*") or t == "*":
            findings.append(
                ScanFinding(
                    tool=label,
                    check="skill_over_broad_grant",
                    severity="high",
                    message=f"Skill grants high-risk tool access: {tool}",
                )
            )
            break

    # Credential path refs in body
    if _CRED_REF.search(body) or _CRED_REF.search(text):
        findings.append(
            ScanFinding(
                tool=label,
                check="skill_credential_ref",
                severity="high",
                message="Skill body references credential path (@.env / @~/.aws / @~/.ssh)",
            )
        )

    # Heuristic + content filter on body
    matched = prompt_guard.heuristic_match(body)
    if matched:
        findings.append(
            ScanFinding(
                tool=label,
                check="injection_heuristic",
                severity="critical",
                message="Prompt-injection pattern in skill body",
                detail=matched[:200],
            )
        )
    try:
        content_filter.check(body)
    except Exception as e:
        findings.append(
            ScanFinding(
                tool=label,
                check="content_filter",
                severity="high",
                message=str(e),
            )
        )

    # Bundled scripts/
    scripts_dir = path.parent / "scripts"
    if scripts_dir.is_dir():
        for sp in scripts_dir.rglob("*"):
            if not sp.is_file():
                continue
            if sp.suffix.lower() not in {".py", ".sh", ".js", ".ts", ".ps1", ".bash", ""}:
                continue
            try:
                stext = sp.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            try:
                content_filter.check(stext)
            except Exception as e:
                findings.append(
                    ScanFinding(
                        tool=f"{label}/scripts/{sp.name}",
                        check="content_filter",
                        severity="high",
                        message=str(e),
                    )
                )

    return findings


def scan_skills(paths: list[str] | str) -> SkillScanReport:
    """Scan one or more skill roots/files offline."""
    roots = [paths] if isinstance(paths, str) else list(paths)
    content_filter = ContentFilter(
        block_code_execution=True,
        block_file_paths=True,
        block_urls=False,
        block_secrets=True,
    )
    prompt_guard = PromptGuardEngine(fail_open=True, heuristic_fallback=True)
    prompt_guard._model = None  # type: ignore[attr-defined]

    findings: list[ScanFinding] = []
    files: list[Path] = []
    root_for: dict[str, Path] = {}
    for root_s in roots:
        root_p = Path(root_s).resolve()
        for f in discover_skill_files(root_s):
            key = str(f.resolve())
            if key in root_for:
                continue
            root_for[key] = root_p if root_p.is_dir() else root_p.parent
            files.append(f)

    for f in files:
        root = root_for[str(f.resolve())]
        findings.extend(
            _scan_skill_file(f, content_filter=content_filter, prompt_guard=prompt_guard, root=root)
        )

    findings.sort(key=lambda x: (-_SEVERITY_RANK[x.severity], x.tool, x.check))
    return SkillScanReport(skill_count=len(files), findings=findings)


def format_skill_report_text(report: SkillScanReport) -> str:
    lines = [
        "MCP-Bastion skill scan",
        f"Skills: {report.skill_count}",
        f"Grade: {report.grade}",
        "",
    ]
    if not report.findings:
        lines.append("No findings - skill files look clean under heuristic + skill checks.")
        return "\n".join(lines)
    lines.append(f"Findings ({len(report.findings)}):")
    for f in report.findings:
        lines.append(f"  [{f.severity.upper()}] {f.tool} - {f.check}: {f.message}")
        if f.detail:
            lines.append(f"           {f.detail}")
    return "\n".join(lines)
