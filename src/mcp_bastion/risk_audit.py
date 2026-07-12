"""
Local MCP risk audit - map what agents can reach before enforcing policy.

Client-side only: discovers MCP client configs, over-broad tool grants, and
standing credential smells. No network, no vault, no login server.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "info"]

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Standing-credential / secret-looking keys in MCP client configs.
_SECRET_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|secret|password|bearer|"
    r"authorization|private[_-]?key|aws_secret|openai|anthropic|hf_token)"
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)^(sk-|pk-|gh[pousr]_|xox[baprs]-|AKIA|ASIA|Bearer\s+|eyJ)"
)
_ENV_REF_RE = re.compile(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^env:")

# Config filenames / relative paths commonly used by MCP hosts.
_CONFIG_CANDIDATES = (
    Path(".cursor") / "mcp.json",
    Path(".vscode") / "mcp.json",
    Path("mcp.json"),
    Path(".mcp.json"),
    Path("claude_desktop_config.json"),
)


@dataclass
class AuditFinding:
    check: str
    severity: Severity
    message: str
    path: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "check": self.check,
            "severity": self.severity,
            "message": self.message,
        }
        if self.path:
            out["path"] = self.path
        if self.detail:
            out["detail"] = self.detail
        from mcp_bastion.taxonomy import tags_for_check

        tags = tags_for_check(self.check)
        if tags:
            out["taxonomy"] = tags
        return out


@dataclass
class RiskAuditReport:
    root: str
    configs_scanned: list[str] = field(default_factory=list)
    server_count: int = 0
    findings: list[AuditFinding] = field(default_factory=list)

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

    def findings_at_or_above(self, min_severity: Severity) -> list[AuditFinding]:
        threshold = _SEVERITY_RANK[min_severity]
        return [f for f in self.findings if _SEVERITY_RANK[f.severity] >= threshold]

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "configs_scanned": list(self.configs_scanned),
            "server_count": self.server_count,
            "grade": self.grade,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
        }


def discover_mcp_config_paths(root: Path) -> list[Path]:
    """Find MCP client config files under root and common user locations."""
    found: list[Path] = []
    root = root.resolve()
    for rel in _CONFIG_CANDIDATES:
        p = root / rel
        if p.is_file():
            found.append(p)

    # Nested Cursor / VS Code project configs (one level of common dirs).
    for sub in ("apps", "packages", "services", "frontend", "backend"):
        for rel in (Path(".cursor") / "mcp.json", Path(".vscode") / "mcp.json"):
            p = root / sub / rel
            if p.is_file():
                found.append(p)

    home = Path.home()
    home_candidates = [
        home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        home / ".config" / "Claude" / "claude_desktop_config.json",
        home / ".cursor" / "mcp.json",
    ]
    for p in home_candidates:
        if p.is_file() and p not in found:
            found.append(p)

    # De-dupe while preserving order.
    seen: set[str] = set()
    unique: list[Path] = []
    for p in found:
        key = str(p.resolve())
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    return raw if isinstance(raw, dict) else None


def _iter_mcp_servers(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Return (name, server_config) pairs from common MCP config shapes."""
    servers: list[tuple[str, dict[str, Any]]] = []
    for key in ("mcpServers", "servers", "mcp"):
        block = data.get(key)
        if isinstance(block, dict):
            for name, cfg in block.items():
                if isinstance(cfg, dict):
                    servers.append((str(name), cfg))
    return servers


def _scan_mapping_for_secrets(
    mapping: dict[str, Any],
    *,
    path: str,
    prefix: str,
    findings: list[AuditFinding],
) -> None:
    if not isinstance(mapping, dict):
        return
    for key, value in mapping.items():
        k = str(key)
        loc = f"{prefix}.{k}" if prefix else k
        if isinstance(value, dict):
            _scan_mapping_for_secrets(value, path=path, prefix=loc, findings=findings)
            continue
        if isinstance(value, list):
            continue
        text = str(value) if value is not None else ""
        key_hit = bool(_SECRET_KEY_RE.search(k))
        val_hit = bool(text) and bool(_SECRET_VALUE_RE.search(text.strip()))
        if not key_hit and not val_hit:
            continue
        if _ENV_REF_RE.match(text.strip()):
            findings.append(
                AuditFinding(
                    check="credential_env_ref",
                    severity="low",
                    message="Credential referenced via environment variable (prefer short-lived secrets)",
                    path=path,
                    detail=loc,
                )
            )
            continue
        if text.strip():
            findings.append(
                AuditFinding(
                    check="standing_credential",
                    severity="high",
                    message="Possible standing credential embedded in MCP client config",
                    path=path,
                    detail=loc,
                )
            )


def _scan_server_entry(
    name: str,
    cfg: dict[str, Any],
    *,
    path: str,
    findings: list[AuditFinding],
) -> None:
    # Over-broad tool grants
    for tools_key in ("allowedTools", "tools", "toolAllowlist", "includeTools"):
        tools = cfg.get(tools_key)
        if tools == "*" or tools == ["*"]:
            findings.append(
                AuditFinding(
                    check="over_permissioned_tools",
                    severity="high",
                    message=f"Server {name!r} allows all tools (*)",
                    path=path,
                    detail=tools_key,
                )
            )
        elif isinstance(tools, list) and len(tools) > 25:
            findings.append(
                AuditFinding(
                    check="broad_tool_surface",
                    severity="medium",
                    message=f"Server {name!r} exposes a large tool list ({len(tools)} tools)",
                    path=path,
                    detail=tools_key,
                )
            )

    # Dangerous command patterns in stdio servers
    cmd = cfg.get("command")
    args = cfg.get("args") or []
    blob = " ".join([str(cmd or "")] + [str(a) for a in args if a is not None])
    if re.search(r"(?i)\b(cmd\.exe|/bin/sh|/bin/bash|powershell)\b", blob):
        findings.append(
            AuditFinding(
                check="shell_launcher",
                severity="medium",
                message=f"Server {name!r} launches via a shell interpreter",
                path=path,
                detail=blob[:200],
            )
        )
    if re.search(r"(?i)filesystem|@modelcontextprotocol/server-filesystem", blob):
        findings.append(
            AuditFinding(
                check="filesystem_server",
                severity="info",
                message=(
                    f"Server {name!r} looks like a filesystem MCP - "
                    "enable filesystem path guards in bastion.yaml"
                ),
                path=path,
                detail=blob[:200],
            )
        )

    env = cfg.get("env")
    if isinstance(env, dict):
        _scan_mapping_for_secrets(env, path=path, prefix=f"{name}.env", findings=findings)
    headers = cfg.get("headers")
    if isinstance(headers, dict):
        _scan_mapping_for_secrets(headers, path=path, prefix=f"{name}.headers", findings=findings)


def run_risk_audit(
    root: str | Path | None = None,
    *,
    extra_config_paths: list[str] | None = None,
) -> RiskAuditReport:
    """Scan local MCP client configs and return a risk report."""
    base = Path(root).resolve() if root else Path.cwd().resolve()
    paths = discover_mcp_config_paths(base)
    for extra in extra_config_paths or []:
        p = Path(extra)
        if p.is_file():
            paths.append(p.resolve())

    report = RiskAuditReport(root=str(base))
    findings: list[AuditFinding] = []

    if not paths:
        findings.append(
            AuditFinding(
                check="no_mcp_configs",
                severity="info",
                message="No MCP client config files found under the scan root or common user paths",
            )
        )

    for path in paths:
        rel = str(path)
        try:
            rel = str(path.relative_to(base)) if path.is_relative_to(base) else str(path)
        except (ValueError, AttributeError):
            rel = str(path)

        report.configs_scanned.append(rel)
        data = _load_json(path)
        if data is None:
            findings.append(
                AuditFinding(
                    check="config_parse_error",
                    severity="medium",
                    message="Could not parse MCP config as JSON object",
                    path=rel,
                )
            )
            continue

        servers = _iter_mcp_servers(data)
        report.server_count += len(servers)
        if not servers:
            findings.append(
                AuditFinding(
                    check="empty_servers",
                    severity="low",
                    message="Config file has no mcpServers / servers entries",
                    path=rel,
                )
            )
            continue

        for name, cfg in servers:
            _scan_server_entry(name, cfg, path=rel, findings=findings)

        # Top-level env-like maps
        for key in ("env", "environment"):
            block = data.get(key)
            if isinstance(block, dict):
                _scan_mapping_for_secrets(block, path=rel, prefix=key, findings=findings)

    # Process env smells for Bastion/MCP-named keys only (names - never values).
    # Ambient developer keys (e.g. OPENAI_API_KEY) are out of scope for this local surface audit.
    for env_key in sorted(os.environ):
        upper = env_key.upper()
        if not _SECRET_KEY_RE.search(env_key):
            continue
        if not (upper.startswith("MCP_") or upper.startswith("BASTION_") or "MCP_BASTION" in upper):
            continue
        findings.append(
            AuditFinding(
                check="standing_env_secret",
                severity="medium",
                message="Process environment contains a long-lived MCP/Bastion credential name",
                detail=env_key,
            )
        )

    findings.sort(key=lambda f: (-_SEVERITY_RANK[f.severity], f.check, f.path or ""))
    report.findings = findings
    return report


def format_risk_audit_text(report: RiskAuditReport) -> str:
    lines = [
        "MCP-Bastion local risk audit",
        f"Root: {report.root}",
        f"Configs scanned: {len(report.configs_scanned)}",
        f"MCP servers found: {report.server_count}",
        f"Grade: {report.grade}",
        "",
    ]
    if report.configs_scanned:
        lines.append("Configs:")
        for c in report.configs_scanned:
            lines.append(f"  - {c}")
        lines.append("")
    if not report.findings:
        lines.append("No findings - local MCP surface looks tight under heuristic checks.")
        return "\n".join(lines)
    lines.append(f"Findings ({len(report.findings)}):")
    for f in report.findings:
        loc = f" ({f.path})" if f.path else ""
        lines.append(f"  [{f.severity.upper()}] {f.check}{loc}: {f.message}")
        if f.detail:
            lines.append(f"           {f.detail}")
    lines.extend(
        [
            "",
            "Next: enable examples/bastion-filesystem-guards.yaml for path/credential denies,",
            "then mcp-bastion scan / redteam before enforcing in production.",
        ]
    )
    return "\n".join(lines)
