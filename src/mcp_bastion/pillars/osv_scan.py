"""
Offline-first OSV.dev dependency CVE lookup.

Default: local DB under .osv/ only (no network).
Online querybatch is opt-in, time-boxed, fail-open with a warning.
Never blocks a scan on OSV errors. Not on the MCP request path.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

logger = logging.getLogger(__name__)

Severity = Literal["critical", "high", "medium", "low", "info"]

OSV_ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

_REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([^\s;#]+)",
)
_PKG_SPEC = re.compile(
    r"^\s*([A-Za-z0-9_@/\-.]+)\s*@?\s*([0-9][^\s]*)\s*$|"
    r"^\s*([A-Za-z0-9_@/\-.]+)\s*==\s*([^\s;#]+)",
)


@dataclass
class DepRef:
    name: str
    version: str
    ecosystem: str = "PyPI"


@dataclass
class OsvFinding:
    package: str
    version: str
    vuln_id: str
    severity: Severity
    summary: str
    ecosystem: str = "PyPI"

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "vuln_id": self.vuln_id,
            "severity": self.severity,
            "summary": self.summary,
            "ecosystem": self.ecosystem,
        }


@dataclass
class OsvReport:
    findings: list[OsvFinding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    packages_checked: int = 0
    db_used: bool = False
    online_used: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "packages_checked": self.packages_checked,
            "finding_count": len(self.findings),
            "db_used": self.db_used,
            "online_used": self.online_used,
            "warnings": list(self.warnings),
            "findings": [f.to_dict() for f in self.findings],
        }


def _parse_version_parts(v: str) -> tuple[Any, ...]:
    try:
        from packaging.version import Version

        return (0, Version(v))
    except Exception:
        parts: list[Any] = []
        for chunk in re.split(r"[.\-+]", v.strip()):
            if chunk.isdigit():
                parts.append(int(chunk))
            else:
                parts.append(chunk)
        return (1, tuple(parts))


def _ver_ge(a: str, b: str) -> bool:
    return _parse_version_parts(a) >= _parse_version_parts(b)


def _ver_lt(a: str, b: str) -> bool:
    return _parse_version_parts(a) < _parse_version_parts(b)


def is_affected(version: str, ranges: list[dict[str, Any]] | None) -> bool:
    """Return True if version is inside any OSV affected range (introduced/fixed events)."""
    if not ranges:
        return False
    for r in ranges:
        if not isinstance(r, dict):
            continue
        introduced: str | None = None
        fixed: str | None = None
        for ev in r.get("events") or []:
            if not isinstance(ev, dict):
                continue
            if "introduced" in ev:
                introduced = str(ev["introduced"])
            if "fixed" in ev:
                fixed = str(ev["fixed"])
        if introduced is None:
            continue
        # OSV uses "0" as unbounded lower bound.
        lower_ok = introduced in ("0", "0.0.0") or _ver_ge(version, introduced)
        if not lower_ok:
            continue
        if fixed is None or _ver_lt(version, fixed):
            return True
    return False


def parse_deps_file(path: str | Path, *, ecosystem: str = "PyPI") -> list[DepRef]:
    """Parse a simple requirements-style file (name==version lines)."""
    text = Path(path).read_text(encoding="utf-8")
    deps: list[DepRef] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("-"):
            continue
        m = _REQ_LINE.match(s)
        if m:
            deps.append(DepRef(name=m.group(1), version=m.group(2), ecosystem=ecosystem))
            continue
        m2 = _PKG_SPEC.match(s)
        if m2:
            name = m2.group(1) or m2.group(3)
            ver = m2.group(2) or m2.group(4)
            if name and ver:
                deps.append(DepRef(name=name, version=ver, ecosystem=ecosystem))
    return deps


def parse_dep_specs(specs: list[str], *, ecosystem: str = "PyPI") -> list[DepRef]:
    out: list[DepRef] = []
    for s in specs:
        m = _REQ_LINE.match(s)
        if m:
            out.append(DepRef(name=m.group(1), version=m.group(2), ecosystem=ecosystem))
            continue
        # name@version
        if "@" in s and "==" not in s:
            name, _, ver = s.partition("@")
            name, ver = name.strip(), ver.strip()
            if name and ver:
                out.append(DepRef(name=name, version=ver, ecosystem=ecosystem))
    return out


def _cvss_base_score(vector_or_score: str) -> float | None:
    s = (vector_or_score or "").strip()
    if not s:
        return None
    # Numeric score directly
    try:
        return float(s)
    except ValueError:
        pass
    # CVSS:3.x/... vector - estimate from severity keywords elsewhere; try trailing number
    m = re.search(r"/(\d+(?:\.\d+)?)\s*$", s)
    if m:
        try:
            return float(m.group(1))
        except ValueError:
            return None
    return None


def _severity_from_vuln(doc: dict[str, Any]) -> Severity:
    """Map OSV severity metadata to Bastion severities (no stub paths)."""
    # Prefer explicit database_specific.severity when present
    db = doc.get("database_specific")
    if isinstance(db, dict):
        sev = str(db.get("severity") or "").strip().upper()
        if sev in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE", "LOW"):
            if sev == "MODERATE":
                return "medium"
            return sev.lower()  # type: ignore[return-value]

    best: float | None = None
    for block in doc.get("severity") or []:
        if not isinstance(block, dict):
            continue
        score_raw = str(block.get("score") or "")
        upper = score_raw.upper()
        if "CRITICAL" in upper:
            return "critical"
        if "HIGH" in upper:
            return "high"
        if "MEDIUM" in upper or "MODERATE" in upper:
            return "medium"
        if "LOW" in upper:
            return "low"
        num = _cvss_base_score(score_raw)
        if num is not None:
            best = num if best is None else max(best, num)

    if best is not None:
        if best >= 9.0:
            return "critical"
        if best >= 7.0:
            return "high"
        if best >= 4.0:
            return "medium"
        return "low"

    # Default for matched OSV vulns with no severity metadata
    return "high"


def _index_local_db(db_dir: Path, ecosystem: str) -> dict[str, list[dict[str, Any]]]:
    """Map normalized package name -> list of OSV vuln JSON docs."""
    eco_dir = db_dir / ecosystem
    index: dict[str, list[dict[str, Any]]] = {}
    if not eco_dir.is_dir():
        return index
    for path in eco_dir.glob("*.json"):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(doc, dict):
            continue
        for aff in doc.get("affected") or []:
            if not isinstance(aff, dict):
                continue
            pkg = aff.get("package") or {}
            if not isinstance(pkg, dict):
                continue
            if str(pkg.get("ecosystem") or "") not in (ecosystem, f"{ecosystem}"):
                # Accept exact ecosystem match; skip others
                if pkg.get("ecosystem") and str(pkg.get("ecosystem")) != ecosystem:
                    continue
            name = str(pkg.get("name") or "").strip().lower()
            if not name:
                continue
            index.setdefault(name, []).append(doc)
    return index


def _findings_from_docs(
    dep: DepRef,
    docs: list[dict[str, Any]],
) -> list[OsvFinding]:
    findings: list[OsvFinding] = []
    seen: set[str] = set()
    for doc in docs:
        vuln_id = str(doc.get("id") or "")
        if not vuln_id or vuln_id in seen:
            continue
        affected_blocks = doc.get("affected") or []
        hit = False
        for aff in affected_blocks:
            if not isinstance(aff, dict):
                continue
            pkg = aff.get("package") or {}
            if isinstance(pkg, dict) and str(pkg.get("name") or "").lower() != dep.name.lower():
                continue
            if is_affected(dep.version, aff.get("ranges")):
                hit = True
                break
            # Also honor explicit versions list when present
            versions = aff.get("versions")
            if isinstance(versions, list) and dep.version in versions:
                hit = True
                break
        if not hit:
            continue
        seen.add(vuln_id)
        summary = str(doc.get("summary") or doc.get("details") or vuln_id)[:240]
        findings.append(
            OsvFinding(
                package=dep.name,
                version=dep.version,
                vuln_id=vuln_id,
                severity=_severity_from_vuln(doc),
                summary=summary.replace("\n", " "),
                ecosystem=dep.ecosystem,
            )
        )
    return findings


def _query_online(
    deps: list[DepRef],
    *,
    timeout_ms: int = 3000,
) -> tuple[list[list[dict[str, Any]]], str | None]:
    """Opt-in OSV querybatch. Returns (per-dep vuln docs, error warning)."""
    payload = {
        "queries": [
            {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version}
            for d in deps
        ]
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        OSV_QUERYBATCH_URL,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "mcp-bastion-osv/1.0"},
        method="POST",
    )
    timeout_s = max(0.5, timeout_ms / 1000.0)
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        return [[] for _ in deps], f"OSV online query failed ({e}); falling back to local index"
    results = body.get("results") or []
    per_dep: list[list[dict[str, Any]]] = []
    for i, _dep in enumerate(deps):
        docs: list[dict[str, Any]] = []
        if i < len(results) and isinstance(results[i], dict):
            for v in results[i].get("vulns") or []:
                if isinstance(v, dict):
                    docs.append(v)
        per_dep.append(docs)
    return per_dep, None


def refresh_osv_db(
    *,
    ecosystem: str = "PyPI",
    db_dir: str | Path = ".osv",
    timeout_s: float = 120.0,
) -> Path:
    """
    Download OSV all.zip for an ecosystem into db_dir/<ecosystem>/.
    User-run / opt-in only (mcp-bastion osv-refresh).
    """
    dest = Path(db_dir) / ecosystem
    dest.mkdir(parents=True, exist_ok=True)
    url = OSV_ZIP_URL.format(ecosystem=ecosystem)
    zip_path = dest / "all.zip"
    req = urllib.request.Request(url, headers={"User-Agent": "mcp-bastion-osv-refresh/1.0"})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp, open(zip_path, "wb") as out:
        while True:
            chunk = resp.read(1024 * 256)
            if not chunk:
                break
            out.write(chunk)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(dest)
    return dest


def scan_dependencies(
    deps: list[DepRef],
    *,
    db_dir: str | Path = ".osv",
    online: bool = False,
    timeout_ms: int = 3000,
    enabled: bool = True,
) -> OsvReport:
    """
    Match deps against local OSV dump; optional online refresh of vulns.

    enabled=False returns empty report (off by default for cost/network).
    """
    report = OsvReport()
    if not enabled:
        report.warnings.append("OSV scan disabled (osv.enabled=false)")
        return report
    if not deps:
        report.warnings.append("No dependencies to check")
        return report

    report.packages_checked = len(deps)
    root = Path(db_dir)
    by_eco: dict[str, list[DepRef]] = {}
    for d in deps:
        by_eco.setdefault(d.ecosystem, []).append(d)

    for ecosystem, group in by_eco.items():
        index = _index_local_db(root, ecosystem)
        if index:
            report.db_used = True
        else:
            report.warnings.append(
                f"No local OSV index for {ecosystem} under {root / ecosystem} "
                f"(run: mcp-bastion osv-refresh --ecosystem {ecosystem})"
            )

        online_by_dep: list[list[dict[str, Any]]] = [[] for _ in group]
        if online:
            online_by_dep, err = _query_online(group, timeout_ms=timeout_ms)
            if err:
                report.warnings.append(err)
            else:
                report.online_used = True

        for dep, online_docs in zip(group, online_by_dep):
            local_docs = index.get(dep.name.lower(), [])
            report.findings.extend(_findings_from_docs(dep, local_docs))
            if online_docs:
                report.findings.extend(_findings_from_docs(dep, online_docs))

    # De-dupe findings
    seen: set[tuple[str, str, str]] = set()
    unique: list[OsvFinding] = []
    for f in report.findings:
        key = (f.package.lower(), f.version, f.vuln_id)
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    report.findings = unique
    return report


def format_osv_report_text(report: OsvReport) -> str:
    lines = [
        "MCP-Bastion OSV dependency scan",
        f"Packages checked: {report.packages_checked}",
        f"Local DB used: {'yes' if report.db_used else 'no'}",
        f"Online used: {'yes' if report.online_used else 'no'}",
        f"Findings: {len(report.findings)}",
        "",
    ]
    for w in report.warnings:
        lines.append(f"WARNING: {w}")
    if report.warnings:
        lines.append("")
    if not report.findings:
        lines.append("No vulnerability matches in local/online OSV data.")
        return "\n".join(lines)
    lines.append("Findings:")
    for f in report.findings:
        lines.append(
            f"  [{f.severity.upper()}] {f.package}@{f.version} - {f.vuln_id}: {f.summary[:120]}"
        )
    return "\n".join(lines)
