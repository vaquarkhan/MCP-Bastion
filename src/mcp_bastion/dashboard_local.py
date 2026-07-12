"""
Local-artifact readers for the MCP-Bastion dashboard.

Zero-infra: reads scan JSON, audit JSONL, bastion.yaml, and attestation files
from disk. No database, login, or cloud calls.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import zipfile
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_GRADE_RANK = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}

# Preferred artifact filenames under .bastion/scan/ (or MCP_BASTION_SCAN_DIR).
_SCAN_KEYS = (
    ("catalog", ("catalog.json", "scan.json", "tools-scan.json")),
    ("skills", ("skills.json", "skill-scan.json", "skills-scan.json")),
    ("osv", ("osv.json", "osv-scan.json", "dependencies.json")),
    ("risk_audit", ("risk-audit.json", "audit.json", "risk_audit.json")),
)

# Runtime pillars → framework coverage for heatmaps.
PILLAR_ASI: dict[str, list[str]] = {
    "prompt_guard": ["ASI01"],
    "pii_redaction": ["ASI06"],
    "rate_limiter": ["ASI08"],
    "circuit_breaker": ["ASI08"],
    "content_filter": ["ASI05"],
    "rbac": ["ASI03"],
    "schema_validation": ["ASI02"],
    "semantic_firewall": ["ASI01", "ASI06"],
    "sensitive_classifier": ["ASI06"],
    "external_policy": ["ASI03"],
    "replay_guard": ["ASI07"],
    "agent_iam": ["ASI03", "ASI10"],
    "server_verification": ["ASI04"],
    "transport_hardening": ["ASI07"],
    "stdio_guard": ["ASI05"],
    "tool_metadata_fingerprint": ["ASI04"],
    "cost_tracker": ["ASI02"],
    "canary": ["ASI01", "ASI09"],
}

PILLAR_LLM: dict[str, list[str]] = {
    "prompt_guard": ["LLM01"],
    "pii_redaction": ["LLM02"],
    "content_filter": ["LLM05"],
    "semantic_firewall": ["LLM01", "LLM04"],
    "sensitive_classifier": ["LLM02"],
    "rbac": ["LLM06"],
    "agent_iam": ["LLM06"],
    "cost_tracker": ["LLM10"],
    "rate_limiter": ["LLM10"],
    "server_verification": ["LLM03"],
    "tool_metadata_fingerprint": ["LLM03"],
}

PILLAR_MCP: dict[str, list[str]] = {
    "pii_redaction": ["MCP01"],
    "content_filter": ["MCP02", "MCP05"],
    "stdio_guard": ["MCP05"],
    "tool_metadata_fingerprint": ["MCP03", "MCP04"],
    "server_verification": ["MCP04", "MCP09"],
    "schema_validation": ["MCP05"],
    "agent_iam": ["MCP06", "MCP07"],
    "rbac": ["MCP06"],
    "replay_guard": ["MCP07"],
    "transport_hardening": ["MCP07"],
    "prompt_guard": ["MCP05"],
}

# Live attack categories for the attack matrix (runtime blocks).
ATTACK_KIND_META: dict[str, dict[str, Any]] = {
    "injection": {
        "label": "Prompt injection",
        "asi": ["ASI01"],
        "llm": ["LLM01"],
        "mcp": ["MCP05"],
    },
    "agent_iam": {
        "label": "Confused deputy / IAM",
        "asi": ["ASI03", "ASI10"],
        "llm": ["LLM06"],
        "mcp": ["MCP06", "MCP07"],
    },
    "server_verification": {
        "label": "Supply-chain mismatch",
        "asi": ["ASI04"],
        "llm": ["LLM03"],
        "mcp": ["MCP04", "MCP09"],
    },
    "rbac": {
        "label": "Privilege abuse",
        "asi": ["ASI03"],
        "llm": ["LLM06"],
        "mcp": ["MCP06"],
    },
    "content_filter": {
        "label": "Unsafe content / paths",
        "asi": ["ASI05"],
        "llm": ["LLM05"],
        "mcp": ["MCP02", "MCP05"],
    },
    "schema_validation": {
        "label": "Schema / tool surface",
        "asi": ["ASI02"],
        "llm": ["LLM06"],
        "mcp": ["MCP05"],
    },
    "semantic_firewall": {
        "label": "Context / memory abuse",
        "asi": ["ASI01", "ASI06"],
        "llm": ["LLM01", "LLM04"],
        "mcp": ["MCP07"],
    },
    "rate_limit": {
        "label": "Rate / cascade pressure",
        "asi": ["ASI08"],
        "llm": ["LLM10"],
        "mcp": ["MCP10"],
    },
    "circuit_breaker": {
        "label": "Upstream failure cascade",
        "asi": ["ASI08"],
        "llm": ["LLM10"],
        "mcp": ["MCP10"],
    },
    "replay": {
        "label": "Replay / session attack",
        "asi": ["ASI07"],
        "llm": ["LLM06"],
        "mcp": ["MCP07"],
    },
    "cost": {
        "label": "Cost / token abuse",
        "asi": ["ASI02"],
        "llm": ["LLM10"],
        "mcp": ["MCP10"],
    },
    "other": {
        "label": "Other policy blocks",
        "asi": [],
        "llm": [],
        "mcp": [],
    },
}


def scan_dir() -> Path:
    raw = os.environ.get("MCP_BASTION_SCAN_DIR", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.cwd() / ".bastion" / "scan").resolve()


def attest_dir() -> Path:
    raw = os.environ.get("MCP_BASTION_ATTEST_DIR", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.cwd() / ".bastion" / "attestations").resolve()


def audit_jsonl_path() -> Path:
    raw = os.environ.get("MCP_BASTION_AUDIT_PATH", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    try:
        from mcp_bastion.config import load_config

        cfg = load_config()
        p = getattr(cfg, "audit_jsonl_path", None) or ".bastion/audit.jsonl"
        return Path(str(p)).expanduser().resolve()
    except Exception:
        return (Path.cwd() / ".bastion" / "audit.jsonl").resolve()


def bastion_yaml_path() -> Path | None:
    for candidate in (
        os.environ.get("BASTION_CONFIG", "").strip(),
        "bastion.yaml",
        "bastion.yml",
    ):
        if not candidate:
            continue
        p = Path(candidate).expanduser()
        if p.is_file():
            return p.resolve()
    return None


def grade_from_severities(severities: list[str]) -> str:
    if not severities:
        return "A"
    worst = max(_SEVERITY_RANK.get(s, 0) for s in severities)
    if worst >= _SEVERITY_RANK["critical"]:
        return "F"
    if worst >= _SEVERITY_RANK["high"]:
        return "D"
    if worst >= _SEVERITY_RANK["medium"]:
        return "C"
    if worst >= _SEVERITY_RANK["low"]:
        return "B"
    return "A"


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = str(f.get("severity") or "info").lower()
        if sev in out:
            out[sev] += 1
        else:
            out["info"] += 1
    return out


def _load_json_file(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"findings": data}
    except Exception as e:
        logger.debug("Failed to read scan artifact %s: %s", path, e)
        return None


def _normalize_scan_doc(kind: str, doc: dict[str, Any], path: Path) -> dict[str, Any]:
    findings = doc.get("findings")
    if not isinstance(findings, list):
        findings = []
    findings = [f for f in findings if isinstance(f, dict)]
    try:
        from mcp_bastion.issue_guides import enrich_finding_with_guide

        findings = [enrich_finding_with_guide(f) for f in findings]
    except Exception:
        pass
    grade = doc.get("grade")
    if not isinstance(grade, str) or grade not in _GRADE_RANK:
        sevs = [str(f.get("severity") or "info") for f in findings]
        grade = grade_from_severities(sevs)
    by_sev = doc.get("by_severity") if isinstance(doc.get("by_severity"), dict) else None
    if not by_sev:
        by_sev = _count_by_severity(findings)
    mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    return {
        "kind": kind,
        "present": True,
        "path": str(path),
        "mtime": mtime,
        "grade": grade,
        "finding_count": int(doc.get("finding_count") or len(findings)),
        "by_severity": by_sev,
        "findings": findings[:100],
        "hint": None,
    }


def _empty_scan(kind: str, hint: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "present": False,
        "path": None,
        "mtime": None,
        "grade": None,
        "finding_count": 0,
        "by_severity": {},
        "findings": [],
        "hint": hint,
    }


def _pick_scan_file(root: Path, kind: str, names: tuple[str, ...]) -> Path | None:
    if not root.is_dir():
        return None
    for name in names:
        p = root / name
        if p.is_file():
            return p
    keywords = {
        "catalog": ("catalog", "tools-scan", "scan-catalog"),
        "skills": ("skill",),
        "osv": ("osv",),
        "risk_audit": ("risk", "risk-audit", "risk_audit"),
    }.get(kind, ())
    candidates: list[Path] = []
    for p in root.glob("*.json"):
        stem = p.stem.lower()
        if kind == "catalog" and any(k in stem for k in ("skill", "osv", "risk", "audit")):
            continue
        if any(k in stem for k in keywords):
            candidates.append(p)
    if not candidates:
        return None
    return max(candidates, key=lambda x: x.stat().st_mtime)


_HINTS = {
    "catalog": "No scan yet — run: mcp-bastion scan tools.json --format json -o .bastion/scan/catalog.json",
    "skills": "No skill scan yet — run: mcp-bastion scan --skills ./skills --format json -o .bastion/scan/skills.json",
    "osv": "No OSV scan yet — run: mcp-bastion osv-scan --format json -o .bastion/scan/osv.json",
    "risk_audit": "No risk audit yet — run: mcp-bastion audit --format json -o .bastion/scan/risk-audit.json",
}


def load_posture(*, demo: bool = False) -> dict[str, Any]:
    """Aggregate latest scan / skill / OSV / risk-audit grades from local JSON."""
    root = scan_dir()
    checks: dict[str, Any] = {}
    for kind, names in _SCAN_KEYS:
        path = _pick_scan_file(root, kind, names)
        if path is None:
            checks[kind] = _empty_scan(kind, _HINTS[kind])
            continue
        doc = _load_json_file(path)
        if doc is None:
            checks[kind] = _empty_scan(kind, f"Unreadable artifact: {path}")
            continue
        checks[kind] = _normalize_scan_doc(kind, doc, path)

    present = [c for c in checks.values() if c.get("present")]
    if not present and demo:
        return _enrich_posture_payload(_demo_posture())

    if present:
        worst = max(present, key=lambda c: _GRADE_RANK.get(str(c.get("grade") or "A"), 0))
        combined = worst["grade"]
    else:
        combined = None

    return _enrich_posture_payload(
        {
            "scan_dir": str(root),
            "combined_grade": combined,
            "checks": checks,
            "demo": False,
            "empty": not bool(present),
        }
    )


def _enrich_posture_payload(posture: dict[str, Any]) -> dict[str, Any]:
    """Attach PMD-style guides to any findings missing them."""
    try:
        from mcp_bastion.issue_guides import enrich_finding_with_guide
    except Exception:
        return posture
    checks = posture.get("checks") or {}
    for doc in checks.values():
        if not isinstance(doc, dict):
            continue
        findings = doc.get("findings") or []
        if not findings:
            continue
        doc["findings"] = [
            enrich_finding_with_guide(f) if isinstance(f, dict) else f for f in findings
        ]
    return posture



def _demo_posture() -> dict[str, Any]:
    """Synthetic posture when MCP_BASTION_DEMO=1 and no scan files exist."""
    return {
        "scan_dir": str(scan_dir()),
        "combined_grade": "C",
        "demo": True,
        "empty": False,
        "checks": {
            "catalog": {
                "kind": "catalog",
                "present": True,
                "path": "(demo)",
                "mtime": datetime.now(timezone.utc).isoformat(),
                "grade": "B",
                "finding_count": 2,
                "by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 1, "info": 0},
                "findings": [
                    {
                        "check": "weak_schema",
                        "severity": "medium",
                        "tool": "run_shell",
                        "message": "Demo: unbounded string arg",
                        "taxonomy": {"asi": ["ASI02"], "mcp": ["MCP05"]},
                    },
                    {
                        "check": "empty_description",
                        "severity": "low",
                        "tool": "legacy_tool",
                        "message": "Demo: missing description",
                        "taxonomy": {"asi": ["ASI04"], "mcp": ["MCP03"]},
                    },
                ],
                "hint": None,
            },
            "skills": {
                "kind": "skills",
                "present": True,
                "path": "(demo)",
                "mtime": datetime.now(timezone.utc).isoformat(),
                "grade": "C",
                "finding_count": 1,
                "by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
                "findings": [
                    {
                        "check": "skill_over_broad_grant",
                        "severity": "medium",
                        "message": "Demo: skill grants * tools",
                        "taxonomy": {"asi": ["ASI02", "ASI03"]},
                    }
                ],
                "hint": None,
            },
            "osv": {
                "kind": "osv",
                "present": True,
                "path": "(demo)",
                "mtime": datetime.now(timezone.utc).isoformat(),
                "grade": "A",
                "finding_count": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "findings": [],
                "hint": None,
            },
            "risk_audit": {
                "kind": "risk_audit",
                "present": True,
                "path": "(demo)",
                "mtime": datetime.now(timezone.utc).isoformat(),
                "grade": "D",
                "finding_count": 1,
                "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
                "findings": [
                    {
                        "check": "standing_credential",
                        "severity": "high",
                        "message": "Demo: API key in mcp.json",
                        "taxonomy": {"asi": ["ASI03"], "mcp": ["MCP01"]},
                    }
                ],
                "hint": None,
            },
        },
    }


def _enabled_pillars_from_config(cfg: Any) -> dict[str, bool]:
    return {
        "prompt_guard": bool(getattr(cfg, "prompt_guard", True)),
        "pii_redaction": bool(getattr(cfg, "pii", False)),
        "rate_limiter": bool(getattr(cfg, "rate_limit", False)),
        "circuit_breaker": bool(getattr(cfg, "circuit_breaker", False)),
        "content_filter": bool(getattr(cfg, "content_filter", False)),
        "rbac": bool(getattr(cfg, "rbac", False)),
        "schema_validation": bool(getattr(cfg, "schema_validation", False)),
        "semantic_firewall": bool(getattr(cfg, "semantic_firewall", False)),
        "sensitive_classifier": bool(getattr(cfg, "sensitive_classifier", False)),
        "external_policy": bool(getattr(cfg, "policy_engine_type", "none") not in (None, "", "none")),
        "replay_guard": bool(getattr(cfg, "replay_guard", False)),
        "agent_iam": bool(getattr(cfg, "agent_iam_enabled", False)),
        "server_verification": bool(getattr(cfg, "server_verification_enabled", False)),
        "transport_hardening": bool(getattr(cfg, "transport_hardening_enabled", True)),
        "stdio_guard": bool(getattr(cfg, "stdio_guard_enabled", False)),
        "tool_metadata_fingerprint": bool(
            getattr(cfg, "tool_metadata_fingerprint_enabled", False)
            or getattr(cfg, "tool_metadata_guard_enabled", False)
        ),
        "cost_tracker": bool(getattr(cfg, "cost_tracker", False)),
        "canary": bool(getattr(cfg, "canary_goallock_enabled", False)),
    }


def load_taxonomy_coverage(
    *,
    posture: dict[str, Any] | None = None,
    metrics: dict[str, Any] | None = None,
    config: Any | None = None,
    framework: str = "asi",
) -> dict[str, Any]:
    """Framework heatmap (asi | mcp | llm): pillar coverage + finding/block hits."""
    from mcp_bastion.taxonomy import ASI_TITLES, LLM_TITLES, MCP_TITLES, TAXONOMY

    fw = (framework or "asi").strip().lower()
    if fw in ("owasp_llm", "llm_top10"):
        fw = "llm"
    if fw in ("owasp_mcp", "mcp_top10"):
        fw = "mcp"
    if fw not in ("asi", "mcp", "llm"):
        fw = "asi"

    titles = {"asi": ASI_TITLES, "mcp": MCP_TITLES, "llm": LLM_TITLES}[fw]
    pillar_map = {"asi": PILLAR_ASI, "mcp": PILLAR_MCP, "llm": PILLAR_LLM}[fw]
    tag_key = fw

    if config is None:
        try:
            from mcp_bastion.config import load_config

            config = load_config()
        except Exception:
            config = None

    enabled = _enabled_pillars_from_config(config) if config is not None else {}
    posture = posture or load_posture()
    metrics = metrics or {}

    pillars_by_id: dict[str, list[str]] = {aid: [] for aid in titles}
    for pillar, ids in pillar_map.items():
        if not enabled.get(pillar):
            continue
        for aid in ids:
            if aid in pillars_by_id and pillar not in pillars_by_id[aid]:
                pillars_by_id[aid].append(pillar)

    finding_hits: dict[str, int] = {aid: 0 for aid in titles}
    checks_by_id: dict[str, list[str]] = {aid: [] for aid in titles}
    samples_by_id: dict[str, list[dict[str, Any]]] = {aid: [] for aid in titles}
    for check_doc in (posture.get("checks") or {}).values():
        for f in check_doc.get("findings") or []:
            if not isinstance(f, dict):
                continue
            tags = f.get("taxonomy") if isinstance(f.get("taxonomy"), dict) else None
            ids = list((tags or {}).get(tag_key) or [])
            if not ids:
                check_id = str(f.get("check") or "")
                ids = list((TAXONOMY.get(check_id) or {}).get(tag_key) or [])
            for aid in ids:
                if aid not in finding_hits:
                    continue
                finding_hits[aid] += 1
                cid = str(f.get("check") or "?")
                if cid not in checks_by_id[aid]:
                    checks_by_id[aid].append(cid)
                if len(samples_by_id[aid]) < 5:
                    samples_by_id[aid].append(
                        {
                            "check": cid,
                            "severity": f.get("severity"),
                            "message": str(f.get("message") or f.get("summary") or "")[:240],
                            "tool": f.get("tool"),
                        }
                    )

    kind_map = {
        "injection": {"asi": ["ASI01"], "llm": ["LLM01"], "mcp": ["MCP05"]},
        "agent_iam": {"asi": ["ASI03", "ASI10"], "llm": ["LLM06"], "mcp": ["MCP06"]},
        "server_verification": {"asi": ["ASI04"], "llm": ["LLM03"], "mcp": ["MCP04"]},
        "rbac": {"asi": ["ASI03"], "llm": ["LLM06"], "mcp": ["MCP06"]},
        "content_filter": {"asi": ["ASI05"], "llm": ["LLM05"], "mcp": ["MCP02"]},
        "schema_validation": {"asi": ["ASI02"], "llm": ["LLM06"], "mcp": ["MCP05"]},
        "semantic_firewall": {"asi": ["ASI01", "ASI06"], "llm": ["LLM01"], "mcp": ["MCP07"]},
        "rate_limit": {"asi": ["ASI08"], "llm": ["LLM10"], "mcp": ["MCP10"]},
        "circuit_breaker": {"asi": ["ASI08"], "llm": ["LLM10"], "mcp": ["MCP10"]},
        "replay": {"asi": ["ASI07"], "llm": ["LLM06"], "mcp": ["MCP07"]},
        "cost": {"asi": ["ASI02"], "llm": ["LLM10"], "mcp": ["MCP10"]},
    }
    block_hits: dict[str, int] = {aid: 0 for aid in titles}
    for kind, n in (metrics.get("blocked_by_kind") or {}).items():
        for aid in (kind_map.get(str(kind)) or {}).get(fw, []):
            if aid in block_hits:
                block_hits[aid] += int(n or 0)

    cells = []
    for aid, title in titles.items():
        pillars = pillars_by_id.get(aid) or []
        fh = finding_hits.get(aid, 0)
        bh = block_hits.get(aid, 0)
        if fh > 0 or bh > 0:
            status = "findings"
        elif pillars:
            status = "covered"
        else:
            status = "unaddressed"
        cells.append(
            {
                "id": aid,
                "title": title,
                "status": status,
                "pillars": pillars,
                "checks": checks_by_id.get(aid) or [],
                "finding_hits": fh,
                "block_hits": bh,
                "samples": samples_by_id.get(aid) or [],
            }
        )

    return {
        "framework": fw,
        "frameworks": ["asi", "mcp", "llm"],
        "cells": cells,
        "enabled_pillars": {k: v for k, v in enabled.items() if v},
        "demo": bool(posture.get("demo")),
    }


def load_attack_matrix(
    *,
    metrics: dict[str, Any] | None = None,
    posture: dict[str, Any] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict[str, Any]:
    """Live attack matrix: categories under pressure from blocks + pre-deploy findings."""
    metrics = metrics or {}
    posture = posture or {}
    incidents = _filter_incidents_by_date(
        list(metrics.get("blocked_incidents") or []),
        date_from=date_from,
        date_to=date_to,
    )
    kinds = dict(metrics.get("blocked_by_kind") or {})
    # Prefer filtered incident counts when a date window is set.
    if date_from or date_to:
        kinds = {}
        for row in incidents:
            k = str(row.get("kind") or "other")
            kinds[k] = kinds.get(k, 0) + 1

    total_blocks = sum(int(v or 0) for v in kinds.values()) or 0
    rows = []
    for kind, meta in ATTACK_KIND_META.items():
        count = int(kinds.get(kind, 0) or 0)
        samples = [r for r in incidents if str(r.get("kind") or "") == kind][:5]
        tools: dict[str, int] = {}
        last_seen = None
        for s in samples:
            t = str(s.get("tool") or "unknown")
            tools[t] = tools.get(t, 0) + 1
            ts = s.get("ts")
            if ts and (last_seen is None or str(ts) > str(last_seen)):
                last_seen = ts
        # Intensity: quiet / watch / active / hot
        if count <= 0:
            intensity = "quiet"
        elif total_blocks and count / total_blocks >= 0.35:
            intensity = "hot"
        elif count >= 10:
            intensity = "active"
        else:
            intensity = "watch"
        top_tool = max(tools.items(), key=lambda x: x[1])[0] if tools else None
        rows.append(
            {
                "kind": kind,
                "label": meta["label"],
                "count": count,
                "share_pct": round(100.0 * count / total_blocks, 1) if total_blocks else 0.0,
                "intensity": intensity,
                "top_tool": top_tool,
                "last_seen": last_seen,
                "asi": meta.get("asi") or [],
                "llm": meta.get("llm") or [],
                "mcp": meta.get("mcp") or [],
                "samples": [
                    {
                        "ts": s.get("ts"),
                        "tool": s.get("tool"),
                        "agent_id": s.get("agent_id"),
                        "reason": str(s.get("reason") or "")[:240],
                        "pillar": s.get("pillar"),
                        "rule": s.get("rule"),
                        "trace_id": s.get("trace_id"),
                        "request_id": s.get("request_id"),
                        "forensic_trace": s.get("forensic_trace") or [],
                    }
                    for s in samples
                ],
            }
        )

    # Pre-deploy finding pressure (not live attacks, but vulnerability exposure).
    finding_pressure = []
    for check_doc in (posture.get("checks") or {}).values():
        if not check_doc.get("present"):
            continue
        for f in check_doc.get("findings") or []:
            if not isinstance(f, dict):
                continue
            finding_pressure.append(
                {
                    "source": check_doc.get("kind"),
                    "check": f.get("check"),
                    "severity": f.get("severity"),
                    "message": str(f.get("message") or f.get("summary") or "")[:240],
                    "tool": f.get("tool"),
                    "taxonomy": f.get("taxonomy") or {},
                }
            )

    active = [r for r in rows if r["count"] > 0]
    active.sort(key=lambda r: -r["count"])
    rows.sort(key=lambda r: (-r["count"], r["label"]))
    return {
        "date_from": date_from,
        "date_to": date_to,
        "total_blocks": total_blocks,
        "active_categories": len(active),
        "rows": rows,
        "finding_pressure": finding_pressure[:40],
        "headline": (
            f"{len(active)} attack categor{'y' if len(active) == 1 else 'ies'} under pressure"
            if active
            else "No live attack pressure in this window"
        ),
    }


def _parse_day(value: str | None) -> str | None:
    if not value:
        return None
    s = str(value).strip()
    if len(s) >= 10:
        return s[:10]
    return None


def _filter_incidents_by_date(
    incidents: list[Any],
    *,
    date_from: str | None = None,
    date_to: str | None = None,
) -> list[dict[str, Any]]:
    df = _parse_day(date_from)
    dt = _parse_day(date_to)
    out: list[dict[str, Any]] = []
    for row in incidents:
        if not isinstance(row, dict):
            continue
        day = _parse_day(str(row.get("ts") or ""))
        if not day:
            if not df and not dt:
                out.append(row)
            continue
        if df and day < df:
            continue
        if dt and day > dt:
            continue
        out.append(row)
    return out


def report_frameworks() -> list[dict[str, str]]:
    return [
        {"id": "soc2", "label": "SOC 2 (evidence)"},
        {"id": "gdpr", "label": "GDPR (evidence)"},
        {"id": "iso27001", "label": "ISO 27001 (evidence)"},
        {"id": "nist_ai_rmf", "label": "NIST AI RMF (evidence)"},
        {"id": "asi", "label": "OWASP ASI Top 10 (evidence)"},
    ]


def _file_sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _latest_attestation(root: Path) -> Path | None:
    if not root.is_dir():
        return None
    files = list(root.glob("*.json"))
    if not files:
        return None
    return max(files, key=lambda p: p.stat().st_mtime)


def load_compliance() -> dict[str, Any]:
    """Last attestation metadata + policy hash from local files."""
    root = attest_dir()
    yaml_path = bastion_yaml_path()
    policy_hash = _file_sha256(yaml_path) if yaml_path else None
    att_path = _latest_attestation(root)
    attestation: dict[str, Any] | None = None
    if att_path is not None:
        doc = _load_json_file(att_path)
        if doc:
            policy = doc.get("policy") if isinstance(doc.get("policy"), dict) else {}
            summary = doc.get("summary") if isinstance(doc.get("summary"), dict) else {}
            attestation = {
                "path": str(att_path),
                "generated_at": doc.get("generated_at"),
                "session_id": doc.get("session_id"),
                "attestation_hash": _file_sha256(att_path),
                "policy_hash": policy.get("policy_hash") or policy_hash,
                "pillars_fired": summary.get("pillars_fired") or [],
                "blocked_count": summary.get("blocked_count"),
                "allowed_count": summary.get("allowed_count"),
                "signed": bool(doc.get("signature")),
            }

    return {
        "disclaimer": (
            "Evidence to support an audit, not a certificate. "
            "MCP-Bastion exports local proof artifacts; it does not certify SOC2/GDPR compliance."
        ),
        "attest_dir": str(root),
        "bastion_yaml": str(yaml_path) if yaml_path else None,
        "policy_hash": policy_hash,
        "attestation": attestation,
        "audit_jsonl": str(audit_jsonl_path()),
        "audit_jsonl_exists": audit_jsonl_path().is_file(),
        "frameworks": report_frameworks(),
    }


def generate_compliance_report_markdown(
    framework: str = "soc2",
    *,
    date_from: str | None = None,
    date_to: str | None = None,
) -> str:
    from mcp_bastion.pillars.compliance_report import generate_report_markdown

    try:
        from mcp_bastion import __version__ as ver
    except Exception:
        ver = "unknown"
    return generate_report_markdown(
        framework=framework,
        audit_path=audit_jsonl_path(),
        date_from=date_from,
        date_to=date_to,
        version=str(ver),
    )


def build_evidence_bundle_zip(
    framework: str = "soc2",
    *,
    date_from: str | None = None,
    date_to: str | None = None,
) -> bytes:
    """Zip attestation (if any) + compliance report + bastion.yaml hash note."""
    buf = BytesIO()
    comp = load_compliance()
    report_md = generate_compliance_report_markdown(
        framework=framework, date_from=date_from, date_to=date_to
    )
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"compliance-{framework}.md", report_md)
        zf.writestr(
            "README.txt",
            (
                "MCP-Bastion evidence bundle\n"
                "Evidence to support an audit, not a certificate.\n"
                f"Generated: {datetime.now(timezone.utc).isoformat()}\n"
                f"Framework: {framework}\n"
                f"Period: {date_from or 'start'} to {date_to or 'end'}\n"
                f"Policy hash: {comp.get('policy_hash') or 'n/a'}\n"
            ),
        )
        meta = {
            "policy_hash": comp.get("policy_hash"),
            "bastion_yaml": comp.get("bastion_yaml"),
            "attestation": comp.get("attestation"),
            "disclaimer": comp.get("disclaimer"),
            "framework": framework,
            "date_from": date_from,
            "date_to": date_to,
            "frameworks": report_frameworks(),
        }
        zf.writestr("manifest.json", json.dumps(meta, indent=2))
        att = comp.get("attestation")
        if isinstance(att, dict) and att.get("path"):
            p = Path(str(att["path"]))
            if p.is_file():
                zf.write(p, arcname=f"attestation/{p.name}")
        yaml_path = bastion_yaml_path()
        if yaml_path and yaml_path.is_file():
            zf.write(yaml_path, arcname="bastion.yaml")
    return buf.getvalue()


def load_observe_status(metrics: dict[str, Any] | None = None) -> dict[str, Any]:
    mode = "enforce"
    try:
        from mcp_bastion.config import load_config

        cfg = load_config()
        mode = str(getattr(cfg, "bastion_mode", "enforce") or "enforce")
    except Exception:
        pass
    metrics = metrics or {}
    would = int(metrics.get("shadow_would_block_total") or 0)
    return {
        "mode": mode,
        "observe": mode == "observe",
        "would_have_blocked": would,
        "nudge": "Ready to enforce? Set mode: enforce in bastion.yaml after reviewing shadow blocks.",
    }


def load_agent_identity_view(
    metrics: dict[str, Any] | None = None,
    config: Any | None = None,
) -> dict[str, Any]:
    """Denied-by-agent counts + agent scope map from config + blocked_incidents."""
    if config is None:
        try:
            from mcp_bastion.config import load_config

            config = load_config()
        except Exception:
            config = None

    metrics = metrics or {}
    incidents = metrics.get("blocked_incidents") or []
    denied: dict[str, int] = {}
    for row in incidents:
        if not isinstance(row, dict):
            continue
        kind = str(row.get("kind") or "")
        reason = str(row.get("reason") or "").lower()
        if kind != "agent_iam" and not (
            "not permitted" in reason or "agent" in reason and "policy" in reason
        ):
            continue
        aid = str(row.get("agent_id") or "unknown") or "unknown"
        denied[aid] = denied.get(aid, 0) + 1

    agents: list[dict[str, Any]] = []
    if config is not None and getattr(config, "agent_iam_enabled", False):
        try:
            from mcp_bastion.pillars.agent_iam import parse_agent_policies

            policies = parse_agent_policies(getattr(config, "agent_iam_agents", []) or [])
            for p in policies:
                at = getattr(p, "allowed_tools", None)
                if at is None:
                    allowed = ["*"]
                else:
                    allowed = list(at)[:40]
                agents.append(
                    {
                        "agent_id": getattr(p, "agent_id", None),
                        "allowed_tools": allowed,
                        "denied_tools": list(getattr(p, "blocked_tools", None) or [])[:40],
                        "roles": [],
                    }
                )
        except Exception:
            for raw in getattr(config, "agent_iam_agents", []) or []:
                if isinstance(raw, dict):
                    agents.append(
                        {
                            "agent_id": raw.get("id") or raw.get("agent_id"),
                            "allowed_tools": list(raw.get("allowed_tools") or [])[:40],
                            "denied_tools": list(raw.get("blocked_tools") or raw.get("denied_tools") or [])[:40],
                            "roles": list(raw.get("roles") or [])[:20],
                        }
                    )

    return {
        "agent_iam_enabled": bool(getattr(config, "agent_iam_enabled", False)) if config else False,
        "denied_by_agent": [
            {"agent_id": k, "denied": v} for k, v in sorted(denied.items(), key=lambda x: -x[1])
        ],
        "scope_map": agents,
        "total_denied": sum(denied.values()),
    }


def load_trends_from_audit(
    *,
    days: int = 14,
    date_from: str | None = None,
    date_to: str | None = None,
) -> dict[str, Any]:
    """Block-rate / PII trends from local audit JSONL (no DB)."""
    path = audit_jsonl_path()
    buckets: dict[str, dict[str, int]] = {}
    if not path.is_file():
        return {
            "path": str(path),
            "present": False,
            "days": [],
            "hint": f"No audit file at {path}",
            "date_from": date_from,
            "date_to": date_to,
        }

    df = _parse_day(date_from)
    dt = _parse_day(date_to)
    try:
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(row, dict):
                    continue
                ts = str(row.get("timestamp") or row.get("ts") or "")
                day = ts[:10] if len(ts) >= 10 else ""
                if not day:
                    continue
                if df and day < df:
                    continue
                if dt and day > dt:
                    continue
                b = buckets.setdefault(day, {"allowed": 0, "blocked": 0, "pii": 0})
                action = str(row.get("action") or "").upper()
                if action == "BLOCKED":
                    b["blocked"] += 1
                elif action == "ALLOWED":
                    b["allowed"] += 1
                pii = row.get("pii_redacted") or row.get("pii_count")
                if isinstance(pii, int):
                    b["pii"] += pii
    except Exception as e:
        logger.debug("audit trend read failed: %s", e)
        return {
            "path": str(path),
            "present": False,
            "days": [],
            "hint": str(e),
            "date_from": date_from,
            "date_to": date_to,
        }

    days_sorted = sorted(buckets.keys())
    if not df and not dt:
        days_sorted = days_sorted[-max(1, days) :]
    series = []
    for d in days_sorted:
        b = buckets[d]
        total = b["allowed"] + b["blocked"]
        series.append(
            {
                "day": d,
                "allowed": b["allowed"],
                "blocked": b["blocked"],
                "pii": b["pii"],
                "block_rate_pct": round(100.0 * b["blocked"] / total, 2) if total else 0.0,
            }
        )
    return {
        "path": str(path),
        "present": True,
        "days": series,
        "date_from": date_from,
        "date_to": date_to,
    }


def load_onboarding(metrics: dict[str, Any] | None = None, posture: dict[str, Any] | None = None) -> dict[str, Any]:
    metrics = metrics or {}
    posture = posture or {}
    req = int(metrics.get("requests_total") or 0)
    blk = int(metrics.get("blocked_total") or 0)
    has_traffic = (req + blk) > 0
    has_scan = any((c or {}).get("present") for c in (posture.get("checks") or {}).values())
    pii_on = False
    try:
        from mcp_bastion.config import load_config

        pii_on = bool(getattr(load_config(), "pii", False))
    except Exception:
        pass
    steps = [
        {
            "id": "secure_fastmcp",
            "label": "Wrap your server with secure_fastmcp / MCPBastionMiddleware",
            "done": has_traffic,
        },
        {
            "id": "scan",
            "label": "Run mcp-bastion scan (catalog) and write JSON under .bastion/scan/",
            "done": has_scan,
        },
        {
            "id": "pii",
            "label": "Enable PII redaction in bastion.yaml (pii: true)",
            "done": pii_on or int(metrics.get("pii_redacted_total") or 0) > 0,
        },
    ]
    show = not has_traffic and not has_scan
    return {"show": show, "steps": steps}


def provenance_from_reason(reason: str, forensic_trace: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Derive pillar + rule hint for forensics 'why blocked' column."""
    pillar = None
    if forensic_trace:
        for step in reversed(forensic_trace):
            if not isinstance(step, dict):
                continue
            if step.get("status") in ("blocked", "would_block"):
                pillar = step.get("pillar")
                break
    from mcp_bastion.pillars.metrics import MetricsStore

    kind = MetricsStore._normalize_reason_kind(reason or "")
    if not pillar:
        pillar = kind if kind != "other" else None
    rule_hints = {
        "injection": "prompt_guard / bastion.yaml prompt_guard",
        "rate_limit": "rate_limit / bastion.yaml rate_limit",
        "rbac": "rbac / bastion.yaml rbac",
        "cost": "cost_tracker / bastion.yaml cost_tracker",
        "schema_validation": "schema_validation / bastion.yaml schema_validation",
        "content_filter": "content_filter / bastion.yaml content_filter",
        "circuit_breaker": "circuit_breaker / bastion.yaml circuit_breaker",
        "replay": "replay_guard / bastion.yaml replay_guard",
        "agent_iam": "agent_iam / bastion.yaml agent_iam.agents",
        "server_verification": "server_verification / bastion.yaml server_verification",
        "semantic_firewall": "semantic_firewall / bastion.yaml semantic_firewall",
        "sensitive_classifier": "sensitive_classifier / bastion.yaml sensitive_classifier",
        "external_policy": "external_policy / bastion.yaml external_policy",
    }
    return {
        "pillar": pillar or kind,
        "kind": kind,
        "rule": rule_hints.get(kind, f"policy / bastion.yaml ({kind})"),
        "policy_source": "bastion.yaml",
    }
