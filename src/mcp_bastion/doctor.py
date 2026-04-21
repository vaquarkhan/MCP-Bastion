"""Health and supply-chain hints for MCP-Bastion (MCP04)."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version("mcp-bastion-python")
    except Exception:
        return "unknown"


def run_doctor(*, config_path: str | None = None, repo_root: Path | None = None) -> dict[str, Any]:
    """
    Run local checks: config parse, repo artifacts, optional pip-audit.
    Returns a JSON-serializable report (never raises for optional tools).
    """
    checks: list[dict[str, Any]] = []
    root = repo_root or Path.cwd()

    # Config
    try:
        from mcp_bastion.config import load_config

        cfg = load_config(config_path)
        checks.append(
            {
                "id": "config_load",
                "ok": True,
                "detail": getattr(cfg, "source_path", None) or str(config_path or "bastion.yaml"),
            }
        )
    except Exception as e:
        checks.append({"id": "config_load", "ok": False, "detail": str(e)})

    # Lockfiles / manifests (MCP04 hygiene); informational only
    manifest_names = ("pyproject.toml", "requirements.txt", "package-lock.json", "pnpm-lock.yaml", "yarn.lock")
    present = [name for name in manifest_names if (root / name).is_file()]
    checks.append(
        {
            "id": "manifests",
            "ok": True,
            "detail": f"present: {present}" if present else "no common lockfiles found in cwd",
        }
    )

    # pip-audit (optional)
    pip_audit = shutil.which("pip-audit")
    if not pip_audit:
        checks.append({"id": "pip_audit", "ok": True, "skipped": True, "detail": "pip-audit not on PATH"})
    else:
        try:
            proc = subprocess.run(
                [pip_audit, "--format", "json"],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(root),
            )
            vulns: list[Any] = []
            if proc.stdout.strip():
                try:
                    data = json.loads(proc.stdout)
                    vulns = data if isinstance(data, list) else data.get("dependencies", [])
                except json.JSONDecodeError:
                    vulns = []
            checks.append(
                {
                    "id": "pip_audit",
                    "ok": proc.returncode == 0,
                    "returncode": proc.returncode,
                    "vulnerabilities_reported": len(vulns) if isinstance(vulns, list) else None,
                }
            )
        except Exception as e:
            checks.append({"id": "pip_audit", "ok": False, "detail": str(e)})

    by_id = {c["id"]: c for c in checks}
    cfg_ok = bool(by_id.get("config_load", {}).get("ok"))
    pa = by_id.get("pip_audit", {})
    pa_ok = bool(pa.get("skipped") or pa.get("ok"))
    ok = cfg_ok and pa_ok
    return {
        "bastion_version": _package_version(),
        "python": sys.version.split()[0],
        "checks": checks,
        "ok": ok,
    }
