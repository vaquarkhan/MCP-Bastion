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

    # PromptGuard ML availability (heuristics still work without it)
    try:
        from mcp_bastion.config import load_config as _load_cfg
        from mcp_bastion.pillars.prompt_guard import HF_ACCESS_URL, PromptGuardEngine

        cfg = _load_cfg(config_path)
        if cfg.prompt_guard:
            engine = PromptGuardEngine(
                threshold=cfg.prompt_guard_threshold,
                model_id=cfg.prompt_guard_model_id,
                fail_open=cfg.prompt_guard_fail_open,
                heuristic_fallback=cfg.prompt_guard_heuristic_fallback,
            )
            try:
                engine.score("health check")
                checks.append({"id": "prompt_guard_ml", "ok": True, "detail": f"model={cfg.prompt_guard_model_id}"})
            except Exception as e:
                checks.append(
                    {
                        "id": "prompt_guard_ml",
                        "ok": False,
                        "detail": (
                            f"Heuristic fallback active; ML unavailable ({e}). "
                            f"Accept access at {HF_ACCESS_URL} and run `huggingface-cli login`."
                        ),
                    }
                )
        else:
            checks.append({"id": "prompt_guard_ml", "ok": True, "skipped": True, "detail": "prompt_guard disabled"})
    except Exception as e:
        checks.append({"id": "prompt_guard_ml", "ok": False, "detail": str(e)})

    try:
        from mcp_bastion.config import load_config as _load_cfg2
        from mcp_bastion.config import _load_server_manifest
        from mcp_bastion.pillars.agent_iam import parse_agent_policies
        from mcp_bastion.pillars.server_verification import ServerVerifier

        cfg2 = _load_cfg2(config_path)
        if cfg2.agent_iam_enabled:
            policies = parse_agent_policies(cfg2.agent_iam_agents)
            checks.append(
                {
                    "id": "agent_iam",
                    "ok": len(policies) > 0,
                    "detail": f"{len(policies)} agent(s) resolved"
                    if policies
                    else "agent_iam enabled but no tokens resolved",
                }
            )
        else:
            checks.append({"id": "agent_iam", "ok": True, "skipped": True, "detail": "agent_iam disabled"})
        if cfg2.server_verification_enabled:
            manifest = _load_server_manifest(cfg2)
            if not manifest:
                checks.append({"id": "server_verification", "ok": False, "detail": "manifest empty"})
            else:
                sv = ServerVerifier(
                    manifest,
                    base_path=cfg2.server_verification_base_path,
                    on_mismatch=cfg2.server_verification_on_mismatch,  # type: ignore[arg-type]
                )
                result = sv.verify()
                checks.append(
                    {
                        "id": "server_verification",
                        "ok": result.ok or cfg2.server_verification_on_mismatch == "warn",
                        "detail": result.summary,
                    }
                )
        else:
            checks.append(
                {"id": "server_verification", "ok": True, "skipped": True, "detail": "server_verification disabled"}
            )
    except Exception as e:
        checks.append({"id": "runtime_governance", "ok": False, "detail": str(e)})

    # Schema validation policy-as-code
    try:
        from mcp_bastion.config import load_config as _load_cfg_schema

        cfg_schema = _load_cfg_schema(config_path)
        if cfg_schema.schema_validation:
            n = len(cfg_schema.schema_validation_schemas)
            if n == 0:
                checks.append(
                    {
                        "id": "schema_validation",
                        "ok": False,
                        "detail": (
                            "schema_validation.enabled is true but schema_validation.schemas is empty - "
                            "no tool arguments will be validated"
                        ),
                    }
                )
            else:
                tools = ", ".join(sorted(cfg_schema.schema_validation_schemas.keys())[:8])
                suffix = "…" if n > 8 else ""
                checks.append(
                    {
                        "id": "schema_validation",
                        "ok": True,
                        "detail": f"{n} tool schema(s) loaded: {tools}{suffix}",
                    }
                )
        else:
            checks.append(
                {"id": "schema_validation", "ok": True, "skipped": True, "detail": "schema_validation disabled"}
            )
    except Exception as e:
        checks.append({"id": "schema_validation", "ok": False, "detail": str(e)})

    try:
        from mcp_bastion.config import load_config as _load_cfg_tmg

        cfg_tmg = _load_cfg_tmg(config_path)
        if cfg_tmg.tool_metadata_guard_enabled:
            if not cfg_tmg.content_filter and not cfg_tmg.prompt_guard:
                checks.append(
                    {
                        "id": "tool_metadata_guard",
                        "ok": False,
                        "detail": (
                            "tool_metadata_guard enabled but content_filter and prompt_guard are both "
                            "disabled; enable at least one for metadata scanning to run"
                        ),
                    }
                )
            else:
                checks.append(
                    {
                        "id": "tool_metadata_guard",
                        "ok": True,
                        "detail": f"on_poison={cfg_tmg.tool_metadata_guard_on_poison}",
                    }
                )
        else:
            checks.append(
                {"id": "tool_metadata_guard", "ok": True, "skipped": True, "detail": "tool_metadata_guard disabled"}
            )
    except Exception as e:
        checks.append({"id": "tool_metadata_guard", "ok": False, "detail": str(e)})

    try:
        from mcp_bastion.config import load_config as _load_cfg_val, validate_bastion_config

        cfg_val = _load_cfg_val(config_path)
        validate_bastion_config(cfg_val)
        checks.append({"id": "config_validation", "ok": True, "detail": "pillar combinations valid"})
    except Exception as e:
        checks.append({"id": "config_validation", "ok": False, "detail": str(e)})

    try:
        from mcp_bastion.config import load_config as _load_cfg_sb
        from mcp_bastion.pillars.state_backend import RedisStateBackend, build_state_backend

        cfg_sb = _load_cfg_sb(config_path)
        kind = (cfg_sb.state_backend or "memory").strip().lower()
        if kind == "redis":
            backend = build_state_backend(
                backend=cfg_sb.state_backend,
                redis_url=cfg_sb.state_backend_redis_url,
                key_prefix=cfg_sb.state_backend_key_prefix,
            )
            ok = isinstance(backend, RedisStateBackend) and backend.ping()
            checks.append(
                {
                    "id": "state_backend_redis",
                    "ok": ok,
                    "detail": cfg_sb.state_backend_redis_url if ok else "Redis ping failed or redis package missing",
                }
            )
        else:
            checks.append(
                {
                    "id": "state_backend_redis",
                    "ok": True,
                    "skipped": True,
                    "detail": f"state_backend={kind} (in-process memory)",
                }
            )
    except Exception as e:
        checks.append({"id": "state_backend_redis", "ok": False, "detail": str(e)})

    # Tool metadata fingerprint (semantic schema drift)
    try:
        from mcp_bastion.config import load_config as _load_cfg3
        from mcp_bastion.pillars.tool_metadata_fingerprint import (
            fingerprint_tools,
            load_expected_fingerprint,
            load_tools_from_json,
            verify_fingerprint,
        )

        cfg3 = _load_cfg3(config_path)
        if cfg3.tool_metadata_fingerprint_enabled:
            fp_path = cfg3.tool_metadata_fingerprint_path
            expected = cfg3.tool_metadata_fingerprint_expected
            p: Path | None = None
            if fp_path:
                cand = Path(fp_path)
                p = cand if cand.is_file() else (root / fp_path if (root / fp_path).is_file() else None)
            if p is not None:
                tools = load_tools_from_json(p)
                if not expected:
                    expected = load_expected_fingerprint(p)
                ok = verify_fingerprint(tools, expected)
                current = fingerprint_tools(tools)
                checks.append(
                    {
                        "id": "tool_metadata_fingerprint",
                        "ok": ok,
                        "detail": f"match={ok} tools={len(tools)} sha256={current[:16]}…",
                    }
                )
            else:
                checks.append(
                    {
                        "id": "tool_metadata_fingerprint",
                        "ok": False,
                        "detail": "fingerprint_path missing or tool_metadata_fingerprint.expected not set",
                    }
                )
        else:
            checks.append(
                {"id": "tool_metadata_fingerprint", "ok": True, "skipped": True, "detail": "disabled"}
            )
    except Exception as e:
        checks.append({"id": "tool_metadata_fingerprint", "ok": False, "detail": str(e)})

    # Registry publisher verification (typosquatting hygiene)
    try:
        from mcp_bastion.config import load_config as _load_cfg4

        cfg4 = _load_cfg4(config_path)
        names = cfg4.governance_allowed_registry_names
        repos = cfg4.governance_allowed_repository_urls
        server_json = root / "server.json"
        if names or repos:
            if not server_json.is_file():
                checks.append(
                    {"id": "registry_publisher", "ok": False, "detail": "server.json not found in repo root"}
                )
            else:
                data = json.loads(server_json.read_text(encoding="utf-8"))
                reg_name = str(data.get("name") or "")
                repo_url = str((data.get("repository") or {}).get("url") or "")
                name_ok = not names or reg_name in names
                repo_ok = not repos or repo_url in repos
                checks.append(
                    {
                        "id": "registry_publisher",
                        "ok": name_ok and repo_ok,
                        "detail": f"name={reg_name!r} repo={repo_url!r}",
                    }
                )
        else:
            checks.append(
                {"id": "registry_publisher", "ok": True, "skipped": True, "detail": "no allowlists configured"}
            )
    except Exception as e:
        checks.append({"id": "registry_publisher", "ok": False, "detail": str(e)})

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

    # pip-audit (optional; try PATH binary then python -m pip_audit)
    pip_audit_bin = shutil.which("pip-audit")
    pip_audit_cmd: list[str] | None = None
    if pip_audit_bin:
        pip_audit_cmd = [pip_audit_bin, "--format", "json"]
    else:
        try:
            import pip_audit  # noqa: F401

            pip_audit_cmd = [sys.executable, "-m", "pip_audit", "--format", "json"]
        except ImportError:
            pip_audit_cmd = None
    if pip_audit_cmd is None:
        checks.append(
            {
                "id": "pip_audit",
                "ok": True,
                "skipped": True,
                "detail": "pip-audit not on PATH and pip_audit module not installed (pip install pip-audit)",
            }
        )
    else:
        try:
            proc = subprocess.run(
                pip_audit_cmd,
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
    pg = by_id.get("prompt_guard_ml", {})
    pg_ok = bool(pg.get("skipped") or pg.get("ok"))
    iam = by_id.get("agent_iam", {})
    iam_ok = bool(iam.get("skipped") or iam.get("ok"))
    sv = by_id.get("server_verification", {})
    sv_ok = bool(sv.get("skipped") or sv.get("ok"))
    tmf = by_id.get("tool_metadata_fingerprint", {})
    tmf_ok = bool(tmf.get("skipped") or tmf.get("ok"))
    reg = by_id.get("registry_publisher", {})
    reg_ok = bool(reg.get("skipped") or reg.get("ok"))
    ok = cfg_ok and pa_ok and pg_ok and iam_ok and sv_ok and tmf_ok and reg_ok
    return {
        "bastion_version": _package_version(),
        "python": sys.version.split()[0],
        "checks": checks,
        "ok": ok,
    }
