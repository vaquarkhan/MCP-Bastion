"""
CLI for MCP-Bastion developers.

Usage:
  mcp-bastion validate [--config PATH]
  mcp-bastion scan TOOLS.json [--baseline FINGERPRINT.json]
  mcp-bastion serve [--config PATH] [--http PORT] [--host HOST]
  mcp-bastion tail [--path PATH] [--lines N] [--config PATH]
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

logger = logging.getLogger("mcp_bastion.cli")


def _configure_cli_logging() -> None:
    if logger.handlers:
        return
    logger.setLevel(logging.INFO)
    out = logging.StreamHandler(sys.stdout)
    out.setLevel(logging.INFO)
    out.addFilter(lambda r: r.levelno == logging.INFO)
    err = logging.StreamHandler(sys.stderr)
    err.setLevel(logging.WARNING)
    logger.addHandler(out)
    logger.addHandler(err)


def _ensure_src_on_path() -> None:
    """If running from repo, add src to PYTHONPATH."""
    cwd = Path.cwd()
    src = cwd / "src"
    if (cwd / "bastion.yaml.example").exists() and src.exists() and str(src) not in sys.path:
        sys.path.insert(0, str(src))


def cmd_validate(config_path: str | None) -> int:
    _configure_cli_logging()
    _ensure_src_on_path()
    try:
        from mcp_bastion.config import load_config, validate_bastion_config
    except ImportError as e:
        logger.error("Error: %s", e)
        return 1
    path = config_path or os.environ.get("BASTION_CONFIG", "bastion.yaml")
    p = Path(path)
    if not p.exists():
        logger.error("Config not found: %s", path)
        return 1
    try:
        config = load_config(path)
        validate_bastion_config(config)
        logger.info("Valid: %s", path)
        logger.info("  prompt_guard=%s pii=%s rate_limit=%s", config.prompt_guard, config.pii, config.rate_limit)
        logger.info("  audit=%s rbac=%s cost_tracker=%s", config.audit, config.rbac, config.cost_tracker)
        return 0
    except Exception as e:
        logger.error("Invalid config: %s", e)
        return 1


def cmd_serve(
    config_path: str | None,
    http_port: int | None,
    host: str,
    proxy_url: str | None = None,
) -> int:
    _configure_cli_logging()
    _ensure_src_on_path()
    try:
        from mcp_bastion.config import load_config
    except ImportError as e:
        logger.error("Error: %s", e)
        return 1
    if config_path:
        os.environ["BASTION_CONFIG"] = config_path
    cfg_path = config_path or os.environ.get("BASTION_CONFIG", "bastion.yaml")
    try:
        load_config(cfg_path)
    except Exception as e:
        logger.error("Config error: %s", e)
        return 1

    port = http_port if http_port is not None else 8080
    if proxy_url:
        try:
            from mcp_bastion.proxy_server import run_proxy_http
        except ImportError as e:
            logger.error("Proxy mode requires uvicorn: %s", e)
            return 1
        run_proxy_http(proxy_url, host=host, port=port, config_path=cfg_path)
        return 0

    root = Path(__file__).resolve().parent.parent.parent
    llm_server = root / "examples" / "llm_server.py"
    if not llm_server.exists():
        llm_server = Path("examples/llm_server.py")
    if not llm_server.exists():
        logger.error("examples/llm_server.py not found. Run from repo root.")
        return 1
    argv = [sys.executable, str(llm_server)]
    if http_port is not None:
        argv.extend(["--http", str(http_port), "--host", host])
    env = os.environ.copy()
    src_path = str(root / "src")
    env["PYTHONPATH"] = os.pathsep.join([src_path, env.get("PYTHONPATH", "")])
    import subprocess
    return subprocess.run(argv, env=env).returncode


def _resolve_dashboard_repo() -> Path | None:
    """Directory that contains dashboard/app.py (prefer cwd so the right clone is used)."""
    cwd = Path.cwd().resolve()
    if (cwd / "dashboard" / "app.py").is_file():
        return cwd
    # Development layout: MCP-Bastion/src/mcp_bastion/cli.py -> repo root is 3 levels up
    here = Path(__file__).resolve()
    for depth in (3, 4):
        cand = here
        for _ in range(depth):
            cand = cand.parent
        if (cand / "dashboard" / "app.py").is_file():
            return cand
    return None


def cmd_dashboard(
    port: int,
    reload: bool = False,
    demo: bool = False,
    no_demo: bool = False,
    no_live: bool = False,
    live: bool = False,
) -> int:
    _configure_cli_logging()
    _ensure_src_on_path()
    if no_demo:
        os.environ["MCP_BASTION_DEMO"] = "0"
    elif demo:
        os.environ["MCP_BASTION_DEMO"] = "1"
    else:
        os.environ.setdefault("MCP_BASTION_DEMO", "1")
    if no_live:
        os.environ["MCP_BASTION_DEMO_LIVE"] = "0"
    elif live:
        os.environ["MCP_BASTION_DEMO_LIVE"] = "1"
    if os.environ.get("MCP_BASTION_DEMO", "").strip().lower() in ("1", "true", "yes"):
        logger.info(
            "Demo metrics: bundled seed on startup (disable: --no-demo). "
            "Background fake traffic is opt-in: --live or MCP_BASTION_DEMO_LIVE=1."
        )
    try:
        import uvicorn
    except ImportError:
        logger.error("Install dashboard deps: pip install fastapi uvicorn")
        return 1
    repo = _resolve_dashboard_repo()
    if repo is None:
        logger.error(
            "dashboard/app.py not found. cd into the MCP-Bastion repo root (folder that contains dashboard/) and retry."
        )
        return 1
    sys.path.insert(0, str(repo))
    sys.path.insert(0, str(repo / "src"))
    dash_py = repo / "dashboard" / "app.py"
    env_reload = os.environ.get("MCP_BASTION_DASHBOARD_RELOAD", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    do_reload = reload or env_reload
    logger.info("Dashboard app: %s", dash_py)
    if do_reload:
        logger.info(
            "Auto-reload enabled (dashboard/ changes). Or set MCP_BASTION_DASHBOARD_RELOAD=1."
        )
    else:
        logger.info(
            "No auto-reload: stop and restart this process after editing dashboard/app.py, "
            "or run: mcp-bastion dashboard --reload"
        )
    bind_host = (os.environ.get("MCP_BASTION_DASHBOARD_HOST") or "0.0.0.0").strip() or "0.0.0.0"
    logger.info("Open http://%s:%s/meta — check ui_revision matches your tree.", bind_host, port)
    uvicorn.run(
        "dashboard.app:app",
        host=bind_host,
        port=port,
        reload=do_reload,
        reload_dirs=[str(repo / "dashboard")] if do_reload else None,
    )
    return 0


def cmd_doctor(config_path: str | None, repo_root: str | None) -> int:
    _configure_cli_logging()
    _ensure_src_on_path()
    try:
        from mcp_bastion.doctor import run_doctor
    except ImportError as e:
        logger.error("Error: %s", e)
        return 1
    root = Path(repo_root).resolve() if repo_root else Path.cwd()
    report = run_doctor(config_path=config_path, repo_root=root)
    logger.info(json.dumps(report, indent=2))
    return 0 if report.get("ok") else 1


def cmd_redteam(config_path: str | None, output_path: str | None = None) -> int:
    _configure_cli_logging()
    _ensure_src_on_path()
    try:
        from mcp_bastion.redteam import run_redteam_sync
    except ImportError as e:
        logger.error("Error: %s", e)
        return 1
    try:
        report = run_redteam_sync(config_path)
        logger.info("Redteam score (all blocks): %.2f%%", float(report.get("score_blocked_pct", 0.0)))
        logger.info(
            "Redteam intended-control block rate: %.2f%%",
            float(report.get("score_intended_blocked_pct", 0.0)),
        )
        if float(report.get("score_guard_unavailable_pct", 0.0)) > 0:
            logger.info(
                "Redteam guard-unavailable block rate: %.2f%% (not policy effectiveness)",
                float(report.get("score_guard_unavailable_pct", 0.0)),
            )
        for line in report.get("interpretation") or []:
            logger.info("Note: %s", line)
        logger.info(
            "Attempts=%s blocked=%s allowed=%s",
            report.get("totals", {}).get("attempts"),
            report.get("totals", {}).get("blocked"),
            report.get("totals", {}).get("allowed"),
        )
        if output_path:
            p = Path(output_path)
            p.write_text(json.dumps(report, indent=2), encoding="utf-8")
            logger.info("Report: %s", p)
        else:
            logger.info(json.dumps(report))
        return 0
    except Exception as e:
        logger.error("Redteam failed: %s", e)
        return 1


def cmd_manifest(files: list[str], base_path: str, output: str | None, sign: bool = False) -> int:
    """Generate SHA-256 manifest for server_verification."""
    _ensure_src_on_path()
    import json
    import os

    from mcp_bastion.pillars.server_verification import build_manifest, sign_manifest

    try:
        manifest = build_manifest(files, base_path=base_path)
    except Exception as e:
        logger.error("manifest failed: %s", e)
        return 1
    payload: dict = {"files": manifest, "algorithm": "sha256"}
    if sign:
        key = os.environ.get("BASTION_MANIFEST_SIGNING_KEY", "")
        if not key:
            logger.error("Set BASTION_MANIFEST_SIGNING_KEY to sign manifest")
            return 1
        payload["algorithm"] = "hmac-sha256"
        payload["signature"] = sign_manifest(manifest, key)
    text = json.dumps(payload, indent=2)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        logger.info("Wrote manifest: %s", output)
    else:
        logger.info(text)
    return 0


def cmd_tail(path: str | None, lines: int, config_path: str | None) -> int:
    """Tail append-only JSONL audit log."""
    _configure_cli_logging()
    _ensure_src_on_path()
    from mcp_bastion.audit_jsonl import AuditJsonlSink

    audit_path = path
    if not audit_path and config_path:
        try:
            from mcp_bastion.config import load_config

            cfg = load_config(config_path)
            audit_path = cfg.audit_jsonl_path
        except Exception as e:
            logger.error("Config error: %s", e)
            return 1
    if not audit_path:
        audit_path = os.environ.get("BASTION_AUDIT_JSONL")
    if not audit_path:
        logger.error("Specify --path, --config with audit.jsonl_path, or BASTION_AUDIT_JSONL")
        return 1
    entries = AuditJsonlSink.tail(audit_path, lines=max(1, lines))
    logger.info(json.dumps(entries, indent=2))
    return 0


def cmd_fingerprint(tools_json: str, output: str | None) -> int:
    """Generate tool metadata fingerprint JSON for schema drift detection."""
    _ensure_src_on_path()
    import json

    from mcp_bastion.pillars.tool_metadata_fingerprint import build_fingerprint_document, load_tools_from_json

    try:
        tools = load_tools_from_json(tools_json)
        doc = build_fingerprint_document(tools)
    except Exception as e:
        logger.error("fingerprint failed: %s", e)
        return 1
    text = json.dumps(doc, indent=2)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        logger.info("Wrote fingerprint: %s", output)
    else:
        logger.info(text)
    return 0


def cmd_attest_export(
    session_id: str,
    config_path: str | None,
    output: str | None,
    sign: bool,
    principal_id: str | None,
    tenant_id: str | None,
) -> int:
    """Export signed governance attestation for an agent session."""
    _configure_cli_logging()
    _ensure_src_on_path()
    try:
        from mcp_bastion.config import load_config
        from mcp_bastion.pillars.governance_attestation import export_session_attestation
    except ImportError as e:
        logger.error("Error: %s", e)
        return 1

    cfg_path = config_path or os.environ.get("BASTION_CONFIG")
    cfg = None
    if cfg_path and Path(cfg_path).exists():
        try:
            cfg = load_config(cfg_path)
        except Exception as e:
            logger.error("Config error: %s", e)
            return 1

    try:
        payload = export_session_attestation(
            session_id,
            config_path=cfg.source_path if cfg else cfg_path,
            principal_id=principal_id,
            tenant_id=tenant_id,
            sign=sign,
        )
    except ValueError as e:
        logger.error("%s", e)
        return 1
    except Exception as e:
        logger.error("attest export failed: %s", e)
        return 1

    text = json.dumps(payload, indent=2)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        logger.info("Wrote attestation: %s", output)
    else:
        logger.info(text)
    return 0


def cmd_scan(
    tools_json: str | None = None,
    *,
    baseline: str | None = None,
    output: str | None = None,
    output_format: str = "text",
    fail_on: str = "high",
    schema_checks: bool = True,
    skills: str | None = None,
) -> int:
    """Static scan of MCP tool definitions and/or agent skill files."""
    _configure_cli_logging()
    _ensure_src_on_path()

    if not tools_json and not skills:
        logger.error("Provide a tools JSON path and/or --skills DIR")
        return 1

    sections: list[str] = []
    worst_findings = False
    threshold = (fail_on or "high").strip().lower()
    if threshold not in ("critical", "high", "medium", "low", "info", "none"):
        logger.error("Invalid --fail-on severity: %s", fail_on)
        return 1

    if tools_json:
        from mcp_bastion.static_scan import format_report_text, scan_tools_file

        p = Path(tools_json)
        if not p.is_file():
            logger.error("Tools file not found: %s", tools_json)
            return 1
        try:
            report = scan_tools_file(str(p), baseline_path=baseline, schema_checks=schema_checks)
        except Exception as e:
            logger.error("scan failed: %s", e)
            return 1
        fmt = (output_format or "text").strip().lower()
        if fmt == "json":
            sections.append(json.dumps({"type": "tools", **report.to_dict()}, indent=2))
        else:
            sections.append(format_report_text(report))
        if threshold != "none" and report.findings_at_or_above(threshold):  # type: ignore[arg-type]
            worst_findings = True

    if skills:
        from mcp_bastion.skill_scan import format_skill_report_text, scan_skills

        try:
            sreport = scan_skills(skills)
        except Exception as e:
            logger.error("skill scan failed: %s", e)
            return 1
        fmt = (output_format or "text").strip().lower()
        if fmt == "json":
            sections.append(json.dumps({"type": "skills", **sreport.to_dict()}, indent=2))
        else:
            sections.append(format_skill_report_text(sreport))
        if threshold != "none" and sreport.findings_at_or_above(threshold):  # type: ignore[arg-type]
            worst_findings = True

    text = "\n\n".join(sections)
    if output:
        Path(output).write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
        logger.info("Wrote scan report: %s", output)
    else:
        print(text)

    if worst_findings:
        logger.error("Scan failed: findings at or above %s severity", threshold)
        return 1
    return 0


def cmd_osv_refresh(
    *,
    ecosystem: str = "PyPI",
    db_dir: str = ".osv",
) -> int:
    """Download local OSV vulnerability dump (opt-in, user-run)."""
    _configure_cli_logging()
    _ensure_src_on_path()
    from mcp_bastion.pillars.osv_scan import refresh_osv_db

    try:
        dest = refresh_osv_db(ecosystem=ecosystem, db_dir=db_dir)
    except Exception as e:
        logger.error("osv-refresh failed: %s", e)
        return 1
    logger.info("OSV DB refreshed: %s", dest)
    print(f"OSV DB refreshed: {dest}")
    return 0


def cmd_osv_scan(
    deps_file: str | None = None,
    *,
    package: list[str] | None = None,
    db_dir: str = ".osv",
    online: bool = False,
    timeout_ms: int = 3000,
    output: str | None = None,
    output_format: str = "text",
    fail_on: str = "high",
) -> int:
    """Offline-first OSV dependency CVE lookup (network only if --online)."""
    _configure_cli_logging()
    _ensure_src_on_path()
    from mcp_bastion.pillars.osv_scan import (
        format_osv_report_text,
        parse_dep_specs,
        parse_deps_file,
        scan_dependencies,
    )

    deps = []
    if deps_file:
        p = Path(deps_file)
        if not p.is_file():
            logger.error("Deps file not found: %s", deps_file)
            return 1
        deps.extend(parse_deps_file(p))
    if package:
        deps.extend(parse_dep_specs(package))
    if not deps:
        logger.error("Provide a deps file and/or --package name==version")
        return 1

    report = scan_dependencies(
        deps,
        db_dir=db_dir,
        online=online,
        timeout_ms=timeout_ms,
        enabled=True,
    )
    fmt = (output_format or "text").strip().lower()
    text = json.dumps(report.to_dict(), indent=2) if fmt == "json" else format_osv_report_text(report)
    if output:
        Path(output).write_text(text + "\n", encoding="utf-8")
        logger.info("Wrote OSV report: %s", output)
    else:
        print(text)

    threshold = (fail_on or "high").strip().lower()
    if threshold == "none":
        return 0
    rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if threshold not in rank:
        logger.error("Invalid --fail-on severity: %s", fail_on)
        return 1
    if any(rank.get(f.severity, 0) >= rank[threshold] for f in report.findings):
        logger.error("OSV scan failed: findings at or above %s", threshold)
        return 1
    return 0


def cmd_audit(
    root: str | None = None,
    *,
    config_paths: list[str] | None = None,
    output: str | None = None,
    output_format: str = "text",
    fail_on: str = "high",
) -> int:
    """Local MCP risk audit - configs, over-broad tools, standing credential smells."""
    _configure_cli_logging()
    _ensure_src_on_path()
    from mcp_bastion.risk_audit import format_risk_audit_text, run_risk_audit

    try:
        report = run_risk_audit(root, extra_config_paths=config_paths)
    except Exception as e:
        logger.error("audit failed: %s", e)
        return 1

    fmt = (output_format or "text").strip().lower()
    if fmt == "json":
        text = json.dumps(report.to_dict(), indent=2)
    else:
        text = format_risk_audit_text(report)

    if output:
        Path(output).write_text(text + ("\n" if not text.endswith("\n") else ""), encoding="utf-8")
        logger.info("Wrote audit report: %s", output)
    else:
        print(text)

    threshold = (fail_on or "high").strip().lower()
    if threshold not in ("critical", "high", "medium", "low", "info", "none"):
        logger.error("Invalid --fail-on severity: %s", fail_on)
        return 1
    if threshold != "none" and report.findings_at_or_above(threshold):  # type: ignore[arg-type]
        logger.error("Audit failed: findings at or above %s severity", threshold)
        return 1
    return 0


def cmd_report(
    *,
    framework: str,
    audit_path: str,
    output: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
) -> int:
    """Generate compliance evidence report from audit JSONL."""
    from mcp_bastion import __version__
    from mcp_bastion.pillars.compliance_report import generate_report_markdown

    p = Path(audit_path)
    if not p.is_file():
        logger.error("Audit log not found: %s", audit_path)
        return 1
    report = generate_report_markdown(
        framework=framework,
        audit_path=p,
        date_from=date_from,
        date_to=date_to,
        version=__version__,
    )
    if output:
        out = Path(output)
        out.write_text(report, encoding="utf-8")
        logger.info("Wrote compliance report to %s", out)
    else:
        print(report)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-bastion",
        description="MCP-Bastion CLI for developers.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__import__('mcp_bastion').__version__}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate_parser = sub.add_parser("validate", help="Validate bastion.yaml")
    validate_parser.add_argument("--config", "-c", help="Path to bastion.yaml", default="bastion.yaml")
    validate_parser.set_defaults(func=lambda **kw: cmd_validate(kw.get("config")))

    serve_parser = sub.add_parser("serve", help="Run MCP server with config")
    serve_parser.add_argument("--config", "-c", help="Path to bastion.yaml", default="bastion.yaml")
    serve_parser.add_argument("--http", type=int, metavar="PORT", default=8080, help="HTTP port (default 8080)")
    serve_parser.add_argument("--host", default="127.0.0.1", help="Bind host (default loopback)")
    serve_parser.add_argument(
        "--proxy",
        metavar="UPSTREAM_URL",
        help="Boundary mode: forward to upstream MCP URL (same bastion.yaml enforcement)",
    )
    serve_parser.set_defaults(
        func=lambda **kw: cmd_serve(
            kw.get("config"),
            kw.get("http"),
            kw.get("host", "127.0.0.1"),
            kw.get("proxy"),
        )
    )

    dash_parser = sub.add_parser("dashboard", help="Run metrics dashboard")
    dash_parser.add_argument("--port", "-p", type=int, default=7000, help="Dashboard port (default 7000)")
    dash_parser.add_argument(
        "--reload",
        action="store_true",
        help="Restart the server when files under dashboard/ change (development). "
        "Or set env MCP_BASTION_DASHBOARD_RELOAD=1.",
    )
    _dash_demo = dash_parser.add_mutually_exclusive_group()
    _dash_demo.add_argument(
        "--demo",
        action="store_true",
        help="Force MCP_BASTION_DEMO=1 (default seeds demo unless MCP_BASTION_DEMO disables it).",
    )
    _dash_demo.add_argument(
        "--no-demo",
        action="store_true",
        help="Do not seed demo metrics; dashboard stays empty until middleware feeds MetricsStore.",
    )
    dash_parser.add_argument(
        "--live",
        action="store_true",
        help="Spawn background fake traffic (moving KPIs). Default is seed-only; same as MCP_BASTION_DEMO_LIVE=1.",
    )
    dash_parser.add_argument(
        "--no-live",
        action="store_true",
        help="Do not spawn background fake traffic (same as MCP_BASTION_DEMO_LIVE=0).",
    )
    dash_parser.set_defaults(
        func=lambda **kw: cmd_dashboard(
            port=kw.get("port", 7000),
            reload=bool(kw.get("reload")),
            demo=bool(kw.get("demo")),
            no_demo=bool(kw.get("no_demo")),
            no_live=bool(kw.get("no_live")),
            live=bool(kw.get("live")),
        )
    )

    redteam_parser = sub.add_parser("redteam", help="Run integrated red-team security suite")
    redteam_parser.add_argument("--config", "-c", help="Path to bastion.yaml", default="bastion.yaml")
    redteam_parser.add_argument("--output", "-o", help="Write JSON report to file", default=None)
    redteam_parser.set_defaults(func=lambda **kw: cmd_redteam(kw.get("config"), kw.get("output")))

    doctor_parser = sub.add_parser("doctor", help="Config + optional supply-chain checks (MCP04)")
    doctor_parser.add_argument("--config", "-c", help="Path to bastion.yaml", default=None)
    doctor_parser.add_argument("--repo-root", help="Directory for manifest discovery", default=None)
    doctor_parser.set_defaults(func=lambda **kw: cmd_doctor(kw.get("config"), kw.get("repo_root")))

    manifest_parser = sub.add_parser("manifest", help="Generate SHA-256 manifest for server_verification")
    manifest_parser.add_argument("files", nargs="+", help="Relative file paths to hash")
    manifest_parser.add_argument("--base-path", default=".", help="Base directory for relative paths")
    manifest_parser.add_argument("--output", "-o", help="Write JSON manifest to file")
    manifest_parser.add_argument(
        "--sign",
        action="store_true",
        help="Add HMAC-SHA256 signature using BASTION_MANIFEST_SIGNING_KEY",
    )
    manifest_parser.set_defaults(
        func=lambda **kw: cmd_manifest(kw.get("files"), kw.get("base_path"), kw.get("output"), kw.get("sign", False))
    )

    fp_parser = sub.add_parser("fingerprint", help="Generate tool metadata fingerprint JSON")
    fp_parser.add_argument("tools_json", help="JSON file with tools list or {tools: [...]}")
    fp_parser.add_argument("--output", "-o", help="Write fingerprint document to file")
    fp_parser.set_defaults(func=lambda **kw: cmd_fingerprint(kw.get("tools_json"), kw.get("output")))

    scan_parser = sub.add_parser(
        "scan",
        help="Static scan of MCP tool definitions (injection, secrets, homoglyphs, drift, schema)",
    )
    scan_parser.add_argument(
        "tools_json",
        nargs="?",
        default=None,
        help="JSON file with tools list or {tools: [...]} (optional if --skills is set)",
    )
    scan_parser.add_argument(
        "--baseline",
        "-b",
        help="Fingerprint JSON from mcp-bastion fingerprint (detect catalog drift)",
    )
    scan_parser.add_argument(
        "--skills",
        help="Scan agent skill files under DIR (SKILL.md / *.skill.md); offline opt-in",
    )
    scan_parser.add_argument("--output", "-o", help="Write report to file")
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Report format (default text)",
    )
    scan_parser.add_argument(
        "--fail-on",
        default="high",
        choices=("critical", "high", "medium", "low", "info", "none"),
        help="Exit 1 if any finding meets this severity (default high; none = always 0)",
    )
    scan_parser.add_argument(
        "--no-schema-checks",
        action="store_true",
        help="Disable structural inputSchema precondition checks (on by default within scan)",
    )
    scan_parser.set_defaults(
        func=lambda **kw: cmd_scan(
            kw.get("tools_json"),
            baseline=kw.get("baseline"),
            output=kw.get("output"),
            output_format=kw.get("format", "text"),
            fail_on=kw.get("fail_on", "high"),
            schema_checks=not kw.get("no_schema_checks", False),
            skills=kw.get("skills"),
        )
    )

    osv_refresh = sub.add_parser(
        "osv-refresh",
        help="Download local OSV vulnerability dump (opt-in; offline scans use this)",
    )
    osv_refresh.add_argument("--ecosystem", default="PyPI", help="OSV ecosystem (default PyPI)")
    osv_refresh.add_argument("--dir", dest="osv_dir", default=".osv", help="Local DB directory")
    osv_refresh.set_defaults(
        func=lambda **kw: cmd_osv_refresh(ecosystem=kw.get("ecosystem", "PyPI"), db_dir=kw.get("osv_dir", ".osv"))
    )

    osv_scan = sub.add_parser(
        "osv-scan",
        help="Offline-first OSV dependency CVE lookup (enable online with --online)",
    )
    osv_scan.add_argument(
        "deps_file",
        nargs="?",
        default=None,
        help="requirements-style file with name==version lines",
    )
    osv_scan.add_argument(
        "--package",
        "-p",
        action="append",
        dest="osv_packages",
        help="Package spec name==version (repeatable)",
    )
    osv_scan.add_argument("--dir", dest="osv_dir", default=".osv", help="Local OSV DB directory")
    osv_scan.add_argument(
        "--online",
        action="store_true",
        help="Opt-in OSV querybatch (fail-open; sends package name+version only)",
    )
    osv_scan.add_argument("--timeout-ms", type=int, default=3000, help="Online timeout (default 3000)")
    osv_scan.add_argument("--output", "-o", help="Write report to file")
    osv_scan.add_argument("--format", choices=("text", "json"), default="text")
    osv_scan.add_argument(
        "--fail-on",
        default="high",
        choices=("critical", "high", "medium", "low", "info", "none"),
    )
    osv_scan.set_defaults(
        func=lambda **kw: cmd_osv_scan(
            kw.get("deps_file"),
            package=kw.get("osv_packages"),
            db_dir=kw.get("osv_dir", ".osv"),
            online=bool(kw.get("online")),
            timeout_ms=int(kw.get("timeout_ms") or 3000),
            output=kw.get("output"),
            output_format=kw.get("format", "text"),
            fail_on=kw.get("fail_on", "high"),
        )
    )

    audit_parser = sub.add_parser(
        "audit",
        help="Local MCP risk audit (client configs, over-broad tools, credential smells)",
    )
    audit_parser.add_argument(
        "--root",
        "-r",
        default=".",
        help="Directory to search for MCP client configs (default: cwd)",
    )
    audit_parser.add_argument(
        "--config",
        "-c",
        action="append",
        dest="audit_configs",
        help="Extra MCP client config JSON path (repeatable)",
    )
    audit_parser.add_argument("--output", "-o", help="Write report to file")
    audit_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Report format (default text)",
    )
    audit_parser.add_argument(
        "--fail-on",
        default="high",
        choices=("critical", "high", "medium", "low", "info", "none"),
        help="Exit 1 if any finding meets this severity (default high; none = always 0)",
    )
    audit_parser.set_defaults(
        func=lambda **kw: cmd_audit(
            root=kw.get("root"),
            config_paths=kw.get("audit_configs"),
            output=kw.get("output"),
            output_format=kw.get("format", "text"),
            fail_on=kw.get("fail_on", "high"),
        )
    )

    tail_parser = sub.add_parser("tail", help="Tail append-only JSONL audit log")
    tail_parser.add_argument("--path", "-p", help="Path to audit JSONL file")
    tail_parser.add_argument("--lines", "-n", type=int, default=20, help="Number of lines (default 20)")
    tail_parser.add_argument("--config", "-c", help="Read audit.jsonl_path from bastion.yaml")
    tail_parser.set_defaults(
        func=lambda **kw: cmd_tail(kw.get("path"), kw.get("lines", 20), kw.get("config"))
    )

    attest_parser = sub.add_parser("attest", help="Governance attestation export")
    attest_sub = attest_parser.add_subparsers(dest="attest_command", required=True)
    export_parser = attest_sub.add_parser("export", help="Export session governance attestation JSON")
    export_parser.add_argument("--session", "-s", required=True, help="Session ID to export")
    export_parser.add_argument("--config", "-c", help="Path to bastion.yaml (for policy hash)")
    export_parser.add_argument("--output", "-o", help="Write JSON to file")
    export_parser.add_argument(
        "--sign",
        action="store_true",
        help="HMAC-SHA256 sign with BASTION_MANIFEST_SIGNING_KEY",
    )
    export_parser.add_argument("--principal-id", help="Optional principal ID in attestation header")
    export_parser.add_argument("--tenant-id", help="Optional tenant ID in attestation header")
    export_parser.set_defaults(
        func=lambda **kw: cmd_attest_export(
            session_id=kw.get("session"),
            config_path=kw.get("config"),
            output=kw.get("output"),
            sign=bool(kw.get("sign")),
            principal_id=kw.get("principal_id"),
            tenant_id=kw.get("tenant_id"),
        )
    )

    report_parser = sub.add_parser("report", help="Generate compliance evidence report from audit JSONL")
    report_parser.add_argument(
        "--framework",
        "-f",
        required=True,
        help="Framework key: soc2, iso27001, gdpr, nist_ai_rmf",
    )
    report_parser.add_argument(
        "--audit",
        "-a",
        required=True,
        help="Path to audit JSONL log",
    )
    report_parser.add_argument("--output", "-o", help="Write markdown report to file")
    report_parser.add_argument("--from", dest="date_from", help="Filter events from ISO date")
    report_parser.add_argument("--to", dest="date_to", help="Filter events to ISO date")
    report_parser.set_defaults(
        func=lambda **kw: cmd_report(
            framework=kw.get("framework"),
            audit_path=kw.get("audit"),
            output=kw.get("output"),
            date_from=kw.get("date_from"),
            date_to=kw.get("date_to"),
        )
    )

    args = parser.parse_args()
    ns = vars(args)
    func = ns.pop("func")
    return func(**ns)


if __name__ == "__main__":
    sys.exit(main())
