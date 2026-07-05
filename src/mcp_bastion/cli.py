"""
CLI for MCP-Bastion developers.

Usage:
  mcp-bastion validate [--config PATH]
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


def cmd_serve(config_path: str | None, http_port: int | None, host: str) -> int:
    _configure_cli_logging()
    _ensure_src_on_path()
    try:
        from mcp_bastion.config import load_config
    except ImportError as e:
        logger.error("Error: %s", e)
        return 1
    if config_path:
        os.environ["BASTION_CONFIG"] = config_path
    try:
        load_config(config_path or os.environ.get("BASTION_CONFIG", "bastion.yaml"))
    except Exception as e:
        logger.error("Config error: %s", e)
        return 1
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
    serve_parser.set_defaults(func=lambda **kw: cmd_serve(kw.get("config"), kw.get("http"), kw.get("host", "127.0.0.1")))

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

    args = parser.parse_args()
    ns = vars(args)
    func = ns.pop("func")
    return func(**ns)


if __name__ == "__main__":
    sys.exit(main())
