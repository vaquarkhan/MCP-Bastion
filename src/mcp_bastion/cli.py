"""
CLI for MCP-Bastion developers.

Usage:
  mcp-bastion validate [--config PATH]
  mcp-bastion serve [--config PATH] [--http PORT] [--host HOST]
  mcp-bastion dashboard [--port PORT]
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
        from mcp_bastion.config import load_config
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


def cmd_dashboard(port: int) -> int:
    _configure_cli_logging()
    _ensure_src_on_path()
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
    # cwd first in path so `import dashboard` always loads this repo, not another package
    sys.path.insert(0, str(repo))
    sys.path.insert(0, str(repo / "src"))
    dash_py = repo / "dashboard" / "app.py"
    logger.info("Dashboard app: %s", dash_py)
    uvicorn.run(
        "dashboard.app:app",
        host="0.0.0.0",
        port=port,
        reload=False,
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
        logger.info("Redteam score (blocked%%): %.2f", float(report.get("score_blocked_pct", 0.0)))
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


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="mcp-bastion",
        description="MCP-Bastion CLI for developers.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    validate_parser = sub.add_parser("validate", help="Validate bastion.yaml")
    validate_parser.add_argument("--config", "-c", help="Path to bastion.yaml", default="bastion.yaml")
    validate_parser.set_defaults(func=lambda **kw: cmd_validate(kw.get("config")))

    serve_parser = sub.add_parser("serve", help="Run MCP server with config")
    serve_parser.add_argument("--config", "-c", help="Path to bastion.yaml", default="bastion.yaml")
    serve_parser.add_argument("--http", type=int, metavar="PORT", default=8080, help="HTTP port (default 8080)")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Bind host")
    serve_parser.set_defaults(func=lambda **kw: cmd_serve(kw.get("config"), kw.get("http"), kw.get("host", "0.0.0.0")))

    dash_parser = sub.add_parser("dashboard", help="Run metrics dashboard")
    dash_parser.add_argument("--port", "-p", type=int, default=7000, help="Dashboard port (default 7000)")
    dash_parser.set_defaults(func=lambda **kw: cmd_dashboard(kw.get("port", 7000)))

    redteam_parser = sub.add_parser("redteam", help="Run integrated red-team security suite")
    redteam_parser.add_argument("--config", "-c", help="Path to bastion.yaml", default="bastion.yaml")
    redteam_parser.add_argument("--output", "-o", help="Write JSON report to file", default=None)
    redteam_parser.set_defaults(func=lambda **kw: cmd_redteam(kw.get("config"), kw.get("output")))

    doctor_parser = sub.add_parser("doctor", help="Config + optional supply-chain checks (MCP04)")
    doctor_parser.add_argument("--config", "-c", help="Path to bastion.yaml", default=None)
    doctor_parser.add_argument("--repo-root", help="Directory for manifest discovery", default=None)
    doctor_parser.set_defaults(func=lambda **kw: cmd_doctor(kw.get("config"), kw.get("repo_root")))

    args = parser.parse_args()
    ns = vars(args)
    func = ns.pop("func")
    return func(**ns)


if __name__ == "__main__":
    sys.exit(main())
