"""
CLI for MCP-Bastion developers.

Usage:
  mcp-bastion validate [--config PATH]
  mcp-bastion serve [--config PATH] [--http PORT] [--host HOST]
  mcp-bastion dashboard [--port PORT] [--reload] [--demo | --no-demo]
"""

from __future__ import annotations

import argparse
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


def cmd_dashboard(port: int, reload: bool = False, demo: bool = False, no_demo: bool = False) -> int:
    _configure_cli_logging()
    _ensure_src_on_path()
    # Default: seed examples/dashboard_demo.py so local graphs are populated without a running MCP server.
    # Opt out: --no-demo or MCP_BASTION_DEMO=0 / false / no
    if no_demo:
        os.environ["MCP_BASTION_DEMO"] = "0"
    elif demo:
        os.environ["MCP_BASTION_DEMO"] = "1"
    else:
        os.environ.setdefault("MCP_BASTION_DEMO", "1")
    if os.environ.get("MCP_BASTION_DEMO", "").strip().lower() in ("1", "true", "yes"):
        logger.info(
            "Demo metrics enabled: graphs seed from examples/dashboard_demo.py on startup (disable: --no-demo)."
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
    # cwd first in path so `import dashboard` always loads this repo, not another package
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
    bind_host = (os.environ.get("MCP_BASTION_DASHBOARD_HOST") or "127.0.0.1").strip() or "127.0.0.1"
    logger.info("Open http://%s:%s/meta — check ui_revision matches your tree.", bind_host, port)
    uvicorn.run(
        "dashboard.app:app",
        host=bind_host,
        port=port,
        reload=do_reload,
        reload_dirs=[str(repo / "dashboard")] if do_reload else None,
    )
    return 0


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
    dash_parser.set_defaults(
        func=lambda **kw: cmd_dashboard(
            port=kw.get("port", 7000),
            reload=bool(kw.get("reload")),
            demo=bool(kw.get("demo")),
            no_demo=bool(kw.get("no_demo")),
        )
    )

    args = parser.parse_args()
    ns = vars(args)
    func = ns.pop("func")
    return func(**ns)


if __name__ == "__main__":
    sys.exit(main())
