#!/usr/bin/env python3
"""
MCP-Bastion dashboard with rich dummy metrics (run from repo root OR from this folder).

  Option A — repo root (recommended):
    Windows:  set PYTHONPATH=src && python examples/dashboard_demo.py
    Unix:     PYTHONPATH=src python examples/dashboard_demo.py

  Option B — examples folder (no PYTHONPATH needed; paths are fixed automatically):
    cd examples
    python dashboard_demo.py

Requires: pip install fastapi uvicorn

Open http://127.0.0.1:PORT/ — if the page loads but metrics fail, use 127.0.0.1 instead of localhost.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import threading
from pathlib import Path

# Repo root: parent of examples/ (this file lives at examples/dashboard_demo.py)
REPO_ROOT = Path(__file__).resolve().parent.parent


def _bootstrap_sys_path() -> None:
    """So `mcp_bastion` and `dashboard` import without PYTHONPATH when cwd is wrong."""
    r = str(REPO_ROOT)
    s = str(REPO_ROOT / "src")
    if r not in sys.path:
        sys.path.insert(0, r)
    if s not in sys.path:
        sys.path.insert(0, s)


_bootstrap_sys_path()

from mcp_bastion.demo_dashboard_metrics import seed_metrics
from mcp_bastion.demo_live_traffic import live_simulator


def _ensure_repo_layout() -> None:
    src = REPO_ROOT / "src"
    if not src.is_dir():
        print(f"Expected src/ under repo root: {REPO_ROOT}", file=sys.stderr)
        print("Run from the MCP-Bastion clone (folder that contains src/ and dashboard/).", file=sys.stderr)
        sys.exit(1)
    if not (REPO_ROOT / "dashboard" / "app.py").is_file():
        print(f"Expected dashboard/app.py under {REPO_ROOT}", file=sys.stderr)
        sys.exit(1)


def _configure_stdio() -> None:
    """Avoid UnicodeEncodeError on Windows (cp1252) when printing before uvicorn starts."""
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if callable(reconf):
            try:
                reconf(encoding="utf-8", errors="replace")
            except Exception:
                pass


def main() -> int:
    _configure_stdio()
    parser = argparse.ArgumentParser(description="MCP-Bastion dashboard with dummy metrics.")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default 127.0.0.1 — use 0.0.0.0 for LAN)",
    )
    parser.add_argument("--port", "-p", type=int, default=7000, help="First port to try (default 7000)")
    parser.add_argument(
        "--no-live",
        action="store_true",
        help="Do not spawn background traffic (static seed only)",
    )
    args = parser.parse_args()

    _ensure_repo_layout()
    os.chdir(REPO_ROOT)

    # Ensure dashboard lifespan/API agree to load synthetic data (matches python dashboard/app.py defaults).
    os.environ["MCP_BASTION_DEMO"] = "1"
    if args.no_live:
        os.environ["MCP_BASTION_DEMO_LIVE"] = "0"
    else:
        os.environ["MCP_BASTION_DEMO_LIVE"] = "1"

    try:
        import uvicorn
    except ImportError:
        print("Install dashboard deps: pip install fastapi uvicorn", file=sys.stderr)
        return 1

    from mcp_bastion.config import load_config

    cfg = load_config()
    rng = random.Random(42)
    seed_metrics(rng, config=cfg)
    print("Seeded dummy metrics (time series + KPIs + alerts).")

    stop = threading.Event()
    if not args.no_live:
        threading.Thread(target=live_simulator, args=(stop, rng, cfg), daemon=True).start()
        print("Background simulation: MCP_BASTION_DEMO_LIVE=1 (use --no-live for static snapshot only).")

    from dashboard.app import app

    for offset in range(8):
        port = args.port + offset
        try:
            print(f"  Open: http://127.0.0.1:{port}/  (or http://localhost:{port}/ )")
            uvicorn.run(app, host=args.host, port=port, log_level="info")
            return 0
        except OSError as e:
            err = str(e).lower()
            if offset < 7 and (
                "10048" in str(e)
                or "address already in use" in err
                or "only one usage" in err
                or "eaddrinuse" in err
            ):
                print(f"Port {port} busy, trying {port + 1}...", file=sys.stderr)
                continue
            print(f"Cannot bind {args.host}:{port}: {e}", file=sys.stderr)
            return 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
