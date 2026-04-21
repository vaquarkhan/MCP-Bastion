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
import time
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


def _ensure_repo_layout() -> None:
    src = REPO_ROOT / "src"
    if not src.is_dir():
        print(f"Expected src/ under repo root: {REPO_ROOT}", file=sys.stderr)
        print("Run from the MCP-Bastion clone (folder that contains src/ and dashboard/).", file=sys.stderr)
        sys.exit(1)
    if not (REPO_ROOT / "dashboard" / "app.py").is_file():
        print(f"Expected dashboard/app.py under {REPO_ROOT}", file=sys.stderr)
        sys.exit(1)


def live_simulator(stop: threading.Event, rng: random.Random) -> None:
    from mcp_bastion.pillars.metrics import MetricsStore

    tools = (
        "read_file",
        "write_file",
        "web_search",
        "invoke_github",
        "query_llm",
        "query_db",
    )
    reasons = (
        "rate limit: too many requests",
        "Prompt injection blocked by guard",
        "RBAC: cannot access tool for role viewer",
        "schema validation failed: missing required field",
        "circuit breaker tripped on upstream",
    )
    users = ("alice@acme.com", "bob@acme.com", "dana@acme.com")
    pii_types = (
        "EMAIL_ADDRESS",
        "PERSON",
        "PHONE_NUMBER",
        "LOCATION",
        "ORGANIZATION",
        "DATE_TIME",
        "IP_ADDRESS",
        "URL",
        "CREDIT_CARD",
        "US_SSN",
        "NRP",
    )

    while not stop.wait(rng.uniform(0.25, 1.1)):
        store = MetricsStore.get()
        roll = rng.random()
        if roll < 0.68:
            store.record_request(rng.choice(tools))
        elif roll < 0.86:
            store.record_blocked(
                rng.choice(reasons),
                rng.choice(tools),
                tenant_id=rng.choice(("acme-prod", "acme-staging", "tenant-demo", "default")),
            )
        elif roll < 0.92:
            store.record_cost(rng.uniform(0.001, 0.06), rng.choice(users))
        elif roll < 0.96:
            if rng.random() < 0.15:
                a, b = rng.sample(pii_types, 2)
                store.record_pii_entities({a: rng.randint(1, 2), b: rng.randint(1, 2)})
            else:
                store.record_pii_entities({rng.choice(pii_types): rng.randint(1, 4)})
        else:
            store.record_tool_latency_ms(rng.choice(tools), rng.uniform(8.0, 90.0))
        store.record_latency_ms(rng.uniform(4.0, 62.0))
        if roll > 0.985:
            store.add_alert("demo", "Synthetic alert from dashboard_demo.py", "warning")


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

    try:
        import uvicorn
    except ImportError:
        print("Install dashboard deps: pip install fastapi uvicorn", file=sys.stderr)
        return 1

    rng = random.Random(42)
    seed_metrics(rng)
    print("Seeded dummy metrics (time series + KPIs + alerts).")

    stop = threading.Event()
    if not args.no_live:
        threading.Thread(target=live_simulator, args=(stop, rng), daemon=True).start()

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
