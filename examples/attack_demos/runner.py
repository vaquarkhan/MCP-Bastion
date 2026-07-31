#!/usr/bin/env python3
"""Run hero attack → defense demos and print a docs-friendly report."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_SRC = _ROOT / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from examples.attack_demos.scenarios import SCENARIOS, ScenarioResult  # noqa: E402


# Force UTF-8 on Windows consoles so demo reports print cleanly
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _fmt(r: ScenarioResult) -> str:
    mark = {
        "blocked": "PASS (blocked)",
        "redacted": "PASS (redacted)",
        "allowed": "INFO (allowed)",
        "skipped": "SKIP",
    }.get(r.outcome, r.outcome.upper())
    code = f" code={r.error_code}" if r.error_code is not None else ""
    exp = f" expected={r.expected_code}" if r.expected_code is not None else ""
    return (
        f"### [{r.id}] {r.title}\n"
        f"- **Feature:** `{r.feature}`\n"
        f"- **Attack:** {r.attack}\n"
        f"- **Result:** {mark}{code}{exp}\n"
        f"- **Detail:** {r.detail}\n"
    )


def _match(only: str, r: ScenarioResult, fn_name: str) -> bool:
    o = only.lower().strip()
    return (
        o == r.id
        or o == r.id.lstrip("0")
        or o in r.feature.lower()
        or o in fn_name.lower()
        or o in r.title.lower()
    )


async def _run(only: str | None) -> list[ScenarioResult]:
    out: list[ScenarioResult] = []
    for fn in SCENARIOS:
        result = await fn()
        if only and not _match(only, result, fn.__name__):
            continue
        out.append(result)
        print(_fmt(result))
        sys.stdout.flush()
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MCP-Bastion attack → defense demos")
    parser.add_argument("--only", help="Filter by scenario id, feature, or name")
    parser.add_argument("--strict", action="store_true", help="Exit 1 if core demos fail to block")
    args = parser.parse_args(argv)

    print("# MCP-Bastion attack -> defense demos\n")
    print("See docs/ATTACK_DEMOS.md and docs/FEATURE_DEEP_DIVE.md.\n")
    results = asyncio.run(_run(args.only))

    if not results:
        print("No scenarios matched.")
        return 2

    blocked = sum(1 for r in results if r.outcome in ("blocked", "redacted"))
    skipped = sum(1 for r in results if r.outcome == "skipped")
    print("---")
    print(f"**Summary:** {blocked} defended, {skipped} skipped (optional deps), {len(results)} run.\n")

    if args.strict:
        hard = [
            r
            for r in results
            if r.outcome == "allowed"
            and r.feature
            in (
                "rate_limit",
                "content_filter",
                "rbac",
                "schema_validation",
                "replay_guard",
                "cost_tracker",
            )
        ]
        if hard:
            print("Strict mode failures:", ", ".join(r.feature for r in hard))
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
