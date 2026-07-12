#!/usr/bin/env python3
"""
Public MCP tools/list census (distribution / credibility script).

External only - not a product feature, never a hosted grading service.
Scan public tool metadata only; do not call tools or send payloads.
Rate-limit, set a User-Agent, respect terms, and notify maintainers
before publishing low grades that name a project.

Usage:
  PYTHONPATH=src python scripts/census_public_mcp.py --catalog examples/fixtures/tools-clean.json
  PYTHONPATH=src python scripts/census_public_mcp.py --urls-file urls.txt --out docs/census/README.md

A urls file is one tools/list JSON URL per line (or local path).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

from mcp_bastion.static_scan import scan_tools  # noqa: E402
from mcp_bastion.pillars.tool_metadata_fingerprint import load_tools_from_json  # noqa: E402

UA = "mcp-bastion-census/1.0 (+https://github.com/vaquarkhan/MCP-Bastion; metadata-only)"


def _load_tools(source: str) -> list[dict]:
    p = Path(source)
    if p.is_file():
        return load_tools_from_json(str(p))
    req = urllib.request.Request(source, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=15) as resp:
        raw = json.loads(resp.read().decode("utf-8"))
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if isinstance(raw, dict) and isinstance(raw.get("tools"), list):
        return [x for x in raw["tools"] if isinstance(x, dict)]
    raise ValueError(f"Unrecognized tools payload from {source}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Grade public MCP tool catalogs (metadata only)")
    ap.add_argument("--catalog", action="append", default=[], help="Local tools JSON path (repeatable)")
    ap.add_argument("--urls-file", help="File with one URL or path per line")
    ap.add_argument("--out", default=str(REPO / "docs" / "census" / "README.md"))
    ap.add_argument("--delay", type=float, default=1.0, help="Seconds between remote fetches")
    args = ap.parse_args()

    sources: list[str] = list(args.catalog or [])
    if args.urls_file:
        for line in Path(args.urls_file).read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                sources.append(s)
    if not sources:
        print("Provide --catalog and/or --urls-file", file=sys.stderr)
        return 1

    rows: list[tuple[str, str, int, int]] = []
    for i, src in enumerate(sources):
        label = Path(src).name if not src.startswith("http") else src
        try:
            tools = _load_tools(src)
            report = scan_tools(tools)
            rows.append((label, report.grade, report.tool_count, len(report.findings)))
        except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError) as e:
            rows.append((label, "ERR", 0, 0))
            print(f"skip {src}: {e}", file=sys.stderr)
        if src.startswith("http") and i + 1 < len(sources):
            time.sleep(max(0.0, args.delay))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Public MCP tool-catalog census",
        "",
        f"Generated: {date.today().isoformat()}",
        "",
        "Metadata-only grades from `mcp-bastion scan`. Not a hosted service.",
        "Do not publish low grades that name a project without maintainer heads-up.",
        "",
        "| Source | Grade | Tools | Findings |",
        "|--------|-------|------:|---------:|",
    ]
    for label, grade, tools, findings in rows:
        lines.append(f"| `{label}` | {grade} | {tools} | {findings} |")
    lines.append("")
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
