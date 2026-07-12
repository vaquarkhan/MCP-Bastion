"""
Proof: filesystem-style tool calls - allow README, deny .env / .git/config.

Uses examples/bastion-filesystem-guards.yaml via load_config + middleware.
Run from repo root:

  PYTHONPATH=src python examples/filesystem_env_deny_demo.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.config import build_middleware_from_config, load_config
from mcp_bastion.errors import ArgumentGuardError, ContentFilterError, MCPBastionError


def _ctx(tool: str, arguments: dict) -> MiddlewareContext:
    return MiddlewareContext(
        message={"method": "tools/call", "params": {"name": tool, "arguments": arguments}},
        request_id="demo",
        session_id="demo",
        metadata={},
    )


async def _call(mw, tool: str, arguments: dict):
    async def handler(c):
        return {"result": {"content": [{"type": "text", "text": "ok"}]}}

    return await mw(_ctx(tool, arguments), handler)


async def main() -> int:
    cfg_path = ROOT / "examples" / "bastion-filesystem-guards.yaml"
    cfg = load_config(str(cfg_path))
    mw = build_middleware_from_config(cfg)
    assert mw is not None

    cases = [
        ("read_text_file", {"path": "project/README.md"}, True),
        ("read_text_file", {"path": "project/.env"}, False),
        ("read_text_file", {"path": "project/.git/config"}, False),
        ("directory_tree", {"path": "project"}, True),
    ]

    print("MCP-Bastion filesystem path guards (proof)")
    print(f"Policy: {cfg_path.name}")
    print("")
    failed = 0
    for tool, args, expect_allow in cases:
        label = f"{tool} {args.get('path')}"
        try:
            await _call(mw, tool, args)
            allowed = True
            reason = "allow"
        except (ArgumentGuardError, ContentFilterError, MCPBastionError) as e:
            allowed = False
            reason = e.__class__.__name__
        ok = allowed == expect_allow
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        verb = "allow" if expect_allow else "deny"
        print(f"  [{mark}] expect {verb:5} | {label} -> {reason}")
    print("")
    if failed:
        print(f"Result: {failed} case(s) failed")
        return 1
    print("Result: all cases matched policy")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
