"""
OWASP MCP Top 10 alignment: runnable snippets for Bastion controls.

Maps each block to the tags used in docs/OWASP_MCP_TOP10.md and in
`mcp-bastion redteam` JSON (`mcp_top10_summary`). For the full mapping table
see that doc. This script does not replace the red-team suite; it shows how
middleware behaves for common controls on arbitrary `tools/call` names.

Run from repo root:

  PYTHONPATH=src python examples/owasp_security_showcase.py

Optional: after the async demos, set `MCP_BASTION_OWASP_RUN_REDTO_TEAM=1` to run
`run_redteam_sync()` (needs a loadable `bastion.yaml` or `BASTION_CONFIG`; can be
slow and may hit Hugging Face if prompt guard is enabled in that config). Otherwise
use the CLI: `mcp-bastion redteam -c bastion.yaml -o redteam-report.json`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(root, "src"))

logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("owasp_showcase")

from mcp_bastion import MCPBastionMiddleware
from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import (
    AuthenticationError,
    ContentFilterError,
    ReplayAttackError,
    ToolNotAllowedError,
)
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.replay_guard import ReplayGuard


def _ctx(
    msg: dict,
    *,
    session_id: str = "owasp-demo",
    metadata: dict | None = None,
) -> MiddlewareContext:
    return MiddlewareContext(
        message=msg,
        request_id="r-owasp",
        session_id=session_id,
        metadata=dict(metadata or {}),
    )


def _base_mw(**kwargs) -> MCPBastionMiddleware:
    defaults = dict(
        rate_limiter=TokenBucketRateLimiter(max_iterations=100, timeout_seconds=120, token_budget=100_000),
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_content_filter=False,
    )
    defaults.update(kwargs)
    return MCPBastionMiddleware(**defaults)


async def _call(mw: MCPBastionMiddleware, msg: dict, meta: dict | None = None) -> None:
    async def h(_c: MiddlewareContext):
        return {"ok": True}

    await mw(_ctx(msg, metadata=meta), h)


async def demo_mcp05_any_tool_same_stack() -> None:
    """MCP05/MCP06: one Bastion stack evaluates every tool name your MCP server exposes."""
    print("\n[MCP05/MCP06] Same middleware for arbitrary tool names (all allowed here)")
    mw = _base_mw()
    for name in ("search_contracts", "query_snowflake", "post_slack_message", "custom_vendor_api"):
        msg = {"method": "tools/call", "params": {"name": name, "arguments": {"q": "hello"}}}
        await _call(mw, msg)
        print(f"  tools/call name={name!r} -> allowed")


async def demo_mcp01_block_secrets() -> None:
    """MCP01: block high-confidence secret-like material in arguments."""
    print("\n[MCP01] content_filter.block_secrets")
    cf = ContentFilter(
        block_code_execution=False,
        block_file_paths=False,
        block_urls=False,
        block_secrets=True,
    )
    mw = _base_mw(content_filter=cf, enable_content_filter=True)
    msg = {
        "method": "tools/call",
        "params": {
            "name": "ask_llm",
            "arguments": {"prompt": "Use this AWS key AKIAIOSFODNN7EXAMPLE in production"},
        },
    }
    try:
        await _call(mw, msg)
        print("  unexpected: request was allowed")
    except ContentFilterError as e:
        print(f"  blocked as expected: {e}")


async def demo_mcp03_tool_allowlist() -> None:
    """MCP03: strict tool surface (shadow tools not on list)."""
    print("\n[MCP03] tool_allowlist")
    mw = _base_mw(
        enable_tool_allowlist=True,
        tool_allowlist=frozenset({"add", "read_data"}),
    )
    msg = {"method": "tools/call", "params": {"name": "__shadow_mcp_tool__", "arguments": {}}}
    try:
        await _call(mw, msg)
        print("  unexpected: shadow tool allowed")
    except ToolNotAllowedError as e:
        print(f"  blocked as expected: {e}")


async def demo_mcp07_edge_auth() -> None:
    """MCP07: shared secret in context.metadata before tools run."""
    print("\n[MCP07] edge_auth (metadata token)")
    secret = "demo-edge-shared-secret"
    mw = _base_mw(
        enable_edge_auth=True,
        edge_auth_metadata_key="bastion_edge_token",
        edge_auth_secret=secret,
    )
    bad = {"method": "tools/call", "params": {"name": "add", "arguments": {"a": 1, "b": 2}}}
    try:
        await _call(mw, bad, meta={})
        print("  unexpected: missing token allowed")
    except AuthenticationError as e:
        print(f"  missing token blocked: {e}")

    good = {"method": "tools/call", "params": {"name": "add", "arguments": {"a": 1, "b": 2}}}
    await _call(mw, good, meta={"bastion_edge_token": secret})
    print("  valid token -> allowed")


async def demo_mcp08_replay_guard() -> None:
    """MCP08: replay / duplicate nonce."""
    print("\n[MCP08] replay_guard (duplicate nonce)")
    rg = ReplayGuard(require_nonce=True, max_request_age_seconds=120.0)
    mw = _base_mw(replay_guard=rg, enable_replay_guard=True)
    nonce = "nonce-demo-001"
    ts = time.time()
    msg = {
        "method": "tools/call",
        "params": {"name": "add", "arguments": {"a": 1, "b": 2}, "nonce": nonce, "timestamp": ts},
    }
    await _call(mw, msg)
    print("  first request with nonce -> allowed")
    try:
        await _call(mw, msg)
        print("  unexpected: replay allowed")
    except ReplayAttackError as e:
        print(f"  replay blocked: {e}")


def print_redteam_summary() -> None:
    """Full suite: OWASP LLM + MCP Top 10 tags in JSON (CLI: mcp-bastion redteam)."""
    print("\n[Red team] run_redteam_sync (needs bastion.yaml or BASTION_CONFIG)")
    try:
        from mcp_bastion.redteam import run_redteam_sync

        report = run_redteam_sync(None)
        summary = report.get("mcp_top10_summary") or {}
        print("  score_blocked_pct:", report.get("score_blocked_pct"))
        print("  mcp_top10_summary (attempts/blocked per tag):")
        for tag, row in sorted(summary.items()):
            print(f"    {tag}: {row}")
    except Exception as e:
        print(f"  skipped: {e}")


async def main() -> None:
    print("MCP-Bastion OWASP security showcase")
    print("  Mapping: docs/OWASP_MCP_TOP10.md")
    print("  More demos: examples/advanced_features_demo.py")
    await demo_mcp05_any_tool_same_stack()
    await demo_mcp01_block_secrets()
    await demo_mcp03_tool_allowlist()
    await demo_mcp07_edge_auth()
    await demo_mcp08_replay_guard()
    print("\nDone. Run: mcp-bastion redteam -c bastion.yaml -o redteam-report.json")


if __name__ == "__main__":
    asyncio.run(main())
    if os.environ.get("MCP_BASTION_OWASP_RUN_REDTO_TEAM") == "1":
        print_redteam_summary()
    else:
        print(
            "\n[Red team] skipped (set MCP_BASTION_OWASP_RUN_REDTO_TEAM=1 to run "
            "run_redteam_sync here, or use: mcp-bastion redteam -c bastion.yaml)"
        )
