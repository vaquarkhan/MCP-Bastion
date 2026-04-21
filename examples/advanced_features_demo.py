"""
Demonstrate newer MCP-Bastion pillars in one script:

- Semantic firewall (intent mismatch and risky tool chains)
- Sensitive business content classifier (weighted local model)
- Session distinct-tool limit (MCP02-style scope creep)
- Tool metadata guard on tools/list (strip poisoned tool descriptions)

Run from repo root:

  PYTHONPATH=src python examples/advanced_features_demo.py

No torch required if prompt_guard stays off for most scenarios; sensitive_classifier
uses the built-in weighted terms (see docs and bastion.advanced.example.yaml).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys

root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(root, "src"))

logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
logger = logging.getLogger("advanced_demo")

from mcp_bastion import MCPBastionMiddleware
from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import SessionScopeExceededError
from mcp_bastion.pillars.content_filter import ContentFilter
from mcp_bastion.pillars.rate_limit import TokenBucketRateLimiter
from mcp_bastion.pillars.sensitive_classifier import SensitiveContentClassifier
from mcp_bastion.pillars.semantic_firewall import SemanticFirewall


def _ctx(msg: dict, *, session_id: str = "demo-session") -> MiddlewareContext:
    return MiddlewareContext(message=msg, request_id="r1", session_id=session_id)


async def _run(name: str, mw, msg: dict, session_id: str = "demo-session") -> None:
    async def handler(_ctx: MiddlewareContext):
        return {"ok": True}

    logger.info("--- %s ---", name)
    try:
        out = await mw(_ctx(msg, session_id=session_id), handler)
        logger.info("result=%s", out)
    except Exception as e:
        logger.info("blocked as expected: %s: %s", type(e).__name__, e)


async def demo_semantic_firewall() -> None:
    mw = MCPBastionMiddleware(
        rate_limiter=TokenBucketRateLimiter(max_iterations=50, timeout_seconds=60, token_budget=50_000),
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_content_filter=False,
        enable_semantic_firewall=True,
        semantic_firewall=SemanticFirewall(),
    )
    msg = {
        "method": "tools/call",
        "params": {"name": "get_weather", "arguments": {"city": "'; DROP TABLE users; --"}},
    }
    await _run("semantic_firewall (SQL-like args on weather tool)", mw, msg)


async def demo_sensitive_classifier() -> None:
    sc = SensitiveContentClassifier(threshold=0.25, use_transformers=False)
    mw = MCPBastionMiddleware(
        rate_limiter=TokenBucketRateLimiter(max_iterations=50, timeout_seconds=60, token_budget=50_000),
        sensitive_classifier=sc,
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_sensitive_classifier=True,
        sensitive_classifier_threshold=0.25,
        sensitive_classifier_block_labels={"sensitive_business"},
    )
    msg = {
        "method": "tools/call",
        "params": {
            "name": "upload_notes",
            "arguments": {"text": "Confidential merger and acquisition strategy for Q4 due diligence"},
        },
    }
    await _run("sensitive_classifier (business-sensitive narrative)", mw, msg)


async def demo_session_tool_limit() -> None:
    mw = MCPBastionMiddleware(
        rate_limiter=TokenBucketRateLimiter(max_iterations=50, timeout_seconds=60, token_budget=50_000),
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        session_max_unique_tools=2,
    )
    sid = "tenant:demo|sess-1"

    async def ok_handler(_ctx: MiddlewareContext):
        return {"ok": True}

    for tool in ("alpha", "beta"):
        msg = {"method": "tools/call", "params": {"name": tool, "arguments": {}}}
        await mw(_ctx(msg, session_id=sid), ok_handler)
        logger.info("allowed tool=%s", tool)

    msg = {"method": "tools/call", "params": {"name": "gamma", "arguments": {}}}
    logger.info("--- session tool limit (3rd distinct tool) ---")
    try:
        await mw(_ctx(msg, session_id=sid), ok_handler)
    except SessionScopeExceededError as e:
        logger.info("blocked as expected: %s", e)


async def demo_tool_metadata_guard() -> None:
    cf = ContentFilter(
        block_code_execution=True,
        block_file_paths=True,
        block_urls=False,
    )
    mw = MCPBastionMiddleware(
        content_filter=cf,
        rate_limiter=TokenBucketRateLimiter(max_iterations=50, timeout_seconds=60, token_budget=50_000),
        enable_prompt_guard=False,
        enable_pii_redaction=False,
        enable_rate_limit=False,
        enable_content_filter=True,
        enable_tool_metadata_guard=True,
        tool_metadata_guard_on_poison="remove_tool",
        tool_metadata_guard_use_content_filter=True,
    )

    poisoned = {
        "name": "safe_tool",
        "description": "Looks fine but references ../../etc/passwd in prose.",
        "inputSchema": {"type": "object", "properties": {}},
    }
    clean = {
        "name": "add",
        "description": "Add two integers.",
        "inputSchema": {"type": "object", "properties": {"a": {}, "b": {}}},
    }

    async def list_handler(_ctx: MiddlewareContext):
        return {"tools": [poisoned, clean]}

    logger.info("--- tool_metadata_guard (tools/list) ---")
    out = await mw(
        _ctx({"method": "tools/list", "params": {}}),
        list_handler,
    )
    assert isinstance(out, dict)
    tools = out.get("tools")
    assert isinstance(tools, list)
    names = [t.get("name") for t in tools if isinstance(t, dict)]
    logger.info("tools after guard names=%s", names)
    assert len(tools) == 1 and tools[0].get("name") == "add", tools


async def main() -> None:
    print("MCP-Bastion advanced_features_demo (see examples/README.md)\n")
    await demo_semantic_firewall()
    await demo_sensitive_classifier()
    await demo_session_tool_limit()
    await demo_tool_metadata_guard()
    print("\nAll advanced demo steps finished.")


if __name__ == "__main__":
    asyncio.run(main())
