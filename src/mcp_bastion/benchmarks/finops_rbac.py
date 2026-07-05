"""
Reproducible RBAC and FinOps/context-reduction benchmarks.

Run via pytest (``tests/test_benchmarks_finops_rbac.py``) or:

    PYTHONPATH=src python scripts/generate_benchmark_report.py
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable

from mcp_bastion.base import MiddlewareContext
from mcp_bastion.errors import RBACError
from mcp_bastion.pillars.output_budget import OutputBudget
from mcp_bastion.pillars.rbac import RBAC
from mcp_bastion.pillars.semantic_cache import SemanticCache, _jaccard_similarity
from mcp_bastion.pillars.tokens import count_text_tokens

BENCHMARK_VERSION = "2.0.0-finops-rbac-v1"


def text_with_approx_tokens(
    target: int,
    *,
    token_counter: Callable[[str], int] | None = None,
) -> str:
    """Build text whose token count is at least ``target`` (tiktoken or char/4 estimate)."""
    counter = token_counter or count_text_tokens
    if target <= 0:
        return ""
    word = "measurement "
    text = word * max(1, target * 2)
    while counter(text) < target:
        text += word
    return text


def run_rbac_matrix(
    permissions: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """Live RBAC matrix: role × tool → allowed/denied."""
    rbac = RBAC(
        permissions
        or {
            "viewer": ["read_file"],
            "admin": ["*"],
        }
    )
    cases = (
        ("viewer", "read_file", True),
        ("viewer", "delete_db", False),
        ("admin", "delete_db", True),
        ("admin", "any_tool", True),
        ("nobody", "read_file", False),
    )
    rows: list[dict[str, Any]] = []
    for role, tool, expect_allowed in cases:
        ctx = MiddlewareContext(message={}, metadata={"role": role})
        allowed = True
        error: str | None = None
        try:
            rbac.check(tool, ctx)
        except RBACError as exc:
            allowed = False
            error = str(exc)
        rows.append(
            {
                "role": role,
                "tool": tool,
                "result": "ALLOWED" if allowed else "DENIED",
                "expected": "ALLOWED" if expect_allowed else "DENIED",
                "pass": allowed == expect_allowed,
                "error": error,
            }
        )
    return {
        "description": "Tool-level RBAC (opt-in; pair with Agent IAM or edge auth for trust)",
        "permissions": rbac.permissions,
        "rows": rows,
        "all_pass": all(r["pass"] for r in rows),
    }


def run_output_budget_benchmarks(
    input_sizes: tuple[int, ...] = (50_000, 10_000, 1_500),
    *,
    max_output_tokens: int = 4000,
    min_tokens: int = 500,
) -> dict[str, Any]:
    """Measure tool-response token reduction (not LLM prompt text)."""
    ob = OutputBudget(
        max_output_tokens=max_output_tokens,
        min_tokens=min_tokens,
        enable_offload=True,
    )
    rows: list[dict[str, Any]] = []
    for target in input_sizes:
        text = text_with_approx_tokens(target)
        original = count_text_tokens(text)
        _out, summary = ob.process_content_items(
            [{"type": "text", "text": text}],
            session_id="benchmark",
            tool_name="large_dump",
        )
        kept = summary.output_tokens
        reduction_pct = round(100.0 * (1.0 - kept / max(1, original)), 2)
        rows.append(
            {
                "target_input_tokens": target,
                "measured_input_tokens": original,
                "output_tokens_kept": kept,
                "tokens_saved": summary.tokens_saved,
                "reduction_pct": reduction_pct,
                "offloaded": summary.offloaded,
                "applied": summary.applied,
            }
        )
    return {
        "description": (
            "Output budget + session offload on tool responses. "
            "Reduction is 0% when already under budget; up to ~99% on oversized dumps."
        ),
        "config": {
            "max_output_tokens": max_output_tokens,
            "min_tokens": min_tokens,
            "enable_offload": True,
        },
        "rows": rows,
    }


def run_lexical_cache_benchmarks(
    similarity_threshold: float = 0.9,
) -> dict[str, Any]:
    """Lexical (Jaccard) cache — not embedding-based semantic search."""
    cache = SemanticCache(similarity_threshold=similarity_threshold)
    cached_query = "find all customers in the database"
    cache.set("search", cached_query, {"hit": True, "rows": 42})

    exact = cache.get("search", cached_query)
    paraphrase = "find all the customers in the database please"
    paraphrase_score = _jaccard_similarity(
        "find all customers in the database",
        "find all the customers in the database please",
    )
    near_miss = cache.get("search", paraphrase)

    return {
        "description": (
            "Lexical similarity cache (word-overlap / Jaccard). "
            "Exact/near-identical queries hit; paraphrases often miss at high thresholds."
        ),
        "similarity_threshold": similarity_threshold,
        "rows": [
            {
                "case": "exact_repeat",
                "query": cached_query,
                "cache_hit": exact is not None,
                "jaccard_vs_cached": 1.0,
            },
            {
                "case": "paraphrase_extra_words",
                "query": paraphrase,
                "cache_hit": near_miss is not None,
                "jaccard_vs_cached": round(paraphrase_score, 4),
            },
        ],
    }


def run_discovery_filter_estimate(
    total_tools: int = 20,
    allowlisted: int = 3,
) -> dict[str, Any]:
    """Estimate tool-catalog token savings when discovery filter hides unused tools."""
    def tool_schema(name: str) -> dict[str, Any]:
        return {
            "name": name,
            "description": f"Tool {name} for benchmark — reads or writes resources.",
            "inputSchema": {
                "type": "object",
                "properties": {"q": {"type": "string", "description": "Query parameter"}},
                "required": ["q"],
            },
        }

    all_tools = [tool_schema(f"tool_{i}") for i in range(total_tools)]
    kept = all_tools[:allowlisted]
    full_json = json.dumps(all_tools)
    filtered_json = json.dumps(kept)
    full_tokens = count_text_tokens(full_json)
    filtered_tokens = count_text_tokens(filtered_json)
    reduction_pct = round(100.0 * (1.0 - filtered_tokens / max(1, full_tokens)), 2)
    return {
        "description": "Discovery filter hides non-allowlisted tools from tools/list (opt-in).",
        "total_tools": total_tools,
        "allowlisted_tools": allowlisted,
        "tools_list_tokens_full": full_tokens,
        "tools_list_tokens_filtered": filtered_tokens,
        "reduction_pct": reduction_pct,
    }


def run_all_benchmarks() -> dict[str, Any]:
    """Full benchmark payload for docs and CI."""
    return {
        "benchmark_version": BENCHMARK_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "token_counter": "tiktoken cl100k_base when installed, else ~4 chars/token",
        "disclaimer": (
            "No single flat 'X% prompt reduction' applies. Savings target oversized tool "
            "outputs and tool catalogs, not user/LLM prompt text. Small responses are unchanged."
        ),
        "rbac": run_rbac_matrix(),
        "output_budget": run_output_budget_benchmarks(),
        "lexical_cache": run_lexical_cache_benchmarks(),
        "discovery_filter": run_discovery_filter_estimate(),
    }
