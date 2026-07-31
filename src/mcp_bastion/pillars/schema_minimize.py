"""
Schema / description minimization for tools/list catalogs.

Opt-in FinOps + context-engineering helper: shrink verbose MCP tool manifests
without removing tools. Complements ``discovery_filter`` allowlisting.

Nature-preserving defaults: disabled unless ``discovery_filter.minimize_schemas: true``.
"""

from __future__ import annotations

import copy
import json
from typing import Any


def _strip_descriptions_in_schema(node: Any) -> Any:
    """Recursively drop ``description`` keys from JSON Schema-like dicts/lists."""
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for k, v in node.items():
            if k == "description":
                continue
            out[k] = _strip_descriptions_in_schema(v)
        return out
    if isinstance(node, list):
        return [_strip_descriptions_in_schema(x) for x in node]
    return node


def minimize_tool_dict(
    tool: dict[str, Any],
    *,
    max_description_chars: int = 160,
    strip_schema_descriptions: bool = True,
) -> dict[str, Any]:
    """
    Return a shallow-copied tool entry with truncated description and optional
    schema description stripping.
    """
    out = dict(tool)
    desc = out.get("description")
    if isinstance(desc, str) and max_description_chars >= 0 and len(desc) > max_description_chars:
        if max_description_chars == 0:
            out["description"] = ""
        else:
            out["description"] = desc[: max(0, max_description_chars - 1)].rstrip() + "…"

    if strip_schema_descriptions:
        for key in ("inputSchema", "input_schema"):
            if key in out and out[key] is not None:
                out[key] = _strip_descriptions_in_schema(copy.deepcopy(out[key]))
    return out


def estimate_tool_tokens(tools: list[dict[str, Any]]) -> int:
    try:
        from mcp_bastion.pillars.tokens import count_text_tokens

        return max(0, count_text_tokens(json.dumps(tools, default=str)))
    except Exception:
        return max(0, len(json.dumps(tools, default=str)) // 4)


def minimize_tools(
    tools: list[Any],
    *,
    max_description_chars: int = 160,
    strip_schema_descriptions: bool = True,
    to_dict: Any = None,
) -> tuple[list[dict[str, Any]], int]:
    """
    Minimize a tools/list array.

    Returns ``(minimized_dicts, tokens_saved_estimate)``.
    """

    def _default_to_dict(entry: Any) -> dict[str, Any]:
        if isinstance(entry, dict):
            return entry
        if hasattr(entry, "model_dump"):
            try:
                return entry.model_dump()
            except Exception:
                pass
        return {"name": str(entry), "description": ""}

    convert = to_dict or _default_to_dict
    before: list[dict[str, Any]] = [convert(t) for t in tools]
    after = [
        minimize_tool_dict(
            td,
            max_description_chars=max_description_chars,
            strip_schema_descriptions=strip_schema_descriptions,
        )
        for td in before
    ]
    saved = max(0, estimate_tool_tokens(before) - estimate_tool_tokens(after))
    return after, saved
