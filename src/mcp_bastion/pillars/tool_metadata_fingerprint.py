"""
Tool metadata fingerprint — detect semantic schema drift (MCP tool description poisoning).

Hashes canonical tool name + description + input schema for comparison at deploy time.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def _tool_canonical(entry: dict[str, Any]) -> dict[str, Any]:
    schema = entry.get("inputSchema") or entry.get("input_schema")
    return {
        "name": str(entry.get("name") or "").strip(),
        "description": str(entry.get("description") or "").strip(),
        "inputSchema": schema,
    }


def fingerprint_tools(tools: list[dict[str, Any]]) -> str:
    """SHA-256 hex of sorted tool metadata (name, description, schema)."""
    canonical = [_tool_canonical(t if isinstance(t, dict) else {"name": str(t)}) for t in tools]
    canonical.sort(key=lambda x: x["name"])
    payload = json.dumps(canonical, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_tools_from_json(path: str | Path) -> list[dict[str, Any]]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        if isinstance(raw.get("tools"), list):
            return [t for t in raw["tools"] if isinstance(t, dict)]
        if isinstance(raw.get("fingerprint"), str) and isinstance(raw.get("tools"), list):
            return [t for t in raw["tools"] if isinstance(t, dict)]
    if isinstance(raw, list):
        return [t for t in raw if isinstance(t, dict)]
    raise ValueError("Expected tools list or {tools: [...]} JSON")


def build_fingerprint_document(tools: list[dict[str, Any]]) -> dict[str, Any]:
    fp = fingerprint_tools(tools)
    return {"algorithm": "sha256", "fingerprint": fp, "tool_count": len(tools), "tools": tools}


def verify_fingerprint(tools: list[dict[str, Any]], expected: str) -> bool:
    return fingerprint_tools(tools) == expected.strip().lower()


def load_expected_fingerprint(path: str | Path) -> str:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, str):
        return raw.strip().lower()
    if isinstance(raw, dict):
        fp = raw.get("fingerprint") or raw.get("sha256")
        if fp:
            return str(fp).strip().lower()
    raise ValueError("Fingerprint file must contain fingerprint or sha256 field")
