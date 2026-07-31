"""
Tool metadata fingerprint - detect semantic schema drift (MCP tool description poisoning).

Hashes canonical tool name + description + input schema for comparison at deploy time.
Optional live pin: hash catalog on first sight, block/warn on later drift (runtime).
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from mcp_bastion.pillars.state_backend import MemoryStateBackend, StateBackend

logger = logging.getLogger(__name__)


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


class LiveCatalogPin:
    """
    Runtime tool-catalog pin.

    - If ``expected`` is set: compare every tools/list against that static hash.
    - If ``pin_on_first_seen``: store first-seen hash in ``StateBackend`` and compare later.
    - ``on_drift``: ``warn`` (metadata only) or ``block`` (raise).
    """

    def __init__(
        self,
        backend: StateBackend | None = None,
        *,
        pin_on_first_seen: bool = False,
        on_drift: str = "warn",
        expected: str | None = None,
        key_prefix: str = "tool_catalog_pin",
        ttl_seconds: float = 86400.0 * 7,
    ) -> None:
        drift = (on_drift or "warn").strip().lower()
        if drift not in ("warn", "block"):
            raise ValueError("on_drift must be 'warn' or 'block'")
        self.backend = backend or MemoryStateBackend()
        self.pin_on_first_seen = bool(pin_on_first_seen)
        self.on_drift = drift
        self.expected = expected.strip().lower() if expected else None
        self.key_prefix = key_prefix
        self.ttl_seconds = float(ttl_seconds) if ttl_seconds > 0 else 86400.0 * 7

    def _key(self, scope: str) -> str:
        return f"{self.key_prefix}:{scope or 'global'}"

    def check(
        self,
        tools: list[dict[str, Any]],
        *,
        scope: str = "global",
    ) -> dict[str, Any]:
        """
        Check catalog fingerprint.

        Returns dict with keys: status (ok|pinned|drift), fingerprint, expected|pinned,
        and optional detail.
        """
        fp = fingerprint_tools(tools)
        if self.expected:
            if fp != self.expected:
                return {
                    "status": "drift",
                    "fingerprint": fp,
                    "expected": self.expected,
                    "detail": "catalog fingerprint != configured expected",
                }
            return {"status": "ok", "fingerprint": fp, "expected": self.expected}

        if not self.pin_on_first_seen:
            return {"status": "ok", "fingerprint": fp, "detail": "pin_on_first_seen disabled"}

        key = self._key(scope)
        stored = self.backend.get(key)
        if not stored:
            self.backend.set(key, fp, ttl_seconds=self.ttl_seconds)
            logger.debug("live catalog pin stored scope=%s fp=%s…", scope, fp[:12])
            return {"status": "pinned", "fingerprint": fp, "pinned": fp}

        if str(stored).strip().lower() != fp:
            return {
                "status": "drift",
                "fingerprint": fp,
                "pinned": str(stored).strip().lower(),
                "detail": "catalog fingerprint drifted from first-seen pin",
            }
        return {"status": "ok", "fingerprint": fp, "pinned": str(stored).strip().lower()}
