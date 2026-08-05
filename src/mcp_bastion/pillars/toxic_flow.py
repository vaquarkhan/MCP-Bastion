"""
Toxic-flow / taint tracking (in-process).

Detect session patterns where sensitive data (PII/secrets) was observed on a tool
result, then a later tool call looks like external egress with that data in args.

This is the class of attack Invariant highlighted (toxic flows): wire proxies struggle
to correlate; an in-process middleware can.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from mcp_bastion.errors import ToxicFlowError

_URL_RE = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


@dataclass
class TaintMark:
    kinds: set[str] = field(default_factory=set)
    tools: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"kinds": sorted(self.kinds), "tools": list(self.tools)[-8:]}


class ToxicFlowTracker:
    """Per-session taint store + egress checks."""

    def __init__(
        self,
        *,
        enabled: bool = True,
        on_violation: str = "block",  # block | warn
    ) -> None:
        self.enabled = enabled
        self.on_violation = on_violation if on_violation in ("block", "warn") else "block"
        self._sessions: dict[str, TaintMark] = defaultdict(TaintMark)

    @staticmethod
    def _is_external_write_tool(tool: str) -> bool:
        t = (tool or "").lower()
        return any(
            x in t
            for x in (
                "webhook",
                "http",
                "fetch",
                "api",
                "post",
                "send",
                "publish",
                "email",
                "mail",
                "upload",
                "slack",
                "discord",
                "telegram",
                "exfil",
            )
        )

    @staticmethod
    def _flatten(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float, bool)):
            return str(value)
        if isinstance(value, dict):
            return " ".join(ToxicFlowTracker._flatten(v) for v in value.values())
        if isinstance(value, (list, tuple)):
            return " ".join(ToxicFlowTracker._flatten(v) for v in value)
        return str(value)

    def mark(
        self,
        session_id: str | None,
        *,
        kinds: list[str] | set[str],
        tool: str | None = None,
    ) -> None:
        if not self.enabled:
            return
        sid = session_id or "default"
        mark = self._sessions[sid]
        for k in kinds:
            if k:
                mark.kinds.add(str(k))
        if tool:
            mark.tools.append(str(tool))

    def mark_from_pii_spans(
        self,
        session_id: str | None,
        entity_types: list[str] | set[str],
        *,
        tool: str | None = None,
    ) -> None:
        kinds = set()
        for et in entity_types:
            e = str(et).upper()
            if any(x in e for x in ("SECRET", "PASSWORD", "KEY", "TOKEN", "CREDENTIAL", "AWS")):
                kinds.add("secret")
            else:
                kinds.add("pii")
        if kinds:
            self.mark(session_id, kinds=kinds, tool=tool)

    def check_egress(self, tool: str, arguments: Any, session_id: str | None) -> None:
        """Raise ToxicFlowError when tainted session calls an egress-like tool with sink args."""
        if not self.enabled:
            return
        sid = session_id or "default"
        mark = self._sessions.get(sid)
        if not mark or not mark.kinds:
            return
        if not self._is_external_write_tool(tool):
            return
        text = self._flatten(arguments)
        has_sink = bool(_URL_RE.search(text) or _EMAIL_RE.search(text))
        if not has_sink:
            return
        msg = (
            f"Toxic flow blocked: session carried {sorted(mark.kinds)} from "
            f"{mark.tools[-3:] or ['prior tools']} then called egress tool {tool!r} "
            f"with URL/email arguments"
        )
        if self.on_violation == "warn":
            return
        raise ToxicFlowError(msg)

    def clear(self, session_id: str | None) -> None:
        self._sessions.pop(session_id or "default", None)
