"""Default-deny destination allowlist for MCP-mediated egress arguments."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from mcp_bastion.errors import EgressDeniedError

URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
HOST_KEYS = frozenset(
    {
        "url",
        "uri",
        "host",
        "hostname",
        "endpoint",
        "base_url",
        "baseurl",
        "webhook",
        "target",
        "destination",
        "server",
        "domain",
    }
)
DEFAULT_EGRESS_TOOL_HINTS = (
    "http",
    "fetch",
    "webhook",
    "email",
    "mail",
    "slack",
    "discord",
    "telegram",
    "post",
    "send",
    "upload",
    "publish",
    "request",
    "api",
)


def _normalize_host(host: str) -> str:
    return str(host or "").strip().lower().rstrip(".")


def _extract_host(raw: str) -> str | None:
    value = str(raw or "").strip()
    if not value:
        return None
    try:
        parsed = urlsplit(value if "://" in value else f"https://{value}")
        return _normalize_host(parsed.hostname or "") or None
    except (TypeError, ValueError):
        return None


class EgressAllowlist:
    """Checks hosts found in egress-like tool arguments in bounded linear time."""

    def __init__(
        self,
        allowed_hosts: list[str] | tuple[str, ...] | set[str] | None = None,
        egress_tool_hints: list[str] | tuple[str, ...] | set[str] | None = None,
    ) -> None:
        self.allowed_hosts = tuple(
            h for h in (_normalize_host(x) for x in (allowed_hosts or ())) if h
        )
        hints = egress_tool_hints or DEFAULT_EGRESS_TOOL_HINTS
        self.egress_tool_hints = tuple(str(x).strip().lower() for x in hints if str(x).strip())

    def is_egress_tool(self, tool: str) -> bool:
        name = str(tool or "").lower()
        return any(hint in name for hint in self.egress_tool_hints)

    def host_allowed(self, host: str) -> bool:
        normalized = _normalize_host(host)
        for allowed in self.allowed_hosts:
            if allowed.startswith("*."):
                suffix = allowed[2:]
                if normalized == suffix or normalized.endswith(f".{suffix}"):
                    return True
            elif normalized == allowed:
                return True
        return False

    def extract_hosts(self, arguments: Any) -> set[str]:
        hosts: set[str] = set()

        def visit(value: Any, key: str = "") -> None:
            if value is None or isinstance(value, (int, float, bool)):
                return
            if isinstance(value, str):
                if key.lower() in HOST_KEYS:
                    host = _extract_host(value)
                    if host:
                        hosts.add(host)
                for match in URL_RE.findall(value):
                    host = _extract_host(match)
                    if host:
                        hosts.add(host)
                return
            if isinstance(value, dict):
                for child_key, child in value.items():
                    visit(child, str(child_key))
                return
            if isinstance(value, (list, tuple)):
                for child in value:
                    visit(child, key)

        visit(arguments)
        return hosts

    def check(self, tool: str, arguments: Any) -> set[str]:
        """Return discovered hosts, or raise on the first denied destination."""
        if not self.is_egress_tool(tool):
            return set()
        hosts = self.extract_hosts(arguments)
        for host in sorted(hosts):
            if not self.host_allowed(host):
                raise EgressDeniedError(
                    f"Request blocked: egress host {host!r} is not allowlisted for tool {tool!r}"
                )
        return hosts
