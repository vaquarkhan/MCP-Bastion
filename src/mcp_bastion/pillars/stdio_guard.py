"""
stdio stdout guard - blocks non-JSON-RPC lines on MCP stdio transport.

Mitigates dependency code printing to stdout and impersonating the MCP server.
Install via install_stdio_guard() before mcp.run() when stdio_guard is enabled.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any, TextIO

logger = logging.getLogger(__name__)

_installed = False


def is_valid_json_rpc_line(line: str) -> bool:
    """Return True if line is empty or valid JSON (object or array)."""
    stripped = line.strip()
    if not stripped:
        return True
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return False
    try:
        json.loads(stripped)
        return True
    except json.JSONDecodeError:
        return False


class JsonRpcStdoutGuard:
    """Wrap stdout and drop lines that are not valid JSON-RPC payloads."""

    def __init__(self, inner: TextIO) -> None:
        self._inner = inner
        self._buffer = ""

    def write(self, s: str) -> int:
        if not s:
            return 0
        self._buffer += s
        written = 0
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            line_with_nl = line + "\n"
            if is_valid_json_rpc_line(line):
                written += self._inner.write(line_with_nl)
            else:
                logger.error(
                    "stdio_guard blocked non-JSON stdout line (%d bytes): %.120r",
                    len(line),
                    line,
                )
        return written

    def flush(self) -> None:
        if self._buffer:
            if is_valid_json_rpc_line(self._buffer):
                self._inner.write(self._buffer)
            else:
                logger.error("stdio_guard blocked trailing non-JSON stdout: %.120r", self._buffer)
            self._buffer = ""
        self._inner.flush()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def install_stdio_guard(*, force: bool = False) -> bool:
    """Replace sys.stdout with JsonRpcStdoutGuard. Idempotent unless force=True."""
    global _installed
    if _installed and not force:
        return False
    if isinstance(sys.stdout, JsonRpcStdoutGuard):
        _installed = True
        return False
    sys.stdout = JsonRpcStdoutGuard(sys.stdout)  # type: ignore[assignment]
    _installed = True
    logger.info("stdio_guard installed on sys.stdout")
    return True


def stdio_guard_installed() -> bool:
    return _installed or isinstance(sys.stdout, JsonRpcStdoutGuard)
