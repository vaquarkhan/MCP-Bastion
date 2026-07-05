"""Append-only JSONL audit file sink for compliance and ``mcp-bastion tail``."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from mcp_bastion.pillars.audit_log import AuditEntry


class AuditJsonlSink:
    """Thread-safe JSONL writer for audit entries."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, entry: AuditEntry) -> None:
        line = entry.to_json() + "\n"
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)

    @staticmethod
    def tail(path: str | Path, *, lines: int = 20) -> list[dict[str, Any]]:
        p = Path(path)
        if not p.exists():
            return []
        raw_lines = p.read_text(encoding="utf-8").splitlines()
        out: list[dict[str, Any]] = []
        for line in raw_lines[-max(1, lines) :]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                out.append({"raw": line})
        return out
