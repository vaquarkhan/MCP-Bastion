"""Optional governance beacon for MCP inventory / shadow-MCP programs (MCP09)."""

from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_sent_lock = threading.Lock()
_sent_urls: set[str] = set()


def reset_registry_beacon_for_tests() -> None:
    """Clear per-URL dedupe state (unit tests only; not for production use)."""
    with _sent_lock:
        _sent_urls.clear()


def send_registry_beacon(url: str, payload: dict[str, Any], *, timeout_seconds: float = 5.0) -> None:
    """POST JSON once per process per URL (best-effort, non-blocking for callers)."""
    with _sent_lock:
        if url in _sent_urls:
            return
        _sent_urls.add(url)

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            resp.read(64)
    except urllib.error.URLError as e:
        logger.info("governance_beacon skipped or failed url=%s err=%s", url, e)
    except Exception as e:
        logger.info("governance_beacon error url=%s err=%s", url, e)


def schedule_registry_beacon(url: str | None, payload: dict[str, Any]) -> None:
    """Fire-and-forget background thread so startup never blocks on registry."""
    if not url:
        return

    def _run() -> None:
        send_registry_beacon(url, payload)

    t = threading.Thread(target=_run, name="mcp-bastion-governance-beacon", daemon=True)
    t.start()
