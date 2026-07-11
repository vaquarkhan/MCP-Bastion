"""
Opt-in threat-intel feed refresh: merge remote regex rules into scanners (fail-safe).
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable

logger = logging.getLogger(__name__)

MAX_FEED_PATTERN_LEN = 512


class ThreatFeed:
    __slots__ = ("url", "scanner", "interval_minutes", "patterns", "_last_key")

    def __init__(self, url: str, scanner: str, interval_minutes: int = 60) -> None:
        self.url = url
        self.scanner = scanner
        self.interval_minutes = max(1, interval_minutes)
        self.patterns: list[str] = []
        self._last_key = ""


class ThreatFeedManager:
    """Background refresh of named scanner rule feeds."""

    def __init__(
        self,
        feeds: list[dict[str, Any]],
        *,
        on_refresh: Callable[[], None] | None = None,
    ) -> None:
        self._feeds = [
            ThreatFeed(
                url=str(f["url"]),
                scanner=str(f.get("scanner", "prompt_injection")),
                interval_minutes=int(f.get("interval_minutes", 60)),
            )
            for f in feeds
            if f.get("url")
        ]
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._on_refresh = on_refresh

    def patterns_for(self, scanner: str) -> list[str]:
        with self._lock:
            out: list[str] = []
            for feed in self._feeds:
                if feed.scanner == scanner:
                    out.extend(feed.patterns)
            return out

    def refresh_feed(self, feed: ThreatFeed) -> None:
        try:
            with urllib.request.urlopen(feed.url, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, json.JSONDecodeError, OSError, TimeoutError) as e:
            logger.warning("threat_feeds: refresh failed %s: %s (keeping last good)", feed.url, e)
            return
        patterns: list[str] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    patterns.append(item)
                elif isinstance(item, dict) and item.get("pattern"):
                    patterns.append(str(item["pattern"]))
        elif isinstance(data, dict) and "patterns" in data:
            patterns = [str(p) for p in data["patterns"]]
        # validate compile
        valid: list[str] = []
        for p in patterns:
            if len(p) > MAX_FEED_PATTERN_LEN:
                logger.warning("threat_feeds: skip oversized pattern from %s", feed.url)
                continue
            try:
                re.compile(p)
                valid.append(p)
            except re.error:
                logger.warning("threat_feeds: skip bad pattern from %s", feed.url)
        with self._lock:
            feed.patterns = valid
        logger.info("threat_feeds: refreshed %d patterns from %s", len(valid), feed.url)
        if self._on_refresh is not None:
            try:
                self._on_refresh()
            except Exception as e:
                logger.warning("threat_feeds: on_refresh callback failed: %s", e)

    def refresh_all(self) -> None:
        for feed in self._feeds:
            self.refresh_feed(feed)

    def start_background(self) -> None:
        if self._thread is not None:
            return
        self.refresh_all()

        def _loop() -> None:
            while not self._stop.wait(30):
                now = time.time()
                for feed in self._feeds:
                    # simple stagger: refresh each feed on its interval
                    key = f"{feed.url}:{int(now // (feed.interval_minutes * 60))}"
                    if feed._last_key != key:
                        feed._last_key = key
                        self.refresh_feed(feed)

        self._thread = threading.Thread(target=_loop, name="bastion-threat-feeds", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
