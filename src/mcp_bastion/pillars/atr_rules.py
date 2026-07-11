"""
Load community ATR (Agent Threat Rules) YAML and compile regex patterns for content matching.
Vendored rules must retain upstream LICENSE (see atr-rules/LICENSE).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")
MAX_ATR_TEXT_LEN = 64_000
MAX_ATR_PATTERN_LEN = 512


def _severity_rank(level: str) -> int:
    lv = str(level or "medium").lower()
    try:
        return _SEVERITY_ORDER.index(lv)
    except ValueError:
        return 2


class ATRRule:
    __slots__ = ("rule_id", "title", "severity", "pattern", "category")

    def __init__(self, rule_id: str, title: str, severity: str, pattern: re.Pattern[str], category: str) -> None:
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.pattern = pattern
        self.category = category


class ATRRuleLoader:
    """Load ATR-style YAML rules from a directory."""

    def __init__(self, rules_dir: str | Path, *, min_severity: str = "medium") -> None:
        self.rules_dir = Path(rules_dir)
        self.min_severity = min_severity
        self._rules: list[ATRRule] = []
        self._loaded = False

    def load(self) -> list[ATRRule]:
        if self._loaded:
            return self._rules
        self._rules = []
        if not self.rules_dir.is_dir():
            logger.warning("atr_rules: rules_dir missing %s", self.rules_dir)
            self._loaded = True
            return self._rules
        try:
            import yaml
        except ImportError:
            logger.warning("atr_rules: PyYAML required")
            self._loaded = True
            return self._rules

        min_rank = _severity_rank(self.min_severity)
        for path in sorted(self.rules_dir.glob("**/*.yml")) + sorted(self.rules_dir.glob("**/*.yaml")):
            if path.name.upper() == "LICENSE":
                continue
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except Exception as e:
                logger.warning("atr_rules: skip %s: %s", path, e)
                continue
            rules = data if isinstance(data, list) else [data]
            for raw in rules:
                if not isinstance(raw, dict):
                    continue
                sev = str(raw.get("severity", raw.get("level", "medium")))
                if _severity_rank(sev) < min_rank:
                    continue
                pattern_src = raw.get("pattern") or raw.get("detection", {}).get("pattern")
                if not pattern_src:
                    continue
                pattern_str = str(pattern_src)
                if len(pattern_str) > MAX_ATR_PATTERN_LEN:
                    logger.warning("atr_rules: skip oversized pattern in %s", path)
                    continue
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                except re.error as e:
                    logger.warning("atr_rules: bad pattern in %s: %s", path, e)
                    continue
                self._rules.append(
                    ATRRule(
                        rule_id=str(raw.get("id", path.stem)),
                        title=str(raw.get("title", raw.get("name", path.stem))),
                        severity=sev,
                        pattern=compiled,
                        category=str(raw.get("category", "unknown")),
                    )
                )
        self._loaded = True
        logger.info("atr_rules: loaded %d rules from %s", len(self._rules), self.rules_dir)
        return self._rules

    def match(self, text: str) -> ATRRule | None:
        if not text or len(text) > MAX_ATR_TEXT_LEN:
            return None
        for rule in self.load():
            if rule.pattern.search(text):
                return rule
        return None

    def denylist_patterns(self) -> list[str]:
        """Export raw pattern strings for ContentFilter merge."""
        return [r.pattern.pattern for r in self.load()]
