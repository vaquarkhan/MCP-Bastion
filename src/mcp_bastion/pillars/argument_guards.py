"""
JSONPath argument guards — block or redact tool arguments before execution.

Inspired by gateway-style DLP patterns: match tool globs + JSONPath + regex on
argument values (including argv-array evasion via space-joined list forms).
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterator, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Literal

GuardAction = Literal["block", "redact"]

REDACTED = "***"


def _candidate_strings(value: Any) -> Iterator[str]:
    """Yield string forms tested against guard regex (handles argv-style lists)."""
    if value is None:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, (int, float, bool)):
        yield str(value)
    elif isinstance(value, list):
        parts: list[str] = []
        for element in value:
            for candidate in _candidate_strings(element):
                yield candidate
                parts.append(candidate)
        if parts:
            yield " ".join(parts)
    elif isinstance(value, dict):
        for sub in value.values():
            yield from _candidate_strings(sub)
    else:
        yield str(value)


@dataclass(frozen=True)
class GuardRule:
    name: str
    match: str
    arg: str
    pattern: str
    action: GuardAction = "block"


def parse_guard_rules(raw: list[dict[str, Any]]) -> list[GuardRule]:
    rules: list[GuardRule] = []
    for entry in raw or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "guard").strip()
        match = str(entry.get("match") or "*").strip()
        arg = str(entry.get("arg") or "$").strip()
        pattern = str(entry.get("pattern") or "").strip()
        if not pattern:
            continue
        action_raw = str(entry.get("action") or "block").strip().lower()
        action: GuardAction = "redact" if action_raw == "redact" else "block"
        rules.append(GuardRule(name=name, match=match, arg=arg, pattern=pattern, action=action))
    return rules


class _CompiledGuard:
    def __init__(self, rule: GuardRule) -> None:
        self.rule = rule
        self._tool_re = re.compile(fnmatch.translate(rule.match))
        self._pattern = re.compile(rule.pattern)
        try:
            from jsonpath_ng import parse as parse_jsonpath
        except ImportError as e:
            raise ImportError(
                "argument_guards requires jsonpath-ng: pip install mcp-bastion-python[policy]"
            ) from e
        self._jsonpath = parse_jsonpath(rule.arg)

    def matches_tool(self, tool: str) -> bool:
        return self._tool_re.match(tool) is not None

    def find_values(self, arguments: Mapping[str, Any]) -> list[Any]:
        return [match.value for match in self._jsonpath.find(dict(arguments))]

    def value_matches(self, value: Any) -> bool:
        return any(self._pattern.search(s) is not None for s in _candidate_strings(value))

    def redact_in_place(self, arguments: dict[str, Any]) -> None:
        for match in self._jsonpath.find(arguments):
            if self.value_matches(match.value):
                match.full_path.update(arguments, REDACTED)


class ArgumentGuardEngine:
    """Evaluate block/redact guard rules on tools/call arguments."""

    def __init__(self, rules: list[GuardRule]) -> None:
        self._guards = [_CompiledGuard(rule) for rule in rules]

    def check_blocking(self, tool: str, arguments: Mapping[str, Any]) -> tuple[bool, str | None]:
        for guard in self._guards:
            if guard.rule.action != "block":
                continue
            if not guard.matches_tool(tool):
                continue
            for value in guard.find_values(arguments):
                if guard.value_matches(value):
                    return False, f"blocked by argument guard '{guard.rule.name}'"
        return True, None

    def redact(self, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        redacted: dict[str, Any] = deepcopy(dict(arguments))
        for guard in self._guards:
            if guard.rule.action != "redact":
                continue
            if not guard.matches_tool(tool):
                continue
            guard.redact_in_place(redacted)
        return redacted
