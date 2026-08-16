"""Deterministic per-parameter business rules for MCP tool calls."""

from __future__ import annotations

import fnmatch
from typing import Any

from mcp_bastion.errors import BusinessRuleDeniedError

_MISSING = object()


def _lookup(value: Any, path: str) -> Any:
    normalized = str(path or "").strip()
    if normalized.startswith("$."):
        normalized = normalized[2:]
    elif normalized == "$":
        return value
    current = value
    for part in normalized.replace("[", ".").replace("]", "").split("."):
        if not part:
            continue
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, (list, tuple)) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return _MISSING
    return current


class BusinessRuleEngine:
    """Evaluate a bounded configured rule list; a matching violation denies."""

    def __init__(
        self,
        rules: list[dict[str, Any]] | None = None,
        *,
        deny_prod_env_from_staging_caller: bool = False,
    ) -> None:
        self.rules = tuple(r for r in (rules or []) if isinstance(r, dict))
        self.deny_prod_env_from_staging_caller = bool(deny_prod_env_from_staging_caller)

    @staticmethod
    def _denied(op: str, actual: Any, expected: Any) -> bool:
        if actual is _MISSING:
            return False
        if op == "eq":
            return actual == expected
        if op == "neq":
            return actual != expected
        if op == "max":
            try:
                return float(actual) > float(expected)
            except (TypeError, ValueError):
                return True
        if op == "min":
            try:
                return float(actual) < float(expected)
            except (TypeError, ValueError):
                return True
        values = expected if isinstance(expected, (list, tuple, set)) else [expected]
        if op == "in":
            return actual in values
        if op == "not_in":
            return actual not in values
        if op == "env_deny":
            text = str(actual).strip().lower()
            return any(str(item).strip().lower() in text for item in values)
        return True  # fail closed for an unknown configured operation

    def check(self, tool: str, arguments: dict[str, Any], caller_meta: dict[str, Any]) -> None:
        if self.deny_prod_env_from_staging_caller:
            caller_env = str(caller_meta.get("env") or caller_meta.get("environment") or "").lower()
            target_env = _lookup(arguments, "environment")
            if target_env is _MISSING:
                target_env = _lookup(arguments, "env")
            if caller_env == "staging" and target_env is not _MISSING and "prod" in str(target_env).lower():
                raise BusinessRuleDeniedError(
                    "Request blocked: staging caller cannot target a production environment"
                )

        for index, rule in enumerate(self.rules):
            pattern = str(rule.get("tool") or "*")
            if not fnmatch.fnmatchcase(tool, pattern):
                continue
            param = str(rule.get("param") or "")
            op = str(rule.get("op") or "").strip().lower()
            actual = _lookup(arguments, param)
            if self._denied(op, actual, rule.get("value")):
                raise BusinessRuleDeniedError(
                    f"Request blocked: business rule {index + 1} denied {tool!r} parameter {param!r} ({op})"
                )
