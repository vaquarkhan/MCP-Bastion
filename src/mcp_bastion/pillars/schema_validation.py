"""
Input/output schema validation for MCP-Bastion.

Validate tool inputs match expected schema. Catch malformed requests.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp_bastion.errors import SchemaValidationError

logger = logging.getLogger(__name__)

_SCHEMA_TYPE_ALIASES: dict[str, type] = {
    "str": str,
    "string": str,
    "int": int,
    "integer": int,
    "float": float,
    "number": float,
    "bool": bool,
    "boolean": bool,
    "dict": dict,
    "object": dict,
    "list": list,
    "array": list,
    "none": type(None),
    "null": type(None),
}


def _resolve_type_spec(type_spec: Any, *, tool: str, arg: str) -> tuple[type, bool]:
    """Return (python_type, required). required defaults True."""
    if isinstance(type_spec, type):
        return type_spec, True
    if isinstance(type_spec, str):
        key = type_spec.strip().lower()
        optional = key.endswith("?")
        if optional:
            key = key[:-1].strip()
        if key not in _SCHEMA_TYPE_ALIASES:
            raise ValueError(
                f"Unknown schema type {type_spec!r} for tool {tool!r} argument {arg!r}. "
                f"Use one of: {', '.join(sorted(_SCHEMA_TYPE_ALIASES))} (append ? for optional)"
            )
        return _SCHEMA_TYPE_ALIASES[key], not optional
    if isinstance(type_spec, dict):
        raw_t = type_spec.get("type", type_spec.get("ty"))
        if raw_t is None:
            raise ValueError(f"Missing type for tool {tool!r} argument {arg!r}")
        py_t, _ = _resolve_type_spec(raw_t, tool=tool, arg=arg)
        required = bool(type_spec.get("required", True))
        return py_t, required
    raise ValueError(f"Invalid schema type for tool {tool!r} argument {arg!r}: {type_spec!r}")


def parse_tool_schemas(raw: Any) -> tuple[dict[str, dict[str, type]], dict[str, set[str]]]:
    """
    Parse ``schema_validation.schemas`` from bastion.yaml.

    Returns ``(schemas, optional_args)`` where ``optional_args[tool]`` is the set of
    argument names that may be omitted.

    Example::

        schemas:
          add:
            a: integer
            b: integer?
          transfer:
            amount: { type: number, required: true }
            memo: { type: string, required: false }
    """
    if not isinstance(raw, dict):
        return {}, {}
    out: dict[str, dict[str, type]] = {}
    optional: dict[str, set[str]] = {}
    for tool, fields in raw.items():
        if not isinstance(fields, dict):
            continue
        tool_schema: dict[str, type] = {}
        opt: set[str] = set()
        for arg, type_spec in fields.items():
            arg_name = str(arg).rstrip("?")
            py_t, required = _resolve_type_spec(type_spec, tool=str(tool), arg=arg_name)
            # Trailing ? on the key also marks optional
            if str(arg).endswith("?"):
                required = False
            tool_schema[arg_name] = py_t
            if not required:
                opt.add(arg_name)
        if tool_schema:
            out[str(tool)] = tool_schema
            if opt:
                optional[str(tool)] = opt
    return out, optional


class SchemaValidator:
    """
    Validate tool arguments against expected schema.

    Schema: { "arg_name": type } e.g. {"customer_id": str, "amount": float}

    When ``strict=True``, arguments not listed in the schema are rejected.
    """

    def __init__(
        self,
        schemas: dict[str, dict[str, type]] | None = None,
        *,
        strict: bool = False,
        optional_args: dict[str, set[str]] | None = None,
    ) -> None:
        self.schemas = schemas or {}
        self.strict = bool(strict)
        self.optional_args = optional_args or {}

    def validate_input(self, tool: str, arguments: dict[str, Any]) -> None:
        """
        Validate arguments against tool schema. Raises SchemaValidationError if invalid.
        """
        schema = self.schemas.get(tool)
        if not schema:
            return

        optional = self.optional_args.get(tool, set())
        for key, expected_type in schema.items():
            if key not in arguments:
                if key in optional:
                    continue
                raise SchemaValidationError(f"Missing required argument: {key}")

            if not _check_type(arguments[key], expected_type):
                raise SchemaValidationError(
                    f"Argument '{key}' expected {expected_type.__name__}, "
                    f"got {type(arguments[key]).__name__}"
                )

        if self.strict:
            extras = sorted(set(arguments) - set(schema))
            if extras:
                raise SchemaValidationError(
                    f"Unexpected argument(s) not in schema: {', '.join(extras)}"
                )


def _check_type(value: Any, expected: type) -> bool:
    """Check value matches expected type."""
    if expected is str and isinstance(value, str):
        return True
    if expected is int and isinstance(value, int) and not isinstance(value, bool):
        return True
    if expected is float and isinstance(value, (int, float)) and not isinstance(value, bool):
        return True
    if expected is bool and isinstance(value, bool):
        return True
    if expected is dict and isinstance(value, dict):
        return True
    if expected is list and isinstance(value, list):
        return True
    return isinstance(value, expected)
