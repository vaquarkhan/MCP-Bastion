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


def parse_tool_schemas(raw: Any) -> dict[str, dict[str, type]]:
    """
    Parse ``schema_validation.schemas`` from bastion.yaml.

    Example::

        schemas:
          add:
            a: integer
            b: integer
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, type]] = {}
    for tool, fields in raw.items():
        if not isinstance(fields, dict):
            continue
        tool_schema: dict[str, type] = {}
        for arg, type_spec in fields.items():
            if isinstance(type_spec, type):
                tool_schema[str(arg)] = type_spec
            elif isinstance(type_spec, str):
                key = type_spec.strip().lower()
                if key not in _SCHEMA_TYPE_ALIASES:
                    raise ValueError(
                        f"Unknown schema type {type_spec!r} for tool {tool!r} argument {arg!r}. "
                        f"Use one of: {', '.join(sorted(_SCHEMA_TYPE_ALIASES))}"
                    )
                tool_schema[str(arg)] = _SCHEMA_TYPE_ALIASES[key]
            else:
                raise ValueError(
                    f"Invalid schema type for tool {tool!r} argument {arg!r}: {type_spec!r}"
                )
        if tool_schema:
            out[str(tool)] = tool_schema
    return out


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


class SchemaValidator:
    """
    Validate tool arguments against expected schema.

    Schema: { "arg_name": type } e.g. {"customer_id": str, "amount": float}
    """

    def __init__(self, schemas: dict[str, dict[str, type]] | None = None) -> None:
        """
        schemas: { "tool_name": {"arg": type, ...} }
        """
        self.schemas = schemas or {}

    def validate_input(self, tool: str, arguments: dict[str, Any]) -> None:
        """
        Validate arguments against tool schema. Raises SchemaValidationError if invalid.
        """
        schema = self.schemas.get(tool)
        if not schema:
            return

        for key, expected_type in schema.items():
            if key not in arguments:
                raise SchemaValidationError(f"Missing required argument: {key}")

            if not _check_type(arguments[key], expected_type):
                raise SchemaValidationError(
                    f"Argument '{key}' expected {expected_type.__name__}, got {type(arguments[key]).__name__}"
                )
