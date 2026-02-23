"""Tests for schema validation pillar."""

import pytest

from mcp_bastion.errors import SchemaValidationError
from mcp_bastion.pillars.schema_validation import SchemaValidator


def test_schema_validator_empty_schema_passthrough():
    """No schema for tool allows any input."""
    sv = SchemaValidator()
    sv.validate_input("unknown_tool", {"a": 1, "b": "x"})


def test_schema_validator_valid_input():
    """Valid input passes."""
    sv = SchemaValidator({"add": {"a": int, "b": int}})
    sv.validate_input("add", {"a": 1, "b": 2})


def test_schema_validator_missing_arg():
    """Missing required arg raises."""
    sv = SchemaValidator({"add": {"a": int, "b": int}})
    with pytest.raises(SchemaValidationError, match="Missing required argument"):
        sv.validate_input("add", {"a": 1})


def test_schema_validator_wrong_type():
    """Wrong type raises."""
    sv = SchemaValidator({"add": {"a": int, "b": int}})
    with pytest.raises(SchemaValidationError, match="expected int"):
        sv.validate_input("add", {"a": 1, "b": "x"})


def test_schema_validator_str_type():
    """String type validated."""
    sv = SchemaValidator({"greet": {"name": str}})
    sv.validate_input("greet", {"name": "alice"})


def test_schema_validator_float_type():
    """Float type validated."""
    sv = SchemaValidator({"calc": {"value": float}})
    sv.validate_input("calc", {"value": 3.14})


def test_schema_validator_dict_type():
    """Dict type validated."""
    sv = SchemaValidator({"config": {"settings": dict}})
    sv.validate_input("config", {"settings": {"a": 1}})


def test_schema_validator_list_type():
    """List type validated."""
    sv = SchemaValidator({"items": {"ids": list}})
    sv.validate_input("items", {"ids": [1, 2, 3]})


def test_schema_validator_bool_type():
    """Bool type validated."""
    sv = SchemaValidator({"flag": {"enabled": bool}})
    sv.validate_input("flag", {"enabled": True})


def test_schema_validator_isinstance_fallback():
    """Custom type uses isinstance fallback."""
    sv = SchemaValidator({"x": {"v": type(None)}})
    sv.validate_input("x", {"v": None})
