"""Tests for provider pricing estimates."""

import json

import pytest

from mcp_bastion.pillars import pricing as pricing_mod


def test_estimate_llm_usd_openai_mini():
    assert pricing_mod.estimate_llm_usd(provider="openai", model="gpt-4o-mini", input_tokens=1_000_000, output_tokens=0) == pytest.approx(0.15, rel=1e-6)


def test_estimate_unknown_returns_zero():
    assert pricing_mod.estimate_llm_usd(provider=None, model="x", input_tokens=1000, output_tokens=0) == 0.0


def test_pricing_overrides_merge(monkeypatch):
    raw = json.dumps({"openai": {"gpt-4o-mini": {"input_per_million": 9.99, "output_per_million": 1.0}}})
    monkeypatch.setenv("BASTION_PRICING_OVERRIDES", raw)
    try:
        v = pricing_mod.estimate_llm_usd(provider="openai", model="gpt-4o-mini", input_tokens=1_000_000, output_tokens=0)
        assert v == pytest.approx(9.99, rel=1e-6)
    finally:
        monkeypatch.delenv("BASTION_PRICING_OVERRIDES", raising=False)


def test_load_table_invalid_json_ignored(monkeypatch):
    monkeypatch.setenv("BASTION_PRICING_OVERRIDES", "not-json")
    try:
        t = pricing_mod._load_table()
        assert "openai" in t
    finally:
        monkeypatch.delenv("BASTION_PRICING_OVERRIDES", raising=False)


def test_load_table_skips_non_dict_model_entries(monkeypatch):
    raw = json.dumps({"openai": {"gpt-x": "not-a-dict", "ok": {"input_per_million": 1.0, "output_per_million": 2.0}}})
    monkeypatch.setenv("BASTION_PRICING_OVERRIDES", raw)
    try:
        t = pricing_mod._load_table()
        assert "ok" in t["openai"]
        assert "gpt-x" not in t["openai"]
    finally:
        monkeypatch.delenv("BASTION_PRICING_OVERRIDES", raising=False)


def test_load_table_skips_non_dict_provider(monkeypatch):
    raw = json.dumps({"badprov": "x", "openai": {"m": {"input_per_million": 1.0, "output_per_million": 1.0}}})
    monkeypatch.setenv("BASTION_PRICING_OVERRIDES", raw)
    try:
        t = pricing_mod._load_table()
        assert "openai" in t
    finally:
        monkeypatch.delenv("BASTION_PRICING_OVERRIDES", raising=False)
