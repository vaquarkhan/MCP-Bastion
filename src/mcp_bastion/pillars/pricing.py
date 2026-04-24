"""
Provider-style USD estimates for cost attribution (FinOps).

Uses published-ish defaults per 1M tokens; override via env JSON
BASTION_PRICING_OVERRIDES e.g. '{"openai":{"gpt-4o":{"input_per_million":2.5,"output_per_million":10}}}'
"""

from __future__ import annotations

import json
import os
from typing import Any

# USD per 1M tokens (input / output); defaults for attribution only
_DEFAULT_TABLE: dict[str, dict[str, dict[str, float]]] = {
    "openai": {
        "gpt-4o": {"input_per_million": 2.50, "output_per_million": 10.00},
        "gpt-4o-mini": {"input_per_million": 0.15, "output_per_million": 0.60},
        "gpt-4-turbo": {"input_per_million": 10.00, "output_per_million": 30.00},
        "default": {"input_per_million": 5.00, "output_per_million": 15.00},
    },
    "anthropic": {
        "claude-3-5-sonnet-20241022": {"input_per_million": 3.00, "output_per_million": 15.00},
        "claude-3-opus-20240229": {"input_per_million": 15.00, "output_per_million": 75.00},
        "default": {"input_per_million": 3.00, "output_per_million": 15.00},
    },
    "google": {
        "gemini-1.5-pro": {"input_per_million": 1.25, "output_per_million": 5.00},
        "default": {"input_per_million": 1.25, "output_per_million": 5.00},
    },
}


def _load_table() -> dict[str, Any]:
    table: dict[str, Any] = json.loads(json.dumps(_DEFAULT_TABLE))
    raw = os.environ.get("BASTION_PRICING_OVERRIDES", "").strip()
    if not raw:
        return table
    try:
        overrides = json.loads(raw)
        if isinstance(overrides, dict):
            for prov, models in overrides.items():
                if not isinstance(models, dict):
                    continue
                table.setdefault(prov, {})
                for model, rates in models.items():
                    if isinstance(rates, dict):
                        table[prov][str(model)] = {
                            "input_per_million": float(rates.get("input_per_million", 0)),
                            "output_per_million": float(rates.get("output_per_million", 0)),
                        }
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return table


def estimate_llm_usd(
    *,
    provider: str | None,
    model: str | None,
    input_tokens: int = 0,
    output_tokens: int = 0,
) -> float:
    """Return estimated USD for token usage (0 if unknown)."""
    if not provider or not model:
        return 0.0
    table = _load_table()
    prov = str(provider).lower().replace(" ", "_")
    models = table.get(prov) or table.get(provider) or {}
    rates = models.get(model) or models.get("default") or {}
    inp = float(rates.get("input_per_million", 0.0))
    out = float(rates.get("output_per_million", 0.0))
    return (max(0, input_tokens) * inp + max(0, output_tokens) * out) / 1_000_000.0
