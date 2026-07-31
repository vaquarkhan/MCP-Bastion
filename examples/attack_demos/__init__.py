"""
Hero attack → defense demos for MCP-Bastion.

Run from repo root:
  PYTHONPATH=src python -m examples.attack_demos
  # or:
  PYTHONPATH=src python examples/attack_demos/runner.py

Docs: docs/ATTACK_DEMOS.md · Feature context: docs/FEATURE_DEEP_DIVE.md
"""

from __future__ import annotations

from .runner import main

__all__ = ["main"]
