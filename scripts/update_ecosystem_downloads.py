#!/usr/bin/env python3
"""Sum PyPI download counts for all Bastion packages into one ecosystem total.

Source: pypistats.org overall API (without_mirrors). New packages may 404 until
indexed; those are recorded as 0. Writes:

  docs/site/assets/ecosystem-downloads.json
  docs/site/assets/ecosystem-downloads-badge.json  (Shields.io endpoint format)
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "docs" / "site" / "assets"
STATS_PATH = OUT_DIR / "ecosystem-downloads.json"
BADGE_PATH = OUT_DIR / "ecosystem-downloads-badge.json"

# Keep in sync with README Framework Integrations + docs/site/integrations.html
PACKAGES: list[tuple[str, str]] = [
    ("mcp-bastion-python", "Core middleware"),
    ("mcp-bastion-langchain", "LangChain"),
    ("mcp-bastion-openai", "OpenAI GPT"),
    ("mcp-bastion-anthropic", "Anthropic Claude"),
    ("mcp-bastion-bedrock", "AWS Bedrock"),
    ("mcp-bastion-gemini", "Google Gemini"),
    ("mcp-bastion-crewai", "CrewAI"),
    ("mcp-bastion-llamaindex", "LlamaIndex"),
    ("mcp-bastion-groq", "Groq"),
    ("mcp-bastion-mistral", "Mistral AI"),
    ("mcp-bastion-cohere", "Cohere"),
    ("mcp-bastion-azure", "Azure OpenAI"),
    ("mcp-bastion-vertexai", "Vertex AI"),
    ("mcp-bastion-huggingface", "Hugging Face"),
    ("mcp-bastion-deepseek", "DeepSeek AI"),
    ("mcp-bastion-together", "Together AI"),
    ("mcp-bastion-fireworks", "Fireworks AI"),
    ("mcp-bastion-litellm", "LiteLLM (100+ providers)"),
    ("mcp-bastion-ollama", "Ollama local models"),
    ("mcp-bastion-openrouter", "OpenRouter gateway"),
    ("mcp-bastion-xai", "xAI Grok"),
    ("mcp-bastion-autogen", "Microsoft AutoGen"),
    ("mcp-bastion-langgraph", "LangGraph"),
    ("mcp-bastion-pydantic-ai", "Pydantic AI"),
    ("mcp-bastion-openai-agents", "OpenAI Agents SDK"),
    ("mcp-bastion-fastmcp", "FastMCP servers"),
]

UA = {"User-Agent": "MCP-Bastion-ecosystem-downloads/1.0 (+https://github.com/vaquarkhan/MCP-Bastion)"}


def _fetch_overall(name: str) -> int:
    url = f"https://pypistats.org/api/packages/{name}/overall"
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            payload = json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 0
        raise
    rows = payload.get("data") or []
    preferred = [r for r in rows if r.get("category") == "without_mirrors"]
    if not preferred:
        preferred = [r for r in rows if r.get("category") == "with_mirrors"]
    return int(sum(int(r.get("downloads") or 0) for r in preferred))


def _format_count(n: int) -> str:
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M".replace(".0M", "M")
    if n >= 1_000:
        return f"{n / 1_000:.1f}k".replace(".0k", "k")
    return str(n)


def main() -> None:
    per_package: list[dict] = []
    total = 0
    for i, (name, protects) in enumerate(PACKAGES):
        if i:
            time.sleep(0.35)
        downloads = _fetch_overall(name)
        total += downloads
        per_package.append(
            {
                "package": name,
                "protects": protects,
                "downloads": downloads,
                "pypi": f"https://pypi.org/project/{name}/",
                "pepy": f"https://pepy.tech/projects/{name}",
                "pypistats": f"https://pypistats.org/packages/{name}",
            }
        )
        print(f"{name}: {downloads}")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stats = {
        "updated_at": now,
        "source": "pypistats.org overall (without_mirrors; with_mirrors fallback)",
        "note": (
            "Sum of per-package download rows. Installing an integration also "
            "pulls mcp-bastion-python, so core + integration counts can overlap."
        ),
        "package_count": len(PACKAGES),
        "total_downloads": total,
        "packages": per_package,
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    STATS_PATH.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    BADGE_PATH.write_text(
        json.dumps(
            {
                "schemaVersion": 1,
                "label": "ecosystem downloads",
                "message": _format_count(total),
                "color": "0B5FFF",
                "namedLogo": "python",
                "cacheSeconds": 3600,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"total_downloads={total} -> {STATS_PATH.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
