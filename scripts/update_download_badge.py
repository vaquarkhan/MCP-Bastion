"""Fetch total downloads for all MCP-Bastion PyPI packages and update README badge."""

import json
import re
import time
import urllib.request

PACKAGES = [
    "mcp-bastion-python",
    "mcp-bastion-langchain",
    "mcp-bastion-openai",
    "mcp-bastion-anthropic",
    "mcp-bastion-bedrock",
    "mcp-bastion-gemini",
    "mcp-bastion-crewai",
    "mcp-bastion-llamaindex",
    "mcp-bastion-groq",
    "mcp-bastion-mistral",
    "mcp-bastion-cohere",
    "mcp-bastion-azure",
    "mcp-bastion-vertexai",
    "mcp-bastion-huggingface",
    "mcp-bastion-deepseek",
    "mcp-bastion-together",
    "mcp-bastion-fireworks",
]


def get_total_downloads(package: str) -> int:
    """Get total downloads from pypistats.org API (public, no key needed)."""
    url = f"https://pypistats.org/api/packages/{package}/overall"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "mcp-bastion-bot"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            # Sum all downloads across all categories
            total = 0
            for row in data.get("data", []):
                if row.get("category") == "without_mirrors":
                    total += row.get("downloads", 0)
            return total
    except Exception as e:
        print(f"    Error fetching {package}: {e}")
        return 0


def format_number(n: int) -> str:
    """Format number with K/M suffix."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def main() -> None:
    total = 0
    for pkg in PACKAGES:
        count = get_total_downloads(pkg)
        print(f"  {pkg}: {count:,}")
        total += count
        time.sleep(2)  # Avoid rate limiting

    formatted = format_number(total)
    print(f"\nTotal across all packages: {total:,} ({formatted})")

    badge_url = (
        f"https://img.shields.io/badge/total%20downloads-{formatted}-brightgreen"
    )

    with open("README.md", "r", encoding="utf-8") as f:
        content = f.read()

    # Replace the total downloads badge line
    pattern = r"\[!\[Total Downloads\]\(https://img\.shields\.io/badge/total%20downloads-[^)]+\)\]\(https://pepy\.tech/projects/mcp-bastion-python\)"
    replacement = f"[![Total Downloads]({badge_url})](https://pepy.tech/projects/mcp-bastion-python)"

    if re.search(pattern, content):
        content = re.sub(pattern, replacement, content)
    else:
        content = content.replace(
            "<!-- mcp-name: io.github.vaquarkhan/mcp-bastion -->",
            f"<!-- mcp-name: io.github.vaquarkhan/mcp-bastion -->\n\n{replacement}",
            1,
        )

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(content)

    print(f"README updated with badge: {formatted}")


if __name__ == "__main__":
    main()
