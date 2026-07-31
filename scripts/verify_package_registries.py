#!/usr/bin/env python3
"""Verify MCP-Bastion / suite packages are downloadable from public registries."""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

CHECKS: list[tuple[str, str, str]] = [
    ("PyPI", "mcp-bastion-python", "https://pypi.org/pypi/mcp-bastion-python/json"),
    ("PyPI", "mcp-bastion-openai", "https://pypi.org/pypi/mcp-bastion-openai/json"),
    ("PyPI", "mcp-bastion-fastmcp", "https://pypi.org/pypi/mcp-bastion-fastmcp/json"),
    ("npmjs", "@mcp-bastion/core", "https://registry.npmjs.org/@mcp-bastion/core"),
    ("npmjs", "@vaquarkhan/mcp-bastion-suite", "https://registry.npmjs.org/@vaquarkhan/mcp-bastion-suite"),
    (
        "Maven Central",
        "io.github.vaquarkhan:mcp-bastion-suite",
        "https://search.maven.org/solrsearch/select?q=g:io.github.vaquarkhan+AND+a:mcp-bastion-suite&rows=1&wt=json",
    ),
    ("NuGet.org", "McpBastionSuite", "https://api.nuget.org/v3-flatcontainer/mcpbastionsuite/index.json"),
    (
        "Go proxy",
        "adapters/go@v0.1.0",
        "https://proxy.golang.org/github.com/vaquarkhan/mcp-bastion-suite/adapters/go/@v/v0.1.0.info",
    ),
]


def _get(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:  # noqa: BLE001
        return 0, str(e)


def main() -> int:
    failed = 0
    print("# Package registry verification\n")
    for registry, name, url in CHECKS:
        code, body = _get(url)
        ok = False
        detail = f"HTTP {code}"
        if registry == "PyPI" and code == 200:
            ver = json.loads(body).get("info", {}).get("version", "?")
            ok, detail = True, f"version={ver}"
        elif registry == "npmjs" and code == 200:
            ok, detail = True, "found"
        elif registry == "Maven Central" and code == 200:
            n = json.loads(body).get("response", {}).get("numFound", 0)
            ok, detail = (n > 0), f"numFound={n}"
        elif registry == "NuGet.org" and code == 200:
            ok, detail = True, "found"
        elif registry == "Go proxy" and code == 200:
            ok, detail = True, body.strip()[:80]
        mark = "PASS" if ok else "FAIL"
        if not ok:
            failed += 1
        print(f"- [{mark}] {registry}: {name} ({detail})")
    print()
    if failed:
        print(f"**{failed} gap(s)** — see docs/PACKAGE_REGISTRY_STATUS.md")
        return 1
    print("All expected public packages OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
