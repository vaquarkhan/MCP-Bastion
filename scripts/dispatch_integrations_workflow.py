"""
Trigger GitHub Actions: publish-integrations.yml for one integration package.

Requires a GitHub personal access token (classic) with ``workflow`` scope, or
fine-grained token with "Actions" write on this repo.

Usage::

    set GITHUB_TOKEN=ghp_...   (Windows)
    python scripts/dispatch_integrations_workflow.py mcp-bastion-langchain

Ref is ``main`` by default; override with --ref.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

REPO = "vaquarkhan/MCP-Bastion"
WORKFLOW = "publish-integrations.yml"


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python dispatch_integrations_workflow.py <package> [--ref main]")
        print("Example: python dispatch_integrations_workflow.py mcp-bastion-langchain")
        return 1
    package = sys.argv[1]
    ref = "main"
    if "--ref" in sys.argv:
        i = sys.argv.index("--ref")
        if i + 1 < len(sys.argv):
            ref = sys.argv[i + 1]
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        print("Error: set environment variable GITHUB_TOKEN (PAT with workflow scope).", file=sys.stderr)
        return 1
    body = json.dumps({"ref": ref, "inputs": {"package": package}}).encode("utf-8")
    url = f"https://api.github.com/repos/{REPO}/actions/workflows/{WORKFLOW}/dispatches"
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status in (200, 201, 204):
                print(f"OK: dispatch queued for package={package!r} ref={ref!r}")
                print("Open: https://github.com/vaquarkhan/MCP-Bastion/actions/workflows/publish-integrations.yml")
                return 0
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="replace")
        print(f"HTTP {e.code}: {err}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
