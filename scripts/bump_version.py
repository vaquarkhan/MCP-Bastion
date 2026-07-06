"""Bump release version across packaging files. Usage: python scripts/bump_version.py 2.0.2"""
from __future__ import annotations

import pathlib
import re
import sys

NEW = sys.argv[1] if len(sys.argv) > 1 else "2.0.2"
OLD = sys.argv[2] if len(sys.argv) > 2 else "2.0.1"


def main() -> None:
    root = pathlib.Path(__file__).resolve().parent.parent
    for p in root.rglob("pyproject.toml"):
        if "node_modules" in p.parts:
            continue
        t = p.read_text(encoding="utf-8")
        t2 = re.sub(rf'^version = "{re.escape(OLD)}"', f'version = "{NEW}"', t, flags=re.M)
        if t2 != t:
            p.write_text(t2, encoding="utf-8")
            print(p.relative_to(root))

    for rel in (
        "packages/core/package.json",
        "server.json",
        "CITATION.cff",
        "src/mcp_bastion/__init__.py",
        "Dockerfile",
        "Dockerfile.dashboard",
    ):
        p = root / rel
        if p.exists() and OLD in p.read_text(encoding="utf-8"):
            p.write_text(p.read_text(encoding="utf-8").replace(OLD, NEW), encoding="utf-8")
            print(rel)

    for p in (root / "integrations").glob("*/src/*/__init__.py"):
        t = p.read_text(encoding="utf-8")
        if OLD in t:
            p.write_text(t.replace(OLD, NEW), encoding="utf-8")
            print(p.relative_to(root))

    for rel in ("docs/site/index.html", "docs/site/integrations.html"):
        p = root / rel
        if not p.exists():
            continue
        t = p.read_text(encoding="utf-8")
        t2 = t.replace("2.0.0", NEW).replace(OLD, NEW)
        if t2 != t:
            p.write_text(t2, encoding="utf-8")
            print(rel)


if __name__ == "__main__":
    main()
