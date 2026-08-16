"""
Build professional documentation HTML under docs/site/guide/ from curated markdown.

Usage:
  python scripts/build_docs_site.py

Requires: markdown (pip install markdown). Safe to run in CI before Pages deploy.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
SITE = ROOT / "docs" / "site"
GUIDE = SITE / "guide"
ASSETS = SITE / "assets"

# Curated IA: (slug, title, source markdown relative to docs/, nav group)
PAGES: list[tuple[str, str, str, str]] = [
    ("index", "Documentation Home", "USER_GUIDE.md", "Start here"),
    ("handbook", "Documentation handbook", "DOCUMENTATION_HANDBOOK.md", "Start here"),
    ("demos", "Demos (attack + dashboard)", "DEMOS.md", "Start here"),
    ("getting-started", "Getting started", "QUICK_START.md", "Start here"),
    ("user-guide", "User guide (end-to-end)", "USER_GUIDE.md", "Start here"),
    ("installation", "Installation & tutorials", "DETAILED_TUTORIAL.md", "Guides"),
    ("configuration", "Configuration reference", "POLICY_AS_CODE.md", "Guides"),
    ("proxy", "HTTP proxy & boundary", "GATEWAY_BOUNDARY.md", "Guides"),
    ("hybrid-transport", "Hybrid MCP transport", "HYBRID_TRANSPORT_TUTORIAL.md", "Guides"),
    ("multi-language", "Multi-language suite", "MULTI_LANGUAGE_SUITE.md", "Guides"),
    ("package-status", "Package registry status", "PACKAGE_REGISTRY_STATUS.md", "Guides"),
    ("pii-vault", "PII vault", "PII_VAULT.md", "Privacy & context"),
    ("pii-vault-tutorial", "PII vault tutorial", "PII_VAULT_TUTORIAL.md", "Privacy & context"),
    ("schema-minimize", "Schema minimize & catalog pin", "SCHEMA_MINIMIZE_LIVE_PIN.md", "Privacy & context"),
    ("pillars", "Security pillars", "PILLARS.md", "Security"),
    ("feature-deep-dive", "Feature deep dive", "FEATURE_DEEP_DIVE.md", "Security"),
    ("features", "Feature enablement", "FEATURES.md", "Security"),
    ("attack-prevention", "Attack prevention", "ATTACK_PREVENTION.md", "Security"),
    ("attack-demos", "Attack demos (GIFs)", "ATTACK_DEMOS.md", "Security"),
    ("cli", "CLI reference", "CLI.md", "Reference"),
    ("metrics", "Metrics", "METRICS.md", "Reference"),
    ("observability", "Dashboard & observability", "DASHBOARD_AND_OBSERVABILITY.md", "Reference"),
    ("otel", "OpenTelemetry (optional)", "OTEL.md", "Reference"),
    ("cra-sbom", "CRA & SBOM", "CRA_SBOM_TUTORIAL.md", "Compliance"),
    ("supply-chain", "Supply chain", "SUPPLY_CHAIN.md", "Compliance"),
    ("developer", "Developer guide", "DEVELOPER_GUIDE.md", "Contribute"),
]

SITE_BASE = "https://vaquarkhan.github.io/MCP-Bastion"
VERSION = "5.1.0"


def _require_markdown():
    try:
        import markdown  # noqa: F401
    except ImportError:
        print("Install markdown: pip install markdown", file=sys.stderr)
        raise SystemExit(1)


def _md_to_html(text: str) -> str:
    import markdown

    # Fix relative .md links to guide HTML where possible
    def link_sub(m: re.Match[str]) -> str:
        label, path = m.group(1), m.group(2)
        if path.startswith(("http://", "https://", "#", "mailto:")):
            return m.group(0)
        name = Path(path.split("#")[0]).name
        for slug, _t, src, _g in PAGES:
            if Path(src).name == name:
                frag = ""
                if "#" in path:
                    frag = "#" + path.split("#", 1)[1]
                return f"[{label}]({slug}.html{frag})"
        # Fall back to GitHub blob for non-curated docs
        if path.endswith(".md") and not path.startswith("../"):
            return f"[{label}](https://github.com/vaquarkhan/MCP-Bastion/blob/main/docs/{path})"
        if path.startswith("../"):
            return f"[{label}](https://github.com/vaquarkhan/MCP-Bastion/blob/main/{path[3:]})"
        # GIF / asset links under docs/images → site assets
        if path.startswith("images/"):
            return f"[{label}](../assets/{path[len('images/'):]})"
        return m.group(0)

    def img_sub(m: re.Match[str]) -> str:
        alt, path = m.group(1), m.group(2)
        if path.startswith(("http://", "https://", "data:")):
            return m.group(0)
        # docs/images/* and docs/site/assets/* — from guide HTML use ../assets/
        if path.startswith("images/"):
            return f"![{alt}](../assets/{path[len('images/'):]})"
        if path.startswith("../images/"):
            # repo-root images/ (SVGs) — GitHub raw for site
            rel = path[len("../images/") :]
            return (
                f"![{alt}](https://raw.githubusercontent.com/vaquarkhan/MCP-Bastion/main/images/{rel})"
            )
        if path.startswith("../dashboard/") or path.startswith("../"):
            return m.group(0)
        return m.group(0)

    text = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", img_sub, text)
    text = re.sub(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)", link_sub, text)
    # Shell already provides the page H1 — strip the markdown document title H1
    # and demote any remaining ATX H1s so we do not show the heading twice.
    text = re.sub(r"(?m)^#\s+[^\n]+\n+", "", text, count=1)
    text = re.sub(r"(?m)^#\s+", "## ", text)
    html_body = markdown.markdown(
        text,
        extensions=["fenced_code", "tables", "toc", "nl2br", "sane_lists"],
        extension_configs={"toc": {"permalink": False}},
    )
    # Mermaid: fenced ```mermaid → <pre class="mermaid"> for mermaid.js (if present)
    html_body = re.sub(
        r'<pre><code class="language-mermaid">(.*?)</code></pre>',
        r'<pre class="mermaid">\1</pre>',
        html_body,
        flags=re.DOTALL,
    )
    # Safety: no body H1 left (shell owns the only H1)
    html_body = html_body.replace("<h1>", "<h2>").replace("</h1>", "</h2>")
    return html_body


def _nav_html(active: str) -> str:
    groups: dict[str, list[tuple[str, str]]] = {}
    for slug, title, _src, group in PAGES:
        groups.setdefault(group, []).append((slug, title))
    parts = ['<nav class="docs-nav" aria-label="Documentation">']
    for group, items in groups.items():
        parts.append(f'<div class="nav-group"><div class="nav-group-title">{html.escape(group)}</div><ul>')
        if group == "Start here":
            parts.append(
                '<li><a href="https://github.com/vaquarkhan/MCP-Bastion/raw/main/MCP-Security-Deck-v3.pdf">'
                "<strong>Benchmark (PDF)</strong></a></li>"
            )
        for slug, title in items:
            cls = ' class="active"' if slug == active else ""
            href = "index.html" if slug == "index" else f"{slug}.html"
            parts.append(f'<li><a href="{href}"{cls}>{html.escape(title)}</a></li>')
        parts.append("</ul></div>")
    parts.append("</nav>")
    return "\n".join(parts)


def _page_shell(title: str, active: str, body: str, *, description: str = "") -> str:
    desc = description or f"MCP-Bastion documentation — {title}"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)} | MCP-Bastion Docs</title>
<meta name="description" content="{html.escape(desc)}">
<meta name="docs-version" content="{VERSION}">
<link rel="stylesheet" href="../assets/guide.css">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Source+Sans+3:wght@400;600;700&family=Source+Code+Pro:wght@400;500&display=swap" rel="stylesheet">
</head>
<body>
<a class="skip-link" href="#main">Skip to content</a>
<header class="docs-header">
  <div class="header-inner">
    <a class="brand" href="../index.html">MCP-Bastion</a>
    <span class="version-badge">{VERSION}</span>
    <nav class="header-links">
      <a href="index.html" class="current">Docs</a>
      <a href="../integrations.html">Integrations</a>
      <a href="https://github.com/vaquarkhan/MCP-Bastion/raw/main/MCP-Security-Deck-v3.pdf"><strong>Benchmark</strong></a>
      <a href="https://github.com/vaquarkhan/MCP-Bastion">GitHub</a>
      <a href="https://pypi.org/project/mcp-bastion-python/{VERSION}/">PyPI</a>
    </nav>
  </div>
</header>
<div class="docs-layout">
  <aside class="docs-sidebar">
    {_nav_html(active)}
  </aside>
  <main id="main" class="docs-main">
    <article class="docs-article">
      <header class="article-header">
        <p class="eyebrow">MCP-Bastion Documentation</p>
        <h1>{html.escape(title)}</h1>
      </header>
      {body}
    </article>
    <footer class="docs-footer">
      <p>MCP-Bastion {VERSION} · <a href="{SITE_BASE}/">Website</a> ·
      <a href="https://github.com/vaquarkhan/MCP-Bastion/blob/main/docs/">Source markdown</a></p>
    </footer>
  </main>
</div>
</body>
</html>
"""


def _home_body() -> str:
    cards = []
    featured = [
        ("handbook.html", "Documentation handbook", "Visual tour: attack GIFs, dashboard, features, multi-language."),
        ("demos.html", "Demos hub", "Attacks, payloads, dashboard tour, and every language."),
        ("observability.html", "Dashboard & observability", "Panels, Prometheus, audit — OTEL optional."),
        ("multi-language.html", "Multi-language suite", "TypeScript, Java, Go, .NET via mcp-bastion-suite."),
        ("feature-deep-dive.html", "Feature deep dive", "Every control: issue → solution → benefits, including dashboard."),
        ("user-guide.html", "User guide (end-to-end)", "Install → configure → proxy → vault → production checklist."),
        ("getting-started.html", "Getting started", "FastMCP, policy-as-code, and CI gate paths."),
    ]
    for href, title, blurb in featured:
        cards.append(
            f'<a class="doc-card" href="{href}"><h3>{html.escape(title)}</h3>'
            f"<p>{html.escape(blurb)}</p></a>"
        )
    return f"""
<p class="lede">Enterprise documentation for MCP-Bastion — security and governance middleware
for the Model Context Protocol. Structured like large-platform handbooks: concepts, getting started,
how-to guides, and reference.</p>
<div class="callout">
  <strong>Current release:</strong> {VERSION} ·
  <code>pip install mcp-bastion-python=={VERSION}</code>
</div>
<h2>Start here</h2>
<div class="card-grid">
{''.join(cards)}
</div>
<h2>Learning paths</h2>
<ol class="paths">
  <li><strong>Developer (minutes):</strong> Getting started → Feature enablement → CLI</li>
  <li><strong>Platform engineer:</strong> User guide → Configuration → Proxy → Metrics</li>
  <li><strong>Security / compliance:</strong> Feature deep dive → Attack demos → Pillars → PII vault → CRA &amp; SBOM</li>
  <li><strong>Other languages:</strong> Multi-language suite → suite tutorials (TS / Java / Go / .NET)</li>
</ol>
"""


def main() -> None:
    _require_markdown()
    GUIDE.mkdir(parents=True, exist_ok=True)
    ASSETS.mkdir(parents=True, exist_ok=True)

    # Write CSS if missing (idempotent overwrite from template next to script expectations)
    css_src = ROOT / "docs" / "site" / "assets" / "guide.css"
    if not css_src.exists():
        print("warn: guide.css missing — run after writing assets/guide.css", file=sys.stderr)

    built = 0
    for slug, title, src, _group in PAGES:
        if slug == "index":
            body = _home_body()
        else:
            path = DOCS / src
            if not path.exists():
                print(f"skip missing {src}", file=sys.stderr)
                continue
            body = _md_to_html(path.read_text(encoding="utf-8"))
        out_name = "index.html" if slug == "index" else f"{slug}.html"
        (GUIDE / out_name).write_text(
            _page_shell(title, slug, body),
            encoding="utf-8",
        )
        built += 1
        print(f"wrote guide/{out_name}")

    print(f"Built {built} pages -> {GUIDE.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
