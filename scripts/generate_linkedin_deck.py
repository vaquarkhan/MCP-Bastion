#!/usr/bin/env python3
"""
Generate a 5-page LinkedIn-style PDF deck for MCP-Bastion 2.0.0.

Usage (from repo root):
    pip install reportlab
    python scripts/generate_linkedin_deck.py
    python scripts/generate_linkedin_deck.py -o docs/MCP-Bastion-2.0.0-LinkedIn-Deck.pdf
"""

from __future__ import annotations

import argparse
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
IMAGES = REPO_ROOT / "images"
DOCS_IMAGES = REPO_ROOT / "docs" / "images"
DEFAULT_OUT = REPO_ROOT / "docs" / "MCP-Bastion-2.0.0-LinkedIn-Deck.pdf"

GITHUB = "https://github.com/vaquarkhan/MCP-Bastion"
PYPI = "https://pypi.org/project/mcp-bastion-python/2.0.0/"
WEBSITE = "https://vaquarkhan.github.io/MCP-Bastion/"
NPM = "https://www.npmjs.com/package/@mcp-bastion/core"
DASHBOARD_DOCKER = f"{GITHUB}/pkgs/container/mcp-bastion-dashboard"

PAGE_W, PAGE_H = landscape((13.333 * inch, 7.5 * inch))
MARGIN = 0.55 * inch

BG = colors.HexColor("#0f172a")
ACCENT = colors.HexColor("#38bdf8")
GREEN = colors.HexColor("#4ade80")
ORANGE = colors.HexColor("#fb923c")
TEXT = colors.HexColor("#e2e8f0")
MUTED = colors.HexColor("#94a3b8")


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "DeckTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=34,
            leading=40,
            textColor=TEXT,
            alignment=TA_CENTER,
            spaceAfter=10,
        ),
        "subtitle": ParagraphStyle(
            "DeckSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=17,
            leading=22,
            textColor=ACCENT,
            alignment=TA_CENTER,
            spaceAfter=8,
        ),
        "pitch": ParagraphStyle(
            "DeckPitch",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=13,
            leading=18,
            textColor=ORANGE,
            alignment=TA_CENTER,
            spaceAfter=10,
        ),
        "h2": ParagraphStyle(
            "DeckH2",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=21,
            leading=26,
            textColor=ACCENT,
            spaceAfter=8,
        ),
        "body": ParagraphStyle(
            "DeckBody",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10.5,
            leading=14,
            textColor=TEXT,
            spaceAfter=5,
        ),
        "bullet": ParagraphStyle(
            "DeckBullet",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=10,
            leading=13,
            textColor=TEXT,
            leftIndent=12,
            bulletIndent=0,
            spaceAfter=3,
        ),
        "link": ParagraphStyle(
            "DeckLink",
            parent=base["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=15,
            textColor=GREEN,
            alignment=TA_CENTER,
        ),
        "footer": ParagraphStyle(
            "DeckFooter",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=8.5,
            textColor=MUTED,
            alignment=TA_CENTER,
        ),
    }


def _img(path: Path, max_w: float, max_h: float) -> Image | Spacer:
    if not path.is_file():
        return Spacer(1, max_h * 0.4)
    im = Image(str(path))
    iw, ih = im.imageWidth, im.imageHeight
    scale = min(max_w / iw, max_h / ih, 1.0)
    im.drawWidth = iw * scale
    im.drawHeight = ih * scale
    return im


def _feature_table(rows: list[tuple[str, str]], styles: dict, col1: float = 2.0) -> Table:
    data = [
        [
            Paragraph(f"<b>{title}</b>", styles["body"]),
            Paragraph(desc, styles["body"]),
        ]
        for title, desc in rows
    ]
    t = Table(data, colWidths=[col1 * inch, (PAGE_W - 2 * MARGIN - col1 * inch)])
    t.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("LINEBELOW", (0, 0), (-1, -2), 0.5, colors.HexColor("#334155")),
            ]
        )
    )
    return t


class SlideCanvas(SimpleDocTemplate):
    def handle_pageBegin(self):
        super().handle_pageBegin()
        self.canv.saveState()
        self.canv.setFillColor(BG)
        self.canv.rect(0, 0, PAGE_W, PAGE_H, fill=1, stroke=0)
        self.canv.setFillColor(ACCENT)
        self.canv.rect(0, PAGE_H - 0.12 * inch, PAGE_W, 0.12 * inch, fill=1, stroke=0)
        self.canv.restoreState()

    def handle_pageEnd(self):
        self.canv.saveState()
        self.canv.setFillColor(MUTED)
        self.canv.setFont("Helvetica", 8)
        self.canv.drawCentredString(
            PAGE_W / 2,
            0.35 * inch,
            "MCP-Bastion 2.0.0  |  The open-source Zero-Trust control plane for MCP agents",
        )
        self.canv.restoreState()
        super().handle_pageEnd()


def build_story(out_path: Path) -> None:
    s = _styles()
    story: list = []
    content_w = PAGE_W - 2 * MARGIN

    # Page 1: Cover + sales pitch
    story.append(Spacer(1, 0.25 * inch))
    story.append(_img(IMAGES / "mcp-bastian.png", content_w * 0.5, 2.0 * inch))
    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("MCP-Bastion", s["title"]))
    story.append(Paragraph("Version 2.0.0", s["subtitle"]))
    story.append(
        Paragraph(
            "The comprehensive open-source stack for production MCP security",
            s["pitch"],
        )
    )
    story.append(
        Paragraph(
            "MCP turned every server into an agent gateway overnight. Bastion is the firewall "
            "that makes that gateway safe to run in production: <b>Agent IAM</b>, manifest "
            "checksums, injection blocking, PII redaction, denial-of-wallet caps, live dashboard, "
            "and audit. Runs <b>in-process</b> with heuristics offline and typical overhead "
            "under <b>5ms</b> on the hot path. No third-party safety API for core pillars.",
            s["body"],
        )
    )
    story.append(Spacer(1, 0.12 * inch))
    story.append(
        Paragraph(
            "PyPI + npm + Docker on GHCR + FastMCP + TypeScript + CI validate + red-team suite. "
            "Ship today, not a roadmap.",
            s["body"],
        )
    )
    story.append(Spacer(1, 0.18 * inch))
    story.append(Paragraph(f'<link href="{GITHUB}">GitHub: github.com/vaquarkhan/MCP-Bastion</link>', s["link"]))
    story.append(Spacer(1, 0.06 * inch))
    story.append(Paragraph(f'<link href="{PYPI}">PyPI: mcp-bastion-python==2.0.0</link>', s["link"]))
    story.append(Spacer(1, 0.06 * inch))
    story.append(Paragraph(f'<link href="{WEBSITE}">Docs: vaquarkhan.github.io/MCP-Bastion</link>', s["link"]))
    story.append(PageBreak())

    # Page 2: Why one stack beats point tools
    story.append(Paragraph("Why Teams Choose MCP-Bastion", s["h2"]))
    story.append(
        Paragraph(
            "Traditional AppSec cannot secure agentic workflows. OWASP MCP Top 10 and NSA guidance "
            "point to <b>runtime governance</b> at the protocol boundary. Bastion ships "
            "<b>18 request-path security features</b>, full MCP surface guards in 2.0.0, FinOps, "
            "and observability in a single drop-in middleware. Pair RBAC with Agent IAM or edge auth "
            "for production identity; use Redis for cross-replica rate limits and cost caps.",
            s["body"],
        )
    )
    why_rows = [
        ("No rewrite", "Drop-in middleware: secure_fastmcp(mcp) or build_middleware_from_config()"),
        ("Privacy your legal team accepts", "PromptGuard heuristics + Presidio run in your process"),
        ("Stop budget burn", "15 calls/session, 60s timeout, 50k token budget on by default"),
        ("Cut token spend", "Discovery filter, output offload (up to ~99% on huge dumps), lexical cache"),
        ("Policy in Git", "bastion.yaml, hot reload, doctor CLI, OWASP-aligned pillars"),
        ("Scale out", "Redis state_backend for shared rate limits, replay, cost caps across pods"),
    ]
    story.append(_feature_table(why_rows, s))
    story.append(Spacer(1, 0.1 * inch))
    story.append(_img(IMAGES / "mcp-bastion-mcp-surface-scale.png", content_w, 2.85 * inch))
    story.append(
        Paragraph(
            "2.0.0 guards tools/call plus resources/read, prompts/get, sampling, and elicitation. "
            "Same pillars on the full MCP surface, not just tool calls.",
            s["footer"],
        )
    )
    story.append(PageBreak())

    # Page 3: Attack coverage (honest framing)
    story.append(Paragraph("OWASP MCP Top 10 + Production Abuse, Addressed at the Boundary", s["h2"]))
    story.append(
        Paragraph(
            "All <b>10 OWASP MCP Top 10 risk categories</b> have mapped controls at the MCP boundary. "
            "Plus FinOps and abuse patterns OWASP does not list separately. Blocked calls surface in "
            "the dashboard, audit JSONL, and Prometheus metrics with standard error codes. "
            "Supply-chain defense is in-process manifest tamper detection, not full SCA/EDR.",
            s["body"],
        )
    )
    owasp_rows = [
        ("MCP01 Token exposure", "PII redaction, audit trail, outbound response scan"),
        ("MCP02 Privilege escalation", "RBAC + Agent IAM, rate limits, cost caps, session tool scope"),
        ("MCP03 Tool poisoning", "Prompt guard, content filter, response scan, metadata guard"),
        ("MCP04 Supply chain", "SHA-256 manifest checksums, doctor CLI (in-process, not sandbox)"),
        ("MCP05 Command injection", "Prompt guard, JSONPath argument guards, schema validation"),
        ("MCP06 Intent subversion", "Rate limits, replay guard, lexical similarity cache"),
        ("MCP07 Weak auth", "RBAC, edge auth, per-agent tokens (Agent IAM)"),
        ("MCP08 Audit gap", "Audit log, dashboard, Prometheus, OTEL, Slack alerts"),
        ("MCP09 Shadow MCP", "Central bastion.yaml policy, metrics, discovery filter"),
        ("MCP10 Context injection", "PII redaction, output budget, response scan, grounding guard"),
    ]
    story.append(_feature_table(owasp_rows, s, col1=2.15))
    story.append(Spacer(1, 0.08 * inch))
    finops_bullets = [
        "<b>Denial of wallet:</b> iteration cap, token budget, USD session/day limits",
        "<b>Runaway loops:</b> session timeout, circuit breaker, per-tool caps",
        "<b>Replay abuse:</b> nonce tracking with Redis-backed shared state",
        "<b>Confused deputy:</b> token-bound agent identities and per-tool RBAC",
    ]
    for b in finops_bullets:
        story.append(Paragraph(f"• {b}", s["bullet"]))
    story.append(Spacer(1, 0.06 * inch))
    story.append(_img(IMAGES / "mcp-bastion-owasp-coverage.png", content_w * 0.62, 1.55 * inch))
    story.append(PageBreak())

    # Page 4: Dashboard
    story.append(Paragraph("Live Dashboard: See Every Block, Threat, and Dollar", s["h2"]))
    story.append(
        Paragraph(
            "Security without visibility is blind. MCP-Bastion ships a <b>real-time web dashboard</b> "
            "on port 7000 (CLI, Docker GHCR, or docker-compose). Every guardrail decision flows "
            "into KPIs, charts, forensics, and alerts your SOC can act on.",
            s["body"],
        )
    )
    dash_rows = [
        ("KPI summary", "Totals, block %, top threat, active users/tenants at a glance"),
        ("Traffic charts", "Request volume, blocked-by-reason/kind with readable tooltips"),
        ("PII forensics", "PII by entity type with severity-style coloring"),
        ("FinOps view", "Cost by user, top tools, latency P50/P95/P99"),
        ("Forensics table", "Tenant filter, trace/replay helpers for incident response"),
        ("Alerts", "Slack webhooks, cost thresholds, recent alerts panel"),
        ("Export paths", "Prometheus /metrics, JSON /api/metrics, OTEL traces"),
        ("Pillar health", "14 dashboard rows mapped to bastion.yaml security pillars"),
    ]
    story.append(_feature_table(dash_rows, s, col1=1.75))
    story.append(Spacer(1, 0.08 * inch))
    story.append(_img(DOCS_IMAGES / "dashboard.png", content_w * 0.58, 2.5 * inch))
    story.append(
        Paragraph(
            "<font face='Courier'>mcp-bastion dashboard --port 7000</font>  |  "
            "<font face='Courier'>docker pull ghcr.io/vaquarkhan/mcp-bastion-dashboard:latest</font>",
            s["footer"],
        )
    )
    story.append(PageBreak())

    # Page 5: Zero-Trust + get started
    story.append(Paragraph("Zero-Trust Control Plane + Get Started", s["h2"]))
    story.append(_img(IMAGES / "mcp-bastion-runtime-governance.png", content_w * 0.55, 2.35 * inch))
    story.append(
        Paragraph(
            "Token to identity to RBAC to checksum to execute. Every agent request verified before "
            "tools, resources, or prompts run. Beyond OWASP: CSRF hardening, stdio JSON guard, "
            "multi-agent session isolation, signed manifests.",
            s["body"],
        )
    )
    story.append(
        Paragraph(
            "627+ pytest tests, 92% coverage, 27 pillars validated end-to-end. "
            "Heuristic PromptGuard works offline; ML depth needs gated Hugging Face access.",
            s["footer"],
        )
    )
    story.append(
        Paragraph(
            "<b>Install:</b> <font face='Courier'>pip install mcp-bastion-python</font>  |  "
            "<font face='Courier'>pip install mcp-bastion-python[redis,policy,dashboard]</font>",
            s["body"],
        )
    )
    story.append(
        Paragraph(
            "<b>Wire in:</b> <font face='Courier'>mcp.add_middleware(build_middleware_from_config())</font>",
            s["body"],
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    links = [
        ("GitHub (star us)", GITHUB),
        ("PyPI 2.0.0", PYPI),
        ("Documentation", WEBSITE),
        ("npm @mcp-bastion/core", NPM),
        ("Dashboard Docker image", DASHBOARD_DOCKER),
    ]
    for label, url in links:
        story.append(Paragraph(f'• <link href="{url}">{label}</link>', s["bullet"]))
    story.append(Spacer(1, 0.12 * inch))
    story.append(
        Paragraph(
            f'<link href="{GITHUB}"><b>Star on GitHub</b></link>  |  '
            f'<link href="{PYPI}"><b>Install from PyPI</b></link>  |  '
            f'<link href="{WEBSITE}"><b>Read the docs</b></link>',
            s["link"],
        )
    )

    doc = SlideCanvas(
        str(out_path),
        pagesize=(PAGE_W, PAGE_H),
        leftMargin=MARGIN,
        rightMargin=MARGIN,
        topMargin=MARGIN,
        bottomMargin=0.55 * inch,
        title="MCP-Bastion 2.0.0",
        author="Vaquar Khan",
    )
    doc.build(story)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate MCP-Bastion LinkedIn PDF deck")
    parser.add_argument("-o", "--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    build_story(args.output)
    print(f"Wrote {args.output} ({args.output.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()
