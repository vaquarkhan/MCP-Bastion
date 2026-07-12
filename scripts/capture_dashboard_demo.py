#!/usr/bin/env python3
"""
Capture live MCP-Bastion dashboard screenshots and build a feature walkthrough GIF.

Requires: dashboard running (default http://127.0.0.1:7000/), playwright, pillow, imageio.
  PYTHONPATH=src MCP_BASTION_DEMO=1 python dashboard/app.py
  python scripts/capture_dashboard_demo.py
"""

from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent.parent
IMAGES = REPO / "images"
OUT_DIR = IMAGES / "dashboard-demo"
DOCS_IMAGES = REPO / "docs" / "images"
SITE_ASSETS = REPO / "docs" / "site" / "assets"

BASE_URL = "http://127.0.0.1:7000/"
VIEWPORT = {"width": 1440, "height": 900}

SLIDES: list[dict[str, str]] = [
    {
        "id": "01-overview",
        "title": "Security overview",
        "caption": "KPIs + posture grades + runtime telemetry in one glance",
        "scroll": "0",
    },
    {
        "id": "02-posture",
        "title": "Pre-deploy posture + prevalidation",
        "caption": "Letter grades + Sonar-style issue list from local scan JSON",
        "anchor": "#dash-posture",
    },
    {
        "id": "03-issue-guide",
        "title": "How to fix (PMD-style guide)",
        "caption": "Why it matters · remediation steps · Bastion knobs · OWASP refs",
        "anchor": "#dash-posture",
        "action": "open_issue_guide",
    },
    {
        "id": "04-owasp",
        "title": "OWASP ASI / MCP / LLM coverage",
        "caption": "Agentic Top 10 heatmap with finding + block pressure",
        "anchor": "#dash-taxonomy",
        "action": "close_modal",
    },
    {
        "id": "05-attack",
        "title": "Live attack matrix",
        "caption": "What is under pressure right now, mapped to OWASP/ASI",
        "anchor": "#dash-attack",
    },
    {
        "id": "06-compliance",
        "title": "Compliance evidence & reports",
        "caption": "SOC2 / GDPR / ISO / NIST / ASI reports + evidence bundle",
        "anchor": "#dash-compliance",
    },
    {
        "id": "07-governance",
        "title": "RBAC + runtime governance",
        "caption": "RBAC, prompt guard, rate/cost, PII, Agent IAM, supply-chain",
        "anchor": "#dash-governance",
    },
    {
        "id": "08-forensics",
        "title": "Forensics + why blocked",
        "caption": "Row list + side Trace / Reproduce detail (wide screen)",
        "anchor": "#dash-forensics",
        "action": "select_forensics",
    },
    {
        "id": "09-agents",
        "title": "Agent IAM / confused-deputy",
        "caption": "Denied-by-agent counts and per-agent tool scope map",
        "anchor": "#dash-agents",
    },
    {
        "id": "10-drift",
        "title": "Posture drift (audit JSONL)",
        "caption": "Daily allow/block, drift Δ, top drivers — local file only",
        "anchor": "#dash-trends",
    },
    {
        "id": "11-finops",
        "title": "Token reduction & cost savings",
        "caption": "Actual vs would-have-been · FinOps saved · avoided by blocks",
        "anchor": "#dash-finops",
    },
    {
        "id": "12-traffic",
        "title": "Traffic & block reasons",
        "caption": "Allowed vs blocked time series, RBAC/injection mix, top tools",
        "anchor": "#dash-traffic",
    },
]


def _font(size: int, bold: bool = False):
    candidates = [
        "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _annotate(shot: Path, title: str, caption: str, out: Path) -> None:
    img = Image.open(shot).convert("RGB")
    # Crop to a readable frame (top portion of long pages)
    w, h = img.size
    crop_h = min(h, int(w * 0.62))
    frame = img.crop((0, 0, w, crop_h))
    banner_h = 110
    canvas = Image.new("RGB", (w, crop_h + banner_h), (12, 18, 34))
    canvas.paste(frame, (0, banner_h))
    draw = ImageDraw.Draw(canvas)
    draw.rectangle((0, 0, w, banner_h), fill=(15, 23, 42))
    draw.text((28, 28), "MCP-Bastion Dashboard", font=_font(22, True), fill=(148, 163, 184))
    draw.text((28, 58), title, font=_font(34, True), fill=(248, 250, 252))
    draw.text((28, 92), caption, font=_font(18), fill=(125, 211, 252))
    # Accent bar
    draw.rectangle((0, banner_h - 4, w, banner_h), fill=(56, 189, 248))
    canvas.save(out, "PNG", optimize=True)


def _build_hero(slides: list[Path], out: Path) -> None:
    """2x2 collage hero for README."""
    picks = slides[:4]
    if len(picks) < 4:
        picks = (picks * 4)[:4]
    tiles = [Image.open(p).convert("RGB") for p in picks]
    tw, th = 720, 405
    resized = []
    for t in tiles:
        r = t.copy()
        r.thumbnail((tw, th))
        pad = Image.new("RGB", (tw, th), (15, 23, 42))
        pad.paste(r, ((tw - r.size[0]) // 2, (th - r.size[1]) // 2))
        resized.append(pad)
    gap = 12
    hero = Image.new("RGB", (tw * 2 + gap * 3, th * 2 + gap * 3 + 72), (12, 18, 34))
    draw = ImageDraw.Draw(hero)
    draw.text(
        (gap * 2, 22),
        "MCP-Bastion · Live security posture + runtime governance dashboard",
        font=_font(28, True),
        fill=(248, 250, 252),
    )
    positions = [
        (gap, 72),
        (gap * 2 + tw, 72),
        (gap, 72 + gap + th),
        (gap * 2 + tw, 72 + gap + th),
    ]
    for img, pos in zip(resized, positions):
        hero.paste(img, pos)
    hero.save(out, "PNG", optimize=True)


def _build_gif(frames: list[Path], out: Path, duration_ms: int = 5000) -> None:
    """
    Build a walkthrough GIF slow enough to read captions + UI.

    Default 5s/frame (was ~2s — too fast on GitHub README).
    Uses Pillow duration in milliseconds (more reliable than imageio seconds).
    """
    imgs = []
    for p in frames:
        im = Image.open(p).convert("RGB")
        # GIF size budget: shrink for GitHub-friendly size
        im.thumbnail((1100, 700))
        imgs.append(im)
    if not imgs:
        raise ValueError("no frames for gif")
    # Hold the first slide a bit longer so readers catch the overview.
    durations = [int(duration_ms * 1.2)] + [int(duration_ms)] * (len(imgs) - 1)
    imgs[0].save(
        out,
        save_all=True,
        append_images=imgs[1:],
        duration=durations,
        loop=0,
        optimize=False,
    )


def rebuild_gif_from_slides(duration_ms: int = 5000) -> Path:
    """Rebuild tour GIF from existing annotated slides (no Playwright needed)."""
    slides_dir = OUT_DIR / "slides"
    annotated = []
    for slide in SLIDES:
        p = slides_dir / f"{slide['id']}.png"
        if not p.exists():
            raise FileNotFoundError(f"Missing slide: {p}")
        annotated.append(p)
    gif = IMAGES / "mcp-bastion-dashboard-tour.gif"
    _build_gif(annotated, gif, duration_ms=duration_ms)
    for dest_root in (DOCS_IMAGES, SITE_ASSETS):
        if not dest_root.exists():
            continue
        dest = dest_root / "mcp-bastion-dashboard-tour.gif"
        shutil.copyfile(gif, dest)
        print("copied", dest)
    return gif


async def capture() -> int:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        print("Install playwright: python -m pip install playwright && python -m playwright install chromium")
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    raw_dir = OUT_DIR / "raw"
    slides_dir = OUT_DIR / "slides"
    raw_dir.mkdir(exist_ok=True)
    slides_dir.mkdir(exist_ok=True)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport=VIEWPORT,
            device_scale_factor=1.25,
            color_scheme="dark",
        )
        page = await context.new_page()
        page.set_default_timeout(30000)
        await page.goto(BASE_URL, wait_until="domcontentloaded")
        # SSE alerts stream keeps the connection open, so avoid networkidle.
        # Force dark theme + wait for KPIs / panels
        await page.evaluate(
            """() => {
              try {
                localStorage.setItem('mcp-bastion-theme', 'dark');
                document.documentElement.setAttribute('data-theme', 'dark');
                if (document.body) document.body.setAttribute('data-theme', 'dark');
              } catch (e) {}
            }"""
        )
        await page.wait_for_timeout(2500)
        # Wait until loading overlay is gone or KPIs non-zero
        try:
            await page.wait_for_function(
                """() => {
                  const el = document.getElementById('kpiReq');
                  return el && el.textContent && el.textContent.trim() !== '0';
                }""",
                timeout=15000,
            )
        except Exception:
            pass
        await page.wait_for_timeout(1500)

        annotated: list[Path] = []
        for slide in SLIDES:
            action = slide.get("action") or ""
            if action == "close_modal":
                await page.evaluate(
                    """() => {
                      const m = document.getElementById('issueDetailModal');
                      if (m) m.classList.remove('open');
                    }"""
                )
                await page.wait_for_timeout(200)
            if slide.get("anchor"):
                await page.evaluate(
                    """(sel) => {
                      const el = document.querySelector(sel);
                      if (el) el.scrollIntoView({behavior: 'instant', block: 'start'});
                    }""",
                    slide["anchor"],
                )
                extra = int(slide.get("scroll_extra") or 0)
                if extra:
                    await page.evaluate("(dy) => window.scrollBy(0, dy)", extra)
            else:
                await page.evaluate("() => window.scrollTo(0, 0)")
            await page.wait_for_timeout(700)

            if action == "open_issue_guide":
                # Open first prevalidate / posture "Why / how to fix" button
                clicked = await page.evaluate(
                    """() => {
                      const btn = document.querySelector('#prevalidateBody [data-pv-i], #postureFindingsBody [data-finding-i], button.btn-linkish');
                      if (!btn) return false;
                      btn.click();
                      return true;
                    }"""
                )
                if clicked:
                    try:
                        await page.wait_for_selector("#issueDetailModal.open", timeout=4000)
                        await page.wait_for_timeout(600)
                        # Prefer guide content visible
                        await page.wait_for_function(
                            """() => {
                              const g = document.getElementById('issueDetailGuide');
                              return g && !g.hidden && (g.textContent || '').length > 40;
                            }""",
                            timeout=4000,
                        )
                    except Exception:
                        pass
                    await page.wait_for_timeout(400)

            if action == "select_forensics":
                await page.evaluate(
                    """() => {
                      const row = document.querySelector('#blockedForensicsBody tr[data-i]');
                      if (row) row.click();
                      const tab = document.querySelector('.forensics-tab[data-fd-tab="trace"]');
                      if (tab) tab.click();
                    }"""
                )
                try:
                    await page.wait_for_selector("#forensicsDetailPanel:not([hidden])", timeout=4000)
                except Exception:
                    pass
                await page.wait_for_timeout(500)

            raw = raw_dir / f"{slide['id']}.png"
            await page.screenshot(path=str(raw), full_page=False)
            ann = slides_dir / f"{slide['id']}.png"
            _annotate(raw, slide["title"], slide["caption"], ann)
            annotated.append(ann)
            print("slide", ann.name)

            if action == "open_issue_guide":
                await page.evaluate(
                    """() => {
                      const m = document.getElementById('issueDetailModal');
                      if (m) m.classList.remove('open');
                    }"""
                )

        # Full-page overview (compressed later)
        full = raw_dir / "full-page.png"
        await page.evaluate("() => window.scrollTo(0, 0)")
        await page.wait_for_timeout(400)
        await page.screenshot(path=str(full), full_page=True)
        await browser.close()

    hero = IMAGES / "mcp-bastion-dashboard.png"
    _build_hero(annotated, hero)
    print("hero", hero)

    gif = IMAGES / "mcp-bastion-dashboard-tour.gif"
    _build_gif(annotated, gif, duration_ms=5000)
    print("gif", gif, "bytes", gif.stat().st_size, "ms/frame", 5000)

    # Also keep a static "tour cover" = first annotated slide enlarged naming
    cover = IMAGES / "mcp-bastion-dashboard-tour.png"
    shutil.copyfile(annotated[0], cover)

    # Mirror into docs paths when present
    for dest_root in (DOCS_IMAGES, SITE_ASSETS):
        if not dest_root.exists():
            continue
        for name in (
            "mcp-bastion-dashboard.png",
            "mcp-bastion-dashboard-tour.gif",
            "mcp-bastion-dashboard-tour.png",
        ):
            src = IMAGES / name
            if src.exists():
                shutil.copyfile(src, dest_root / name)
                print("copied", dest_root / name)

    # Feature index markdown snippet for humans
    index = OUT_DIR / "README.md"
    lines = [
        "# Dashboard demo captures",
        "",
        "Generated by `scripts/capture_dashboard_demo.py` against a local demo dashboard.",
        "",
        "| Slide | Feature |",
        "|-------|---------|",
    ]
    for s, p in zip(SLIDES, annotated):
        lines.append(f"| ![](slides/{p.name}) | **{s['title']}** — {s['caption']} |")
    lines.extend(
        [
            "",
            "Published assets:",
            "- `images/mcp-bastion-dashboard.png` (README hero collage)",
            "- `images/mcp-bastion-dashboard-tour.gif` (feature walkthrough)",
            "- `images/mcp-bastion-dashboard-tour.png` (first frame)",
            "",
        ]
    )
    index.write_text("\n".join(lines), encoding="utf-8")
    return 0


def main() -> int:
    # Rebuild slow GIF from existing slides without re-capturing:
    #   python scripts/capture_dashboard_demo.py --gif-only
    # Optional: --duration-ms 6000
    args = [a for a in sys.argv[1:] if a]
    duration_ms = 5000
    if "--duration-ms" in args:
        i = args.index("--duration-ms")
        try:
            duration_ms = int(args[i + 1])
        except (IndexError, ValueError):
            print("usage: --duration-ms <int>", file=sys.stderr)
            return 2
    if "--gif-only" in args:
        try:
            gif = rebuild_gif_from_slides(duration_ms=duration_ms)
            print("gif", gif, "bytes", gif.stat().st_size, "ms/frame", duration_ms)
            return 0
        except Exception as e:
            print("gif rebuild failed:", e, file=sys.stderr)
            return 1
    try:
        return asyncio.run(capture())
    except Exception as e:
        print("capture failed:", e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
