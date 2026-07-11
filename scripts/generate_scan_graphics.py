#!/usr/bin/env python3
"""Generate Scan → Test → Enforce and mcp-bastion scan CLI graphics for README / GitHub Pages."""

from __future__ import annotations

import shutil
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

REPO = Path(__file__).resolve().parent.parent
IMAGES = REPO / "images"
DOCS_IMAGES = REPO / "docs" / "images"
SITE_ASSETS = REPO / "docs" / "site" / "assets"

BG = (15, 23, 42)
BG2 = (30, 27, 75)
SCAN = (56, 189, 248)
TEST = (250, 204, 21)
ENFORCE = (74, 222, 128)
MUTED = (148, 163, 184)
WHITE = (248, 250, 252)
ACCENT = (99, 102, 241)


def _font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
    ]
    for path in candidates:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _rounded_rect(draw: ImageDraw.ImageDraw, xy, radius: int, fill, outline=None, width: int = 1) -> None:
    draw.rounded_rectangle(xy, radius=radius, fill=fill, outline=outline, width=width)


def generate_scan_test_enforce_banner(path: Path) -> None:
    w, h = 1920, 1080
    img = Image.new("RGB", (w, h), BG)
    draw = ImageDraw.Draw(img)

    for i in range(h):
        t = i / h
        r = int(BG[0] + (BG2[0] - BG[0]) * t * 0.6)
        g = int(BG[1] + (BG2[1] - BG[1]) * t * 0.6)
        b = int(BG[2] + (BG2[2] - BG[2]) * t * 0.6)
        draw.line([(0, i), (w, i)], fill=(r, g, b))

    draw.text((w // 2, 120), "MCP-BASTION", font=_font(42, True), fill=MUTED, anchor="mm")
    draw.text((w // 2, 230), "SCAN  →  TEST  →  ENFORCE", font=_font(118, True), fill=WHITE, anchor="mm")
    draw.text(
        (w // 2, 340),
        "No other tool has all three",
        font=_font(52, True),
        fill=ACCENT,
        anchor="mm",
    )
    draw.text(
        (w // 2, 410),
        "Privacy-first · In-process · MCP-native · FinOps + CI testing companion",
        font=_font(30),
        fill=MUTED,
        anchor="mm",
    )

    cards = [
        ("SCAN", "mcp-bastion scan", "Tool poisoning · homoglyphs · drift", SCAN),
        ("TEST", "mcp-bastion redteam", "OWASP MCP Top 10 harness", TEST),
        ("ENFORCE", "bastion.yaml", "Runtime on every MCP method", ENFORCE),
    ]
    card_w, card_h = 520, 360
    gap = 60
    total = len(cards) * card_w + (len(cards) - 1) * gap
    x0 = (w - total) // 2
    y0 = 500

    for idx, (title, cmd, desc, color) in enumerate(cards):
        x = x0 + idx * (card_w + gap)
        _rounded_rect(draw, (x, y0, x + card_w, y0 + card_h), 28, (255, 255, 255, 8), outline=color, width=4)
        draw.rectangle((x, y0, x + card_w, y0 + 12), fill=color)
        draw.text((x + card_w // 2, y0 + 70), title, font=_font(64, True), fill=color, anchor="mm")
        draw.text((x + card_w // 2, y0 + 165), cmd, font=_font(28, True), fill=WHITE, anchor="mm")
        draw.text((x + card_w // 2, y0 + 250), desc, font=_font(24), fill=MUTED, anchor="mm", align="center")

    draw.text(
        (w // 2, h - 70),
        "pip install mcp-bastion-python==3.0.0",
        font=_font(28),
        fill=MUTED,
        anchor="mm",
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, "PNG", optimize=True)
    print(f"Wrote {path}")


def generate_scan_cli_graphic(path: Path) -> None:
    w, h = 1600, 900
    img = Image.new("RGB", (w, h), BG)
    draw = ImageDraw.Draw(img)

    _rounded_rect(draw, (60, 60, w - 60, h - 60), 24, (24, 33, 58), outline=(51, 65, 85), width=2)
    draw.text((100, 100), "mcp-bastion scan", font=_font(36, True), fill=SCAN)
    draw.text((100, 155), "examples/fixtures/tools-poisoned.json", font=_font(26), fill=MUTED)

    y = 220
    lines = [
        ("MCP-Bastion static tool scan", WHITE, True),
        ("Tools: 3", MUTED, False),
        ("Fingerprint (sha256): a3f8…", MUTED, False),
        ("Grade: F", (248, 113, 113), True),
        ("", WHITE, False),
        ("Findings (4):", WHITE, True),
        ("[CRITICAL] run_shell — injection_heuristic", (248, 113, 113), False),
        ("[CRITICAL] run_shell — content_filter: API key material", (248, 113, 113), False),
        ("[HIGH] read_file — homoglyph: read_fi1e typosquat", TEST, False),
        ("[LOW] run_shell — empty_description rug-pull risk", MUTED, False),
    ]
    for text, color, bold in lines:
        if not text:
            y += 12
            continue
        draw.text((120, y), text, font=_font(28 if bold else 24, bold), fill=color)
        y += 46 if bold else 40

    _rounded_rect(draw, (980, 220, 1500, 760), 20, (15, 23, 42), outline=SCAN, width=3)
    draw.text((1240, 270), "CHECKS", font=_font(34, True), fill=SCAN, anchor="mm")
    checks = [
        "Injection in tool metadata",
        "Secrets & code-exec patterns",
        "Homoglyph / typosquat pairs",
        "Hidden Unicode characters",
        "Fingerprint drift vs baseline",
    ]
    cy = 330
    for c in checks:
        draw.text((1020, cy), f"✓  {c}", font=_font(24), fill=ENFORCE)
        cy += 52

    draw.text((1240, 820), "Client-side · No cloud · No ML download", font=_font(22), fill=MUTED, anchor="mm")

    path.parent.mkdir(parents=True, exist_ok=True)
    img.save(path, "PNG", optimize=True)
    print(f"Wrote {path}")


def sync_assets() -> None:
    pairs = [
        ("mcp-bastion-scan-test-enforce.png",),
        ("mcp-bastion-scan-cli.png",),
    ]
    for (name,) in pairs:
        src = IMAGES / name
        for dest_dir in (DOCS_IMAGES, SITE_ASSETS):
            dest_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest_dir / name)
            print(f"Copied -> {dest_dir / name}")

    dash_src = DOCS_IMAGES / "dashboard.png"
    dash_dest = IMAGES / "mcp-bastion-dashboard.png"
    if dash_src.exists():
        shutil.copy2(dash_src, dash_dest)
        shutil.copy2(dash_src, SITE_ASSETS / "dashboard.png")
        print(f"Synced dashboard -> {dash_dest}")


def main() -> None:
    IMAGES.mkdir(parents=True, exist_ok=True)
    generate_scan_test_enforce_banner(IMAGES / "mcp-bastion-scan-test-enforce.png")
    generate_scan_cli_graphic(IMAGES / "mcp-bastion-scan-cli.png")
    sync_assets()


if __name__ == "__main__":
    main()
