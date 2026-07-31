#!/usr/bin/env python3
"""
Generate scripted terminal-style attack -> defense GIFs (video-like).

Shows: attack payload -> Bastion intercept -> BLOCKED/REDACTED + error code -> user value.

  python scripts/generate_attack_demo_gifs.py
"""

from __future__ import annotations

import shutil
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "images" / "attack-demos"
DOCS_IMG = ROOT / "docs" / "images" / "attack-demos"
SITE_ASSETS = ROOT / "docs" / "site" / "assets" / "attack-demos"

W, H = 1080, 640
DURATION_MS = 2400

SCENARIOS: list[dict] = [
    {
        "id": "01-prompt-guard",
        "feature": "prompt_guard",
        "title": "Prompt injection defense",
        "attack_cmd": 'tools/call run cmd="Ignore previous instructions..."',
        "attack_note": "Jailbreak in tool arguments",
        "bastion": "prompt_guard (ML + heuristics)",
        "result": "BLOCKED",
        "code": "-32001",
        "value": "Tool never runs. Agent takeover / instruction override stopped.",
    },
    {
        "id": "02-pii",
        "feature": "pii",
        "title": "PII leakage defense",
        "attack_cmd": "tools/call get_profile -> SSN + email in output",
        "attack_note": "Sensitive data heading back to the model",
        "bastion": "pii redaction (Presidio)",
        "result": "REDACTED",
        "code": "<US_SSN> <EMAIL_ADDRESS>",
        "value": "Model/logs never see raw PII. Privacy & compliance risk reduced.",
    },
    {
        "id": "03-rate-limit",
        "feature": "rate_limit",
        "title": "Agent loop / denial-of-wallet",
        "attack_cmd": "tools/call x6 with max_iterations=5",
        "attack_note": "Runaway agent burning tokens & API quota",
        "bastion": "rate_limit token bucket",
        "result": "BLOCKED",
        "code": "-32002",
        "value": "Loop stopped. Protects spend and upstream quotas.",
    },
    {
        "id": "04-content-filter",
        "feature": "content_filter",
        "title": "Path traversal defense",
        "attack_cmd": 'tools/call read_file path="/etc/passwd"',
        "attack_note": "Sensitive host file access attempt",
        "bastion": "content_filter (paths/code)",
        "result": "BLOCKED",
        "code": "-32005",
        "value": "Host secrets & system files stay unreachable via MCP tools.",
    },
    {
        "id": "05-rbac",
        "feature": "rbac",
        "title": "Unauthorized tool access",
        "attack_cmd": 'role=viewer tools/call write',
        "attack_note": "Over-privileged tool use (confused deputy)",
        "bastion": "rbac least privilege",
        "result": "BLOCKED",
        "code": "-32006",
        "value": "Viewers cannot call admin tools. Privilege sprawl contained.",
    },
    {
        "id": "06-schema",
        "feature": "schema_validation",
        "title": "Invalid / crafted args",
        "attack_cmd": "tools/call add {a:1}  # missing b:int",
        "attack_note": "Schema bypass / type confusion",
        "bastion": "schema_validation",
        "result": "BLOCKED",
        "code": "-32007",
        "value": "Bad args fail closed. Less silent corruption & injection via shape.",
    },
    {
        "id": "07-replay",
        "feature": "replay_guard",
        "title": "Replay attack defense",
        "attack_cmd": "same request_id + nonce sent twice",
        "attack_note": "Captured or duplicated mutating call",
        "bastion": "replay_guard",
        "result": "BLOCKED",
        "code": "-32008",
        "value": "No double-charge / double-email from replayed MCP calls.",
    },
    {
        "id": "08-cost",
        "feature": "cost_tracker",
        "title": "Cost overrun defense",
        "attack_cmd": "session spend > max_cost_per_session",
        "attack_note": "FinOps ceiling breached",
        "bastion": "cost_tracker",
        "result": "BLOCKED",
        "code": "-32009",
        "value": "Hard spend stop per session/day. Predictable agent cost.",
    },
]


def _font(size: int, bold: bool = False):
    for path in (
        "C:/Windows/Fonts/consolab.ttf" if bold else "C:/Windows/Fonts/consola.ttf",
        "C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf",
        "C:/Windows/Fonts/arialbd.ttf" if bold else "C:/Windows/Fonts/arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
        if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    ):
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _wrap(draw, text: str, font, max_w: int) -> list[str]:
    words = text.split()
    lines, cur = [], ""
    for w in words:
        trial = f"{cur} {w}".strip()
        if draw.textlength(trial, font=font) <= max_w:
            cur = trial
        else:
            if cur:
                lines.append(cur)
            cur = w
    if cur:
        lines.append(cur)
    return lines or [text]


def _chrome(title: str, step: str) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    img = Image.new("RGB", (W, H), (10, 14, 23))
    draw = ImageDraw.Draw(img)
    # title bar
    draw.rectangle((0, 0, W, 56), fill=(22, 27, 34))
    draw.ellipse((18, 18, 34, 34), fill=(255, 95, 86))
    draw.ellipse((42, 18, 58, 34), fill=(255, 189, 46))
    draw.ellipse((66, 18, 82, 34), fill=(39, 201, 63))
    draw.text((100, 16), f"mcp-bastion demo  |  {title}", font=_font(18, True), fill=(201, 209, 217))
    draw.text((W - 200, 18), step, font=_font(16), fill=(88, 166, 255))
    # terminal body
    draw.rounded_rectangle((24, 72, W - 24, H - 56), radius=12, fill=(13, 17, 23), outline=(48, 54, 61), width=2)
    # footer
    draw.rectangle((0, H - 44, W, H), fill=(22, 27, 34))
    draw.text(
        (24, H - 30),
        "Run live:  PYTHONPATH=src python -m examples.attack_demos",
        font=_font(14),
        fill=(139, 148, 158),
    )
    return img, draw


def frame_attack(s: dict) -> Image.Image:
    img, draw = _chrome(s["title"], "1/4 ATTACK")
    y = 100
    draw.text((48, y), "$ agent -> MCP tools/call", font=_font(18), fill=(139, 148, 158))
    y += 40
    draw.text((48, y), s["attack_cmd"], font=_font(20, True), fill=(255, 123, 114))
    y += 50
    for line in _wrap(draw, s["attack_note"], _font(20), W - 120):
        draw.text((48, y), line, font=_font(20), fill=(255, 166, 87))
        y += 32
    y += 24
    draw.text((48, y), "Without Bastion: tool executes / data leaks / spend continues.", font=_font(18), fill=(139, 148, 158))
    return img


def frame_intercept(s: dict) -> Image.Image:
    img, draw = _chrome(s["title"], "2/4 BASTION")
    y = 100
    draw.text((48, y), "$ mcp-bastion  [middleware | proxy]", font=_font(18), fill=(139, 148, 158))
    y += 44
    draw.text((48, y), f"Evaluating pillar: {s['bastion']}", font=_font(22, True), fill=(88, 166, 255))
    y += 48
    draw.text((48, y), "Policy: bastion.yaml  |  mode: enforce", font=_font(18), fill=(201, 209, 217))
    y += 40
    draw.text((48, y), "Path: client -> Bastion -> tool server", font=_font(18), fill=(139, 148, 158))
    y += 50
    draw.text((48, y), ">>> intercepting before tool side-effects...", font=_font(18, True), fill=(210, 168, 255))
    return img


def frame_result(s: dict) -> Image.Image:
    blocked = s["result"] == "BLOCKED"
    color = (255, 123, 114) if blocked else (63, 185, 80)
    img, draw = _chrome(s["title"], f"3/4 {s['result']}")
    y = 100
    draw.text((48, y), f"RESULT: {s['result']}", font=_font(28, True), fill=color)
    y += 52
    draw.text((48, y), f"MCP error / signal:  {s['code']}", font=_font(22, True), fill=(255, 215, 110))
    y += 48
    draw.text((48, y), f"feature: {s['feature']}", font=_font(18), fill=(201, 209, 217))
    y += 40
    draw.text((48, y), "PASS (scripted demo)  examples.attack_demos", font=_font(18), fill=(63, 185, 80))
    y += 50
    draw.text((48, y), "Tool side-effect prevented (or output scrubbed).", font=_font(18), fill=(139, 148, 158))
    return img


def frame_value(s: dict) -> Image.Image:
    img, draw = _chrome(s["title"], "4/4 VALUE")
    y = 100
    draw.text((48, y), "HOW BASTION HELPS YOU", font=_font(22, True), fill=(63, 185, 80))
    y += 48
    for line in _wrap(draw, s["value"], _font(22), W - 120):
        draw.text((48, y), line, font=_font(22), fill=(248, 250, 252))
        y += 36
    y += 28
    draw.text((48, y), "Docs: FEATURE_DEEP_DIVE · ATTACK_DEMOS · DOCUMENTATION_BIBLE", font=_font(16), fill=(139, 148, 158))
    y += 36
    draw.text((48, y), f"$ python -m examples.attack_demos --only {s['feature']}", font=_font(16, True), fill=(88, 166, 255))
    return img


def _save_gif(frames: list[Image.Image], path: Path, duration: int = DURATION_MS) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rgb = [f.convert("RGB") for f in frames]
    durs = [int(duration * 1.1)] + [duration] * (len(rgb) - 1)
    rgb[0].save(path, save_all=True, append_images=rgb[1:], duration=durs, loop=0, optimize=False)


def _copy(src: Path) -> None:
    for dest in (DOCS_IMG, SITE_ASSETS):
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dest / src.name)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    frames_dir = OUT / "frames"
    frames_dir.mkdir(exist_ok=True)
    master: list[Image.Image] = []

    intro, draw = _chrome("Attack -> Defense Tour", "TOUR")
    draw.text((48, 110), "Scripted demos: see Bastion value per feature", font=_font(24, True), fill=(248, 250, 252))
    draw.text((48, 170), "Prompt · PII · Rate · Content · RBAC · Schema · Replay · Cost", font=_font(18), fill=(88, 166, 255))
    draw.text((48, 220), "Each clip: ATTACK -> BASTION -> BLOCK/REDACT -> VALUE", font=_font(18), fill=(201, 209, 217))
    draw.text((48, 280), "$ PYTHONPATH=src python -m examples.attack_demos --strict", font=_font(16, True), fill=(63, 185, 80))
    master.append(intro)

    for s in SCENARIOS:
        frames = [frame_attack(s), frame_intercept(s), frame_result(s), frame_value(s)]
        for i, fr in enumerate(frames, 1):
            fr.save(frames_dir / f"{s['id']}-f{i}.png", "PNG", optimize=True)
        gif = OUT / f"{s['id']}.gif"
        _save_gif(frames, gif)
        _copy(gif)
        print("wrote", gif.relative_to(ROOT))
        master.extend([frames[0], frames[2], frames[3]])

    tour = ROOT / "images" / "mcp-bastion-attack-defense-tour.gif"
    _save_gif(master, tour, duration=1600)
    for dest in (ROOT / "docs" / "images", ROOT / "docs" / "site" / "assets"):
        dest.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(tour, dest / tour.name)
    print("wrote", tour.relative_to(ROOT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
