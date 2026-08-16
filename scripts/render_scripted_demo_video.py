#!/usr/bin/env python3
"""Render a scripted MCP-Bastion demo video + WebVTT captions for GitHub Pages.

Captions intentionally avoid em dashes (U+2014). Uses dashboard demo slides when
present; falls back to README collage assets. Requires ffmpeg on PATH.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SLIDES = ROOT / "images" / "dashboard-demo" / "slides"
OUT_DIR = ROOT / "docs" / "site" / "assets" / "video"
OUT_MP4 = OUT_DIR / "mcp-bastion-5.1.0-tour.mp4"
OUT_VTT = OUT_DIR / "mcp-bastion-5.1.0-tour.vtt"
SECONDS_PER_SLIDE = 4

# Scripted narration cues (no em dashes).
CUES: list[tuple[str, str]] = [
    ("01-overview.png", "MCP-Bastion 5.1.0. Cost-aware runtime governance for AI agents."),
    ("02-posture.png", "Pre-deploy posture grades and local scan findings before tools go live."),
    ("03-issue-guide.png", "Issue guides map each finding to remediation and Bastion knobs."),
    ("04-owasp.png", "OWASP ASI, MCP, and LLM coverage heatmaps with block pressure."),
    ("05-attack.png", "Live attack matrix shows which threat classes are under pressure now."),
    ("06-compliance.png", "Evidence and reports for operators. Bastion emits traces, not legal advice."),
    ("07-governance.png", "RBAC, prompt guard, rate and cost caps, PII, and Agent IAM."),
    ("08-forensics.png", "Forensics explain why a call was blocked, with pillar provenance."),
    ("09-agents.png", "Agent IAM stops confused-deputy tool access outside policy."),
    ("10-drift.png", "Posture drift from audit JSONL: allow versus block over time."),
    ("11-finops.png", "FinOps: token reduction and cost avoided by policy blocks."),
    ("12-traffic.png", "Traffic and deny reasons across the governed MCP path."),
]


def _pick_frames() -> list[tuple[Path, str]]:
    frames: list[tuple[Path, str]] = []
    for name, cue in CUES:
        path = SLIDES / name
        if path.is_file():
            frames.append((path, cue))
    if frames:
        return frames
    # Fallback collage assets
    fallbacks = [
        (ROOT / "images" / "mcp-bastion-dashboard.png", CUES[0][1]),
        (ROOT / "images" / "mcp-bastion-scan-test-enforce.png", "Scan, test, then enforce on the MCP path."),
        (ROOT / "images" / "mcp-bastion-attack-defense-tour.gif", "Attack to defense walkthrough."),
    ]
    for path, cue in fallbacks:
        if path.is_file():
            frames.append((path, cue))
    return frames


def _write_vtt(cues: list[str], path: Path, seconds: int) -> None:
    lines = ["WEBVTT", ""]
    for i, text in enumerate(cues):
        start = i * seconds
        end = (i + 1) * seconds
        # Avoid em dashes in caption text.
        clean = text.replace("\u2014", "-").replace("\u2013", "-")
        lines.append(f"{_ts(start)} --> {_ts(end)}")
        lines.append(clean)
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def _ts(total: int) -> str:
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}.000"


def main() -> int:
    if not shutil.which("ffmpeg"):
        print("ffmpeg not found on PATH", file=sys.stderr)
        return 1
    frames = _pick_frames()
    if not frames:
        print("No slide images found", file=sys.stderr)
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    work = OUT_DIR / "_frames"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    cues: list[str] = []
    for i, (src, cue) in enumerate(frames):
        dest = work / f"frame_{i:03d}.png"
        # Normalize to PNG for concat demuxer.
        if src.suffix.lower() == ".png":
            shutil.copy2(src, dest)
        else:
            subprocess.run(
                [
                    "ffmpeg",
                    "-y",
                    "-i",
                    str(src),
                    "-frames:v",
                    "1",
                    str(dest),
                ],
                check=True,
                capture_output=True,
            )
        cues.append(cue)

    list_file = work / "list.txt"
    # Each still shown for SECONDS_PER_SLIDE via concat demuxer.
    entries = []
    for i in range(len(cues)):
        entries.append(f"file 'frame_{i:03d}.png'")
        entries.append(f"duration {SECONDS_PER_SLIDE}")
    # Last frame must be listed again without duration for concat.
    entries.append(f"file 'frame_{len(cues) - 1:03d}.png'")
    list_file.write_text("\n".join(entries) + "\n", encoding="utf-8")

    cmd = [
        "ffmpeg",
        "-y",
        "-f",
        "concat",
        "-safe",
        "0",
        "-i",
        str(list_file.name),
        "-vf",
        "scale=1280:720:force_original_aspect_ratio=decrease,pad=1280:720:(ow-iw)/2:(oh-ih)/2,format=yuv420p",
        "-r",
        "30",
        "-movflags",
        "+faststart",
        str(OUT_MP4.resolve()),
    ]
    subprocess.run(cmd, check=True, cwd=work)
    _write_vtt(cues, OUT_VTT, SECONDS_PER_SLIDE)
    shutil.rmtree(work)
    print(f"Wrote {OUT_MP4.relative_to(ROOT)}")
    print(f"Wrote {OUT_VTT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
