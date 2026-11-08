# /// script
# requires-python = ">=3.10"
# dependencies = ["pillow"]
# ///
"""Render the real demo transcript as a terminal video (typewriter reveal, 1280x720).

The text is the actual output of demo/demo.py, captured to demo/DEMO-OUTPUT.txt. Nothing is
retimed to look better than it is: lines appear in order, at a constant reading pace.
"""

import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
TEXT = (ROOT / "demo" / "DEMO-OUTPUT.txt").read_text(encoding="utf-8").splitlines()
W, H = 1280, 720
FPS = 24
LINES_PER_SEC = 7.0
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
BOLD_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"

font = ImageFont.truetype(FONT_PATH, 15)
bold = ImageFont.truetype(BOLD_PATH, 15)
small = ImageFont.truetype(FONT_PATH, 13)

BG = (11, 13, 18)
FG = (212, 206, 194)
DIM = (120, 128, 140)
GOLD = (245, 213, 71)
CYAN = (95, 208, 207)
RED = (244, 87, 95)
MAX_LINES = 34
LINE_H = 19


def color_for(line: str):
    if "PASS" in line[:6]:
        return (95, 190, 120)
    if line.strip().startswith("===") or "BLASTRADIUS //" in line:
        return GOLD
    if "Risk level: HIGH" in line or "HIGH" in line and "Risk" in line:
        return RED
    if line.startswith("  ") and ('"' in line or "exists=" in line):
        return FG
    if not line.strip():
        return DIM
    return FG


def render(view: list[str], cut: int) -> Image.Image:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # window chrome
    d.rectangle([0, 0, W, 34], fill=(18, 21, 28))
    for i, c in enumerate([(244, 87, 95), (234, 176, 76), (95, 190, 120)]):
        d.ellipse([16 + i * 18, 12, 26 + i * 18, 22], fill=c)
    d.text((440, 11), "blastradius 2.0 — demo/demo.py", font=small, fill=DIM)
    d.line([0, 34, W, 34], fill=(30, 35, 44))

    y = 48
    for idx, line in enumerate(view):
        text = line[:150]
        if idx == len(view) - 1:
            text = text[:cut]
        d.text((22, y), text, font=bold if text.startswith(("===", "BLASTRADIUS")) else font,
               fill=color_for(text))
        y += LINE_H
        if y > H - 20:
            break
    d.text((22, H - 14), "$ python3 demo/demo.py", font=small, fill=DIM)
    return img


def main() -> int:
    frames_dir = Path("/tmp/brframes")
    frames_dir.mkdir(exist_ok=True)
    for f in frames_dir.glob("*.png"):
        f.unlink()

    total_chars_per_line = 8  # reveal speed within the newest line
    visible: list[str] = []
    frame = 0
    step = FPS / LINES_PER_SEC  # frames per line

    for i, line in enumerate(TEXT):
        visible.append(line)
        start = len(visible) - 1
        for sub in range(0, len(line) + 1, max(1, len(line) // 6 or 1)):
            view = visible[-MAX_LINES:]
            render(view, sub).save(frames_dir / f"{frame:05d}.png")
            frame += 1
        for _ in range(int(step)):
            view = visible[-MAX_LINES:]
            render(view, len(line)).save(frames_dir / f"{frame:05d}.png")
            frame += 1

    # hold the final screen
    for _ in range(FPS * 3):
        render(visible[-MAX_LINES:], 10_000).save(frames_dir / f"{frame:05d}.png")
        frame += 1

    out = ROOT / "demo" / "blastradius-demo.mp4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(FPS),
                    "-i", str(frames_dir / "%05d.png"), "-c:v", "libx264", "-crf", "20",
                    "-pix_fmt", "yuv420p", "-movflags", "+faststart", str(out)], check=True)
    dur = frame / FPS
    print(f"{out}  {out.stat().st_size/1024/1024:.1f} MB  {dur:.1f}s  {frame} frames")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
