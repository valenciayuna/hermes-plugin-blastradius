#!/usr/bin/env python3
"""Turn the demo mp4 into a README-friendly GIF (GitHub plays GIFs inline, mp4 blobs it does not)."""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "demo" / "blastradius-demo.mp4"
OUT = ROOT / "demo" / "blastradius-demo.gif"

WIDTH = 900
FPS = 10

# two-pass palette: the text has to stay readable at this width, which a naive GIF would destroy
palette = Path("/tmp/br-palette.png")
subprocess.run([
    "ffmpeg", "-y", "-loglevel", "error", "-i", str(SRC),
    "-vf", f"fps={FPS},scale={WIDTH}:-1:flags=lanczos,palettegen=max_colors=128:stats_mode=full",
    str(palette),
], check=True)

subprocess.run([
    "ffmpeg", "-y", "-loglevel", "error", "-i", str(SRC), "-i", str(palette),
    "-lavfi", f"fps={FPS},scale={WIDTH}:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3",
    "-loop", "0", str(OUT),
], check=True)

size = OUT.stat().st_size
print(f"{OUT}  {size/1024/1024:.1f} MB")
if size > 9 * 1024 * 1024:
    print("too big for a comfortable README, reducing width")
    subprocess.run([
        "ffmpeg", "-y", "-loglevel", "error", "-i", str(SRC), "-i", str(palette),
        "-lavfi", f"fps={FPS},scale=700:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=bayer:bayer_scale=3",
        "-loop", "0", str(OUT),
    ], check=True)
    print(f"reduced: {OUT.stat().st_size/1024/1024:.1f} MB")
