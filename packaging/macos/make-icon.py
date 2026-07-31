#!/usr/bin/env python3
"""Generate the app icon: a gold crosshair ring on the console's dark ground.

Pure stdlib (zlib + struct) so it runs on any macOS box with no pip install, and
the icon is REPRODUCIBLE — the .icns in this repo is exactly what this script
emits. Shape is a squircle (the macOS superellipse), drawn with 4x supersampling.

    python3 packaging/macos/make-icon.py out.png
    # then: sips/iconutil turn it into AppIcon.icns (see bundle-macos.sh)
"""
import math
import struct
import sys
import zlib

SIZE = 1024
SS = 4  # supersampling factor

# The GUI's palette (src/main.rs): GROUND, GOLD, HOLD.
GROUND = (10, 12, 9)
PANEL = (22, 26, 16)
GOLD = (230, 189, 84)


def squircle(nx, ny, n=4.0, r=0.92):
    """Inside the macOS-style superellipse |x|^n + |y|^n <= r^n."""
    return abs(nx) ** n + abs(ny) ** n <= r**n


def sample(x, y):
    """Colour + coverage at a supersampled pixel, in normalized [-1, 1] space."""
    nx = (x + 0.5) / (SIZE * SS / 2) - 1.0
    ny = (y + 0.5) / (SIZE * SS / 2) - 1.0
    if not squircle(nx, ny):
        return None  # transparent outside the app shape
    d = math.hypot(nx, ny)
    # Ring: the crosshair's reticle.
    if 0.60 <= d <= 0.68:
        return GOLD
    # Inner target dot.
    if d <= 0.10:
        return GOLD
    # Crosshair arms — gapped at the ring so the mark reads as a reticle.
    arm = 0.035
    if abs(nx) <= arm and (0.20 <= abs(ny) <= 0.86):
        return GOLD
    if abs(ny) <= arm and (0.20 <= abs(nx) <= 0.86):
        return GOLD
    # Ground, lifted slightly toward the centre so it is not a flat black slab.
    t = max(0.0, 1.0 - d / 1.2)
    return tuple(int(GROUND[i] + (PANEL[i] - GROUND[i]) * t) for i in range(3))


def render():
    rows = []
    for y in range(SIZE):
        row = bytearray()
        for x in range(SIZE):
            r = g = b = a = 0
            for sy in range(SS):
                for sx in range(SS):
                    c = sample(x * SS + sx, y * SS + sy)
                    if c is not None:
                        r += c[0]
                        g += c[1]
                        b += c[2]
                        a += 255
            n = SS * SS
            rows.append
            row += bytes((r // n, g // n, b // n, a // n))
        rows.append(bytes(row))
    return rows


def png(rows, path):
    raw = b"".join(b"\x00" + r for r in rows)

    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))

    out = b"\x89PNG\r\n\x1a\n"
    out += chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
    out += chunk(b"IDAT", zlib.compress(raw, 9))
    out += chunk(b"IEND", b"")
    with open(path, "wb") as f:
        f.write(out)


if __name__ == "__main__":
    png(render(), sys.argv[1] if len(sys.argv) > 1 else "icon.png")
