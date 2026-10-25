#!/usr/bin/env python3
"""
build_cp437.py -- Make cp437-8x8.txt, the font comrun draws text screens with,
from unscii-8.

Why this exists
---------------
A text screen is character codes and colours; without the glyphs it is boxes.
The CGA's glyphs are in IBM's ROM and are not shipped here, so the font is
unscii-8 by viznut, which its author placed in the public domain (README.md
beside this file has the source, the licence text and the date). This script
is how the shipped table was made from it, so that it can be made again and
checked: every line of cp437-8x8.txt comes from one line of unscii-8.hex.

How it works
------------
Each byte of code page 437 is mapped to the Unicode character the PC draws for
it -- the graphic characters for 0x01..0x1F and 0x7F, not the control codes --
and that character's glyph is looked up in unscii-8.hex, the Unifont-style
hex file: `CODEPOINT:ROWS`, eight rows of eight pixels, the leftmost pixel in
the high bit, which is also how the CGA's ROM stores its glyphs.

What it does not do
-------------------
It does not draw a glyph unscii-8 lacks. Four code points have none, and their
lines say so with "-"; comrun draws those as a hollow box. Byte 0x00 is the
one exception made by hand: it is blank on the CGA, and unscii-8's U+0000 is a
double-width cell, so it is written as eight empty rows.

Usage:
    python tools/fonts/build_cp437.py unscii-8.hex > tools/fonts/cp437-8x8.txt
"""

import argparse
import hashlib
import sys
from pathlib import Path

# What the PC draws for the bytes below 0x20 and for 0x7F; the rest of the
# code page is Python's cp437 codec. Byte 0xFF is the no-break space.
GRAPHIC = [0x0000, 0x263A, 0x263B, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022,
           0x25D8, 0x25CB, 0x25D9, 0x2642, 0x2640, 0x266A, 0x266B, 0x263C,
           0x25BA, 0x25C4, 0x2195, 0x203C, 0x00B6, 0x00A7, 0x25AC, 0x21A8,
           0x2191, 0x2193, 0x2192, 0x2190, 0x221F, 0x2194, 0x25B2, 0x25BC]

HEADER = """\
# cp437-8x8.txt -- an 8x8 font for code page 437, from unscii-8 by viznut,
# which its author placed in the public domain. README.md beside this file
# has the source, the licence text and the date.
#
# One line per byte of code page 437: the byte in hex, its eight rows from
# the top as hex (the leftmost pixel in the high bit, as the CGA's own ROM
# stores them), and the Unicode character it is. A "-" in place of the rows:
# unscii-8 has no glyph for that character, and comrun draws a hollow box.
#
# Made by: python tools/fonts/build_cp437.py unscii-8.hex
# from unscii-8.hex with SHA-256 {sha}
"""


def unicode_of(byte):
    """The character code page 437 draws for a byte."""
    if byte < 0x20:
        return GRAPHIC[byte]
    if byte == 0x7F:
        return 0x2302
    return ord(bytes([byte]).decode("cp437"))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("hex", help="unscii-8.hex, as downloaded")
    args = ap.parse_args()
    raw = Path(args.hex).read_bytes()
    glyphs = {}
    for line in raw.decode("ascii").splitlines():
        code, rows = line.strip().split(":")
        glyphs[int(code, 16)] = rows
    out = [HEADER.format(sha=hashlib.sha256(raw).hexdigest())]
    for byte in range(256):
        u = unicode_of(byte)
        rows = "0" * 16 if byte == 0 else glyphs.get(u)
        if rows is not None and len(rows) != 16:
            raise SystemExit(f"U+{u:04X} is not 8 pixels wide in {args.hex}; "
                             f"is this unscii-8.hex and not unscii-16?")
        out.append(f"{byte:02X} {rows or '-'} U+{u:04X}\n")
    # Bytes, so the lines end the same on every system.
    sys.stdout.buffer.write("".join(out).encode("ascii"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
