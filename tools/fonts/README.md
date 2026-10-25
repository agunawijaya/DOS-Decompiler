# The font comrun draws text with

`cp437-8x8.txt` is the 8x8 font `comrun.py` uses to draw text screens when
`--font` gives none. It is code page 437 taken from **unscii-8, version 2.1,
by viznut**, which its author has placed in the public domain. The CGA's own
font is in IBM's ROM and is not shipped here.

## Where it comes from

| | |
|---|---|
| Source | <http://viznut.fi/unscii/> (the page links the files below) |
| File used | `unscii-8.hex`, SHA-256 `03094f7fbab7085cf6a6b624cee61e47e71ce5d0c2f308c2f4436afdc17f776c` |
| Source package read for the licence | `unscii-2.1-src.tar.gz`, SHA-256 `4d1215d495e49d005ae70828ec1529e997049b9a7f152b9439d78c7e70c65b57` |
| Fetched | 2026-10-25 |
| Made with | `python tools/fonts/build_cp437.py unscii-8.hex > tools/fonts/cp437-8x8.txt` |

## Licence

From `unscii.txt` in the source package, verbatim:

> Everything made by me (viznut) is in the Public Domain.
>
> The first source font, Fixedsys Excelsior, is also in the Public Domain.
>
> Those pieces that come from the Unifont project (unifont.hex, hex2bdf.pl)
> are under GPL. For this reason, unscii-16-full also falls under GPL.

And from the page at the source URL, verbatim:

> "unscii-16-full" falls under GPL because of how Unifont is licensed; the
> other variants are in the Public Domain.

`unscii-8` is not `unscii-16-full`, and nothing from Unifont is in it: it is
assembled from viznut's own source files (`unscii.txt` and the files it
includes; the package's `Makefile` lists them).

## Not IBM's font

The prompt that asked for this font ruled out a dump of IBM's character ROM.
unscii-8 is a design of its own that picks, character by character, the shape
several 1980s system fonts agree on (its `unscii.txt` names them: Amiga,
Amstrad CPC, Atari 8-bit, Atari arcade, Atari ST, BBC Micro, Commodore 64 and
the IBM PC's CGA font). How close it comes to IBM's was measured against the
transcription of the IBM PC 8x8 font in the same package (`font-pc8.txt`,
which is a reference for the author and is **not** shipped here): of the 250
code page 437 characters both have, **54 are identical** -- 17 of them box
drawing in 0xB0..0xDF, which can only be drawn one way, 15 of the graphic
characters in 0x01..0x1F, 11 of the 94 printable ASCII characters -- and the
median character differs from IBM's in 11 of its 64 pixels.

## What it covers

252 of the 256 characters of code page 437, including every box-drawing,
shade and block character games draw with (0xB0..0xDF), the graphic
characters 0x01..0x1F, and the Greek and mathematical characters 0xE0..0xFE.
Byte 0x00 is drawn blank, as on the CGA, by hand: unscii-8's U+0000 is a
double-width cell. Four have no glyph in unscii-8 and are drawn as a hollow
box, and `comrun` counts the cells that hold them:

| Byte | Character |
|---|---|
| 0x0F | ☼ U+263C |
| 0x7F | ⌂ U+2302 |
| 0xA9 | ⌐ U+2310 |
| 0xF9 | ∙ U+2219 |

`--font FILE` takes any 2,048-byte 8x8 font instead, for example a dump of
the user's own adapter.
