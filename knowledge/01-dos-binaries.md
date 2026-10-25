# DOS binaries: what the decompiler needs to be told

## MZ layout

A DOS `.EXE` is a 28-byte header, an optional relocation table, then the load
image. Three details cause most confusion:

- **`CS:IP` is relative to the load image**, not the file. The entry point in
  the file is `header_size + (CS << 4) + IP`.
- **The declared image can be shorter than the file.** `pages` and
  `bytes_on_last_page` define where the loader stops reading. Anything after
  that is invisible to DOS *and* to the disassembler: overlays, appended data,
  packer payloads. `mzinfo.py` reports it as `trailing-data`.
- **Relocations reveal the segment inventory.** Each entry points at a 16-bit
  segment value inside the image that the loader fixes up. Reading those
  values back gives you the segments the program actually constructs, without
  executing anything.

Two details of how DOS reads the header, from FreeDOS's and DOSBox's loaders
(`kernel/task.c` and `src/dos/dos_execute.cpp`, read 2026-10-19). Ghidra's MZ
loader differs on both (`04-pitfalls.md`):

- **Every relocation entry adds the load segment once, in table order.** A word
  listed twice gets it twice; a later entry sees what an earlier one wrote.
- **Bytes-on-last-page 0 means the last page is full.** Both loaders load
  whole pages, `pages * 512 - header`. That also means bytes after the declared
  end, inside the last page, reach memory. They still belong to no part of the
  program.

`tools/loadimage.py expected GAME.EXE` writes all of this down from the file
alone: the module's file range and digest, every relocation with its word
before and after the fixup, the entry and stack, anything appended.

The pipeline corrects both divergences by default, before anything reads the
program's bytes, then checks the result against the file, not against the
correction. The corrections are recorded: each one, with its value before and
after, in `load-corrections.json`, and the count in `loadimage.json` and in
`functions.json`. `-NoLoadCorrection` leaves Ghidra's own load in place to
compare.

A `.COM` file has no header at all: it loads at offset `0x100` in a single
segment. Tell the disassembler that base or every address is wrong by `0x100`.

## Memory models, and why they change everything

The memory model decides how many segments exist and therefore how the whole
binary should be mapped.

| Model | Code | Data | Pointers |
|---|---|---|---|
| tiny | one segment, shared with data | shared | near |
| small | one 64 KB `_TEXT` | one 64 KB `DGROUP` | near |
| medium | many code segments | one `DGROUP` | far code, near data |
| compact | one `_TEXT` | many data segments | near code, far data |
| large / huge | many | many | far both |

Diagnosing it from the binary:

- **Very few relocations relative to size** → small or tiny. Near pointers
  need no fixups, so only the startup code requires them. Sopwith: 2
  relocations for 60 KB, both adjacent to the entry point. So `mzinfo.py`'s
  `few-relocations` note is normal on a small-model program; on one that is
  otherwise large-model, it means something is hiding.
- **Many relocations, `CALL FAR` everywhere** → medium or large.
- **`DS` reloaded frequently** → far data, so compact or large.

Sopwith is small model. Everything lives in one code segment and one data
group, which is why simple offset arithmetic works throughout.

## Segments to define before decompiling

Give the disassembler the real segment layout. From Sopwith's rebuilt map:

```
1000:0000  BEGTEXT   CODE       7 bytes
1000:0010  _TEXT     CODE   35192 bytes
189b:0002  _DATA     DATA    8202 bytes
1a9b:000c  CONST     DATA    3043 bytes
1b5b:0002  _BSS      BSS    28572 bytes
```

`_BSS` occupies no file bytes; it is allocated at load. If the disassembler
tries to read it you get either garbage or a "no file data available for
defined segment" complaint. That message is informational, not an error.

## Packers

If the entry point is preceded or followed by one of these, unpack before
doing anything else — otherwise you decompile the decompressor:

| Signature | Packer |
|---|---|
| `LZ91`, `LZ09` | LZEXE |
| `PKLITE` | PKLITE |
| `diet` | DIET |
| `EXEPACK` | Microsoft EXEPACK |
| `UPX!` | UPX |

`mzinfo.py` scans for all of these and flags a hit near the entry point as an
error rather than a note. A packed file also shows a near-empty relocation
table and a tiny apparent code region.

## Overlays

Overlaid programs load code on demand into a shared region, so several
different functions occupy the same addresses at different times. A single
flat disassembly of such a file is nonsense. Signs: an `FBOV` signature, a
non-zero overlay number in the header, or a large block of trailing data.
Each overlay must be disassembled as its own address space.

**Microsoft LINK's overlays are in the executable, after the root.** The
Ancient Art of War (1987, Microsoft C 5.1) is the case read whole; its manager
is LINK's. Each module is an MZ of its own -- header, relocation table, image
-- with its overlay number at 0x1A, starting on the 512-byte page after the
one before. The manager finds module N by reading headers from the start of
the file and stepping each one's *page count* times 512 (the root's first:
47 pages, so the first module at 0x5E00), reads the image to the overlay area,
and adds the load segment to each word the module's relocation table names.
That table counts segments from the program's start, as the root's does: all
six modules' tables name segment 0482, where the area starts, and their other
segments lie above it.

A call into an overlay is `int 3Fh` followed by a byte and a word, the overlay
segment's index in the manager's tables and the offset in that segment; the
call returns past the three bytes. Ghidra decodes those three bytes as
instructions: the session that read The Ancient Art of War found `main` and
four other root functions decompiled wrongly from their first overlay call on.
The manager installs vector 3Fh through `INT 21h AH=25h` with the number read
from a variable, so the install is not a constant pattern in the bytes; the
calls are.

`tools/overlays.py` lists the modules the same way and writes one *view* per
module: the root's image with the module's at the area, and both relocation
tables -- what memory holds while that module is resident. A view is refused
when the area is not empty in the root (LINK leaves it zero), the module would
not fit, or a relocation crosses into the other's bytes; the area's segment is
the lowest link segment any module's relocations name, or `--load-segment`.
Each view's record (`VIEW.view.json`) goes through the pipeline into
`loadimage.json` as `overlay_view`. All six of The Ancient Art of War's views
verify, 58 checks each, and the function counts match the hand-built views
of the session that found the format: 417, 346, 292, 307, 352 and 312.

What a view cannot show: the rest of the area after a smaller module, zero in
the view, holds at run time whatever a larger one left there; and which
`int 3Fh` reaches which module is in the manager's tables, not read here.

## Hardware constants worth memorising

These identify what a function does faster than any structural analysis.

| Value | Meaning |
|---|---|
| `0xB800` | CGA / text video memory |
| `0xB000` | MDA / Hercules |
| `0xA000` | EGA / VGA graphics |
| `0x2000` | CGA odd-scanline offset — even and odd rows live in separate banks |
| `0x3D4`, `0x3D8`, `0x3D9` | CGA CRTC and mode registers |
| `0x40`–`0x43` | PIT — timing and PC-speaker sound |
| `0x60`, `0x61` | keyboard controller, speaker gate |
| `0x201` | joystick |
| `0x388`, `0x389` | AdLib |
| `INT 10h` | BIOS video |
| `INT 16h` | BIOS keyboard |
| `INT 21h` | DOS services |
| `INT 1Ch` | timer tick user hook — the game's heartbeat |
| `INT 09h` | keyboard hardware interrupt — custom key handling |
| `INT 1Bh` | Ctrl-Break |
| `INT 33h` | mouse |

A function hooking `INT 1Ch` and `INT 09h` is the game's input and timing
core. Sopwith hooks `0x1B`, `0x1C` and `0x09`, and its CGA code uses `0xB800`
with the `0x2000` bank offset and XOR writes — the XOR both draws and erases,
and the value read back doubles as collision detection.
