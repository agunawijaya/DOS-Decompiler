#!/usr/bin/env python3
"""
comrun.py -- Run a DOS program under emulation and capture what it draws.

Why this exists
---------------
Everything else here reads a binary without executing it, and that discipline
is worth keeping: a screen drawn from the file alone is a claim about the file.
But it leaves one thing unmeasurable. A static reader can count what it failed
to explain; it cannot tell whether what it *did* explain is right, because it
has nothing to compare against.

That gap is not hypothetical. Hard Hat Mack's placement extraction reached
100% of the calls it reached while laying a fourteen-girder floor out as a
diagonal staircase, and the number was identical before and after the fix.

This supplies the missing reference. It runs the program, lets its start-up
code do whatever it does -- including patching its own tables, which Hard Hat
Mack does and which no amount of reading the file will reveal -- then calls a
chosen routine and dumps the framebuffer.

The static render remains the deliverable. This is the referee.

What it emulates, and what it refuses to
----------------------------------------
Enough DOS and BIOS to get a game to its first screen, and no more:

  * INT 10h  a mode set and a palette call go into the CGA's registers, for
             drawing (below); with --bios-text the cursor and the text calls
             are drawn too; with --adapter ega or tandy, that adapter's own
             calls (below); everything else is recorded and ignored
  * INT 21h  the handful of functions a game uses before drawing
  * INT 20h  terminate
  * IN/OUT   port reads return a value that keeps timing loops moving, writes
             are logged; there is no hardware here, except the CGA's
             registers, which are kept, its light pen latch, an 8253 count
             the program latched, and the keyboard, the timer, the PIC's
             mask and its end-of-interrupt, when keys or ticks go through
             the hardware

The processor is an 8088 (--cpu 8088, the default): a LOCK prefix Unicorn
refuses is stepped over, as the 8088 ran it on any instruction, and a divide
error returns past the divide. --cpu 386 leaves Unicorn as it is. On both, a
divide error and the trap flag's INT 1 go to a handler the program put in
the vector, and a divide error with none ends the run as DOS would.

The adapter is a CGA (--adapter cga, the default, as always). --adapter ega
answers INT 10h AH=12h as an EGA with 256 KB and draws mode 0Dh from four
planes at A000; --adapter tandy has a Tandy 1000's ROM signature and draws
mode 9 from its pages. Both answer INT 11h with an equipment word that says
so. A register value the model does not model stops the run, or the
picture, rather than be drawn wrong, and says which.

It does not emulate a disk. The timer is a word at 0040:006C advanced every
20,000 instructions unless asked for more: `--timer-isr` sends one interrupt
straight to the handler that holds its vector, and `--timer hw` raises IRQ 0
through whatever vector 8 holds, as the 8253 and the PIC do -- masked by port
0x21, held until the last one is acknowledged, and passed by the BIOS's own
INT 08h, when it gets there, to 0040:006C and INT 1Ch. `--timer auto` starts
as the default and switches the moment the program replaces vector 8 or 1Ch:
Moon Patrol (1983) installs its own INT 08h. It does emulate a keyboard, but only
because it has to: a title screen that asks for one or two players never
reaches the game otherwise, and `--call` cannot substitute, because the routine
you would call reads state that the title screen was supposed to set. Zaxxon
arrives at its game loop with an empty object table and draws a black frame
until something answers `INT 16h`.

`--keys` is that answer -- a queue consumed by `INT 16h`, one entry per read,
after which the program is told the keyboard is empty again. Each entry is
either a character (`1`) or a full `AX` as scancode:ASCII (`0x4800` for the up
arrow, which has no character at all).

A game that installs its own `INT 09h` handler never asks `INT 16h` anything:
it reads port 0x60 when IRQ 1 fires. Rollo and Moon Bugs (Windmill, 1983) are
written that way and stopped in their title loops for want of a key. With
`--keyboard hw` the same queue goes through the hardware instead: each key is
a make code in port 0x60 and an interrupt through whatever vector 9 holds,
then its break code the same way, `--key-every` instructions apart; port
0x64 says when a scancode is waiting, for a program that polls with IRQ 1
masked; the PIC's mask and end-of-interrupt are honoured. A key that reaches
the BIOS's own handler goes on into the `INT 16h` buffer, as it would on the
machine. `--keyboard auto` starts on `INT 16h` and moves the keys not yet read
to the hardware the moment the program replaces vector 9. The default is
`bios`, and with it nothing here behaves differently from before.

What it draws
-------------
The framebuffer at B800:0, as the CGA's registers say to draw it once the
program has set any of them -- mode control (0x3D8), colour select (0x3D9),
the CRTC's columns, rows, scanlines per row and start address (0x3D4/0x3D5),
or a mode or palette through `INT 10h`, which writes the same registers. Until
it has, the picture is 320x200 mode 4 in palette 1, as it always was. Text is
drawn with the font in tools/fonts/ -- code page 437 from unscii-8, which is in
the public domain; the CGA's own is in IBM's ROM and is not shipped -- or with
`--font`. Text a program writes through `INT 10h` rather than into the
framebuffer is drawn only with `--bios-text`: Alley Cat (1984) asks its first
question that way, and without it the screen stays black. With --adapter ega
in mode 0Dh the picture is the EGA's planes from the CRTC's start address,
and with --adapter tandy in mode 9 the Tandy's shown page, each through its
palette and at the scale of a 320-wide CGA picture; see EGA and Tandy.

What it loads
-------------
`.COM` and MZ. An MZ needs a loader rather than a memcpy -- the header says
where the image ends, every relocation entry names a segment word that has the
load segment added to it, and CS:IP and SS:SP come from the header. Skipping
any of that gives a program that starts and then behaves inexplicably.

It also answers enough of DOS to reach a first screen: the version, memory
allocation, and file open/read/seek/close against `--files`. That last one is
not a nicety. Karateka keeps its artwork in ninety files beside the
executable, and a game that cannot find its data does not fail loudly -- it
prints a line and exits, which looks exactly like a harness bug.

Compiled languages need more than a game written in assembly does, because
their runtimes ask DOS questions a game never would. A Turbo Pascal program's
`Dos` unit reaches for the directory search calls, the clock, the file
timestamp and the drive-is-remote IOCTL before it draws anything, so those are
answered too -- The Oregon Trail checks a licence file's age against the clock
on its fourth statement.

And it fills in the interrupt vector table, which matters more than it sounds.
Trapping the `int` instruction only catches programs that use it; Turbo
Pascal's `MsDos` and `Intr` read the vector out of the table and far-call it
instead. Against a zeroed table that is a call to 0000:0000, and the program
wanders off without ever raising an interrupt anyone could see. Every vector
points at an `int n` / `iret` stub, so both routes arrive at the same place.
Once the program puts a handler of its own in a vector, its `int n` goes to
that handler, as on the machine -- Tapper's file shim on INT 80h, an overlay
manager on INT 3Fh -- and the run says which vectors it replaced.

Usage:
    python comrun.py GAME.COM --png screen.png
    python comrun.py GAME.EXE --files . --png screen.png
    python comrun.py GAME.COM --keys 1 --stop-at 0x3B1 --png frame.png
    python comrun.py GAME.COM --keyboard hw --keys 0x3B00,1 --png frame.png
    python comrun.py GAME.EXE --keyboard auto --at D22E=0x3920 --png menu.png
    python comrun.py GAME.COM --adapter ega --keys 2 --png ega.png
    python comrun.py GAME.COM --call 0x14D8 --png level1.png
    python comrun.py GAME.COM --call 0x14D8 --watch 0x217,0x268,0x2b1 \\
                              --json blits.json
"""

import argparse
import json
import struct
import sys
from fnmatch import fnmatch
from pathlib import Path

try:
    from unicorn import (Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_MEM_WRITE,
                         UC_HOOK_MEM_READ, UC_HOOK_INTR, UC_HOOK_INSN, UC_HOOK_INSN_INVALID,
                         UC_PROT_ALL, UcError)
    from unicorn.x86_const import (
        UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX,
        UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP, UC_X86_REG_SP,
        UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS,
        UC_X86_REG_IP, UC_X86_REG_AL, UC_X86_REG_EFLAGS,
        UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
        UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
        UC_X86_REG_EIP, UC_X86_REG_FS, UC_X86_REG_GS,
        UC_X86_REG_FPCW, UC_X86_REG_FPSW, UC_X86_REG_FPTAG, UC_X86_REG_FP0,
        UC_X86_INS_IN, UC_X86_INS_OUT)
except ImportError:  # pragma: no cover
    print("comrun: unicorn is required (pip install unicorn)", file=sys.stderr)
    raise

SEG = 0x1000                    # where the program is loaded
BASE = SEG << 4
VIDEO = 0xB800 << 4             # CGA framebuffer
MEMSZ = 0x200000                # 2 MB flat, covers the program and the screen
LOAD = 0x100                    # a .COM starts here, after its PSP
STUBS = 0x0F000                 # interrupt stubs, just below the program
# F000:FF53, where the IBM BIOS keeps an `iret`: a program points a vector at
# it to switch a handler off. Jungle Hunt (1983) points INT 1Ch there, and the
# first tick the BIOS's INT 08h passed on ran into the empty memory that is
# all this harness has at F000. A vector holding it has no handler, here as
# on the machine. Kept out of memory, so that a run that wanders through F000
# goes as it always went.
BIOS_IRET = (0xF000, 0xFF53)

# CGA mode 4 palette 1, high intensity -- the one nearly every game used.
PALETTES = {
    "0": [(0, 0, 0), (0, 170, 0), (170, 0, 0), (170, 85, 0)],
    "1": [(0, 0, 0), (85, 255, 255), (255, 85, 255), (255, 255, 255)],
}


ZF = 0x40                       # the zero flag, bit 6 of FLAGS
IF = 0x200                      # the interrupt flag, bit 9 -- see _fire_isr
TF = 0x100                      # the trap flag, cleared with IF on entry
CF = 0x01                       # the carry flag -- DOS's error flag

# The processor the program is run as. Unicorn is a later x86, and it differs
# from the 8088 in two ways a program of the period can meet: it refuses a
# LOCK prefix on some instructions the 8088 ran it on, and it reports a
# divide error at the divide rather than after it. --cpu 8088 (the default,
# as sweep.py's) gives the 8088's answer to both; 386 leaves Unicorn's.
CPUS = ("8088", "386")

# The 8088's prefixes: the four segment overrides, LOCK and the two repeats.
# 0x66, 0x67, 0x64 and 0x65 are prefixes from the 386 on; on an 8088 they are
# other instructions altogether.
PREFIXES = frozenset((0x26, 0x2E, 0x36, 0x3E, 0xF0, 0xF2, 0xF3))


def lock_prefix(raw):
    """Where a LOCK prefix is among an instruction's prefixes, or None."""
    for at, byte in enumerate(raw):
        if byte == 0xF0:
            return at
        if byte not in PREFIXES:
            return None
    return None


def divide_length(raw):
    """The length of the instruction at the start of `raw` when it is one that
    raises the divide error -- DIV or IDIV (F6 or F7 with ModRM reg 6 or 7)
    or AAM, which divides AL by its immediate -- or None. 16-bit addressing,
    as an 8088 has: ModRM mod 1 adds a byte, mod 2 a word, and mod 0 a word
    when r/m is 6 (a direct address)."""
    at = 0
    while at < len(raw) and raw[at] in PREFIXES:
        at += 1
    if at + 1 >= len(raw):
        return None
    opcode, modrm = raw[at], raw[at + 1]
    if opcode == 0xD4:
        return at + 2
    if opcode not in (0xF6, 0xF7) or (modrm >> 3) & 7 not in (6, 7):
        return None
    mod, rm = modrm >> 6, modrm & 7
    disp = {0: 2 if rm == 6 else 0, 1: 1, 2: 2, 3: 0}[mod]
    return at + 2 + disp


# What a context restore must carry over: every register a real-mode program
# can change. Restoring a context resets the rest -- which is the point, see
# _clear_exception.
CPU_REGISTERS = (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                 UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_EBP, UC_X86_REG_ESP,
                 UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS,
                 UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_EIP, UC_X86_REG_EFLAGS,
                 UC_X86_REG_FPCW, UC_X86_REG_FPSW, UC_X86_REG_FPTAG) + tuple(
                     UC_X86_REG_FP0 + i for i in range(8))

# Instructions between two scancodes from --keyboard hw: a key is pressed,
# held this long, released, and the next one pressed this long after. An
# 8088 at 4.77 MHz runs very roughly 300,000 to 600,000 instructions a
# second, so this is a short press. It has to be long, not short: a game that
# reads its keyboard through its own handler usually keeps a flag per key,
# set on the make code and cleared on the break, and polls the flags once a
# frame. A press shorter than a frame is never seen.
KEY_EVERY = 200_000
KEY_RETRY = 500                 # a scancode waiting for IF or an EOI asks again

# Instructions between two IRQ 0 from --timer hw or auto. The 8253 ticks
# 18.2 times a second, and an 8088 runs very roughly 300,000 to 600,000
# instructions in one, so a tick is some 16,000 to 33,000 instructions. The
# same 20,000 as the tick written to 0040:006C without the hardware, so a run
# keeps the same sense of time either way. A program that reprograms the
# 8253 for a faster tick is not modelled: the period stays this.
TIMER_EVERY = 20_000

# The longest slice the run loop takes while --keyboard or --timer auto has
# not yet seen its vector replaced. The write that decides cannot stop the
# emulator itself (see _on_vector9_write), so the loop looks this often; a
# key or a tick is due thousands of instructions after the decision, so the
# delay changes nothing it schedules.
AUTO_SLICE = 1_000

# Scancode set 1, the XT's, for the keys a character can name. A key with no
# character (an arrow, a function key) is given as a full AX, 0xSSCC, exactly
# as --keys already takes it, and its scancode is SS. Shift is not pressed for
# you: an upper-case letter is its key, unshifted.
SCANCODES = {"\x1b": 0x01, "-": 0x0C, "=": 0x0D, "\x08": 0x0E, "\t": 0x0F,
             "[": 0x1A, "]": 0x1B, "\r": 0x1C, ";": 0x27, "'": 0x28, "`": 0x29,
             "\\": 0x2B, ",": 0x33, ".": 0x34, "/": 0x35, " ": 0x39}
SCANCODES.update({c: 0x02 + i for i, c in enumerate("1234567890")})
SCANCODES.update({c: 0x10 + i for i, c in enumerate("qwertyuiop")})
SCANCODES.update({c: 0x1E + i for i, c in enumerate("asdfghjkl")})
SCANCODES.update({c: 0x2C + i for i, c in enumerate("zxcvbnm")})


def scancode_of(ax):
    """The make code for a --keys entry, or None if it names no key."""
    if ax > 0xFF:
        return ax >> 8
    return SCANCODES.get(chr(ax).lower())

# One fixed timestamp for every file, packed the way DOS packs them: the date
# is (year-1980)<<9 | month<<5 | day and the time is hour<<11 | minute<<5 |
# second/2. It must agree with what INT 21h AH=2Ah and AH=2Ch report, because
# programs compare the two -- The Oregon Trail decides whether a network
# licence is stale by subtracting a file's timestamp from the clock, and a
# harness whose clock disagrees with its filesystem answers that question at
# random.
DOS_DATE = ((1990 - 1980) << 9) | (6 << 5) | 1          # 1 June 1990
DOS_TIME = (10 << 11) | (30 << 5) | 0                   # 10:30:00


def mz_header(data):
    """The fields a loader needs, or None if this is not an MZ."""
    if len(data) < 0x20 or data[:2] not in (b"MZ", b"ZM"):
        return None
    last, pages, nreloc, hdr_paras = struct.unpack_from("<HHHH", data, 2)
    minalloc = struct.unpack_from("<H", data, 10)[0]
    ss, sp, _, ip, cs, reloc = struct.unpack_from("<HHHHHH", data, 14)
    hdr = hdr_paras * 16
    end = (pages - 1) * 512 + (last or 512)
    if not (0 < hdr <= len(data)):
        return None
    return {"hdr": hdr, "end": min(end, len(data)), "nreloc": nreloc,
            "reloc": reloc, "cs": cs, "ip": ip, "ss": ss, "sp": sp,
            "minalloc": minalloc}


# The CGA's sixteen colours, in RGBI order.
RGBI = [(0, 0, 0), (0, 0, 170), (0, 170, 0), (0, 170, 170),
        (170, 0, 0), (170, 0, 170), (170, 85, 0), (170, 170, 170),
        (85, 85, 85), (85, 85, 255), (85, 255, 85), (85, 255, 255),
        (255, 85, 85), (255, 85, 255), (255, 255, 85), (255, 255, 255)]


class CGA:
    """What the program told the colour adapter, register by register.

    The framebuffer alone does not say what is on the screen. The same 16 KB
    is 320 by 200 four-colour pixels in mode 4 and eighty columns of
    character-and-attribute pairs in text mode, and which one is decided by
    the mode-control register at port 0x3D8, the colour-select register at
    0x3D9 and the 6845 CRTC behind 0x3D4/0x3D5. Moon Bugs programs all three
    itself: for play it sets eighty-column text with two scanlines per
    character row and fills the screen with character 0xDE, a right-hand half
    block, so that every cell is two pixels in two of sixteen colours -- a
    160 by 100 picture. Read as mode 4 that is vertical stripes, which is what
    the capture of it showed.

    INT 10h counts too, because the BIOS sets a mode by writing these same
    registers (the IBM BIOS's tables, below) and a palette call by writing
    0x3D9. A program that sets mode 4 through the BIOS and then pokes 0x3D9
    is rendered with both.

    Nothing here is consulted until the program touches the adapter: until
    then `programmed` is False and the picture is drawn as mode 4, as it
    always was. A mode this does not model (INT 10h AL=7 and above) also
    falls back to that, and says so.
    """

    # 0x3D8 after INT 10h AH=00 for modes 0..6, and the CRTC tables the IBM
    # BIOS loads with them. Moon Bugs' own graphics table is the third with
    # R2 one less -- the horizontal position it lets the player adjust.
    MODE_CONTROL = {0: 0x2C, 1: 0x28, 2: 0x2D, 3: 0x29, 4: 0x2A, 5: 0x2E, 6: 0x1E}
    CRTC_40 = [0x38, 0x28, 0x2D, 0x0A, 0x1F, 0x06, 0x19, 0x1C,
               0x02, 0x07, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00]
    CRTC_80 = [0x71, 0x50, 0x5A, 0x0A, 0x1F, 0x06, 0x19, 0x1C,
               0x02, 0x07, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00]
    CRTC_GFX = [0x38, 0x28, 0x2D, 0x0A, 0x7F, 0x06, 0x64, 0x70,
                0x02, 0x01, 0x06, 0x07, 0x00, 0x00, 0x00, 0x00]

    def __init__(self):
        # What DOS hands a program on a colour adapter: mode 3.
        self.mode, self.color = self.MODE_CONTROL[3], 0x30
        self.crtc = list(self.CRTC_80) + [0, 0]
        self.index = 0
        self.programmed = False
        self.unsupported = None     # a BIOS mode number this does not model
        self.writes = {"bios": [], "ports": set()}

    def bios_mode(self, al):
        """INT 10h AH=00, as the IBM BIOS does it."""
        mode = al & 0x7F
        self.programmed = True
        self.writes["bios"].append(f"mode {mode}")
        if mode not in self.MODE_CONTROL:
            self.unsupported = mode
            return
        self.unsupported = None
        self.mode = self.MODE_CONTROL[mode]
        # 0x30 for every mode but 6, whose 0x3F is the foreground colour.
        self.color = 0x3F if mode == 6 else 0x30
        table = (self.CRTC_40 if mode in (0, 1) else
                 self.CRTC_80 if mode in (2, 3) else self.CRTC_GFX)
        self.crtc[:16] = table

    def bios_palette(self, bh, bl):
        """INT 10h AH=0Bh. BH=0 sets the background (bits 0-3) and, in
        320-wide graphics, the intensity (bit 4); BH=1 the palette."""
        self.programmed = True
        self.writes["bios"].append(f"palette BH={bh} BL={bl}")
        if bh == 0:
            self.color = (self.color & 0xE0) | (bl & 0x1F)
        elif bh == 1:
            self.color = (self.color & 0xDF) | ((bl & 1) << 5)

    def out(self, port, value, size=1):
        """A write to the adapter's ports. True when the port was one of its.

        0x3D0 to 0x3D7 all reach the CRTC: the even ones select a register
        and the odd ones write it. A word written to the index port writes
        the data port too, AL first, which is how `out dx, ax` programs a
        register in one instruction."""
        if not 0x3D0 <= port <= 0x3D9:
            return False
        self.programmed = True
        self.writes["ports"].add(port)
        if port == 0x3D8:
            self.mode = value & 0xFF
        elif port == 0x3D9:
            self.color = value & 0xFF
        elif port <= 0x3D7 and port % 2 == 0:
            self.index = value & 0x1F
            if size == 2:
                self._crtc_write((value >> 8) & 0xFF)
        elif port <= 0x3D7:
            self._crtc_write(value & 0xFF)
        return True

    def _crtc_write(self, value):
        if self.index < len(self.crtc):
            self.crtc[self.index] = value

    def describe(self):
        m, r = self.mode, self.crtc
        if not m & 0x08:
            kind = "video disabled"
        elif m & 0x02:
            kind = ("640-wide graphics" if m & 0x10 else "320-wide graphics")
        else:
            kind = f"{r[1]}-column text"
        return (f"{kind}, 3D8=0x{m:02X} 3D9=0x{self.color:02X}, {r[1]} columns by "
                f"{r[6]} rows of {(r[9] & 0x1F) + 1} scanlines, start "
                f"0x{(r[12] << 8 | r[13]) & 0x3FFF:04X}")


class PIT:
    """The 8253's three counters, as far as a program reads one back.

    The Ancient Art of War (1987) measures the processor before its title: it
    loads counter 2 with 0x7950, latches it (port 0x43, read/write bits 00)
    and counts its own loops until the latched count is below 100. The
    alternating answer that keeps a timing loop moving never is, and the loop
    never ends. A latched count is answered from this model: what the program
    loaded, counted down at the 8253's 1,193,182 Hz -- in this harness's time
    65,536 counts to a timer tick, so 3.28 to an instruction by default.
    Modes 2 and 3 reload when they reach the end (mode 3 counting in twos),
    the others count on through zero; counter 2 holds while port 0x61 bit 0
    closes its gate and starts again when it opens. A read with no latch is
    answered as before: games read port 0x40 for a random number, and those
    runs are not changed."""

    def __init__(self):
        self.reload = [0x10000] * 3
        self.loaded = [0] * 3           # the clock at which each began counting
        self.mode = [3, 3, 3]
        self.access = [3, 3, 3]         # 1 low byte, 2 high byte, 3 low then high
        self.pending = [None] * 3       # a low byte waiting for its high byte
        self.latched = [[], [], []]     # a latched count's bytes still to be read
        self.gate2 = False
        self.latches = 0

    def count(self, channel, now):
        if channel == 2 and not self.gate2:
            return self.reload[2] & 0xFFFF
        elapsed, reload = now - self.loaded[channel], self.reload[channel]
        if self.mode[channel] & 3 in (2, 3):
            step = 2 if self.mode[channel] & 3 == 3 else 1
            return (reload - (elapsed * step) % reload) & 0xFFFF
        return (reload - elapsed) & 0xFFFF

    def control(self, value, now):
        channel = value >> 6
        if channel == 3:
            return                      # the 8254's read-back; the 8253 has none
        if (value >> 4) & 3 == 0:
            c = self.count(channel, now)
            self.latched[channel] = [c & 0xFF, c >> 8]
            self.latches += 1
            return
        self.access[channel], self.mode[channel] = (value >> 4) & 3, (value >> 1) & 7
        self.pending[channel] = None

    def write(self, channel, value, now):
        if self.access[channel] == 1:
            count = value
        elif self.access[channel] == 2:
            count = value << 8
        elif self.pending[channel] is None:
            self.pending[channel] = value
            return
        else:
            count, self.pending[channel] = self.pending[channel] | (value << 8), None
        self.reload[channel] = count or 0x10000
        self.loaded[channel] = now

    def gate(self, on, now):
        if on and not self.gate2:
            self.loaded[2] = now
        self.gate2 = on

    def read(self, channel):
        """The next byte of a latched count, or None when none is latched."""
        return self.latched[channel].pop(0) if self.latched[channel] else None


# The CGA's frame in the 8253's counts: 912 dots by 262 lines at 14.318 MHz,
# which the 8253's clock divides by 12 -- 59.92 frames a second.
CGA_FRAME = 912 * 262 // 12


def light_pen(crtc, now):
    """The address the 6845 is reading at `now`, in the 8253's counts: what
    its light pen registers (16 and 17) take when the latch is set through
    port 0x3DC. Jungle Hunt (1983) sets it to find the beam, divides the
    address by forty to get the row, and waits for row 99 to start its
    timer; the alternating answer a port read gets made that division
    overflow. The beam sweeps the CRTC's total -- columns by scanlines, rows
    of R9+1 lines and R5 more -- once a frame; the address is the row's
    start plus the column, as the 6845's counter runs on through the margins."""
    lines_per_row = (crtc[9] & 0x1F) + 1
    columns = crtc[0] + 1
    lines = (crtc[4] + 1) * lines_per_row + crtc[5]
    t = now % CGA_FRAME
    line = t * lines // CGA_FRAME
    column = (t * lines % CGA_FRAME) * columns // CGA_FRAME
    start = (crtc[12] << 8) | crtc[13]
    return (start + (line // lines_per_row) * crtc[1] + column) & 0x3FFF


# What --adapter ega and tandy answer when a program asks which adapter there
# is. The equipment word (INT 11h, and 0040:0010) says one floppy drive and
# the planar RAM bits an XT sets; bits 4 and 5 are the video at start-up: 00
# for an adapter with its own BIOS (an EGA), 10 for 80-column colour (a
# Tandy 1000, like a CGA). The machine byte at F000:FFFE is 0xFF, an IBM PC's,
# which is also what a Tandy 1000's ROM holds; a Tandy is told apart by the
# 0x21 at F000:C000. --adapter cga writes none of these: comrun never has,
# and cga keeps every run as it was.
EQUIPMENT = {"ega": 0x000D, "tandy": 0x002D}
MACHINE_BYTE = 0xFFFFE
TANDY_SIGNATURE = 0xFC000
ADAPTERS = ("cga", "ega", "tandy")


def rgbi(value):
    """An EGA palette register in a 200-line mode, as the RGBI colour it
    shows: bits 0-2 are blue, green and red, bit 4 the intensity -- the
    CGA's sixteen, which is what a 200-line monitor can show."""
    return (value & 7) | ((value >> 1) & 8)


class EGA:
    """The EGA in mode 0Dh -- 320 by 200 in sixteen colours -- register by
    register: what Rampage (1986) and The Ancient Art of War (1987) use,
    measured, and no more.

    Video memory is four planes of 64 KB behind the window at A000. A byte
    written there goes to each plane the sequencer's map mask (3C4/3C5 index
    2) enables, as the graphics controller (3CE/3CF) makes it: in write mode
    0 the byte rotated by the data rotate register, or the set/reset colour
    on the planes enable set/reset names; then combined with the latches by
    the function (replace, and, or, xor); then the bit mask chooses, bit by
    bit, between that and the latches. Write mode 1 stores the latches; write
    mode 2 spreads the byte's low four bits over the planes. A read loads all
    four latches and returns, in read mode 0, the plane read map select
    names, or in read mode 1 a bit for each pixel whose colour matches the
    colour compare register in the planes colour don't care keeps.

    What is drawn: 200 lines of the planes from the CRTC's start address
    (3D4/3D5 index 12 and 13), the CRTC's offset register (index 0x13) apart,
    each pixel's four bits through the sixteen palette registers of the
    attribute controller (3C0, or INT 10h AH=10h). In a 200-line mode a
    palette register is RGBI: bits 0-2 and bit 4.

    Not modelled, and refused rather than guessed: odd/even addressing (the
    graphics controller's mode bit 4, its miscellaneous register's chain bit,
    the sequencer's memory mode bit 2 clear), write mode 3, which the EGA does
    not have, the CGA-style shift register (mode bit 5), horizontal panning
    and a split screen (the CRTC's line compare inside the picture). A write
    to a register index the EGA does not have is ignored, as the EGA ignores
    it, and counted."""

    GC_NAMES = ("set/reset", "enable set/reset", "colour compare", "data rotate",
                "read map select", "mode", "miscellaneous", "colour don't care",
                "bit mask")
    # The registers the IBM EGA BIOS loads for mode 0Dh that matter here; its
    # CRTC table holds more, which change only the timing.
    SEQ_0D = [0x03, 0x0B, 0x0F, 0x00, 0x06]
    GC_0D = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0F, 0xFF]
    PALETTE_0D = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]
    CRTC_0D = {0x01: 0x27, 0x07: 0x11, 0x09: 0x00, 0x0C: 0x00, 0x0D: 0x00,
               0x13: 0x14, 0x18: 0xFF}

    def __init__(self):
        self.planes = [bytearray(0x10000) for _ in range(4)]
        self.latches = [0, 0, 0, 0]
        # As DOS leaves an EGA: text mode 3, the A000 window not mapped.
        self.mode = 3
        self.seq, self.seq_index = [0x03, 0x00, 0x03, 0x00, 0x03], 0
        self.gc, self.gc_index = [0, 0, 0, 0, 0, 0x10, 0x0E, 0x00, 0xFF], 0
        self.crtc, self.crtc_index = [0] * 25, 0
        self.palette = list(self.PALETTE_0D)
        self.attr = {0x10: 0x08, 0x11: 0x00, 0x12: 0x0F, 0x13: 0x00}
        self.attr_index, self.attr_data = 0, False
        self.ignored = {}           # (port, index) -> writes to a register the EGA lacks
        self.writes = {"bios": [], "ports": set()}
        self.reads = self.written = 0

    def bios_mode(self, al):
        """INT 10h AH=00 on an EGA. Mode 0Dh loads its registers and clears
        the planes unless AL bit 7 asks to keep them; another mode leaves the
        window unmapped here, and a CGA mode is drawn by the CGA's model."""
        self.mode = al & 0x7F
        self.writes["bios"].append(f"mode {self.mode:02X}h")
        if self.mode != 0x0D:
            self.seq[4], self.gc[5], self.gc[6] = 0x03, 0x10, 0x0E
            return
        self.seq = list(self.SEQ_0D)
        self.gc = list(self.GC_0D)
        self.palette = list(self.PALETTE_0D)
        self.attr = {0x10: 0x01, 0x11: 0x00, 0x12: 0x0F, 0x13: 0x00}
        for index, value in self.CRTC_0D.items():
            self.crtc[index] = value
        if not al & 0x80:
            for plane in self.planes:
                plane[:] = bytes(0x10000)

    def set_palette(self, index, value):
        if index < 16:
            self.palette[index] = value & 0x3F
        elif index in self.attr:
            self.attr[index] = value

    def out(self, port, value, size=1):
        """A write to the EGA's ports. A word goes out as two bytes, to the
        port and the next: `out dx, ax` at 3C4 writes the index then the
        register, as at 3CE and 3D4. True when the port was the EGA's."""
        if port not in (0x3C0, 0x3C4, 0x3C5, 0x3CE, 0x3CF, 0x3D4, 0x3D5):
            return False
        self.writes["ports"].add(port)
        self._out(port, value & 0xFF)
        if size == 2:
            self._out(port + 1, (value >> 8) & 0xFF)
        return True

    def _out(self, port, v):
        if port == 0x3C4:
            self.seq_index = v & 0x07
        elif port == 0x3C5:
            if self.seq_index < len(self.seq):
                self.seq[self.seq_index] = v
            else:
                self._ignore(0x3C5, self.seq_index)
        elif port == 0x3CE:
            self.gc_index = v & 0x0F
        elif port == 0x3CF:
            if self.gc_index < len(self.gc):
                self.gc[self.gc_index] = v
            else:
                # Rampage writes `out dx, ax` with AX 0x00CD here: index 0x0D,
                # which the EGA does not have, so the write goes nowhere.
                self._ignore(0x3CF, self.gc_index)
        elif port == 0x3C0:
            # One port for both: a flip-flop, which a read of 3DA resets,
            # takes an index, then a value, then an index again.
            if not self.attr_data:
                self.attr_index = v & 0x1F
            else:
                self.set_palette(self.attr_index, v)
            self.attr_data = not self.attr_data
        elif port == 0x3D4:
            self.crtc_index = v & 0x1F
        elif port == 0x3D5 and self.crtc_index < len(self.crtc):
            self.crtc[self.crtc_index] = v

    def _ignore(self, port, index):
        self.ignored[(port, index)] = self.ignored.get((port, index), 0) + 1

    def maps_a000(self):
        """Whether the window at A000 reaches the planes: the miscellaneous
        register's memory map 0 or 1."""
        return (self.gc[6] >> 2) & 3 in (0, 1)

    def refusal(self):
        """Why memory cannot be read or written as modelled now, or None."""
        if self.gc[5] & 0x10 or self.gc[6] & 0x02 or not self.seq[4] & 0x04:
            return (f"odd/even addressing (graphics mode {self.gc[5]:02X}h, "
                    f"miscellaneous {self.gc[6]:02X}h, sequencer memory mode "
                    f"{self.seq[4]:02X}h) is not modelled")
        if self.gc[5] & 3 == 3:
            return "write mode 3 is not an EGA write mode"
        return None

    def write(self, at, value):
        gc, latches, planes = self.gc, self.latches, self.planes
        mode, mask, bits = gc[5] & 3, self.seq[2] & 0x0F, gc[8]
        function = (gc[3] >> 3) & 3
        if mode == 0:
            turn = gc[3] & 7
            value = ((value >> turn) | (value << (8 - turn))) & 0xFF
        for p in range(4):
            if not mask >> p & 1:
                continue
            if mode == 1:
                planes[p][at] = latches[p]
                continue
            if mode == 0:
                data = ((0xFF if gc[0] >> p & 1 else 0) if gc[1] >> p & 1 else value)
            else:
                data = 0xFF if value >> p & 1 else 0
            if function == 1:
                data &= latches[p]
            elif function == 2:
                data |= latches[p]
            elif function == 3:
                data ^= latches[p]
            planes[p][at] = (data & bits) | (latches[p] & ~bits & 0xFF)
        self.written += 1

    def read(self, at):
        gc, latches = self.gc, self.latches
        for p in range(4):
            latches[p] = self.planes[p][at]
        self.reads += 1
        if not gc[5] & 0x08:
            return latches[gc[4] & 3]
        same = 0xFF
        for p in range(4):
            if gc[7] >> p & 1:
                same &= ~(latches[p] ^ (0xFF if gc[2] >> p & 1 else 0)) & 0xFF
        return same

    def display_refusal(self):
        """Why the picture cannot be drawn as modelled, or None."""
        if self.gc[5] & 0x20:
            return "the CGA-style shift register (graphics mode bit 5) is not modelled"
        if self.attr.get(0x13, 0) & 0x0F:
            return f"horizontal panning ({self.attr[0x13]:02X}h) is not modelled"
        line_compare = self.crtc[0x18] | ((self.crtc[0x07] >> 4) & 1) << 8
        if line_compare < 200:
            return f"a split screen at line {line_compare} is not modelled"
        return None

    def start(self):
        return (self.crtc[0x0C] << 8) | self.crtc[0x0D]

    def describe(self):
        return (f"mode 0Dh, 320x200 in 16 colours: start 0x{self.start():04X}, "
                f"{self.crtc[0x13] * 2} bytes a line, palette "
                + " ".join(f"{v:02X}" for v in self.palette))


def render_ega(ega):
    """Mode 0Dh as the registers say to draw it, three times in both
    directions, as a 320-wide CGA picture is: (PIL image, notes)."""
    from PIL import Image
    img = Image.new("RGB", (320, 200))
    px = img.load()
    start, stride = ega.start(), ega.crtc[0x13] * 2
    enabled = ega.attr.get(0x12, 0x0F) & 0x0F
    colours = [RGBI[rgbi(v)] for v in ega.palette]
    p0, p1, p2, p3 = ega.planes
    for y in range(200):
        base = start + y * stride
        for column in range(40):
            at = (base + column) & 0xFFFF
            b0, b1, b2, b3 = p0[at], p1[at], p2[at], p3[at]
            for k in range(8):
                bit = 7 - k
                index = (((b0 >> bit) & 1) | (((b1 >> bit) & 1) << 1)
                         | (((b2 >> bit) & 1) << 2) | (((b3 >> bit) & 1) << 3)) & enabled
                px[column * 8 + k, y] = colours[index]
    notes = []
    if ega.ignored:
        notes.append("ignored, as the EGA ignores them: " + ", ".join(
            f"{n:,} write{'' if n == 1 else 's'} to {port:X}h index {index:02X}h"
            for (port, index), n in sorted(ega.ignored.items())))
    return img.resize((960, 600), Image.NEAREST), notes


class Tandy:
    """The Tandy 1000's video in mode 9 -- 320 by 200 in sixteen colours,
    32 KB -- as Rampage (1986) uses it.

    Video memory is part of the machine's RAM, counted in 16 KB pages, and two
    page registers say which: the CRT page is shown, the CPU page is what the
    window at B800 reaches, and a program draws on one while showing the
    other. Port 3DF holds both (bits 0-2 the CRT page, 3-5 the CPU page, 6-7
    the addressing; 11 is the 32 KB graphics modes'), as INT 10h AH=05h
    AL=80h-83h reads and sets them. In 32 KB modes a page number's low bit is
    ignored. The eight pages are kept here, and the window is the CPU page's
    two: when the CPU page changes, the window is put away and the new page
    brought in. A program that reaches the pages through their place in its
    own RAM rather than through B800 is not modelled.

    A line is 160 bytes, two pixels a byte, high nibble first, and the lines
    are in four banks of 8 KB: line y at (y mod 4) * 0x2000 + (y div 4) *
    160. Each pixel goes through a palette register of the video gate array
    (index 3DA, data 3DE, registers 10h-1Fh; or INT 10h AH=10h), whose four
    bits are the CGA's RGBI."""

    WINDOW = 0x8000

    def __init__(self):
        self.pages = bytearray(0x20000)
        self.mode = 3
        # The BIOS sets both page registers to the top of the 128 KB the
        # video pages are counted in, and Rampage's own first write agrees.
        self.crt_page, self.cpu_page, self.addressing = 6, 6, 3
        self.palette = list(range(16))
        self.border = 0
        self.gate_index = 0
        self.gate = {}              # video gate array registers other than the palette
        self.writes = {"bios": [], "ports": set()}

    def base(self, page):
        return (page & 6) * 0x4000

    def set_palette(self, index, value):
        if index < 16:
            self.palette[index] = value & 0x0F

    def set_border(self, value):
        self.border = value & 0x0F

    def describe(self):
        return (f"mode 9, 320x200 in 16 colours: CRT page {self.crt_page}, CPU page "
                f"{self.cpu_page}, palette " + " ".join(f"{v:X}" for v in self.palette))


def render_tandy(tandy, shown):
    """Mode 9 from the 32 KB `shown`, three times in both directions."""
    from PIL import Image
    img = Image.new("RGB", (320, 200))
    px = img.load()
    colours = [RGBI[v] for v in tandy.palette]
    for y in range(200):
        base = (y & 3) * 0x2000 + (y >> 2) * 160
        for column in range(160):
            v = shown[base + column]
            px[column * 2, y] = colours[v >> 4]
            px[column * 2 + 1, y] = colours[v & 0x0F]
    notes = []
    if tandy.gate:
        notes.append("video gate array registers written and not modelled: " + ", ".join(
            f"{index:02X}h={value:02X}h" for index, value in sorted(tandy.gate.items())))
    return img.resize((960, 600), Image.NEAREST), notes


# The glyphs a picture can be drawn from without a font: blank, the full
# block and the four half blocks, which are geometry, not lettering. They are
# what the 160 by 100 arrangement draws with, and all there is if the shipped
# font below cannot be read; anything else is then drawn as a hollow box and
# counted.
BLOCK_GLYPHS = {0x00: [0] * 8, 0x20: [0] * 8, 0xFF: [0] * 8,
                0xDB: [0xFF] * 8, 0xDC: [0] * 4 + [0xFF] * 4,
                0xDD: [0xF0] * 8, 0xDE: [0x0F] * 8, 0xDF: [0xFF] * 4 + [0] * 4}
UNKNOWN_GLYPH = [0x00, 0x7E, 0x42, 0x42, 0x42, 0x42, 0x7E, 0x00]
MAX_LINES = 300                 # more than a CGA's 262 can show

# The font text is drawn with when --font gives none: code page 437 from
# unscii-8, which its author placed in the public domain. The CGA's own
# glyphs are in IBM's ROM and are not shipped. tools/fonts/README.md has the
# source, the licence and what it lacks.
FONT = Path(__file__).resolve().parent / "fonts" / "cp437-8x8.txt"
_shipped = {}


def shipped_font():
    """(2,048 bytes of glyphs, the bytes the font has no glyph for), from
    tools/fonts/cp437-8x8.txt; (None, ()) if it cannot be read, and the
    picture is then drawn as it was before a font was shipped. A byte with no
    glyph is given the hollow box."""
    if "font" not in _shipped:
        glyphs, missing = bytearray(2048), []
        try:
            lines = FONT.read_text(encoding="ascii").splitlines()
        except OSError:
            _shipped["font"] = (None, ())
            return _shipped["font"]
        for line in lines:
            if not line.strip() or line.startswith("#"):
                continue
            code, rows, _ = line.split()
            code = int(code, 16)
            if rows == "-":
                missing.append(code)
                glyphs[code * 8:code * 8 + 8] = bytes(UNKNOWN_GLYPH)
            else:
                glyphs[code * 8:code * 8 + 8] = bytes.fromhex(rows)
        _shipped["font"] = (bytes(glyphs), tuple(missing))
    return _shipped["font"]


def render_cga(fb, cga, palette=None, font=None, missing=()):
    """The picture the registers describe: (PIL image, notes).

    The image is at pixel resolution and already scaled for viewing: three
    times in both directions for a 320-wide picture, as the old renderer
    did, so a standard mode 4 comes out identical to it; twice across and
    three times down for a 640-wide one, which keeps roughly the same shape.
    `palette` ("0" or "1") overrides 0x3D9's palette in 320-wide graphics.
    `missing` lists the characters `font` has no glyph for, which it draws
    as boxes; they are counted.
    """
    from PIL import Image
    notes = []
    m, r = cga.mode, cga.crtc
    cols, rows, lines = r[1], r[6] & 0x7F, (r[9] & 0x1F) + 1
    start = (r[12] << 8 | r[13]) & 0x3FFF
    graphics, hires = bool(m & 0x02), bool(m & 0x10)
    if graphics:
        width = cols * (16 if hires else 8)
    else:
        width = cols * 8
    height = min(rows * lines, MAX_LINES)
    if rows * lines > MAX_LINES:
        notes.append(f"{rows} rows of {lines} scanlines is more than a CGA shows; "
                     f"the first {MAX_LINES} are drawn")
    if not m & 0x08 or not width or not height:
        why = ("video is disabled (3D8 bit 3 clear)" if not m & 0x08 else
               f"the CRTC displays {cols} columns by {rows} rows")
        notes.append(f"the screen is blank: {why}. The framebuffer still holds "
                     f"whatever was drawn; --render mode4 shows it as before")
        img = Image.new("RGB", (max(width, 320), max(height, 200)))
        return img.resize((img.width * 3, img.height * 3), Image.NEAREST), notes

    img = Image.new("RGB", (width, height))
    px = img.load()
    if graphics and not hires:
        if palette is not None:
            colours = list(PALETTES[palette])
            colours[0] = RGBI[cga.color & 0x0F]
        else:
            bright = 8 if cga.color & 0x10 else 0
            which = ((3, 4, 7) if m & 0x04 else
                     (3, 5, 7) if cga.color & 0x20 else (2, 4, 6))
            colours = [RGBI[cga.color & 0x0F]] + [RGBI[c + bright] for c in which]
    elif graphics:
        colours = [RGBI[0], RGBI[cga.color & 0x0F]]
    unknown = 0
    for line in range(height):
        row, scan = divmod(line, lines)
        base = start + row * cols                # a word address, as the CRTC counts
        for col in range(cols):
            if graphics:
                at = (((base + col) * 2) & 0x1FFF) | ((scan & 1) << 13)
                for half in (0, 1):
                    v = fb[at + half]
                    if hires:
                        x0 = col * 16 + half * 8
                        for k in range(8):
                            px[x0 + k, line] = colours[(v >> (7 - k)) & 1]
                    else:
                        x0 = col * 8 + half * 4
                        for k in range(4):
                            px[x0 + k, line] = colours[(v >> (6 - k * 2)) & 3]
            else:
                at = ((base + col) * 2) & 0x3FFF
                ch, attr = fb[at], fb[(at + 1) & 0x3FFF]
                if font is not None:
                    bits = font[ch * 8 + (scan & 7)]
                    if ch in missing and scan == 0:
                        unknown += 1
                else:
                    glyph = BLOCK_GLYPHS.get(ch)
                    if glyph is None:
                        glyph = UNKNOWN_GLYPH
                        if scan == 0:
                            unknown += 1
                    bits = glyph[scan & 7]
                fg = RGBI[attr & 0x0F]
                bg = RGBI[(attr >> 4) & (0x07 if m & 0x20 else 0x0F)]
                for k in range(8):
                    px[col * 8 + k, line] = fg if (bits >> (7 - k)) & 1 else bg
    if unknown and font is not None:
        notes.append(f"{unknown} character cells hold "
                     + ", ".join(f"0x{c:02X}" for c in missing)
                     + f", which the font has no glyph for, and are drawn as boxes; "
                       f"--font takes an 8x8 font (2,048 bytes) that has them")
    elif unknown:
        notes.append(f"{unknown} character cells hold a character with no built-in "
                     f"glyph and are drawn as boxes; give --font with an 8x8 font "
                     f"(2,048 bytes) to draw them")
    across = 3 if width <= 320 else 2
    return img.resize((width * across, height * 3), Image.NEAREST), notes


class Machine:
    def __init__(self, image, trace=False, keys=(), files=None):
        self.image = image
        # Image offsets are `flat - BASE - LOAD` for both .COM and MZ, because
        # this loader places an MZ image after the PSP as well.
        #
        # A note against repeating a mistake: this was "corrected" once to
        # `BASE` for MZ, on the theory that an MZ image starts at BASE and the
        # extra 0x100 was why --stop-at never fired on a hunting routine. Both
        # halves were wrong. --stop-at never fired because the routine returns
        # before reaching that address, and the change dropped the agreement
        # between a listing and an execution trace from 99.6% to 31.6%. The
        # 31.6% run is the one that identified the error: its unmatched
        # addresses were all exactly 0x100 above decoded ones.
        self.img_bias = BASE + LOAD
        self.trace = trace
        self.keys = list(keys)  # AX values INT 16h will hand out, in order
        self.keys_read = 0
        # Polls of INT 16h AH=01 since the last blocking read, and how many to
        # answer "nothing waiting" before admitting there is. None disables it
        # and restores the old behaviour, which is right for a game with no
        # flush loops. See the AH=01 handler for why this exists.
        self.polls = 0
        self.poll_patience = None
        # The interrupt NUMBER to deliver periodically, and how often. None
        # means do not -- right for a program that reads 0040:006C rather than
        # hooking the vector. A number, not an address, so that nothing is
        # delivered until the program has installed a handler. See _fire_isr.
        self.isr_vector = None
        self.isr_every = 20_000
        self.isr_fired = 0
        self.isr_masked = 0     # deliveries skipped because IF was clear
        self.ticks = 0          # what INT 1Ah reports, one per call
        self.stop_off = None    # --stop-at, counted rather than first-hit
        self.stop_after = 1
        self.stop_hits = 0
        self.ints = []          # (int number, AH) as they were requested
        # vector -> (how many `int`s went to the program's own handler, and
        # which handlers): see _to_program.
        self.dispatched = {}
        self.ports = []         # (direction, port, value)
        self.blits = []         # whatever --watch asked for
        self.watch = {}
        self.steps = 0
        self.stopped = None
        self.recent = [0] * 512
        # Every image offset the program actually executed. Off by
        # default: a set with a million entries costs real time, and
        # it is only wanted when something is being checked against
        # a static reading.
        self.exec_map = None
        # The same with the CS each instruction ran under and its length:
        # {(linear address, CS, size)}, for --exec-map-json. A linear address
        # says where, and only CS:IP says at which origin -- which is what
        # comrec checks its layout against.
        self.exec_where = None
        # ADDR -> [AX, ...]: keys handed over only when the program reaches a
        # chosen instruction. `--keys` alone is a blind queue, and a game that
        # polls the keyboard eats it: The Oregon Trail issues 81,665 INT 16h
        # reads while consuming 73 queued keys, so a sequence meant for its
        # prompts is swallowed by an animation loop long before the prompt
        # appears. Triggering on an address puts the key where it is wanted.
        self.at_keys = {}
        # A gated queue: keys wait here and one is released whenever execution
        # reaches any address in `self.gates`. --at ties a key to one place;
        # this ties the whole sequence to "wherever the program actually reads
        # a key", which is what you want when a program has nine such places
        # and polls the keyboard tens of thousands of times between them.
        self.gates = set()
        self.gated = []
        self.gate_every = 400_000        # instructions between releases
        self.last_release = 0
        # Every file read, when asked for. A short read is a silent failure in
        # a program that checks the byte count: Genus's container reader treats
        # 83 bytes where it asked for 84 as a corrupt archive and returns an
        # error its caller turns into a blank screen.
        # Addresses at which to dump DS:SI and ES:DI. A watch that only reads
        # globals cannot see a string being compared on the stack, which is
        # where the interesting ones live.
        self.ptr_watch = {}
        self.trace_io = False
        self.io_log = []
        self.pending_key = None     # what port 0x60 should hand over next
        # The hardware keyboard: --keyboard hw or auto. Off by default, and
        # while off nothing below is consulted and INT 16h, port 0x60 and the
        # run loop behave exactly as they always have. See _keyboard_step.
        self.keyboard = "bios"
        self.hw_keys = []           # AX values still to go through the hardware
        self.hw_every = KEY_EVERY   # instructions between two scancodes
        self.hw_due = None          # self.steps at which the next one is due
        self.hw_scancodes = []      # make then break of the key in flight
        self.hw_ax = 0              # that key's AX, for a BIOS that reads it
        self.hw_waiting = False     # latched in port 0x60, IRQ 1 not yet taken
        self.kbd_latch = 0          # what port 0x60 holds
        self.kbd_full = False       # port 0x64 bit 0: a scancode nobody read
        self.kbd_route = None       # what --keyboard auto decided, once it has
        self.kbd_hooked = None      # (step, segment, offset) of the program's INT 09h
        self.kbd_log = {"scancodes": 0, "irq": 0, "to_bios": 0, "held": 0,
                        "masked": 0, "eoi": 0}
        self.pic_mask = 0           # port 0x21; bit 1 masks the keyboard
        self.in_service = set()     # IRQ levels taken and not yet acknowledged
        self._watching_vector9 = False
        # The timer as hardware: --timer hw or auto. Off by default, and while
        # off the tick at 0040:006C is advanced directly, as it always was,
        # and --timer-isr is the only way a handler runs. See _timer_step.
        self.timer = "bios"
        self.timer_every = TIMER_EVERY  # instructions between two IRQ 0
        self.timer_due = None       # self.steps at which the next one is due
        self.timer_route = None     # what --timer auto decided, once it has
        self.timer_hooked = None    # (step, vector, segment, offset) that decided it
        self.timer_handler = None   # (segment, offset) the last IRQ 0 went to
        self.user_tick = None       # (segment, offset) of the INT 1Ch the BIOS raised
        self.pending_1c = False     # the BIOS's INT 08h has an INT 1Ch to raise
        self.timer_log = {"irq": 0, "to_program": 0, "to_bios": 0, "int1c": 0,
                          "held": 0, "masked": 0, "eoi": 0}
        self._watching_timer = False
        self.cga = CGA()            # what the program told the display adapter
        # Which adapter the machine has: --adapter. cga answers every question
        # as comrun always has; ega and tandy add their identity, registers
        # and memory (set_adapter).
        self.adapter = "cga"
        self.ega = None             # the EGA model, with --adapter ega
        self.tandy = None           # the Tandy 1000's video, with --adapter tandy
        self.identity_reads = {}    # ROM address -> reads, with ega or tandy
        self.pit = PIT()            # the 8253, for a count the program latches
        self.pen = 0                # the light pen latch: the address it took
        self.pen_presets = 0
        # The processor: --cpu. See CPUS, _on_invalid and _cpu_exception.
        self.cpu = "8088"
        self.lock_steps = 0         # LOCK prefixes the 8088 stepped over
        self.lock_sites = set()     # and where
        self._lock_resume = None    # the instruction a LOCK was stepped over in
        self._lock_patch = None     # (address, byte) to put back after it ran
        self.exceptions = {}        # vector -> (deliveries, handlers), as dispatched
        self._exception_taken = False
        # --at: each key's path, (step, image offset, AX, path) in order.
        self.at_log = []
        self.at_hardware = False    # an --at key went through IRQ 1
        self._at_resume = None      # the address an --at key's IRQ 1 interrupted
        self._at_queued = []        # at_log entries of --at keys in hw_keys, in order
        self._at_pressed = None     # the at_log entry of the key in flight, if one
        # Text written through INT 10h -- the cursor calls and AH=09h, 0Ah and
        # 0Eh -- drawn into the framebuffer with the font, as the BIOS does:
        # --bios-text. Off by default, and while off those calls are what they
        # always were, ignored, and only counted.
        self.bios_text = False
        self.video_mode = 3         # the BIOS's mode number, as INT 10h AH=0Fh says it
        self.bios_chars = 0         # characters written through INT 10h
        self.font = None            # what --bios-text draws with; the shipped font if None
        self.no_joystick = False    # port 0x201 as a machine with no game adapter
        self.files = Path(files) if files else None
        self.open_files = {}        # handle -> [bytes, position, name]
        self.next_handle = 5        # 0-4 are the standard ones
        # Where INT 21h AH=48 hands out memory. This is set properly once the
        # image is loaded; a fixed 0x4000 was fine while every program here was
        # a .COM under 64 KB, and quietly wrong for anything larger. The
        # Oregon Trail unpacks to 201 KB, so DOS was handing its font library a
        # buffer that overlapped the program's own stack, and the corruption
        # only surfaced 1.16 million instructions later as a `retf` to nowhere.
        self.next_para = 0x4000
        self.file_reads = []        # what the program opened
        self.file_misses = []       # and what it looked for and did not find
        self.dta = BASE + 0x80
        self.find_pending = []      # what FindNext still has to hand back
        self.output = []            # whatever the program printed

        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, MEMSZ, UC_PROT_ALL)
        # A plausible PSP. Mostly zero is right -- no command tail, no
        # arguments -- but two words are not optional.
        #
        # PSP+2 is the segment one past the memory DOS gave the program,
        # and a zero there means it was given none. Karateka reads it,
        # prints "Insufficient memory" and exits twenty-three instructions
        # in. That is not a crash and does not look like a bug in the
        # harness; it looks like a game that refuses to run.
        psp = bytearray(0x100)
        psp[0:2] = b"\xCD\x20"          # int 20h, the ancient exit path
        psp[2:4] = struct.pack("<H", 0x9FFF)   # top of a 640 KB machine
        psp[0x2C:0x2E] = struct.pack("<H", 0)  # no environment
        self.uc.mem_write(BASE, bytes(psp))

        # An interrupt vector table that points somewhere.
        #
        # Trapping the `int` instruction is not enough, because not every
        # program uses it. Turbo Pascal's `MsDos` and `Intr` read the vector
        # out of the table and *far-call it*:
        #
        #     lds bx, [bx]        ; the handler, from 0000:0084 for INT 21h
        #     push ds / push bx   ; and call it, with flags already pushed
        #
        # With a zeroed table that is a call to 0000:0000, and the program
        # disappears into the interrupt vector table itself. The Oregon Trail
        # does this on its fourth statement and the run ends in `int 20h`
        # 1.17 million instructions later, looking for all the world like a
        # program that decided not to start.
        #
        # So every vector gets a two-instruction stub -- `int n` then `iret` --
        # in the paragraph below the program. Reached by `int`, the stub is
        # never used; reached by a far call, it raises the interrupt the
        # normal way and returns through the frame the caller pushed, which is
        # already an iret frame because it pushed the flags first.
        self.uc.mem_write(STUBS, b"".join(
            bytes([0xCD, n, 0xCF, 0x90]) for n in range(256)))
        self.uc.mem_write(0, b"".join(
            struct.pack("<HH", n * 4, STUBS >> 4) for n in range(256)))

        self.mz = mz_header(image)
        if self.mz is None:
            # A .COM: the whole file is the image and it runs from 0x100, with
            # every segment register pointing at the PSP.
            self.uc.mem_write(BASE + LOAD, bytes(image))
            for r in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
                      UC_X86_REG_SS):
                self.uc.reg_write(r, SEG)
            self.uc.reg_write(UC_X86_REG_SP, 0xFFFE)
            self.next_para = SEG + ((len(image) + 0xFFF) >> 4)
            self._enable_interrupts()
        else:
            self._load_mz(image, self.mz)
            self._enable_interrupts()
            # Above the block DOS would have given the program: the image plus
            # whatever `minalloc` demanded, which for a packed file covers the
            # room the decompressor needs.
            span = self.mz["end"] - self.mz["hdr"] + self.mz.get("minalloc", 0) * 16
            self.next_para = SEG + ((span + 0xFFF) >> 4)

        self.uc.hook_add(UC_HOOK_INTR, self._on_int)
        self.uc.hook_add(UC_HOOK_INSN, self._on_in, None, 1, 0, UC_X86_INS_IN)
        self.uc.hook_add(UC_HOOK_INSN, self._on_out, None, 1, 0, UC_X86_INS_OUT)
        self.uc.hook_add(UC_HOOK_CODE, self._on_code)
        # Called only for an instruction Unicorn refuses, so it costs nothing
        # until then; see _on_invalid.
        self.uc.hook_add(UC_HOOK_INSN_INVALID, self._on_invalid)
        # The CPU's state with no exception in progress: see _clear_exception.
        self._clean = self.uc.context_save()

    def _load_mz(self, image, h):
        """Load an MZ the way DOS does, relocations and all.

        A `.COM` needs no loader: the file is the image, it goes at 0x100, and
        every segment register points at the PSP. An MZ needs four things done
        to it, and skipping any of them gives a program that starts and then
        behaves inexplicably rather than one that fails:

          * the load image is the file minus its header, and no more -- the
            page count and last-page size say where it ends, and anything after
            is the linker's or the packer's, not the program's;
          * every entry in the relocation table names a word holding a segment
            that was written as if the program loaded at zero. Each one has the
            real load segment added to it. Miss this and far calls go to
            wherever the program would have been on a machine that does not
            exist;
          * CS:IP and SS:SP come from the header, not from convention;
          * DS and ES point at the PSP, which is one paragraph *before* the
            image. Programs read the command tail through them and set DS
            themselves when they are ready.
        """
        hdr, end, nreloc, reloc_off = h["hdr"], h["end"], h["nreloc"], h["reloc"]
        load = SEG + (LOAD >> 4)          # the image sits after the PSP
        body = image[hdr:end]
        self.uc.mem_write(BASE + LOAD, bytes(body))

        for k in range(nreloc):
            off, seg = struct.unpack_from("<HH", image, reloc_off + k * 4)
            at = ((load + seg) << 4) + off
            cur = struct.unpack_from("<H", bytes(self.uc.mem_read(at, 2)), 0)[0]
            self.uc.mem_write(at, struct.pack("<H", (cur + load) & 0xFFFF))

        self.uc.reg_write(UC_X86_REG_CS, (load + h["cs"]) & 0xFFFF)
        self.uc.reg_write(UC_X86_REG_IP, h["ip"])
        self.uc.reg_write(UC_X86_REG_SS, (load + h["ss"]) & 0xFFFF)
        self.uc.reg_write(UC_X86_REG_SP, h["sp"])
        self.uc.reg_write(UC_X86_REG_DS, SEG)
        self.uc.reg_write(UC_X86_REG_ES, SEG)
        self.mz_entry = (h["cs"] << 4) + h["ip"]

    # -- hooks ---------------------------------------------------------------

    # The BIOS keeps its 18.2 Hz tick count at 0040:006C, and a game that wants
    # to wait reads it there rather than asking through INT 1Ah -- reading two
    # words is cheaper than an interrupt. Karateka spins on it in its start-up:
    #
    #     xor ax, ax / mov ds, ax / mov bx, 0x46c
    #     mov si, [bx] / inc si
    #     .wait: cmp si, [bx] / jne .wait
    #
    # Answering INT 1Ah is not enough, because nothing here asks. Leave the
    # counter at zero and the program waits for a tick that never comes: no
    # crash, no message, a black screen and the whole instruction budget spent
    # on two instructions.
    TICK_EVERY = 20_000

    def _on_code(self, uc, addr, size, _):
        if (self._lock_resume is not None or self._lock_patch is not None) \
                and self._after_lock(addr):
            return
        if self._at_resume == addr:
            # Back where an --at key's IRQ 1 interrupted the program, before
            # the instruction ran: the same arrival, already counted, so no
            # second key, step, watch or stop hit.
            self._at_resume = None
            return
        self.steps += 1
        # A ring of the last few addresses. A fault reports where it landed;
        # what you need is where it came from, and by then the registers no
        # longer say. Sixteen entries is enough to see the far call that did it.
        self.recent[self.steps & 511] = addr
        if self.exec_map is not None:
            self.exec_map.add(addr - self.img_bias)
        if self.exec_where is not None:
            self.exec_where.add((addr, uc.reg_read(UC_X86_REG_CS), size))
        if self.steps % self.TICK_EVERY == 0:
            # With the timer as hardware the BIOS's own INT 08h counts the
            # tick, when IRQ 0 reaches it; a program that replaces vector 8
            # and never passes the tick on stops the count, as on the machine.
            if not self._timer_irq():
                self.ticks += 1
                uc.mem_write(0x46C, struct.pack("<I", self.ticks))
        off = addr - self.img_bias
        if off in self.ptr_watch:
            def rd(seg, ofs, n=16):
                try:
                    return bytes(uc.mem_read((seg << 4) + ofs, n))
                except UcError:
                    return b""
            ds = uc.reg_read(UC_X86_REG_DS)
            es = uc.reg_read(UC_X86_REG_ES)
            si = uc.reg_read(UC_X86_REG_SI)
            di = uc.reg_read(UC_X86_REG_DI)
            self.io_log.append(
                f"at {off:#07x}  DS:SI={ds:04X}:{si:04X} {rd(ds, si)!r}"
                f"  ES:DI={es:04X}:{di:04X} {rd(es, di)!r}")
            self.ptr_watch[off] -= 1
            if self.ptr_watch[off] <= 0:
                del self.ptr_watch[off]

        if self.gated and off in self.gates:
            self.keys.append(self.gated.pop(0))
            self._sync_kbd()
        elif (self.gated and not self.keys and not self.gates
                and self.steps - self.last_release > self.gate_every):
            # No gates named: make a key available at a steady interval and
            # let the program take it when it next looks.
            #
            # When gates *are* named, none of these fallbacks fire, and that is
            # essential rather than tidy. A prompt commonly begins by draining
            # the keyboard -- `while KeyPressed do ReadKey` -- to throw away
            # anything typed ahead. A harness that hands out a key whenever the
            # queue runs dry feeds that loop for ever and the screen never
            # advances, which is exactly how The Oregon Trail's landmark
            # screens looked for eleven attempts.
            self.last_release = self.steps
            self.keys.append(self.gated.pop(0))
            self._sync_kbd()
        pending = self.at_keys.get(off)
        if pending:
            self._at_arrival(uc, addr, off, pending.pop(0))
        if off in self.watch:
            self.watch[off](off)
        # Stopping on the *nth* arrival, not the first, is what makes a game
        # loop inspectable: the interesting frame is rarely the opening one.
        if off == self.stop_off:
            self.stop_hits += 1
            if self.stop_hits >= self.stop_after:
                self.stopped = f"reached 0x{off:X} for the {self.stop_hits}. time"
                uc.emu_stop()

    # -- interrupts the program serves itself -------------------------------
    #
    # Unicorn hands every `int n` to the hook below instead of going through
    # the vector table, so a vector the program has replaced was never used:
    # Tapper (1983) installs an INT 80h that reads its data file sector by
    # sector through DOS, and its `int 80h` reached nothing here, the read
    # never happened, and the game stopped on its disk error. So an `int n` goes
    # where the CPU would send it -- the handler in vector n, with FLAGS, CS
    # and the return IP pushed and IF and TF cleared -- whenever vector n is
    # no longer the stub this harness put there. Every other `int` is
    # answered here exactly as before, and so is an `int` from a stub itself:
    # that is a program's handler passing a call on to the vector it
    # replaced, which the stub turns back into this harness's own service.

    def _program_vector(self, num):
        """seg:off of the handler the program put in vector `num`, or None
        while the vector still holds this harness's stub (or nothing)."""
        off, seg = struct.unpack("<HH", self.uc.mem_read(num * 4, 4))
        if (seg, off) in ((STUBS >> 4, num * 4), (0, 0), BIOS_IRET):
            return None
        return seg, off

    # The one-byte forms: `int3` (CC) raises INT 3 and `into` (CE) INT 4 when
    # the overflow flag is set. Both leave IP past themselves, as `int n` does.
    ONE_BYTE = {3: 0xCC, 4: 0xCE}

    def _software_int(self, uc, num, cs, ip):
        """Whether the instruction just before CS:IP raised INT num: `int n`,
        or `int3` or `into`. A CPU exception is not one: its IP is the
        faulting instruction's or the next one's, and neither is preceded by
        an instruction naming the vector."""
        try:
            if bytes(uc.mem_read((cs << 4) + ip - 2, 2)) == bytes((0xCD, num)):
                return True
            return (num in self.ONE_BYTE
                    and uc.mem_read((cs << 4) + ip - 1, 1)[0] == self.ONE_BYTE[num])
        except UcError:
            return False

    def _to_program(self, uc, num):
        """Send an `int n` the program executed to its own handler, when it
        has one. True when it went there."""
        cs = uc.reg_read(UC_X86_REG_CS)
        ip = uc.reg_read(UC_X86_REG_IP)         # past the `int n`
        at = (cs << 4) + ip - 2
        if STUBS <= at < STUBS + 0x400:
            return False                        # passed on to the vector it replaced
        if not self._software_int(uc, num, cs, ip):
            return False                        # a CPU exception, not an `int n`
        handler = self._program_vector(num)
        if handler is None:
            return False
        self._enter(uc, handler, cs, ip)
        count, handlers = self.dispatched.get(num, (0, []))
        if handler not in handlers:
            handlers.append(handler)
        self.dispatched[num] = (count + 1, handlers)
        return True

    def _enter(self, uc, handler, cs, ip):
        """What the CPU does to take an interrupt: FLAGS, CS and the return
        IP pushed, IF and TF cleared, and on at the handler."""
        seg, off = handler
        flags = uc.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
        sp = (uc.reg_read(UC_X86_REG_SP) - 6) & 0xFFFF
        ss = uc.reg_read(UC_X86_REG_SS)
        uc.mem_write((ss << 4) + sp, struct.pack("<HHH", ip, cs, flags))
        uc.reg_write(UC_X86_REG_SP, sp)
        uc.reg_write(UC_X86_REG_EFLAGS, flags & ~(IF | TF))
        uc.reg_write(UC_X86_REG_CS, seg)
        uc.reg_write(UC_X86_REG_IP, off)

    # -- the exceptions the CPU raises itself --------------------------------
    #
    # The Microsoft C and Turbo Pascal runtimes put their own handler in
    # vector 0, and so does The Dam Busters (1984); a divide error went to
    # this harness's answer all the same, which was to do nothing -- and
    # Unicorn, asked to carry on, ran the divide again and called the second
    # fault a double fault and the third a reason to stop, with nothing said.
    # The 8088 raises two exceptions of its own: the divide error, INT 0, by
    # DIV, IDIV and AAM, and with the trap flag set INT 1 after every
    # instruction. Both go through the vector as an interrupt does. Where they
    # return differs from later processors: an 8088's divide error pushes the
    # address of the instruction AFTER the divide, a 286's or later's the
    # divide itself. Intel says so in the 80386 Programmer's Reference Manual
    # (1986), section 14.7, "Differences From 8086", item 3: "Divide
    # exceptions on the 80386 always leave the saved CS:IP value pointing to
    # the instruction that failed. On the 8086/8088, the CS:IP value points
    # to the next instruction." --cpu 8088 returns after the divide; 386 to it.

    def _cpu_exception(self, uc, num):
        """INT 0 or INT 1 raised by the CPU rather than by an instruction
        naming it: to the program's handler when it has one. True when this
        dealt with it."""
        cs = uc.reg_read(UC_X86_REG_CS)
        ip = uc.reg_read(UC_X86_REG_IP)
        here = (cs << 4) + ip
        if self._software_int(uc, num, cs, ip) or STUBS <= here < STUBS + 0x400:
            return False
        handler = self._program_vector(num)
        if num == 0:
            # Unicorn leaves IP on the divide, as a later x86 does.
            try:
                size = divide_length(bytes(uc.mem_read(here, 8)))
            except UcError:
                size = None
            if size is None:
                return False
            if handler is None:
                self.stopped = (f"divide error at {cs:04X}:{ip:04X} (image "
                                f"{here - self.img_bias:#08x}); the program has no INT 00h "
                                f"handler of its own, and DOS's prints \"Divide overflow\" "
                                f"and ends the program")
                uc.emu_stop()
                return True
            back = (ip + size) & 0xFFFF if self.cpu == "8088" else ip
            # Unicorn keeps a record of the fault until something it trusts
            # delivers it, and this hook is not that: the next divide error
            # would arrive as a double fault. The run loop clears the record.
            self._exception_taken = True
            uc.emu_stop()
        else:
            # The trap flag: IP is already past the instruction, on any CPU.
            # With no handler of the program's, the BIOS's INT 1 is an `iret`.
            if handler is None:
                return True
            back = ip
        self._enter(uc, handler, cs, back)
        count, handlers = self.exceptions.get(num, (0, []))
        if handler not in handlers:
            handlers.append(handler)
        self.exceptions[num] = (count + 1, handlers)
        return True

    def _clear_exception(self):
        """After a divide error went to the program's handler: put the CPU in
        a state with no exception in progress, every register as it is.

        Unicorn takes an exception the way QEMU does, remembering it until it
        has been delivered by QEMU's own code -- which a hook that delivers it
        is not. A second divide error is then taken for a fault during the
        first and becomes a double fault (INT 8), and a third ends the run
        with no hook called: measured, on four divides by zero in a row. A
        context saved before the run has nothing in progress; restored, with
        the registers written back, the next divide error is INT 0 again."""
        values = [(r, self.uc.reg_read(r)) for r in CPU_REGISTERS]
        self.uc.context_restore(self._clean)
        for r, value in values:
            self.uc.reg_write(r, value)
        self._exception_taken = False

    # -- LOCK on an 8088 -------------------------------------------------------
    #
    # Jungle Hunt (1983) times its port writes with `lock nop` and loops with
    # `lock loop`. The 8088 asserts its LOCK pin for the instruction and runs
    # it, whatever it is. A 386 refuses LOCK on anything that is not a
    # read-modify-write of memory, and Unicorn refuses it on fewer -- measured,
    # on `nop` and on arithmetic into a register (add, inc, not, cmp), with
    # or without a segment override; it runs `lock mov`, `lock loop`, `lock
    # out` and the memory forms, ignoring the prefix itself. Under --cpu 8088
    # an instruction it refuses for its LOCK runs without it.

    def _on_invalid(self, uc, _):
        """An instruction Unicorn refuses: under --cpu 8088, run one it
        refuses for its LOCK prefix without the prefix. True to go on."""
        if self.cpu != "8088":
            return False
        cs = uc.reg_read(UC_X86_REG_CS)
        ip = uc.reg_read(UC_X86_REG_IP)
        here = (cs << 4) + ip
        try:
            raw = bytes(uc.mem_read(here, 15))
        except UcError:
            return False
        at = lock_prefix(raw)
        if at is None:
            return False
        self.lock_steps += 1
        self.lock_sites.add(here - self.img_bias)
        if at == 0:
            # The prefix first: start the instruction one byte later.
            uc.reg_write(UC_X86_REG_IP, (ip + 1) & 0xFFFF)
            self._lock_resume = here + 1
        else:
            # After other prefixes: in its place, a copy of the prefix before
            # it, which changes nothing a prefix means, until the instruction
            # has run (_after_lock).
            self._lock_patch = (here + at, 0xF0)
            uc.mem_write(here + at, raw[at - 1:at])
            uc.ctl_remove_cache(here + at, here + at + 1)
            self._lock_resume = here
        return True

    def _after_lock(self, addr):
        """True for the instruction a LOCK was just stepped over in, arriving
        again: it was counted when it first arrived. Otherwise put back the
        byte a LOCK after other prefixes was replaced with, now that its
        instruction has run."""
        if addr == self._lock_resume:
            self._lock_resume = None
            return True
        self._restore_lock()
        return False

    def _restore_lock(self):
        if self._lock_patch is not None:
            at, byte = self._lock_patch
            self._lock_patch = None
            self.uc.mem_write(at, bytes((byte,)))
            self.uc.ctl_remove_cache(at, at + 1)

    def cpu_summary(self):
        """One line on what the CPU model did that Unicorn would not have, or
        None when it did nothing."""
        parts = []
        if self.lock_steps:
            sites = sorted(self.lock_sites)
            parts.append(f"a LOCK prefix stepped over {self.lock_steps:,} time"
                         f"{'' if self.lock_steps == 1 else 's'}, at "
                         + ", ".join(f"{a:#x}" for a in sites[:6])
                         + (f" and {len(sites) - 6} more" if len(sites) > 6 else ""))
        names = {0: "divide error", 1: "single-step trap"}
        for num, (count, handlers) in sorted(self.exceptions.items()):
            where = ", ".join(f"{s:04X}:{o:04X}" for s, o in handlers)
            how = ""
            if num == 0:
                how = (", each returning after its divide, as an 8088's does"
                       if self.cpu == "8088" else
                       ", each returning to its divide, as a 386's does")
            parts.append(f"{names[num]} {count:,} time{'' if count == 1 else 's'} to the "
                         f"program's INT {num:02X}h at {where}{how}")
        if not parts:
            return None
        return f"cpu       : {self.cpu}: " + "; ".join(parts)

    def replaced_vectors(self):
        """The vectors that hold the program's own handlers now."""
        return [n for n in range(256) if self._program_vector(n) is not None]

    def vector_summary(self):
        """One line on the vectors the program replaced and the `int`s that
        went to its handlers, for the end of a run."""
        now = self.replaced_vectors()
        named = [f"INT {n:02X}h" for n in now]
        named += [f"INT {n:02X}h (put back by the end)" for n in sorted(self.dispatched)
                  if n not in now]
        sent = ", ".join(
            f"INT {n:02X}h {count:,} time{'' if count == 1 else 's'} to "
            + ", ".join(f"{s:04X}:{o:04X}" for s, o in handlers)
            for n, (count, handlers) in sorted(self.dispatched.items()))
        return (f"vectors   : the program replaced {', '.join(named)}; its own `int` "
                f"went to its handlers: {sent}")

    def _on_int(self, uc, num, _):
        ah = (uc.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        self.ints.append((num, ah))
        if self._to_program(uc, num):
            return
        if num in (0, 1) and self._cpu_exception(uc, num):
            return
        if num == 0x20:
            self.stopped = "int 0x20"
            uc.emu_stop()
        elif num == 0x21 and ah in (0x4C, 0x00):
            self.stopped = "int 0x21 exit"
            uc.emu_stop()
        elif num == 0x21:
            self._dos(uc, ah)
        elif num == 0x10 and ah == 0x00:
            self.cga.bios_mode(uc.reg_read(UC_X86_REG_AX) & 0xFF)
            if self.bios_text:
                self._bios_set_mode(uc.reg_read(UC_X86_REG_AX) & 0xFF)
            if self.ega is not None:
                self.ega.bios_mode(uc.reg_read(UC_X86_REG_AX) & 0xFF)
            if self.tandy is not None:
                self._tandy_mode(uc.reg_read(UC_X86_REG_AX) & 0xFF)
        elif num == 0x10 and self.adapter != "cga" and self._adapter_bios(uc, ah):
            pass
        elif num == 0x11 and self.adapter != "cga":
            uc.reg_write(UC_X86_REG_AX, EQUIPMENT[self.adapter])
        elif num == 0x10 and ah == 0x0B:
            bx = uc.reg_read(UC_X86_REG_BX)
            self.cga.bios_palette(bx >> 8, bx & 0xFF)
        elif num == 0x10 and ah in (0x02, 0x03, 0x09, 0x0A, 0x0E, 0x0F):
            self._bios_video_text(uc, ah)
        elif num == 0x09 and self._hardware_keys():
            self._bios_keyboard()
        elif num == 0x08 and self._timer_irq():
            self._bios_timer(uc)
        elif num == 0x08 and self._hardware_keys():
            # The BIOS's timer handler, reached by a program that chains to
            # it. It acknowledges IRQ 0 itself, and so must this, or the PIC
            # model holds IRQ 0 in service for ever and the keyboard's own
            # acknowledgement is taken as IRQ 0's.
            self.in_service.discard(0)
        elif num == 0x13 and ah == 0x00:
            # Reset the disk system: there is no disk here to reset, so it
            # succeeds, AH 0 and carry clear, as the BIOS's does. Not a
            # nicety: Tapper's file shim returns through `iret`, so its
            # caller's carry is whatever it was before `int 80h`, set on the
            # first read of a span; four retries and this reset are what
            # clear it, on the machine and here.
            uc.reg_write(UC_X86_REG_AX, uc.reg_read(UC_X86_REG_AX) & 0x00FF)
            uc.reg_write(UC_X86_REG_EFLAGS, uc.reg_read(UC_X86_REG_EFLAGS) & ~CF)
        elif num == 0x1A and ah == 0x00:
            # The BIOS tick count. Answering with a constant is not "no
            # effect": `int 0x1a / cmp dl, [last] / je` is how a game waits for
            # the clock to move, and a constant makes it wait forever. Zaxxon
            # spends its whole instruction budget in that loop between the
            # title screen and the game. Advance it by one per call, for the
            # same reason the port reads alternate.
            self.ticks += 1
            uc.reg_write(UC_X86_REG_CX, self.ticks >> 16)
            uc.reg_write(UC_X86_REG_DX, self.ticks & 0xFFFF)
        elif num == 0x16 and ah in (0x00, 0x10):
            # And on a blocking read too. A screen that calls ReadKey without
            # polling first would otherwise wait for ever: the gate fires on
            # the poll, and there is no poll.
            if not self.keys and self.gated and not self.gates:
                self.keys.append(self.gated.pop(0))
            self._sync_kbd()
            # Read a key, blocking. There is nothing to block on here, so an
            # empty queue returns zero rather than hanging.
            uc.reg_write(UC_X86_REG_AX, self.keys.pop(0) if self.keys else 0)
            self.keys_read += 1
            self.polls = 0
        elif num == 0x16 and ah in (0x01, 0x11):
            # Release one gated key when the program *asks whether* a key is
            # waiting, not when it reads one. Gating on the read alone
            # deadlocks any `repeat until KeyPressed` loop: the poll never sees
            # a key, so the read is never reached, so the key is never
            # released. Releasing on an empty queue gives exactly one key per
            # read, which is what a prompt expects.
            if not self.keys and self.gated:
                self.keys.append(self.gated.pop(0))
            # Peek. The answer is in the zero flag: set means nothing waiting.
            # Unicorn's interrupt hook does not run a real interrupt sequence,
            # so no FLAGS word is pushed and none is popped by an iret -- what
            # is written here is what the program sees.
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            # Two loops ask this question and they want opposite answers.
            #
            #   while KeyPressed do ReadKey;      { throw away type-ahead }
            #   repeat until KeyPressed;          { wait for the player }
            #
            # Answering "yes, a key is waiting" satisfies the second and is
            # eaten by the first, which is why a queue meant for a whole game
            # vanishes in one screen: The Oregon Trail consumed 88 keys in 88
            # reads without ever pausing. Answering "no" does the reverse and
            # hangs the wait.
            #
            # What separates them is persistence. A flush asks a handful of
            # times and gives up; a wait asks until the answer changes. So say
            # no until the question has been repeated `poll_patience` times
            # since the last real read, then say yes. The threshold is a
            # measurement of the program's behaviour, not of ours -- if a game
            # flushed with a longer loop than it waits with, this would be the
            # wrong way round, and the symptom would be visible as keys
            # disappearing again.
            self.polls += 1
            if self.poll_patience is not None and self.polls < self.poll_patience:
                uc.reg_write(UC_X86_REG_EFLAGS, flags | ZF)
                return
            if self.keys:
                uc.reg_write(UC_X86_REG_AX, self.keys[0])
                flags &= ~ZF
            else:
                flags |= ZF
            uc.reg_write(UC_X86_REG_EFLAGS, flags)
        # Everything else is acknowledged by doing nothing. Setting a video
        # mode, printing a string and reading the clock all have the same
        # effect on what we are measuring: none.

    # ---------------------------------------------------------------- DOS
    #
    # Enough of INT 21h to get a game with external data files to its first
    # screen. Karateka needs it: ninety data files beside the executable, and
    # without file I/O the program reaches its first `open` and stops being a
    # game. Answering "no such file" is not neutral either -- a game that
    # cannot find its artwork usually prints a message and exits, which looks
    # exactly like a program that crashed.
    #
    # Carry is the error flag throughout: clear for success, set for failure
    # with the code in AX. Unicorn's interrupt hook does not push or pop FLAGS,
    # so whatever is written here is what the program reads.

    def _fail(self, uc, code):
        uc.reg_write(UC_X86_REG_AX, code)
        uc.reg_write(UC_X86_REG_EFLAGS,
                     uc.reg_read(UC_X86_REG_EFLAGS) | CF)

    def _ok(self, uc, ax=0):
        uc.reg_write(UC_X86_REG_AX, ax)
        uc.reg_write(UC_X86_REG_EFLAGS,
                     uc.reg_read(UC_X86_REG_EFLAGS) & ~CF)

    def _str_at(self, uc, seg, off, limit=128):
        addr = (seg << 4) + off
        raw = bytes(uc.mem_read(addr, limit))
        return raw.split(b"\x00")[0].decode("latin-1")

    def _resolve(self, name):
        r"""A DOS path, against the directory the game's files are in.

        Case matters here and does not on DOS, so the match is case-insensitive
        and the drive and directory parts are dropped: a game that opens
        `C:\KARATEKA\KM0.DAT` means the file called KM0.DAT.
        """
        if self.files is None:
            return None
        leaf = name.replace("/", "\\").split("\\")[-1].strip().upper()
        for f in self.files.iterdir():
            if f.is_file() and f.name.upper() == leaf:
                return f
        return None

    def _find(self, pattern):
        """The files a DOS `FindFirst` pattern matches, in directory order.

        Only the leaf is used, for the same reason `_resolve` drops the path:
        a program that searches `C:\\OT\\*.PCL` means the .PCL files in the
        directory it was given.
        """
        if self.files is None:
            return []
        leaf = pattern.replace("/", "\\").split("\\")[-1].strip().upper()
        return sorted(
            (f for f in self.files.iterdir()
             if f.is_file() and fnmatch(f.name.upper(), leaf or "*.*")),
            key=lambda f: f.name.upper())

    def _write_dta(self, uc, path):
        """Fill the disk transfer area with one DOS directory entry.

        21 reserved bytes, then attribute, time, date, size and an ASCIIZ name.
        Turbo Pascal's `SearchRec` is laid over this same 43 bytes, which is why
        its `Fill` field is exactly 21 long and its `Time` is a `LongInt`: the
        time and date words are adjacent and it reads both at once.
        """
        entry = (b"\x00" * 21
                 + bytes([0x20])                        # archive
                 + struct.pack("<HH", DOS_TIME, DOS_DATE)
                 + struct.pack("<I", path.stat().st_size)
                 + path.name.upper().encode("ascii", "replace")[:12] + b"\x00")
        uc.mem_write(self.dta, entry)

    # The BIOS keyboard buffer, at 0040:001A onward. Turbo Pascal's Crt unit
    # does not call INT 16h to answer KeyPressed -- it compares the buffer's
    # head and tail pointers in the BIOS data area directly. A harness that
    # only answers the interrupt is invisible to it, and any `repeat until
    # KeyPressed` loop waits for ever. The Oregon Trail sits on its landmark
    # screens exactly that way.
    KB_HEAD, KB_TAIL, KB_BUF = 0x41A, 0x41C, 0x41E

    def _sync_kbd(self):
        """Make the BIOS buffer agree with the queue: one key waiting, or none."""
        if self.keys:
            self.uc.mem_write(self.KB_BUF, struct.pack("<H", self.keys[0]))
            self.uc.mem_write(self.KB_HEAD, struct.pack("<H", 0x1E))
            self.uc.mem_write(self.KB_TAIL, struct.pack("<H", 0x20))
        else:
            self.uc.mem_write(self.KB_HEAD, struct.pack("<H", 0x1E))
            self.uc.mem_write(self.KB_TAIL, struct.pack("<H", 0x1E))


    def _dos(self, uc, ah):
        ax = uc.reg_read(UC_X86_REG_AX)
        ds = uc.reg_read(UC_X86_REG_DS)
        dx = uc.reg_read(UC_X86_REG_DX)

        if ah == 0x09:                      # print a $-terminated string
            # Worth capturing rather than ignoring: when a game refuses to run,
            # this is where it says why, and the message is usually the fastest
            # route to the reason.
            raw = bytes(uc.mem_read((ds << 4) + dx, 512))
            self.output.append(raw.split(b"$")[0].decode("latin-1"))
            return
        if ah == 0x02:                      # print one character
            self.output.append(chr(uc.reg_read(UC_X86_REG_DX) & 0xFF))
            return
        if ah in (0x06, 0x07, 0x08, 0x0B):
            # Console I/O. AH=06h with DL=FF is the classic non-blocking key
            # check: a character in AL with ZF clear, or nothing with ZF set.
            #
            # Answering it as a generic success is worse than not answering at
            # all. Karateka's start-up is `call check_key / jne again`, so a
            # handler that leaves ZF alone spins forever -- three million
            # iterations of six instructions, no output, black screen. It looks
            # like a hang and is a question nobody answered.
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            if ah == 0x06 and (dx & 0xFF) != 0xFF:
                self.output.append(chr(dx & 0xFF))
                return
            if self.keys:
                ch = self.keys.pop(0) & 0xFF
                self.keys_read += 1
                uc.reg_write(UC_X86_REG_AX,
                             (uc.reg_read(UC_X86_REG_AX) & 0xFF00) | ch)
                flags &= ~ZF
            else:
                uc.reg_write(UC_X86_REG_AX,
                             uc.reg_read(UC_X86_REG_AX) & 0xFF00)
                flags |= ZF
            uc.reg_write(UC_X86_REG_EFLAGS, flags)
            return
        if ah == 0x30:                      # get DOS version
            # A program that asks and is told 0 concludes it is on DOS 1 and
            # refuses to run. Karateka does exactly that, in its first twenty
            # instructions.
            uc.reg_write(UC_X86_REG_AX, 0x1E03)     # 3.30, major in AL
            return
        if ah in (0x25, 0x35):              # set / get interrupt vector
            # Against a real table, so SwapVectors round-trips: a program that
            # saves the vectors, installs its own and puts them back gets its
            # own values returned rather than zero.
            n = (ax & 0xFF) * 4
            if ah == 0x35:
                off, seg = struct.unpack("<HH", uc.mem_read(n, 4))
                uc.reg_write(UC_X86_REG_BX, off)
                uc.reg_write(UC_X86_REG_ES, seg)
            else:
                uc.mem_write(n, struct.pack("<HH", dx, ds))
                if n == 9 * 4:
                    self._vector9_set(ds, dx)
                    if self.kbd_route is not None and self.hw_keys:
                        uc.emu_stop()
                elif n in (8 * 4, 0x1C * 4) and self._timer_vector_set(n // 4, ds, dx):
                    uc.emu_stop()
            return
        if ah == 0x1A:                      # set disk transfer address
            self.dta = ((ds << 4) + dx)
            return
        if ah == 0x2A:                      # get date
            uc.reg_write(UC_X86_REG_CX, 1990)
            uc.reg_write(UC_X86_REG_DX, 0x0601)     # 1 June
            uc.reg_write(UC_X86_REG_AX, 5)          # a Friday
            return
        if ah in (0x48,):                   # allocate memory
            # Hand out a block above everything, and never reuse it. Nothing
            # here frees anything, and a game that allocates once at start-up
            # -- which is nearly all of them -- never notices.
            uc.reg_write(UC_X86_REG_AX, self.next_para)
            self.next_para += uc.reg_read(UC_X86_REG_BX)
            self._ok(uc, self.next_para)
            return
        if ah in (0x49, 0x4A):              # free / resize
            self._ok(uc)
            return

        if ah in (0x3D, 0x3C, 0x6C):        # open / create
            name = self._str_at(uc, ds, dx)
            path = self._resolve(name)
            if path is None:
                self.file_misses.append(name)
                self._fail(uc, 2)           # file not found
                return
            h = self.next_handle
            self.next_handle += 1
            self.open_files[h] = [path.read_bytes(), 0, path.name]
            self.file_reads.append(path.name)
            if self.trace_io:
                self.io_log.append(f"open {path.name} -> handle {h}, "
                                   f"{len(self.open_files[h][0]):,} bytes")
            self._ok(uc, h)
            return
        if ah == 0x3E:                      # close
            self.open_files.pop(uc.reg_read(UC_X86_REG_BX), None)
            self._ok(uc)
            return
        if ah == 0x3F:                      # read
            bx = uc.reg_read(UC_X86_REG_BX)
            n = uc.reg_read(UC_X86_REG_CX)
            f = self.open_files.get(bx)
            if f is None:
                self._fail(uc, 6)           # invalid handle
                return
            data, pos, fname = f
            chunk = data[pos:pos + n]
            f[1] = pos + len(chunk)
            if self.trace_io:
                short = "  SHORT" if len(chunk) < n else ""
                self.io_log.append(
                    f"read {fname} handle {bx} at {pos} want {n} got "
                    f"{len(chunk)}{short}")
            uc.mem_write((ds << 4) + dx, chunk)
            if chunk:
                # Unicorn keeps its translation of code it has run, and a
                # write from here, outside the guest, does not throw it away:
                # an overlay read over the one before it ran the old one's
                # code from the cache.
                uc.ctl_remove_cache((ds << 4) + dx, (ds << 4) + dx + len(chunk))
            self._ok(uc, len(chunk))
            return
        # The five below are what a Turbo Pascal program's `Dos` unit calls,
        # and without them a Pascal program stops at its own first statement.
        # The Oregon Trail opens PRODUCT.PF, stats it, reads its timestamp and
        # asks whether the drive is a network drive -- all before it draws
        # anything -- and answering none of them looks exactly like a crash.
        if ah == 0x2C:                      # get time
            uc.reg_write(UC_X86_REG_CX, (10 << 8) | 30)     # 10:30
            uc.reg_write(UC_X86_REG_DX, 0)                  # 00.00 seconds
            return
        if ah == 0x44:                      # IOCTL
            al = ax & 0xFF
            if al == 0x09:                  # is this drive remote?
                # Say local. A network drive is the unusual answer, and it is
                # the one that turns licence checks on: The Oregon Trail asks
                # exactly this and only enforces its lab licence if the bit is
                # set. Anything that wants to test the other branch should say
                # so deliberately rather than inherit it from a default.
                uc.reg_write(UC_X86_REG_DX, 0x0800)
                self._ok(uc)
                return
            self._ok(uc)
            return
        if ah in (0x4E, 0x4F):              # find first / find next
            if ah == 0x4E:
                self.find_pending = self._find(self._str_at(uc, ds, dx))
            entry = self.find_pending.pop(0) if self.find_pending else None
            if entry is None:
                self._fail(uc, 18)          # no more files
                return
            self._write_dta(uc, entry)
            self._ok(uc)
            return
        if ah == 0x57:                      # get / set a file's timestamp
            al = ax & 0xFF
            if al == 0x00:
                uc.reg_write(UC_X86_REG_CX, DOS_TIME)
                uc.reg_write(UC_X86_REG_DX, DOS_DATE)
            # AL=1 sets it; nothing here writes to disk, so accept and forget.
            self._ok(uc)
            return
        if ah == 0x36:                      # free space on a drive
            uc.reg_write(UC_X86_REG_AX, 4)          # sectors per cluster
            uc.reg_write(UC_X86_REG_BX, 0x2000)     # free clusters
            uc.reg_write(UC_X86_REG_CX, 512)        # bytes per sector
            uc.reg_write(UC_X86_REG_DX, 0x4000)     # clusters on the drive
            return

        if ah == 0x42:                      # seek
            bx = uc.reg_read(UC_X86_REG_BX)
            f = self.open_files.get(bx)
            if f is None:
                self._fail(uc, 6)
                return
            cx = uc.reg_read(UC_X86_REG_CX)
            off = ((cx << 16) | dx) & 0xFFFFFFFF
            whence = ax & 0xFF
            base = {0: 0, 1: f[1], 2: len(f[0])}.get(whence, 0)
            f[1] = max(0, min(len(f[0]), base + off))
            if self.trace_io:
                self.io_log.append(f"seek {f[2]} handle {bx} whence {whence} "
                                   f"-> {f[1]}")
            uc.reg_write(UC_X86_REG_DX, (f[1] >> 16) & 0xFFFF)
            self._ok(uc, f[1] & 0xFFFF)
            return

        # Anything else is acknowledged as success. Saying "unsupported" would
        # be more honest and less useful: most of what is left is console
        # output, and a game that cannot print does not stop being a game.
        self._ok(uc)

    # A warning about the port reads below, paid for on Zaxxon. Alternating
    # values keep timing loops moving, which is what they are for -- but a
    # *joystick* is detected by writing to port 0x201 and counting how long a
    # bit stays set, and an alternating bit answers that probe successfully.
    # So an emulated Zaxxon decides a joystick is attached, ignores the
    # keyboard queue, and plays a different game from the one you asked for.
    # The state it reaches is real, it is simply not the state a keyboard
    # player reaches. Check the flags byte before trusting a captured frame.

    def _on_in(self, uc, port, size, _=None):
        """Value for an IN instruction.

        Unicorn takes the *return value* of this hook as the byte read, not a
        success flag. Returning True therefore feeds 1 into every port read,
        which is not obviously wrong until a keyboard handler translates
        scancode 1 instead of the key you delivered and stores it happily.
        """
        if port == 0x60 and self.pending_key is not None:
            # The keyboard data port. A handler reads it once per interrupt,
            # so the value is consumed rather than repeated.
            v = self.pending_key
            self.pending_key = None
            self.ports.append(("in", port, v))
            return v
        if port in (0x60, 0x64) and self._hardware_keys():
            # The keyboard as hardware. Port 0x60 holds the last scancode
            # until the next replaces it -- reading it twice gives the same
            # byte, which handlers that read it once to decide and once to
            # store rely on. Port 0x64 is the AT controller's status: bit 0
            # says a scancode is waiting, which is what a program polling
            # with IRQ 1 masked looks at; bits 2 and 4 say the system passed
            # its self-test and the keyboard is not inhibited.
            if port == 0x60:
                v = self.kbd_latch
                self.kbd_full = False
            else:
                v = 0x14 | (1 if self.kbd_full else 0)
            self.ports.append(("in", port, v))
            return v
        if 0x40 <= port <= 0x42:
            v = self.pit.read(port - 0x40)
            if v is not None:
                self.ports.append(("in", port, v))
                return v
        if port == 0x3D5 and self.cga.index in (0x10, 0x11):
            # The light pen registers: the address the latch took.
            v = (self.pen >> 8) & 0x3F if self.cga.index == 0x10 else self.pen & 0xFF
            self.ports.append(("in", port, v))
            return v
        if port == 0x3DA and self.ega is not None:
            # The status port; reading it also resets the attribute
            # controller's flip-flop to take an index next. The value is the
            # alternating one below, as before.
            self.ega.attr_data = False
        if port == 0x201 and self.no_joystick:
            # No game adapter: an empty port reads 0xFF, so the axis bits
            # never fall and no button is down. Rollo probes for a joystick
            # this way, and the alternating answer below told it one was
            # there; its title loop then took a "button" from the noise and
            # started a game nobody asked for -- an Esc that should only have
            # changed the menu appeared to start play.
            self.ports.append(("in", port, 0xFF))
            return 0xFF
        # Timing loops read a port until a bit changes. Alternating the value
        # keeps them moving instead of spinning forever; a constant is how an
        # emulator hangs on 1980s code.
        self.ports.append(("in", port, None))
        return len(self.ports) & 0xFF

    def _on_out(self, uc, port, size, value, _=None):
        self.ports.append(("out", port, value))
        self.cga.out(port, value, size)
        if self.ega is not None:
            self.ega.out(port, value, size)
        elif self.tandy is not None and port in (0x3DA, 0x3DE, 0x3DF):
            self._tandy_out(port, value & 0xFF)
        if port == 0x20 and (value == 0x20 or 0x60 <= value <= 0x67):
            # End of interrupt: 0x20 acknowledges the most urgent level in
            # service (the lowest number), 0x60+n acknowledges level n.
            level = (min(self.in_service) if value == 0x20 and self.in_service
                     else value - 0x60 if value != 0x20 else None)
            if level is not None:
                self.in_service.discard(level)
                if level == 1:
                    self.kbd_log["eoi"] += 1
                elif level == 0:
                    self.timer_log["eoi"] += 1
        elif port == 0x21:
            self.pic_mask = value & 0xFF
        elif port == 0x43:
            self.pit.control(value & 0xFF, self.pit_now())
        elif 0x40 <= port <= 0x42:
            self.pit.write(port - 0x40, value & 0xFF, self.pit_now())
        elif port == 0x61:
            self.pit.gate(bool(value & 1), self.pit_now())
        elif port == 0x3DC:
            # Preset the light pen latch: it takes the address now. 0x3DB
            # clears it, which changes nothing a program can read back.
            self.pen = light_pen(self.cga.crtc, self.pit_now())
            self.pen_presets += 1
        return True

    def pit_now(self):
        """The time in the 8253's counts: 65,536 to a timer tick, and a tick
        is --timer-every instructions."""
        return self.steps * 0x10000 // self.timer_every

    # -- text through the BIOS ----------------------------------------------
    #
    # Alley Cat (1984) asks "Do you want to use a joystick (Y/N)?" and lists
    # its skill levels through INT 10h AH=0Eh, a character a call, on a
    # 320-wide graphics screen. Answered by doing nothing, those calls leave
    # the screen black, and a run waiting on the question looks like a run
    # waiting on nothing. With --bios-text they are drawn as the BIOS draws
    # them: in a text mode the character goes into the framebuffer at the
    # cursor; in graphics it is drawn from the font over the whole 8x8 cell,
    # in the colour BL gives (bit 7: exclusive-or). The cursor is where the
    # BIOS keeps it, at 0040:0050, and a line written past the bottom scrolls.

    COLUMNS = {0: 40, 1: 40, 2: 80, 3: 80, 4: 40, 5: 40, 6: 80}
    PAGE = {40: 0x800, 80: 0x1000}     # a text page's bytes, as the BIOS lays them out

    def enable_bios_text(self, font=None):
        """--bios-text: draw INT 10h text, starting as DOS leaves a colour
        adapter -- mode 3, the cursor home."""
        self.bios_text, self.font = True, font
        self.uc.mem_write(0x449, bytes([3]))
        self.uc.mem_write(0x44A, struct.pack("<H", 80))

    def _bios_set_mode(self, al):
        """INT 10h AH=00 for --bios-text: what the BIOS keeps about the mode,
        and a cleared screen unless AL bit 7 asks to keep it."""
        mode = al & 0x7F
        self.video_mode = mode
        self.uc.mem_write(0x449, bytes([mode]))
        self.uc.mem_write(0x44A, struct.pack("<H", self.COLUMNS.get(mode, 80)))
        self.uc.mem_write(0x450, bytes(16))
        if not al & 0x80 and mode in self.COLUMNS:
            self.uc.mem_write(VIDEO, b"\x20\x07" * 0x2000 if mode < 4 else bytes(0x4000))

    def _bios_video_text(self, uc, ah):
        """INT 10h AH=02h, 03h, 09h, 0Ah, 0Eh and 0Fh."""
        cx = uc.reg_read(UC_X86_REG_CX)
        if ah in (0x09, 0x0A, 0x0E):
            self.bios_chars += 1 if ah == 0x0E else cx
        if not self.bios_text or self.video_mode not in self.COLUMNS:
            return
        ax, bx = uc.reg_read(UC_X86_REG_AX), uc.reg_read(UC_X86_REG_BX)
        cols = self.COLUMNS[self.video_mode]
        page = (bx >> 8) & (7 if cols == 40 else 3) if self.video_mode < 4 else 0
        col, row = uc.mem_read(0x450 + page * 2, 2)
        if ah == 0x02:
            dx = uc.reg_read(UC_X86_REG_DX)
            uc.mem_write(0x450 + page * 2, bytes([dx & 0xFF, dx >> 8]))
        elif ah == 0x03:
            uc.reg_write(UC_X86_REG_DX, (row << 8) | col)
            uc.reg_write(UC_X86_REG_CX, 0x0607)
        elif ah == 0x0F:
            uc.reg_write(UC_X86_REG_AX, (cols << 8) | self.video_mode)
            uc.reg_write(UC_X86_REG_BX, bx & 0x00FF)
        elif ah in (0x09, 0x0A):
            # CX copies from the cursor on, which does not move.
            for n in range(row * cols + col, min(row * cols + col + cx, 25 * cols)):
                self._bios_put(ax & 0xFF, n // cols, n % cols, bx & 0xFF, page,
                               ah == 0x09)
        else:
            ch = ax & 0xFF
            if ch == 0x08:
                col = max(0, col - 1)
            elif ch == 0x0A:
                row += 1
            elif ch == 0x0D:
                col = 0
            elif ch != 0x07:
                self._bios_put(ch, row, col, bx & 0xFF, page, False)
                col += 1
                if col == cols:
                    col, row = 0, row + 1
            if row == 25:
                self._bios_scroll(page, cols)
                row = 24
            uc.mem_write(0x450 + page * 2, bytes([col, row]))

    def _bios_put(self, ch, row, col, colour, page, with_attribute):
        """One character at a cell, as the BIOS writes it."""
        cols = self.COLUMNS[self.video_mode]
        if self.video_mode < 4:
            at = VIDEO + page * self.PAGE[cols] + (row * cols + col) * 2
            self.uc.mem_write(at, bytes([ch, colour]) if with_attribute else bytes([ch]))
            return
        font = self.font if self.font is not None else shipped_font()[0]
        if font is None:
            return
        for scan in range(8):
            y, bits = row * 8 + scan, font[ch * 8 + scan]
            at = VIDEO + (y & 1) * 0x2000 + (y >> 1) * 80
            if self.video_mode == 6:
                at, cell = at + col, bytes([bits])
            else:
                word = sum((colour & 3) << (14 - 2 * k) for k in range(8)
                           if bits & (0x80 >> k))
                at, cell = at + col * 2, bytes([word >> 8, word & 0xFF])
            if colour & 0x80:
                cell = bytes(a ^ b for a, b in zip(cell, self.uc.mem_read(at, len(cell))))
            self.uc.mem_write(at, cell)

    def _bios_scroll(self, page, cols):
        """A line written past the bottom: the screen moves up one row."""
        if self.video_mode < 4:
            base, row = VIDEO + page * self.PAGE[cols], cols * 2
            text = bytes(self.uc.mem_read(base + row, row * 24))
            self.uc.mem_write(base, text + b"\x20\x07" * cols)
            return
        for bank in (VIDEO, VIDEO + 0x2000):
            lines = bytes(self.uc.mem_read(bank + 4 * 80, 96 * 80))
            self.uc.mem_write(bank, lines + bytes(4 * 80))

    # -- the adapter ----------------------------------------------------------
    #
    # The Ancient Art of War (1987) will not start without "EGA or VGA card or
    # Tandy 1000", and asks in four ways before its title: INT 11h, INT 10h
    # AX=1A00h (a VGA's BIOS answers AL=1Ah), INT 10h AH=12h BL=10h (an EGA's
    # BIOS changes BL; it wants 3, 256 KB) and the byte at F000:C000 (0x21
    # on a Tandy 1000). Rampage (1986) asks nothing: the player chooses CGA,
    # EGA or Tandy, and it draws as it was told. An adapter answers as its
    # BIOS would; AX=1A00h goes unanswered on all three, which is how a BIOS
    # without VGA support leaves it.

    def set_adapter(self, name):
        """--adapter: the display adapter the machine has."""
        if name not in ADAPTERS:
            raise ValueError(f"adapter {name!r}: one of {', '.join(ADAPTERS)}")
        self.adapter = name
        if name == "cga":
            return
        self.uc.mem_write(0x410, struct.pack("<H", EQUIPMENT[name]))
        self.uc.mem_write(MACHINE_BYTE, bytes((0xFF,)))
        if name == "tandy":
            self.uc.mem_write(TANDY_SIGNATURE, bytes((0x21,)))
            self.tandy = Tandy()
        else:
            self.ega = EGA()
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._on_planes_write, None,
                             0xA0000, 0xAFFFF)
            self.uc.hook_add(UC_HOOK_MEM_READ, self._on_planes_read, None,
                             0xA0000, 0xAFFFF)
        # Which of the questions the program asked, for the summary: the two
        # ROM bytes are read, not asked for, so only a hook sees them.
        for at in (TANDY_SIGNATURE, MACHINE_BYTE, 0x410):
            self.uc.hook_add(UC_HOOK_MEM_READ, self._on_identity_read, None, at, at + 1)

    def _on_identity_read(self, uc, access, address, size, value, _):
        at = address & ~1               # each hooked range is two bytes from an even one
        self.identity_reads[at] = self.identity_reads.get(at, 0) + 1

    def _refuse(self, uc, why):
        if self.stopped is None:
            cs, ip = uc.reg_read(UC_X86_REG_CS), uc.reg_read(UC_X86_REG_IP)
            self.stopped = (f"EGA at {cs:04X}:{ip:04X}: {why}; the run stops rather "
                            f"than draw it wrong")
        uc.emu_stop()

    def _on_planes_write(self, uc, access, address, size, value, _):
        ega = self.ega
        if not ega.maps_a000():
            return
        why = ega.refusal()
        if why:
            self._refuse(uc, why)
            return
        for i in range(size):
            ega.write((address - 0xA0000 + i) & 0xFFFF, (value >> (8 * i)) & 0xFF)

    def _on_planes_read(self, uc, access, address, size, value, _):
        # A read hook runs before the read, so what is written here is what
        # the program reads: measured, a word read included.
        ega = self.ega
        if not ega.maps_a000():
            return
        why = ega.refusal()
        if why:
            self._refuse(uc, why)
            return
        uc.mem_write(address, bytes(ega.read((address - 0xA0000 + i) & 0xFFFF)
                                    for i in range(size)))

    def _adapter_bios(self, uc, ah):
        """INT 10h as an EGA's or a Tandy 1000's BIOS answers it, for the
        calls the CGA's does not have. True when this answered it."""
        ax, bx = uc.reg_read(UC_X86_REG_AX), uc.reg_read(UC_X86_REG_BX)
        al = ax & 0xFF
        target = self.ega or self.tandy
        if ah == 0x12 and self.ega is not None and bx & 0xFF == 0x10:
            # EGA information: BH 0, a colour adapter; BL 3, 256 KB; CH 0,
            # no feature bits; CL 9, the switches of an Enhanced Color Display.
            uc.reg_write(UC_X86_REG_BX, 0x0003)
            uc.reg_write(UC_X86_REG_CX, 0x0009)
            return True
        if ah == 0x10 and al in (0x00, 0x01, 0x02):
            # Palette registers: AL 00h one (BL) to BH, 01h the border to BH,
            # 02h all sixteen and the border from 17 bytes at ES:DX. The
            # border is the EGA's overscan register, 11h.
            if al == 0x00:
                writes = [(bx & 0xFF, bx >> 8)]
            elif al == 0x01:
                writes = [(16, bx >> 8)]
            else:
                es, dx = uc.reg_read(UC_X86_REG_ES), uc.reg_read(UC_X86_REG_DX)
                writes = list(enumerate(bytes(uc.mem_read((es << 4) + dx, 17))))
            for index, value in writes:
                if index < 16:
                    target.set_palette(index, value)
                elif self.ega is not None:
                    self.ega.set_palette(0x11, value)
                else:
                    self.tandy.set_border(value)
            target.writes["bios"].append(f"AX={ax:04X}h")
            return True
        if ah == 0x05 and self.tandy is not None and al & 0x80:
            # The Tandy's CRT and CPU page registers: AL 80h reads them into
            # BH and BL, 81h sets the CPU page from BL, 82h the CRT page from
            # BH, 83h both.
            t = self.tandy
            if al == 0x80:
                uc.reg_write(UC_X86_REG_BX, (t.crt_page << 8) | t.cpu_page)
            else:
                crt = (bx >> 8) & 7 if al & 0x02 else t.crt_page
                cpu = bx & 7 if al & 0x01 else t.cpu_page
                self._tandy_pages(crt, cpu, t.addressing)
            return True
        return False

    def _tandy_mode(self, al):
        """INT 10h AH=00 on a Tandy 1000: mode 9 is its 320x200 in sixteen
        colours, drawn from the pages; the CGA's modes are the CGA's."""
        t = self.tandy
        t.mode = al & 0x7F
        t.writes["bios"].append(f"mode {t.mode:02X}h")
        if t.mode != 9:
            return
        t.palette = list(range(16))
        self._tandy_pages(6, 6, 3)
        if not al & 0x80:
            self.uc.mem_write(VIDEO, bytes(Tandy.WINDOW))

    def _tandy_pages(self, crt, cpu, addressing):
        """New page registers: the window put away into the CPU page it
        showed, and the new CPU page brought into it."""
        t = self.tandy
        old, new = t.base(t.cpu_page), t.base(cpu)
        if old != new:
            t.pages[old:old + Tandy.WINDOW] = bytes(self.uc.mem_read(VIDEO, Tandy.WINDOW))
            self.uc.mem_write(VIDEO, bytes(t.pages[new:new + Tandy.WINDOW]))
        t.crt_page, t.cpu_page, t.addressing = crt, cpu, addressing

    def _tandy_out(self, port, value):
        t = self.tandy
        if port == 0x3DF:
            t.writes["ports"].add(port)
            self._tandy_pages(value & 7, (value >> 3) & 7, (value >> 6) & 3)
        elif port == 0x3DA:
            t.gate_index = value & 0x1F
        elif port == 0x3DE:
            t.writes["ports"].add(port)
            if 0x10 <= t.gate_index <= 0x1F:
                t.set_palette(t.gate_index - 0x10, value)
            elif t.gate_index == 0x02:
                t.set_border(value)
            else:
                t.gate[t.gate_index] = value & 0xFF

    def tandy_shown(self):
        """The 32 KB the CRT page shows: the window when it is also the CPU
        page, else the page as it was put away."""
        t = self.tandy
        if t.base(t.crt_page) == t.base(t.cpu_page):
            return bytes(self.uc.mem_read(VIDEO, Tandy.WINDOW))
        start = t.base(t.crt_page)
        return bytes(t.pages[start:start + Tandy.WINDOW])

    def adapter_summary(self):
        """One line on the adapter and what the program asked it, or None for
        cga when the program asked nothing an EGA or a VGA would answer."""
        asked = {}
        for num, ah in self.ints:
            if num == 0x11 or (num == 0x10 and ah in (0x12, 0x1A)):
                key = "INT 11h" if num == 0x11 else f"INT 10h AH={ah:02X}h"
                asked[key] = asked.get(key, 0) + 1
        if self.adapter == "cga":
            if not any(k.startswith("INT 10h") for k in asked):
                return None
            return ("adapter   : cga -- the program asked for an EGA (INT 10h AH=12h) or a "
                    "VGA (AH=1Ah) and was told none; --adapter ega answers as an EGA")
        parts = [f"{k} {n:,} time{'' if n == 1 else 's'}" for k, n in sorted(asked.items())]
        names = {TANDY_SIGNATURE: "F000:C000", MACHINE_BYTE: "F000:FFFE", 0x410: "0040:0010"}
        parts += [f"read {names[at]} {n:,} time{'' if n == 1 else 's'}"
                  for at, n in sorted(self.identity_reads.items())]
        said = {"ega": "an EGA with 256 KB (INT 10h AH=12h BL=10h), no VGA, equipment word "
                       f"{EQUIPMENT['ega']:04X}h",
                "tandy": "a Tandy 1000 (0x21 at F000:C000), equipment word "
                         f"{EQUIPMENT['tandy']:04X}h"}[self.adapter]
        return (f"adapter   : {self.adapter}, answering as {said}; the program asked: "
                + (", ".join(parts) if parts else "nothing"))

    # -- running -------------------------------------------------------------

    def run(self, start=None, stop=None, budget=20_000_000):
        """Execute from an image offset until it returns, exits or runs out.

        `start=None` means the program's own entry point: 0 for a `.COM`, and
        for an MZ whatever `CS:IP` in the header says, which is frequently not
        the beginning of the image.
        """
        if start is None:
            start = getattr(self, "mz_entry", 0)
        addr = BASE + LOAD + start
        end = BASE + LOAD + stop if stop is not None else BASE + 0xFFFF
        left = budget
        # Without a keyboard to drive this is the loop it always was: one
        # slice for the whole budget, or one per timer interrupt, delivered at
        # the same instruction counts as before. The keyboard only shortens a
        # slice to reach the moment its next scancode is due.
        timer_left = self.isr_every
        if self.keyboard == "hw" and self.hw_keys and self.hw_due is None:
            self.hw_due = self.steps + self.hw_every
        if self.keyboard == "auto" and not self._watching_vector9:
            # Only for auto: a memory hook, even on four bytes, is a cost on
            # every run, and nothing else needs it.
            self.uc.hook_add(UC_HOOK_MEM_WRITE, self._on_vector9_write, None,
                             9 * 4, 9 * 4 + 3)
            self._watching_vector9 = True
        if self.timer == "auto" and not self._watching_timer:
            for vector in (0x08, 0x1C):
                self.uc.hook_add(UC_HOOK_MEM_WRITE, self._on_timer_vector_write, None,
                                 vector * 4, vector * 4 + 3)
            self._watching_timer = True
        while left > 0:
            n = min(left, timer_left) if self.isr_vector else left
            for wait in (self._keyboard_wait(), self._timer_wait()):
                if wait is not None:
                    n = min(n, max(1, wait))
            if self._auto_undecided():
                n = min(n, AUTO_SLICE)
            before = self.steps
            try:
                self.uc.emu_start(addr, end, count=n)
            except UcError as e:
                self.stopped = self.stopped or f"fault: {e} at {self._where()}"
                break
            finally:
                self._restore_lock()
            # What actually ran, which is n unless --keyboard auto ended the
            # slice at the moment the program replaced vector 9.
            ran = self.steps - before
            left -= ran
            timer_left -= ran
            if self.stopped is not None:
                break
            taken = self._exception_taken
            if taken:
                self._clear_exception()
            cs = self.uc.reg_read(UC_X86_REG_CS)
            ip = self.uc.reg_read(UC_X86_REG_IP)
            addr = (cs << 4) + ip
            wait = self._keyboard_wait()
            tick = self._timer_wait()
            if addr == end or left <= 0 or not (taken or self.isr_vector or wait is not None
                                                or tick is not None
                                                or self._auto_undecided()):
                break
            # IRQ 0 before IRQ 1, as the PIC ranks them: due together, the
            # keyboard's waits behind the timer's until it is acknowledged.
            if self.pending_1c:
                addr = self._user_tick(cs, ip)
            elif self.isr_vector and timer_left <= 0:
                timer_left = self.isr_every
                addr = self._fire_isr(cs, ip)
            elif tick is not None and tick <= 0:
                addr = self._timer_step(cs, ip)
            elif wait is not None and wait <= 0:
                addr = self._keyboard_step(cs, ip)
        if self.stopped is None:
            if stop is not None:
                self.stopped = "reached the stop address"
            else:
                # Say WHERE the budget ran out, not just that it did. A run
                # that ends on the budget is usually a run stuck in a loop,
                # and without an address the only move left is to raise the
                # budget -- which is the wrong move, and an expensive one:
                # The Oregon Trail was given 1.5 then 3 billion instructions
                # and produced byte-identical results both times, because it
                # had stopped making progress long before either limit.
                self.stopped = f"budget exhausted at {self._where()}"
        return self.stopped

    # -- the keyboard as hardware ------------------------------------------
    #
    # Rollo and Moon Bugs (Windmill Software, 1983) never call INT 16h. Each
    # writes its own handler into the INT 09h slot of the vector table, reads
    # the scancode from port 0x60, keeps a flag per key, and acknowledges the
    # PIC; the game polls the flags. A queue consumed by INT 16h never reaches
    # it, and both runs stop in their title loops. So a key here can also be
    # what it is on the machine: a make code in port 0x60 and an interrupt on
    # IRQ 1, through whatever vector 9 holds, then the break code the same way.

    def _hardware_keys(self):
        """True while keys go through port 0x60 rather than INT 16h."""
        return self.keyboard == "hw" or self.kbd_route == "hardware" or self.at_hardware

    # -- a key at a chosen moment --------------------------------------------
    #
    # --at hands a key over when the program reaches an address, and it goes
    # the way the program reads the keyboard at that moment, whatever
    # --keyboard says about the --keys queue. The Dam Busters (1984) reads its
    # title's key through INT 16h and installs its own INT 09h only after the
    # title; a key sent to port 0x60 there would reach the BIOS and, through
    # its buffer, INT 16h anyway, and one put in the buffer after the program
    # has its own handler would never be seen. So: while vector 9 is the
    # BIOS's, the key goes into the BIOS's buffer, for INT 16h; once it is the
    # program's, it is a make code in port 0x60 and IRQ 1 through its handler
    # at once, and the break code --key-every instructions later. A handler
    # that chains to the BIOS's puts it in the buffer as well, so a program
    # that reads both gets both.

    def _at_arrival(self, uc, addr, off, ax):
        """An --at key, at the moment the program reached `off`."""
        handler = self._program_vector(9)
        if handler is None or scancode_of(ax) is None:
            self.keys.append(ax)
            self._sync_kbd()
            path = ("the BIOS's buffer, for INT 16h" if handler is None else
                    f"the BIOS's buffer: it names no key, so no scancode can go to "
                    f"the handler at {handler[0]:04X}:{handler[1]:04X}")
            self.at_log.append([self.steps, off, ax, path])
            return
        self.at_hardware = True
        # Ahead of the --keys still queued, behind any --at key not yet pressed.
        self.hw_keys.insert(len(self._at_queued), ax)
        self._at_queued.append(len(self.at_log))
        if not (self.hw_scancodes or self.hw_waiting):
            self.hw_due = self.steps
        self.at_log.append([self.steps, off, ax,
                            f"port 0x60 and IRQ 1, to the program's INT 09h at "
                            f"{handler[0]:04X}:{handler[1]:04X}"])
        # Stopped here, before this instruction runs, so that the run loop
        # raises IRQ 1 now rather than at the end of its slice; it then runs
        # from here again, which _on_code knows is not a second arrival.
        self._at_resume = addr
        uc.emu_stop()

    def at_summary(self):
        """The lines that say which way each --at key went."""
        lines = [f"key at {off:#x}, instruction {step:,}: AX {ax:#06x} through {path}"
                 for step, off, ax, path in self.at_log]
        left = {off: len(keys) for off, keys in self.at_keys.items() if keys}
        for off, n in sorted(left.items()):
            lines.append(f"key at {off:#x}: {n} never handed over -- the program did not "
                         f"get there {'again' if any(o == off for _, o, _, _ in self.at_log) else ''}"
                         .rstrip())
        return lines

    def _auto_undecided(self):
        """An --keyboard or --timer auto still waiting for the program to
        replace its vector, with something to move when it does. The run
        loop slices short meanwhile, so the switch takes effect within
        AUTO_SLICE instructions of the write that decides it."""
        return ((self.keyboard == "auto" and self.kbd_route is None and bool(self.keys))
                or (self.timer == "auto" and self.timer_route is None))

    def _vector9(self):
        off, seg = struct.unpack("<HH", self.uc.mem_read(9 * 4, 4))
        return seg, off

    def _keyboard_wait(self):
        """Instructions until the keyboard next wants the run to stop, or None
        when it has nothing to do -- in which case the loop is the old one."""
        if not self._hardware_keys():
            return None
        if not (self.hw_keys or self.hw_scancodes or self.hw_waiting):
            return None
        if self.hw_due is None:
            self.hw_due = self.steps + self.hw_every
        return self.hw_due - self.steps

    def _on_vector9_write(self, uc, access, address, size, value, _):
        """--keyboard auto: the moment the program writes vector 9.

        Watching the write, rather than looking at the vector now and then, is
        what makes auto mean what it says. A program that installs its handler
        and reads its first key within forty instructions has had both keys
        through INT 16h before any periodic look would notice."""
        if self.keyboard != "auto" or self.kbd_route is not None:
            return
        vector = bytearray(uc.mem_read(9 * 4, 4))
        at = address - 9 * 4
        vector[at:at + size] = value.to_bytes(8, "little")[:size][:4 - at]
        off, seg = struct.unpack("<HH", bytes(vector))
        # No emu_stop here: stopped from inside a memory write, Unicorn runs
        # the writing instruction a second time, and an install that saves
        # the old vector with `xchg` -- Moon Patrol's does -- swaps it back
        # and keeps its own segment as the "old" one. The run loop takes
        # short slices until this decides instead (AUTO_SLICE).
        self._vector9_set(seg, off)

    def _vector9_set(self, seg, off):
        """The program's vector 9 is now seg:off; with --keyboard auto, decide."""
        if self.keyboard != "auto" or self.kbd_route is not None:
            return
        if seg == (STUBS >> 4) or (seg, off) in ((0, 0), BIOS_IRET):
            return
        # The program has its own handler now, so the keys it has not read
        # yet go the way its handler expects them.
        self.kbd_route = "hardware"
        self.kbd_hooked = (self.steps, seg, off)
        self.hw_keys, self.keys = self.keys, []
        self._sync_kbd()
        self.hw_due = self.steps + self.hw_every

    def _keyboard_step(self, cs, ip):
        """Between two slices: latch a scancode in port 0x60 and raise IRQ 1.
        Returns where execution continues."""
        here = (cs << 4) + ip
        if self.hw_due is None or self.steps < self.hw_due:
            return here
        if not self.hw_waiting:
            if not self.hw_scancodes:
                if not self.hw_keys:
                    return here
                self.hw_ax = self.hw_keys.pop(0)
                self._at_pressed = self._at_queued.pop(0) if self._at_queued else None
                make = scancode_of(self.hw_ax)
                self.hw_scancodes = [make, make | 0x80]
            # The scancode is in port 0x60 from now on, whether or not the
            # interrupt can be taken yet.
            self.kbd_latch = self.hw_scancodes.pop(0)
            self.kbd_full = True
            self.hw_waiting = True
            self.kbd_log["scancodes"] += 1
        if self.pic_mask & 0x02:
            # IRQ 1 is masked: the program polls port 0x64 instead, and the
            # scancode waits in port 0x60 for it.
            self.kbd_log["masked"] += 1
            self.hw_waiting = False
            self.hw_due = self.steps + self.hw_every
            return here
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
        if not flags & IF or self.in_service & {0, 1}:
            # Not now: interrupts are off, or the PIC has not been told the
            # last one was handled (or the timer's, which outranks it). The
            # hardware would hold IRQ 1 pending; ask again shortly.
            self.kbd_log["held"] += 1
            self.hw_due = self.steps + KEY_RETRY
            return here
        seg, off = self._vector9()
        hooked = seg != (STUBS >> 4) and (seg, off) not in ((0, 0), BIOS_IRET)
        if hooked and self.kbd_hooked is None:
            self.kbd_hooked = (self.steps, seg, off)
        if (seg, off) == BIOS_IRET:
            # Straight back, and no end of interrupt: the PIC holds IRQ 1.
            self.in_service.add(1)
            self.hw_waiting = False
            self.kbd_log["irq"] += 1
            self.hw_due = self.steps + self.hw_every
            return here
        sp = (self.uc.reg_read(UC_X86_REG_SP) - 6) & 0xFFFF
        ss = self.uc.reg_read(UC_X86_REG_SS)
        self.uc.mem_write((ss << 4) + sp, struct.pack("<HHH", ip, cs, flags))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        # The CPU clears IF and TF on the way in; the handler's iret puts back
        # the FLAGS pushed above.
        self.uc.reg_write(UC_X86_REG_EFLAGS, flags & ~(IF | TF))
        self.uc.reg_write(UC_X86_REG_CS, seg)
        self.in_service.add(1)
        self.hw_waiting = False
        self.kbd_log["irq"] += 1
        self.hw_due = self.steps + self.hw_every
        return (seg << 4) + off

    def _bios_keyboard(self):
        """What the BIOS's own INT 09h handler does with a scancode: a make
        code becomes a key in the INT 16h buffer; the PIC is acknowledged.

        Reached when IRQ 1 finds vector 9 still pointing at the BIOS, or when
        the program's handler chains to the vector it replaced. The key put
        in the buffer is the --keys entry itself, so INT 16h hands over the
        same AX it would have without the hardware in between."""
        code = self.kbd_latch
        self.kbd_full = False
        if not code & 0x80:
            self.keys.append(self.hw_ax)
            self._sync_kbd()
            self.kbd_log["to_bios"] += 1
            if self._at_pressed is not None:
                entry = self.at_log[self._at_pressed]
                if entry[2] == self.hw_ax and "INT 16h too" not in entry[3]:
                    entry[3] += (", which passed it on to the BIOS's, so it is in the "
                                 "buffer for INT 16h too")
        self.in_service.discard(1)

    def keyboard_summary(self, total):
        """One line on where the keys went, for the end of a run."""
        k = self.kbd_log
        left = len(self.hw_keys)
        if self.keyboard == "auto" and self.kbd_route is None:
            return ("keyboard  : auto -- INT 09h was never replaced, so every key went "
                    "to INT 16h, as with --keyboard bios")
        how = ("--keyboard hw" if self.keyboard == "hw" else
               f"auto: the program replaced INT 09h at instruction "
               f"{self.kbd_hooked[0]:,}")
        line = (f"keyboard  : hardware ({how}): {k['scancodes']} scancodes in port "
                f"0x60, IRQ 1 taken {k['irq']} times")
        if self.kbd_hooked:
            line += f" by the handler at {self.kbd_hooked[1]:04X}:{self.kbd_hooked[2]:04X}"
        if k["to_bios"]:
            line += f"; {k['to_bios']} reached the BIOS handler and so INT 16h"
        if k["masked"]:
            line += f"; {k['masked']} left in the port with IRQ 1 masked"
        if k["held"]:
            line += f"; {k['held']} times held back for IF or an EOI"
        line += f"; {left} of {total} keys never pressed"
        if self.hw_scancodes or self.hw_waiting:
            line += ", and the last was still down when the run ended"
        if k["irq"] and not k["eoi"] and not k["to_bios"] and k["held"]:
            line += ("\n            the handler never acknowledged the PIC (no EOI on "
                     "port 0x20), so every later IRQ 1 waited for one")
        return line

    # -- the timer as hardware --------------------------------------------
    #
    # --timer-isr delivers one interrupt number to whatever handler holds its
    # vector, every N instructions, and that is all it does: it ignores the
    # PIC's mask, never waits for an end-of-interrupt, and a handler that
    # passes the tick on to the BIOS reaches a stub that does nothing, so the
    # BIOS never counts it and never raises INT 1Ch. Moon Patrol (1983)
    # replaces vector 8 with its own handler. Here IRQ 0 is what it is on the
    # machine: a frame pushed and a jump through whatever vector 8 holds,
    # masked by port 0x21 bit 0, held while IF is clear or an IRQ 0 is still
    # in service; and when it reaches the BIOS -- directly, or because the
    # program's handler jumped on to the vector it replaced -- the BIOS's
    # INT 08h runs: the tick at 0040:006C, INT 1Ch, the acknowledgement.

    def _timer_irq(self):
        """True while the tick is IRQ 0 rather than a word written now and then."""
        return self.timer == "hw" or self.timer_route == "hardware"

    def _timer_wait(self):
        """Instructions until the next IRQ 0 is due, or None while the timer
        is not hardware -- in which case the run loop is the old one."""
        if not self._timer_irq():
            return None
        if self.timer_due is None:
            self.timer_due = self.steps + self.timer_every
        return self.timer_due - self.steps

    def _on_timer_vector_write(self, uc, access, address, size, value, _):
        """--timer auto: the moment the program writes vector 8 or 1Ch."""
        if self.timer != "auto" or self.timer_route is not None:
            return
        vector = 0x08 if address < 0x1C * 4 else 0x1C
        current = bytearray(uc.mem_read(vector * 4, 4))
        at = address - vector * 4
        current[at:at + size] = value.to_bytes(8, "little")[:size][:4 - at]
        off, seg = struct.unpack("<HH", bytes(current))
        self._timer_vector_set(vector, seg, off)    # no emu_stop: see _on_vector9_write

    def _timer_vector_set(self, vector, seg, off):
        """The program's vector 8 or 1Ch is now seg:off; with --timer auto,
        decide. True when this decided it."""
        if self.timer != "auto" or self.timer_route is not None:
            return False
        if seg == (STUBS >> 4) or (seg, off) in ((0, 0), BIOS_IRET):
            return False
        self.timer_route = "hardware"
        self.timer_hooked = (self.steps, vector, seg, off)
        self.timer_due = self.steps + self.timer_every
        return True

    def _timer_step(self, cs, ip):
        """Between two slices: raise IRQ 0. Returns where execution continues."""
        here = (cs << 4) + ip
        if self.timer_due is None or self.steps < self.timer_due:
            return here
        if self.pic_mask & 0x01:
            # Masked at the PIC: this tick never reaches the CPU.
            self.timer_log["masked"] += 1
            self.timer_due = self.steps + self.timer_every
            return here
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
        if not flags & IF or 0 in self.in_service:
            # Interrupts are off, or the last IRQ 0 was never acknowledged.
            # The PIC holds the request; ask again shortly.
            self.timer_log["held"] += 1
            self.timer_due = self.steps + KEY_RETRY
            return here
        off, seg = struct.unpack("<HH", self.uc.mem_read(8 * 4, 4))
        if (seg, off) == BIOS_IRET:
            # Straight back, and no end of interrupt: the PIC holds IRQ 0.
            self.in_service.add(0)
            self.timer_log["irq"] += 1
            self.timer_due = self.steps + self.timer_every
            return here
        sp = (self.uc.reg_read(UC_X86_REG_SP) - 6) & 0xFFFF
        ss = self.uc.reg_read(UC_X86_REG_SS)
        self.uc.mem_write((ss << 4) + sp, struct.pack("<HHH", ip, cs, flags))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        self.uc.reg_write(UC_X86_REG_EFLAGS, flags & ~(IF | TF))
        self.uc.reg_write(UC_X86_REG_CS, seg)
        self.in_service.add(0)
        self.timer_log["irq"] += 1
        if seg != (STUBS >> 4):
            self.timer_log["to_program"] += 1
            self.timer_handler = (seg, off)
        self.timer_due = self.steps + self.timer_every
        return (seg << 4) + off

    def _bios_timer(self, uc):
        """What the BIOS's own INT 08h does with IRQ 0: count the tick at
        0040:006C, raise INT 1Ch, acknowledge the PIC.

        Reached when IRQ 0 finds vector 8 still the BIOS's, or when the
        program's handler goes on to the vector it replaced. The IBM BIOS
        acknowledges after INT 1Ch returns; this does before, which differs
        only for an INT 1Ch handler that turns interrupts back on."""
        self.ticks += 1
        uc.mem_write(0x46C, struct.pack("<I", self.ticks))
        self.timer_log["to_bios"] += 1
        self.in_service.discard(0)
        off, seg = struct.unpack("<HH", uc.mem_read(0x1C * 4, 4))
        if seg != (STUBS >> 4) and (seg, off) not in ((0, 0), BIOS_IRET):
            # Raised between two slices, from the stub's `iret`, which then
            # returns from the IRQ 0 frame as the BIOS's own handler would.
            self.pending_1c = True
            uc.emu_stop()

    def _user_tick(self, cs, ip):
        """INT 1Ch, raised by the BIOS's INT 08h: a frame back to where the
        BIOS was, and the program's handler. Returns where execution goes."""
        self.pending_1c = False
        off, seg = struct.unpack("<HH", self.uc.mem_read(0x1C * 4, 4))
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
        sp = (self.uc.reg_read(UC_X86_REG_SP) - 6) & 0xFFFF
        ss = self.uc.reg_read(UC_X86_REG_SS)
        self.uc.mem_write((ss << 4) + sp, struct.pack("<HHH", ip, cs, flags))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        self.uc.reg_write(UC_X86_REG_EFLAGS, flags & ~(IF | TF))
        self.uc.reg_write(UC_X86_REG_CS, seg)
        self.timer_log["int1c"] += 1
        self.user_tick = (seg, off)
        return (seg << 4) + off

    def timer_summary(self):
        """One line on where the ticks went, for the end of a run."""
        t = self.timer_log
        if self.timer == "auto" and self.timer_route is None:
            return ("timer     : auto -- neither INT 08h nor INT 1Ch was replaced, so the "
                    "tick went to 0040:006C, as with --timer bios")
        if self.timer == "hw":
            how = "--timer hw"
        else:
            step, vector, seg, off = self.timer_hooked
            how = (f"auto: the program replaced INT {vector:02X}h at instruction {step:,}, "
                   f"with {seg:04X}:{off:04X}")
        line = f"timer     : IRQ 0 ({how}): raised {t['irq']:,} times"
        if t["to_program"]:
            seg, off = self.timer_handler
            line += f", {t['to_program']:,} to the program's handler at {seg:04X}:{off:04X}"
        line += f"; the BIOS's INT 08h ran {t['to_bios']:,} times"
        if t["int1c"]:
            seg, off = self.user_tick
            line += f" and raised INT 1Ch {t['int1c']:,} times, to {seg:04X}:{off:04X}"
        if t["masked"]:
            line += f"; {t['masked']:,} masked at the PIC"
        if t["held"]:
            line += f"; held {t['held']:,} times for IF or an EOI"
        if t["to_program"] and not t["eoi"] and not t["to_bios"] and t["held"]:
            line += ("\n            the handler never acknowledged the PIC (no EOI on port "
                     "0x20), so every later IRQ 0 waited for one")
        return line

    def _enable_interrupts(self):
        """Start with IF set, the way DOS hands a program control.

        Unicorn starts with FLAGS at 0x0002 -- interrupts disabled -- which no
        real program has ever seen. It went unnoticed while nothing here
        delivered an interrupt; the moment something did, every delivery was
        correctly refused and the timer never ticked.
        """
        self.uc.reg_write(UC_X86_REG_EFLAGS,
                          self.uc.reg_read(UC_X86_REG_EFLAGS) | IF)

    def _fire_isr(self, cs, ip):
        """Deliver a timer interrupt to the handler the program installed.

        Ticking the BIOS word at 0040:006C is not enough for a game that hooks
        the timer itself. The Oregon Trail installs this at image 0x10441:

            push ax..bp / mov ax, 0x3348 / mov ds, ax   ; DGROUP, hardcoded
            les ax, [0x16B2] / add ax, 1 / adc dx, 0    ; a 32-bit counter
            mov [0x16B2], ax / mov [0x16B4], dx
            iret

        and its hunting mini-game then waits for that counter to become
        non-zero, in five instructions at image 0x764F. Nothing in an emulator
        that only answers interrupts ever runs the handler, so the counter
        stays at zero and the loop spins for ever -- 3,000,000,000 instructions
        produced byte-identical output to 1,500,000,000, which is what a run
        that has stopped making progress looks like.

        So do what the hardware does: push FLAGS, CS and IP, and continue at
        the handler. Its own `iret` pops the frame and resumes exactly where
        the program was interrupted, which is the whole point of the frame.

        Take an interrupt *number* and read the live vector, rather than an
        address. An earlier version took the address and was wrong in a way
        worth keeping: The Oregon Trail ships packed with LZEXE, so twenty
        thousand instructions in, the handler's address still holds compressed
        bytes. Jumping there destroyed the run -- no interrupts requested, no
        ports written, no keys read, and 99,999 timer interrupts delivered
        into rubbish. Reading the vector each time waits for the program to
        install its handler, because until it does the slot still points at
        our own stub and there is nothing to deliver.
        """
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
        if not flags & IF:
            # Hardware does not deliver a maskable interrupt while IF is
            # clear, and neither may this. Ignoring that broke a run after
            # 26.9 million instructions with two interrupts delivered: Turbo
            # Pascal's Crt closes `cli` around the port writes in Sound and
            # Delay, and a frame pushed inside one of those leaves the routine
            # somewhere it cannot return from. Respecting IF is not politeness,
            # it is the contract the program was written against.
            self.isr_masked += 1
            return (cs << 4) + ip
        vec = self.uc.mem_read(self.isr_vector * 4, 4)
        off, seg = struct.unpack("<HH", vec)
        if seg == (STUBS >> 4) or (seg, off) in ((0, 0), BIOS_IRET):
            return (cs << 4) + ip          # not hooked yet -- nothing to do
        sp = self.uc.reg_read(UC_X86_REG_SP)
        ss = self.uc.reg_read(UC_X86_REG_SS)
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS) & 0xFFFF
        sp = (sp - 6) & 0xFFFF
        self.uc.mem_write((ss << 4) + sp, struct.pack("<HHH", ip, cs, flags))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        if self._hardware_keys():
            # The CPU clears IF on the way into any interrupt. This did not,
            # and nothing could tell while the timer was the only interrupt
            # delivered; with a keyboard as well, a scancode taken one
            # instruction into a timer handler nests where hardware would not
            # let it. Runs without hardware keys keep the old behaviour, so
            # their timer deliveries land exactly where they always did.
            self.uc.reg_write(UC_X86_REG_EFLAGS, flags & ~(IF | TF))
            if self.isr_vector == 0x08:
                self.in_service.add(0)
        # CS must move with the jump. Unicorn keeps a segment base and a
        # 16-bit IP separately, so restarting at the handler's linear address
        # while CS still names the interrupted segment leaves the two
        # disagreeing -- and one delivery was enough to end a run 26.9 million
        # instructions in, every time, at the same instruction. Frequency was
        # never the variable: 20,000 crashed after two deliveries and 200,000
        # after one.
        self.uc.reg_write(UC_X86_REG_CS, seg)
        self.isr_fired += 1
        return (seg << 4) + off

    def _where(self):
        """CS:IP and the bytes there, because a fault without an address is not
        a diagnosis. The image offset is what every document quotes, so give
        that too rather than making the reader do the arithmetic."""
        cs = self.uc.reg_read(UC_X86_REG_CS)
        ip = self.uc.reg_read(UC_X86_REG_IP)
        flat = (cs << 4) + ip
        try:
            raw = bytes(self.uc.mem_read(flat, 8)).hex(" ")
        except UcError:
            raw = "unreadable"
        hist = [self.recent[(self.steps + i) & 511] for i in range(1, 513)]
        hist = [a - self.img_bias for a in hist if a]
        # The interesting moment is not the fault, it is the step that left the
        # program. A fault deep in low memory has already lost the trail, so
        # report the last instructions that were still inside the image.
        top = len(self.image) + 0x10000
        inside = [a for a in hist if 0 <= a < top]
        left = ""
        for i, a in enumerate(hist):
            if not (0 <= a < top) and i:
                left = f"\n  left the image after {hist[i - 1]:#x}"
                break
        return (f"{cs:04X}:{ip:04X} (image {flat - self.img_bias:#08x}) "
                f"[{raw}]{left}\n  last inside: "
                + (" -> ".join(f"{a:#x}" for a in inside[-8:])
                   or "(nothing in range)"))

    def call(self, off, budget=20_000_000, seg=None):
        """Call a routine and stop when it returns.

        A sentinel return address is pushed and used as the stop point, so a
        routine that returns normally ends the run rather than falling into
        whatever follows it.

        `seg` makes it a *far* call, which a compiled program needs. Every unit
        of a Turbo Pascal program is its own segment and every entry point into
        one is `lcall seg:off`; calling such a routine at a flat image offset
        runs it with the wrong CS, so its string constants resolve to garbage
        and it usually returns immediately having drawn nothing. That is what
        an attempt to photograph The Oregon Trail's hunting screen did -- it
        landed back on the main menu and looked like the routine had declined
        to run.
        """
        sentinel = 0xFFF0
        sp = self.uc.reg_read(UC_X86_REG_SP)
        if seg is not None:
            sp -= 2                       # a far return needs CS as well
            self.uc.mem_write(BASE + sp, struct.pack("<H", SEG))
        sp -= 2
        self.uc.mem_write(BASE + sp, struct.pack("<H", sentinel))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        self.stopped = None
        if seg is not None:
            self.uc.reg_write(UC_X86_REG_CS, seg)
            start = (seg << 4) + off
        else:
            start = BASE + LOAD + off
        first = self.steps
        while True:
            try:
                self.uc.emu_start(start, BASE + sentinel,
                                  count=max(1, budget - (self.steps - first)))
            except UcError as e:
                self.stopped = self.stopped or f"fault: {e} at {self._where()}"
            finally:
                self._restore_lock()
            if self.stopped is not None or not self._exception_taken:
                break
            # A divide error went to the program's handler: on from there.
            self._clear_exception()
            start = (self.uc.reg_read(UC_X86_REG_CS) << 4) + self.uc.reg_read(UC_X86_REG_IP)
        return self.stopped or "returned"

    def key(self, scancode, handler):
        """Deliver one keypress through the program's own INT 9 handler.

        Writing the translated key straight into the game's variable would be
        easier and would prove less: the handler is where the scancode is
        filtered, acknowledged and translated, and a game that reads the
        keyboard itself keeps its own idea of what is held down. So the
        interrupt is staged the way the hardware stages it -- flags, CS and the
        *current* IP pushed -- and the handler runs to its own `iret`, which
        lands execution back exactly where it was.

        Pushing a sentinel return address instead is the obvious shortcut and
        it destroys the thing you were driving: the program resumes at an
        address it never came from and faults on the first fetch.
        """
        cs = self.uc.reg_read(UC_X86_REG_CS)
        ip = self.uc.reg_read(UC_X86_REG_IP)
        self.pending_key = scancode
        sp = self.uc.reg_read(UC_X86_REG_SP)
        for word in (0x0202, cs, ip):           # FLAGS, CS, IP
            sp -= 2
            self.uc.mem_write(BASE + sp, struct.pack("<H", word))
        self.uc.reg_write(UC_X86_REG_SP, sp)
        self.stopped = None
        try:
            self.uc.emu_start((cs << 4) + handler + LOAD, (cs << 4) + ip,
                              count=200_000)
        except UcError as e:
            self.stopped = f"fault in the key handler: {e}"
        return self.stopped or "handled"

    def play(self, handler, keys, slice_len=400_000, slices=40):
        """Let the program run, delivering a key between slices.

        Calling a game's routines by hand gets you a screen; it does not get
        you a game. A title loop is waiting for a keypress and the only way
        past it is to keep running and keep pressing. Execution resumes from
        wherever each slice ended, so the program follows its own control flow
        throughout -- this drives it, it does not simulate it.
        """
        for n in range(slices):
            cs = self.uc.reg_read(UC_X86_REG_CS)
            ip = self.uc.reg_read(UC_X86_REG_IP)
            self.stopped = None
            try:
                self.uc.emu_start((cs << 4) + ip, BASE + 0xFFFF,
                                  count=slice_len)
            except UcError as e:
                return f"fault after {n} slices: {e}"
            if self.stopped:
                return self.stopped
            if keys:
                self.key(keys[n % len(keys)], handler)
        return f"ran {slices} slices"

    def framebuffer(self):
        return self.uc.mem_read(VIDEO, 0x4000)

    def read(self, off, n):
        """Memory at a *file* offset -- a .COM's byte 0 lives at 0x100."""
        return self.uc.mem_read(BASE + LOAD + off, n)


def to_png(fb, path, palette="1", scale=3):
    from PIL import Image
    pal = PALETTES[palette]
    img = Image.new("RGB", (320, 200))
    px = img.load()
    for row in range(200):
        # The two banks: even scanlines at 0x0000, odd at 0x2000.
        base = (row & 1) * 0x2000 + (row >> 1) * 80
        for b in range(80):
            v = fb[base + b]
            for k in range(4):
                px[b * 4 + k, row] = pal[(v >> (6 - k * 2)) & 3]
    img.resize((320 * scale, 200 * scale), Image.NEAREST).save(path)
    return img


def loaded_image(machine):
    """The program's image as loaded, relocations applied: what an executed
    instruction's bytes are compared with at the end of a run."""
    size = (len(machine.image) if machine.mz is None
            else machine.mz["end"] - machine.mz["hdr"])
    return bytes(machine.uc.mem_read(BASE + LOAD, size))


def exec_map_json(machine, loaded, binary):
    """--exec-map-json: every instruction the run executed, with the CS:IP it
    ran at, and whether its bytes were still the ones loaded when the run
    ended. A linear address says where an instruction was; only CS:IP says
    at which origin it ran, which is what comrec --seeds-from checks its
    layout against. And code that was decompressed, patched or copied over is
    not the file's: comrec must not take the file's bytes there for what ran."""
    now = bytes(machine.uc.mem_read(BASE + LOAD, len(loaded)))
    rows = set()
    for addr, cs, size in machine.exec_where:
        off = addr - machine.img_bias
        if off < 0:
            continue        # the interrupt stubs below the program
        changed = off + size <= len(loaded) and now[off:off + size] != loaded[off:off + size]
        rows.add((off, cs, addr - (cs << 4), size, int(changed)))
    return {"tool": "comrun --exec-map-json", "binary": binary,
            "format": "COM" if machine.mz is None else "MZ",
            "image_offset": "the linear address less 0x10100: a .COM's file offset, "
                            "an MZ's offset past its header",
            "instructions": machine.steps,
            "columns": ["image_offset", "cs", "ip", "size", "changed"],
            "executed": sorted(rows)}


def run_summary(machine, args, why, keys, screen_lines):
    """What --summary-json writes: the run's result as data, for a caller that
    is not a terminal (the MCP server's comrun). The same facts the printed
    report gives, read from the machine, not parsed back out of the text."""
    m = machine
    lines = {}
    if args.timer != "bios":
        lines["timer"] = m.timer_summary()
    if args.keys and args.keyboard != "bios":
        lines["keyboard"] = m.keyboard_summary(len(keys))
    if m.dispatched:
        lines["vectors"] = m.vector_summary()
    for key, line in (("cpu", m.cpu_summary()), ("adapter", m.adapter_summary())):
        if line:
            lines[key] = line
    if m.at_log or any(m.at_keys.values()):
        lines["at"] = m.at_summary()
    printed = "".join(m.output).replace("\r\n", "\n").strip()
    png = args.png if args.png is None or Path(args.png).exists() else None
    summary = {
        "binary": str(args.binary), "format": "COM" if m.mz is None else "MZ",
        "instructions": m.steps, "stopped": why,
        "interrupts": sorted({f"{n:02X}h" for n, _ in m.ints}),
        "ports_written": [f"0x{p:X}" for p in sorted({p for d, p, _ in m.ports if d == "out"})],
        "keys_given": len(keys), "keys_read": m.keys_read,
        "replaced_vectors": [f"{n:02X}h" for n in m.replaced_vectors()],
        "dispatched": {f"{n:02X}h": {"count": c, "handlers": [f"{s:04X}:{o:04X}" for s, o in h]}
                       for n, (c, h) in sorted(m.dispatched.items())},
        "files_opened": list(dict.fromkeys(m.file_reads)),
        "files_not_found": list(dict.fromkeys(m.file_misses)),
        "printed": printed.split("\n") if printed else [],
        "bios_characters": m.bios_chars, "summary_lines": lines,
        "screen": screen_lines, "png": png, "exec_map_json": args.exec_map_json,
        "exec_map": args.exec_map,
    }
    # Only when there is something to say, so that a run that met none of
    # these writes what it always wrote.
    if m.adapter != "cga":
        summary["adapter"] = m.adapter
    if m.lock_steps or m.exceptions:
        summary["cpu"] = {
            "model": m.cpu, "lock_prefixes_stepped_over": m.lock_steps,
            "lock_sites": [f"0x{a:X}" for a in sorted(m.lock_sites)],
            "exceptions": {f"{n:02X}h": {"count": c,
                                         "handlers": [f"{s:04X}:{o:04X}" for s, o in h]}
                           for n, (c, h) in sorted(m.exceptions.items())}}
    if m.at_log or any(m.at_keys.values()):
        summary["at_keys"] = [{"image_offset": f"0x{off:X}", "instruction": step,
                               "ax": f"0x{ax:04X}", "path": path}
                              for step, off, ax, path in m.at_log]
    return summary


def draw_screen(machine, path, render="cga", palette=None, font=None):
    """Write the screen to a PNG; the lines that say how it was drawn.

    As mode 4, exactly as before, when asked to or when the program never
    touched the adapter -- and then there is nothing to say. Otherwise from
    the CGA's registers, and the lines say what they held. With --adapter
    ega or tandy, in mode 0Dh or 9, from that adapter's model instead -- or
    not at all, and the lines say why, when the registers hold what the model
    does not model; then no PNG is left at `path`, not even an earlier one."""
    cga = machine.cga
    if render == "cga" and machine.ega is not None and machine.ega.mode == 0x0D:
        ega = machine.ega
        why = ega.display_refusal()
        if why:
            Path(path).unlink(missing_ok=True)
            return [f"screen    : EGA {ega.describe()}",
                    f"            not drawn: {why}"]
        img, notes = render_ega(ega)
        img.save(path)
        how = ", ".join(ega.writes["bios"][-3:] + [f"port 0x{p:X}" for p in sorted(ega.writes["ports"])])
        return ([f"screen    : EGA {ega.describe()}", f"            set by {how}"]
                + [f"            {note}" for note in notes])
    if render == "cga" and machine.tandy is not None and machine.tandy.mode == 9:
        t = machine.tandy
        img, notes = render_tandy(t, machine.tandy_shown())
        img.save(path)
        how = ", ".join(t.writes["bios"][-3:] + [f"port 0x{p:X}" for p in sorted(t.writes["ports"])])
        return ([f"screen    : Tandy {t.describe()}", f"            set by {how}"]
                + [f"            {note}" for note in notes])
    if render == "mode4" or not cga.programmed or cga.unsupported is not None:
        to_png(machine.framebuffer(), path, palette or "1")
        if cga.unsupported is not None and render == "cga":
            lines = [f"screen    : INT 10h set mode {cga.unsupported}, which this "
                     f"renderer does not model; drawn as mode 4"]
            owner = {0x0D: "EGA's: --adapter ega", 0x09: "Tandy 1000's: --adapter tandy"}
            if cga.unsupported in owner and machine.adapter == "cga":
                lines.append(f"            mode {cga.unsupported:02X}h is the "
                             f"{owner[cga.unsupported]} draws it")
            return lines
        return []
    font, missing = (font, ()) if font is not None else shipped_font()
    img, notes = render_cga(machine.framebuffer(), cga, palette, font, missing)
    img.save(path)
    how = ", ".join(cga.writes["bios"][-3:] +
                    [f"port 0x{p:X}" for p in sorted(cga.writes["ports"])])
    return ([f"screen    : CGA {cga.describe()}", f"            set by {how}"]
            + [f"            {note}" for note in notes])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--gate", metavar="ADDR[,ADDR...]", default="",
                    help="release one --keys entry each time execution reaches "
                         "any of these addresses -- typically every call site "
                         "of the routine that reads a key")
    ap.add_argument("--watch-ptr", metavar="ADDR[:N]", default="",
                    help="dump DS:SI and ES:DI when an address is reached, "
                         "N times (default 4)")
    ap.add_argument("--trace-io", action="store_true",
                    help="log every file open, read and seek")
    ap.add_argument("--at", metavar="ADDR=KEY[,...]", default="",
                    help="hand a key over when the program reaches an image "
                         "offset, rather than queueing it blind. Repeat an "
                         "address to deliver several, one each time it is "
                         "reached. It goes the way the program reads the "
                         "keyboard then, whatever --keyboard says: into the "
                         "BIOS's buffer for INT 16h while vector 9 is the "
                         "BIOS's, as a scancode and IRQ 1 through the "
                         "program's own INT 09h once it has one. The output "
                         "says which, for each key")
    ap.add_argument("--adapter", choices=ADAPTERS, default="cga",
                    help="the display adapter. cga (the default): as always. "
                         "ega: answers INT 10h AH=12h as an EGA with 256 KB, "
                         "INT 11h and 0040:0010 with an equipment word saying "
                         "so, and draws mode 0Dh from four planes at A000 "
                         "through the sequencer, graphics controller, CRTC "
                         "and attribute registers. tandy: 0x21 at F000:C000, "
                         "as a Tandy 1000's ROM, and mode 9 drawn from its "
                         "pages. A register value the model does not model "
                         "stops the run, or the picture, and says which")
    ap.add_argument("--cpu", choices=CPUS, default="8088",
                    help="the processor. 8088 (the default): a LOCK prefix "
                         "Unicorn refuses is stepped over, as the 8088 ran it "
                         "on any instruction, and a divide error returns to "
                         "the instruction after the divide. 386: as Unicorn "
                         "is -- LOCK refused on nop and arithmetic into a "
                         "register, a divide error returning to the divide. "
                         "On both, a divide error or the trap flag's INT 1 "
                         "goes to the program's own handler when it has one")
    ap.add_argument("--poke", metavar="OFF=VAL[,...]", default="",
                    help="write a word at an image offset before --call. A "
                         "routine usually refuses to run without the state a "
                         "real game would have reached first: The Oregon "
                         "Trail's hunting screen tests the bullet count and "
                         "returns immediately when it is zero.")
    ap.add_argument("--call", metavar="OFF|SEG:OFF", help="after start-up, call this file offset")
    ap.add_argument("--stop-at", help="stop the start-up run at this offset "
                                      "instead of letting it reach its budget")
    ap.add_argument("--stop-after", type=int, default=1, metavar="N",
                    help="stop on the Nth arrival at --stop-at, not the first")
    ap.add_argument("--watch", help="log calls arriving at these offsets")
    ap.add_argument("--vars", default="0x6d9b,0x6d9c,0x6d97",
                    help="variables to record at each watched call")
    ap.add_argument("--timer-isr", metavar="INT[,N]",
                    help="deliver interrupt INT (hex, e.g. 1c) to whatever "
                         "handler the program has installed, every N "
                         "instructions (default 20000), pushing a real "
                         "FLAGS/CS/IP frame so its iret resumes correctly. "
                         "For a game that hooks the timer and waits on a "
                         "counter its own handler increments. The vector is "
                         "read at each delivery, so nothing is sent until the "
                         "program has hooked it")
    ap.add_argument("--timer", choices=("bios", "hw", "auto"), default="bios",
                    help="how time passes. bios (the default): the tick at "
                         "0040:006C is advanced every 20,000 instructions, as "
                         "always, and only --timer-isr runs a handler. hw: IRQ 0 "
                         "every --timer-every instructions, through whatever "
                         "INT 08h vector holds, masked by port 0x21 and held "
                         "until the last one is acknowledged; one that reaches "
                         "the BIOS's INT 08h counts the tick and raises INT 1Ch. "
                         "auto: bios until the program replaces vector 8 or "
                         "1Ch, then hw. The output says which happened")
    ap.add_argument("--timer-every", type=int, default=TIMER_EVERY, metavar="N",
                    help=f"with --timer hw or auto, instructions between two "
                         f"IRQ 0 (default {TIMER_EVERY:,})")
    ap.add_argument("--poll-patience", type=int, metavar="N",
                    help="answer INT 16h AH=01 with 'nothing waiting' until it "
                         "has been asked N times since the last real read. "
                         "Defeats a `while KeyPressed do ReadKey` flush loop, "
                         "which otherwise swallows the whole --keys queue")
    ap.add_argument("--keys", help="keystrokes for INT 16h, comma separated: "
                                   "a character, or a full AX as 0xSSCC "
                                   "(scancode:ASCII)")
    ap.add_argument("--keyboard", choices=("bios", "hw", "auto"), default="bios",
                    help="where --keys go. bios (the default): to INT 16h, as "
                         "always. hw: through the hardware -- each key a make "
                         "and a break code in port 0x60, each raising IRQ 1 "
                         "through whatever INT 09h vector holds, for a game "
                         "with its own keyboard handler; a key that reaches "
                         "the BIOS's handler goes on to INT 16h. auto: INT 16h "
                         "until the program replaces vector 9, then the keys "
                         "not yet read go through the hardware. The output "
                         "says which happened")
    ap.add_argument("--no-joystick", action="store_true",
                    help="answer port 0x201 with 0xFF, as a PC with no game "
                         "adapter does. Without it the port's alternating "
                         "answer passes a joystick probe, and a game that "
                         "finds one reads its buttons from noise (Zaxxon, "
                         "Rollo)")
    ap.add_argument("--key-every", type=int, default=KEY_EVERY, metavar="N",
                    help=f"with --keyboard hw or auto, instructions between "
                         f"two scancodes: how long a key is held, and how long "
                         f"until the next (default {KEY_EVERY:,})")
    ap.add_argument("--ax", help="value to put in AX before --call")
    ap.add_argument("--handler", help="INT 9 handler offset, for --scancodes")
    ap.add_argument("--scancodes",
                    help="raw scancodes to deliver through the program's own "
                         "INT 9 handler after --call, comma separated hex. "
                         "Use this for a game that reads the keyboard port "
                         "itself; --keys is for one that asks DOS or the BIOS")
    ap.add_argument("--files", metavar="DIR",
                    help="directory the program's data files are in; "
                         "without it every open fails, and a game that "
                         "cannot find its artwork usually prints a "
                         "message and exits")
    ap.add_argument("--budget", type=int, default=20_000_000)
    ap.add_argument("--png")
    ap.add_argument("--palette", default=None, choices=sorted(PALETTES),
                    help="force the 320-wide palette (0 or 1, as bright as "
                         "mode 4's default). Without it the palette is what "
                         "the program set, or 1 if it set none")
    ap.add_argument("--render", choices=("cga", "mode4"), default="cga",
                    help="cga (the default): draw what the CGA's registers "
                         "say -- mode, palette, columns, rows, scanlines per "
                         "row, start address -- once the program has set "
                         "any of them, by port or by INT 10h. mode4: draw the "
                         "framebuffer as 320x200 mode 4 whatever was set, as "
                         "before")
    ap.add_argument("--font", metavar="FILE",
                    help="an 8x8 font, 2,048 bytes, for text screens. Without "
                         "it the shipped one is used, tools/fonts/cp437-8x8.txt "
                         "(unscii-8, public domain), which lacks four code "
                         "points; they are drawn as boxes")
    ap.add_argument("--bios-text", action="store_true",
                    help="draw what the program writes through INT 10h (AH=09h, "
                         "0Ah, 0Eh, with the cursor calls 02h and 03h and the "
                         "mode in 0Fh) into the framebuffer, as the BIOS does: in "
                         "a text mode at the cursor, in graphics from the font in "
                         "BL's colour. Without it those calls are ignored, as "
                         "always, and a screen made of them stays blank")
    ap.add_argument("--json")
    ap.add_argument("--exec-map", metavar="FILE",
                    help="write every image offset the program executed, "
                         "for checking a disassembly against a run")
    ap.add_argument("--exec-map-json", metavar="FILE",
                    help="write every instruction executed as JSON, with the "
                         "CS:IP it ran at and whether its bytes were still the "
                         "ones loaded when the run ended: what comrec "
                         "--seeds-from checks against its layout")
    ap.add_argument("--dump", help="write a memory range as OFF:LEN")
    ap.add_argument("--summary-json", metavar="FILE",
                    help="also write the run's result as JSON: where it stopped, "
                         "the interrupts, the vectors the program replaced and "
                         "the `int`s sent to them, files, what it printed, how the "
                         "screen was drawn. The printed report is unchanged")
    args = ap.parse_args()

    keys = []
    for k in (args.keys.split(",") if args.keys else []):
        keys.append(int(k, 0) if k.lower().startswith("0x") else ord(k[0]))

    if args.keyboard != "bios":
        unnamed = [k for k in keys if scancode_of(k) is None]
        if unnamed:
            ap.error(f"no scancode for {', '.join(repr(chr(k)) for k in unnamed)}; give "
                     f"such a key as 0xSSCC, its scancode and ASCII code")
        if args.gate:
            ap.error("--gate hands keys to INT 16h at chosen places; with --keyboard hw "
                     "or auto the keys go through port 0x60 on a schedule instead. Use "
                     "--at, which goes the way the program reads at that moment")
    at_keys = {}
    for item in (x for x in args.at.split(",") if x.strip()):
        a, _, k = item.partition("=")
        if not k:
            ap.error(f"--at {item!r}: give ADDR=KEY, an image offset in hex and a key")
        # Same convention as --keys: 0x.. is a full AX, anything else is the
        # character itself.
        val = int(k, 0) if k.lower().startswith("0x") else ord(k[0])
        at_keys.setdefault(int(a, 16), []).append(val)
    if args.timer != "bios" and args.timer_isr:
        ap.error("--timer-isr sends one interrupt straight to its handler; --timer hw "
                 "or auto raises IRQ 0 through vector 8, and the BIOS's INT 08h raises "
                 "INT 1Ch from it. Use one or the other")
    font = None
    if args.font:
        font = Path(args.font).read_bytes()
        if len(font) != 2048:
            ap.error(f"{args.font} is {len(font):,} bytes; an 8x8 font for 256 "
                     f"characters is 2,048")

    image = Path(args.binary).read_bytes()
    m = Machine(image, keys=keys,
                files=args.files or Path(args.binary).parent)
    m.keyboard, m.hw_every = args.keyboard, args.key_every
    m.timer, m.timer_every = args.timer, args.timer_every
    m.no_joystick = args.no_joystick
    m.cpu = args.cpu
    m.set_adapter(args.adapter)
    # Before the start-up run, so that a key can wait for the place the
    # program reads it during start-up -- a title screen. They were read after
    # it, and so reached only a routine run by --call.
    m.at_keys = at_keys
    if args.bios_text:
        m.enable_bios_text(font)
    if args.keyboard == "hw":
        m.hw_keys, m.keys = m.keys, []
    if args.exec_map:
        m.exec_map = set()
    loaded = None
    if args.exec_map_json:
        m.exec_where = set()
        loaded = loaded_image(m)

    if args.timer_isr:
        spec = args.timer_isr.split(",")
        m.isr_vector = int(spec[0], 16)
        if len(spec) > 1:
            m.isr_every = int(spec[1], 0)
        print(f"timer ISR: INT {m.isr_vector:02X}h every "
              f"{m.isr_every} instructions, once the program hooks it")
    if args.poll_patience is not None:
        m.poll_patience = args.poll_patience
        print(f"poll patience: {args.poll_patience} (a flush loop sees an "
              "empty keyboard)")
    if args.gate:
        m.gates = {int(a, 16) for a in args.gate.split(",") if a.strip()}
        m.gated, m.keys = m.keys, []
        print(f"gated: {len(m.gated)} keys, released at "
              f"{len(m.gates)} addresses")
    if m.at_keys:
        print("keys on arrival: " + ", ".join(
            f"{a:#x} -> {len(v)}" for a, v in sorted(m.at_keys.items())))
    m.trace_io = args.trace_io
    for item in (x for x in args.watch_ptr.split(",") if x.strip()):
        a, _, n = item.partition(":")
        m.ptr_watch[int(a, 16)] = int(n) if n else 4
        m.trace_io = True


    watch = [int(x, 16) for x in args.watch.split(",")] if args.watch else []
    varlist = [int(x, 16) for x in args.vars.split(",")] if args.vars else []
    if watch:
        def make(off):
            def hit(_o):
                vals = {}
                for v in varlist:
                    vals[f"{v:#06x}"] = m.read(v - 0x100, 2)[0]
                m.blits.append({"routine": f"0x{off:05X}", "vars": vals})
            return hit
        for w in watch:
            m.watch[w] = make(w)

    stop = int(args.stop_at, 16) if args.stop_at else None
    if stop is not None:
        m.stop_off, m.stop_after = stop, args.stop_after
    if m.mz is not None:
        print(f"format    : MZ, {m.mz['hdr']}-byte header, "
              f"{m.mz['nreloc']} relocations applied; "
              f"entry CS:IP {m.mz['cs']:04X}:{m.mz['ip']:04X} "
              f"-> image offset 0x{m.mz_entry:X}")
    why = m.run(None, stop=None, budget=args.budget)
    print(f"start-up: {m.steps:,} instructions, stopped: {why}")
    print(f"  interrupts requested: "
          + ", ".join(sorted({f"{n:02X}h" for n, _ in m.ints})) or "  none")
    outs = sorted({p for d, p, _ in m.ports if d == "out"})
    if outs:
        print("  ports written: " + ", ".join(f"{p:#04x}" for p in outs))
    if m.isr_fired or m.isr_masked:
        print(f"  timer interrupts delivered: {m.isr_fired:,}"
              + (f", {m.isr_masked:,} skipped with interrupts disabled"
                 if m.isr_masked else ""))
    if args.timer != "bios":
        print("  " + m.timer_summary())
    if m.bios_chars and m.cga.programmed and not args.bios_text:
        # Only for a program that set the adapter up: one that never did
        # prints to a DOS console, which is not what is being drawn.
        print(f"  INT 10h   : {m.bios_chars:,} characters written through the BIOS "
              f"(AH=09h, 0Ah, 0Eh) are not on the screen drawn; --bios-text draws them")
    if args.keys and args.keyboard != "bios":
        print("  " + m.keyboard_summary(len(keys)))
    if args.keys and (args.keyboard == "bios" or m.keys_read):
        print(f"  keyboard: {m.keys_read} reads, {len(m.keys)} of "
              f"{len(keys)} keys unused")
    if m.dispatched:
        print("  " + m.vector_summary())
    if not args.call:
        for line in m.at_summary():
            print("  " + line)
    for line in (m.cpu_summary(), m.adapter_summary()):
        if line:
            print("  " + line)

    # These three were collected and then thrown away, which was the wrong
    # trade: when a program stops early it usually says why, and what it went
    # looking for is the other half of the answer. A run that ends at int 20h
    # with a file miss in the list has already diagnosed itself.
    if m.file_reads:
        print("  files opened: " + ", ".join(dict.fromkeys(m.file_reads)))
    if m.file_misses:
        print("  files NOT found: " + ", ".join(dict.fromkeys(m.file_misses))
              + ("" if m.files else "   (no --files given)"))
    if m.output:
        text = "".join(m.output).replace("\r\n", "\n").strip()
        if text:
            print("  the program printed:")
            for line in text.split("\n"):
                print(f"      {line}")

    for item in (x for x in args.poke.split(",") if x.strip()):
        off, _, val = item.partition("=")
        at, v = int(off, 0), int(val, 0)
        m.uc.mem_write(BASE + at, struct.pack("<H", v))
        print(f"poked image {at:#07x} = {v}")

    if args.call:
        if args.ax:
            m.uc.reg_write(UC_X86_REG_AX, int(args.ax, 0))
        before = m.steps
        if ":" in args.call:
            cseg, coff = (int(x, 16) for x in args.call.split(":"))
            why = m.call(coff, budget=args.budget, seg=cseg)
        else:
            why = m.call(int(args.call, 16), budget=args.budget)
        print(f"call {args.call}: {m.steps - before:,} instructions, {why}")
        for line in m.at_summary():
            print("  " + line)

    if args.scancodes and args.handler:
        h = int(args.handler, 16)
        for k in args.scancodes.split(","):
            why = m.key(int(k, 16), h)
            print(f"key {k}: {why}")

    if m.blits:
        print(f"\n{len(m.blits)} watched calls")
        for b in m.blits[:10]:
            print(f"  {b['routine']}  "
                  + "  ".join(f"[{k}]={v}" for k, v in b["vars"].items()))
        if len(m.blits) > 10:
            print(f"  ... {len(m.blits) - 10} more")

    if args.dump:
        off, n = args.dump.split(":")
        data = bytes(m.read(int(off, 16), int(n, 0)))
        print(f"\nmemory at {off}, {n} bytes:")
        print("  " + data.hex(" "))

    screen_lines = []
    if args.png:
        lines = draw_screen(m, args.png, args.render, args.palette, font)
        screen_lines = lines
        if lines:
            print("")
            for line in lines:
                print(line)
        if Path(args.png).exists():
            print(f"\nwrote {args.png}")
    if args.json:
        Path(args.json).write_text(json.dumps(
            {"stopped": why, "steps": m.steps, "blits": m.blits}, indent=2),
            encoding="utf-8")
        print(f"wrote {args.json}")
    if m.trace_io and m.io_log:
        print("")
        print(f"file activity ({len(m.io_log)} operations):")
        for line in m.io_log:
            print("   " + line)

    if args.exec_map:
        hit = sorted(a for a in m.exec_map if a >= 0)
        Path(args.exec_map).write_text(chr(10).join(f"{a:x}" for a in hit))
        print(f"executed {len(hit):,} distinct addresses -> {args.exec_map}")
    if args.exec_map_json:
        data = exec_map_json(m, loaded, Path(args.binary).name)
        Path(args.exec_map_json).write_text(json.dumps(data), encoding="utf-8")
        changed = sum(row[4] for row in data["executed"])
        print(f"executed {len(data['executed']):,} distinct CS:IP"
              + (f", {changed:,} of them in bytes changed since they were loaded"
                 if changed else "") + f" -> {args.exec_map_json}")
    if args.summary_json:
        Path(args.summary_json).write_text(
            json.dumps(run_summary(m, args, why, keys, screen_lines), indent=2),
            encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
