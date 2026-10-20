#!/usr/bin/env python3
"""
emuverify.py -- Decide whether two functions are the same by running them.

Every other tool in this package *scores* a resemblance. This one tests an
equivalence: it executes both candidates on identical inputs under an 8086
emulator and compares what they actually did. A function that returns the same
values and writes the same bytes to the same places, over and over, on inputs
chosen to make it branch, is not merely similar.

That matters because resemblance saturates. Constants, strings, call-graph
position and control-flow shape between them reach about 0.88 precision on
Sopwith, and the remaining errors are pairs that genuinely look alike.
Behaviour distinguishes those.

What it is for
--------------
Carrying names from a binary you understand to one you do not: a rebuilt
binary to a shipped one, one release to the next, a DOS build to its Amiga
sibling. Emulation does not care that the compiler differed.

How a function is run
---------------------
  * The load image is mapped at segment 0x1000; DGROUP goes wherever the
    binary's own layout puts it, so global offsets line up between builds.
    A linker map names DGROUP. Without one it is the segment the program's
    startup loads into DS, found by running the startup; failing that, the
    lowest relocated segment, which is a code segment when far code sits
    below the data. Which one was used is said on stderr.
  * A function is found by its whole entry, segment and offset, through the
    verified load mapping. One outside the segment the image starts in runs
    at its own CS:IP, entered with a far return address when it ends in RETF.
    (A function in the first segment that ends in RETF is still entered as a
    near one, as before.) A linker map's symbols in segment 0000 are read as
    they always were; one in any other segment the map's segment table calls
    CODE goes through the same entry locator, and is far when its bytes up to
    the next code symbol hold RETF and no RET.
  * Small model, so SS == DS. Arguments are pushed right-to-left (cdecl) with
    a sentinel return address underneath; execution stops when it returns.
  * Calls are *not* followed. Each is skipped and given a deterministic stub
    return value, in call order. Two implementations of the same function make
    the same calls in the same order, so they see the same stubs -- and the
    callee's own behaviour stays out of the comparison.
  * Interrupts are skipped. Nothing here should reach real hardware.

What is compared
----------------
Return registers, the set of DGROUP writes (offset and value, stack frame
excluded), and the number of calls made -- across several input vectors. A
pair matches only if every vector agrees, and only if the function did
something observable: a routine that ignores its arguments and returns zero
matches every other such routine, so those are reported as indistinguishable
rather than as matches.

Either map may be a functions.json from the pipeline instead. It is checked
against the executable beside it on the command line and refused if it was
made from a different file, or if the handshake.json beside it says the
export drifted from its profile; --accept-profile-drift reads it anyway, and
says so (tools/evidence.py).

The report goes to stdout; --json writes the full result, matches, ambiguous
and uninformative functions included. --dgroup-a/--dgroup-b give the data
segment paragraph when it cannot be read from the map or the startup,
--limit profiles only the first N functions of each side, and --quiet drops
the progress lines on stderr.

Sweeps
------
`emuverify.py sweep` answers a different question: does a candidate -- a
rebuilt binary, a Python reference, a JavaScript port -- compute exactly what
one routine of the original computes, on every input of a domain? It runs the
original under this emulation case after case, compares, and prints the first
input where they disagree and how much of the routine the sweep exercised.
The four vectors above are not involved. tools/sweep.py has the domain, the
candidate contract and the output; knowledge/18-oracle-sweeps.md has worked
examples.

Usage:
    python emuverify.py a.exe a.map b.exe b.map
    python emuverify.py a.exe a.map b.exe b.map --json result.json --quiet
    python emuverify.py known.exe known.map target.exe out/functions.json
    python emuverify.py sweep GAME.EXE 1000:0049 --domain muldiv.json \\
           --candidate port.mjs:muldiv --functions out/functions.json
"""

import argparse
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402
import loadimage  # noqa: E402

try:
    from unicorn import (Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE,
                         UC_HOOK_INTR, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE,
                         UcError)
    from unicorn.x86_const import (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX,
                                   UC_X86_REG_DX, UC_X86_REG_SI, UC_X86_REG_DI,
                                   UC_X86_REG_BP, UC_X86_REG_SP, UC_X86_REG_IP,
                                   UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
                                   UC_X86_REG_SS, UC_X86_REG_FLAGS)
except ImportError:  # pragma: no cover
    print("emuverify: unicorn is required (pip install unicorn)", file=sys.stderr)
    raise

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
except ImportError:  # pragma: no cover
    print("emuverify: capstone is required (pip install capstone)", file=sys.stderr)
    raise

MEM_SIZE = 0x110000          # a little over 1 MB, so segment 0x1000 + 64K fits
IMAGE_SEG = 0x1000
IMAGE_BASE = IMAGE_SEG << 4
SENTINEL_IP = 0xFFF0         # return address that means "the function ended"
STACK_TOP = 0xFF00           # SP within DGROUP; small model puts SS == DS
FRAME_GUARD = 0xF000         # writes above this are stack frame, not globals
MAX_INSNS = 40000

# Input vectors, and there are deliberately only four.
#
# The obvious intuition -- more inputs means more discrimination means more
# matches -- is wrong here, and measurably so. Sweeping the count against
# Sopwith's two builds:
#
#     vectors    1    2    3    4    5    6    8   10   12
#     matches   93  107  110  110  110   98   97   97   97
#
# with zero incorrect matches throughout. One vector is genuinely too few:
# functions that ignore their arguments cannot be told apart, so they are
# filtered as uninformative. Past five it degrades, because the extra vectors
# were wilder -- values like 0x8000 and 0x5000 used as pointers -- and a wild
# access lands somewhere that depends on code generation. That breaks matches
# between two builds of the *same* function, which is exactly the thing we are
# trying not to do.
#
# So: keep arguments inside plausible data ranges. Zero and one separate
# functions branching on emptiness; 0xFFFF is -1 to signed code and a large
# bound to unsigned; the last vector points at modest DGROUP offsets so that
# pointer arguments dereference real globals.
VECTORS = [
    (0, 0, 0, 0),
    (1, 2, 3, 4),
    (0xFFFF, 1, 0, 7),
    (0x0100, 0x0200, 0x0300, 0x0400),
]


def load_image(exe_path):
    data = Path(exe_path).read_bytes()
    if data[:2] not in (b"MZ", b"ZM"):
        raise SystemExit(f"{exe_path}: not an MZ executable")
    hdr = struct.unpack_from("<H", data, 8)[0] * 16
    pages = struct.unpack_from("<H", data, 4)[0]
    last = struct.unpack_from("<H", data, 2)[0]
    end = (pages - 1) * 512 + (last if last else 512) if pages else len(data)
    return data[hdr:end]


def dgroup_paragraph(mapfile):
    """Paragraph of DGROUP, taken from any data symbol in the map."""
    import re
    pat = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4,8})\s+"
                     r"[A-Za-z_@$?][\w@$?.]*\s*$")
    for line in Path(mapfile).read_text(encoding="latin-1",
                                        errors="replace").splitlines():
        m = pat.match(line)
        if m:
            seg = int(m.group(1), 16)
            if seg != 0:
                return seg
    raise SystemExit(f"{mapfile}: no data segment found")


def code_symbols(mapfile):
    import re
    pat = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4,8})\s+"
                     r"([A-Za-z_@$?][\w@$?.]*)\s*$")
    out = {}
    for line in Path(mapfile).read_text(encoding="latin-1",
                                        errors="replace").splitlines():
        m = pat.match(line)
        if m and int(m.group(1), 16) == 0:
            name = m.group(3)
            out.setdefault(name, int(m.group(2), 16))
    return out


# A linker map's segment table, in the two formats this era's maps come in.
# Microsoft LINK gives linear start, stop and length, then name and class:
#     " 00130H 0013FH 00010H FAR_TEXT               CODE"
# Open Watcom's wlink gives name, class, group, segment:offset and size:
#     "_TEXT                  CODE           AUTO           0000:0000       0000b48c"
MS_SEGMENT = re.compile(r"^\s*([0-9A-Fa-f]{5})H\s+([0-9A-Fa-f]{5})H\s+([0-9A-Fa-f]{5})H"
                        r"\s+(\S+)\s+(\S+)\s*$")
WATCOM_SEGMENT = re.compile(r"^\s*(\S+)\s+(\S+)\s+(\S+)\s+([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4,8})"
                            r"\s+([0-9A-Fa-f]+)\s*$")
# And where each puts DGROUP: " 0014:0   DGROUP" under "Origin   Group"
# (Microsoft), "DGROUP                          0b49:0000            00001ab0"
# (Watcom).
MS_DGROUP = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]+)\s+DGROUP\s*$")
WATCOM_DGROUP = re.compile(r"^\s*DGROUP\s+([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4,8})\s+[0-9A-Fa-f]+\s*$")
MAP_SYMBOL = re.compile(r"^\s*([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4,8})\s+"
                        r"([A-Za-z_@$?][\w@$?.]*)\s*$")


def map_lines(mapfile):
    return Path(mapfile).read_text(encoding="latin-1", errors="replace").splitlines()


def map_layout(mapfile):
    """What a linker map says about the program's layout: its code segments,
    linear (start, end inclusive) from the start of the image, and DGROUP's
    paragraph when the map names it."""
    code, dgroup = [], None
    for line in map_lines(mapfile):
        m = MS_SEGMENT.match(line)
        if m and m.group(5).upper().endswith("CODE"):
            code.append((int(m.group(1), 16), int(m.group(2), 16)))
            continue
        m = WATCOM_SEGMENT.match(line)
        if m and m.group(2).upper().endswith("CODE"):
            start = (int(m.group(4), 16) << 4) + int(m.group(5), 16)
            code.append((start, start + max(int(m.group(6), 16), 1) - 1))
            continue
        m = MS_DGROUP.match(line) or WATCOM_DGROUP.match(line)
        if m and dgroup is None:
            dgroup = int(m.group(1), 16)
    return {"code": code, "dgroup": dgroup}


def in_code(layout, linear):
    return any(lo <= linear <= hi for lo, hi in layout["code"])


def dgroup_from_map(mapfile, layout):
    """(paragraph, how). The map's own DGROUP when it names one. Otherwise
    the first symbol outside segment 0000 that is not in a code segment, and
    failing that the old rule, dgroup_paragraph(): the first symbol outside
    segment 0000, which in a map with far code can be a far routine."""
    if layout["dgroup"] is not None:
        return layout["dgroup"], "the linker map's DGROUP"
    for line in map_lines(mapfile):
        m = MAP_SYMBOL.match(line)
        if m and int(m.group(1), 16) != 0 and \
                not in_code(layout, (int(m.group(1), 16) << 4) + int(m.group(2), 16)):
            return int(m.group(1), 16), "the segment of the map's first data symbol"
    return dgroup_paragraph(mapfile), "the segment of the map's first symbol outside 0000"


def returns_far(image, start, end):
    """RETF and never RET in image[start:end]: the rule the functions.json
    side applies to a function's mnemonics, here on the bytes a map's symbol
    has up to the next code symbol."""
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    seen = {i.mnemonic for i in md.disasm(bytes(image[start:end]), start)}
    return "retf" in seen and "ret" not in seen


def map_entries(mapfile, exe, image):
    """Every code symbol of a linker map, and the map's layout.

    Segment 0000 is read exactly as code_symbols() always has: {name: image
    offset}. That is all the code of a small-model program and a fraction of
    any other's: a far routine's symbol is in a segment of its own, and was
    dropped (tests/farcall: `_farfunc` at 0003:0000). A symbol outside 0000
    is code when the map's segment table puts it in a segment of class CODE.
    It goes through the same entry locator as functions.json
    (loadimage.locate_entries), by the linear rule -- a map's segments are
    the image's own paragraphs, and there is no load record to consult -- and
    becomes an Entry, entered far when its bytes up to the next code symbol
    hold RETF and no RET. A map without a segment table gives segment 0000
    only, as before."""
    out = code_symbols(mapfile)
    layout = map_layout(mapfile)
    if not layout["code"]:
        return out, layout
    others, starts = [], set()
    for line in map_lines(mapfile):
        m = MAP_SYMBOL.match(line)
        if not m:
            continue
        seg, off, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
        linear = (seg << 4) + off
        if seg == 0 or in_code(layout, linear):
            starts.add(linear)
        if seg != 0 and in_code(layout, linear) and name not in out \
                and all(name != n for n, _, _ in others):
            others.append((name, seg, off))
    if not others:
        return out, layout
    entries = [f"{(IMAGE_SEG + seg) & 0xFFFF:04x}:{off:04x}" for _, seg, off in others]
    where, _, load = loadimage.locate_entries(
        mapfile, {"functions": [{"entry": e} for e in entries],
                  "observed_profile": {"load_segment": f"0x{IMAGE_SEG:04x}"}}, exe, beside=False)
    for (name, seg, off), e in zip(others, entries):
        w = where[e]
        start = w["image_offset"]
        end = min([hi + 1 for lo, hi in layout["code"] if lo <= start <= hi]
                  + [s for s in starts if s > start])
        out[name] = Entry(IMAGE_SEG + w["segment"] - load, w["offset"],
                          returns_far(image, start, end))
    return out, layout


def relocated_segments(exe_path):
    """The segment words the loader patches: the value at every relocation
    target, as the file holds it (relative to the start of the image)."""
    data = Path(exe_path).read_bytes()
    hdr = struct.unpack_from("<H", data, 8)[0] * 16
    nreloc = struct.unpack_from("<H", data, 6)[0]
    table = struct.unpack_from("<H", data, 24)[0]
    values = []
    for i in range(nreloc):
        off, seg = struct.unpack_from("<HH", data, table + i * 4)
        pos = hdr + (seg << 4) + off
        if pos + 2 <= len(data):
            values.append(struct.unpack_from("<H", data, pos)[0])
    return values


def dgroup_from_relocations(exe_path):
    """Recover the data segment from the MZ relocation table.

    A binary with no linker map still tells you where DGROUP is: in a
    small-model program the startup loads it from a relocated word, so the
    relocation targets hold the segment values the loader patches in. The
    lower of them is DGROUP; the higher is the stack.
    """
    values = relocated_segments(exe_path)
    if not values:
        raise SystemExit(f"{exe_path}: no relocations, cannot locate DGROUP")
    return min(values)


STARTUP_BUDGET = 100_000    # instructions of startup to run looking for DS


def dgroup_from_startup(exe_path, budget=STARTUP_BUDGET):
    """The data segment the program's own startup loads into DS.

    The lowest relocated segment is DGROUP only when nothing relocated sits
    below the data. Far code placed before it is relocated too -- every far
    call's segment word is -- and then the guess is a code segment
    (tests/farcall: the far segment, 0x0003, where DGROUP is 0x0005). The
    startup is not guessing: it loads DGROUP into DS before C code runs. So
    run it, under comrun.py's loader (relocations, PSP, enough DOS to get
    through a C runtime's version check), and take the first value DS takes
    that the loader relocated: one of the relocated segment words, or the
    header's SS.

    That condition is what keeps a packed file from answering. EXEPACK's
    decompressor sets DS to its own code segment within five instructions
    (adventur.exe: 0x0f77), and nothing relocated it, so it is passed over.
    Returns (paragraph, (segment, offset) of the instruction that loaded it,
    relative to the image), or None.
    """
    import comrun   # here, so the comparison itself does not depend on it
    from unicorn.x86_const import UC_X86_REG_DS as DS, UC_X86_REG_CS as CS
    try:
        data = Path(exe_path).read_bytes()
        machine = comrun.Machine(data)
    except Exception:   # noqa: BLE001 -- any failure to load means no answer
        return None
    if machine.mz is None:
        return None
    load = comrun.SEG + (comrun.LOAD >> 4)
    accepted = set(relocated_segments(exe_path)) | {machine.mz["ss"]}
    seen = {"ds": machine.uc.reg_read(DS), "at": None, "found": None}

    def watch(uc, address, size, _):
        ds = uc.reg_read(DS)
        if ds != seen["ds"] and (ds - load) & 0xFFFF in accepted:
            seen["found"] = ((ds - load) & 0xFFFF, seen["at"])
            machine.stopped = "DS loaded"
            uc.emu_stop()
        seen["ds"] = ds
        cs = uc.reg_read(CS)
        seen["at"] = ((cs - load) & 0xFFFF, address - (cs << 4))

    machine.uc.hook_add(comrun.UC_HOOK_CODE, watch)
    try:
        machine.run(budget=budget)
    except Exception:   # noqa: BLE001
        return None
    return seen["found"]


def locate_dgroup(exe_path):
    """DGROUP for a binary read without a linker map: (paragraph, how it was
    found, where -- segment:offset at segment 0x1000 -- or None).

    The startup's DS first; the lowest relocated segment when the startup
    does not load a relocated one within STARTUP_BUDGET instructions. Raises
    SystemExit, as before, when there is neither."""
    found = dgroup_from_startup(exe_path)
    if found is not None:
        paragraph, (seg, off) = found
        return (paragraph, "the segment the startup loads into DS",
                f"{(IMAGE_SEG + seg) & 0xFFFF:04x}:{off:04x}")
    return (dgroup_from_relocations(exe_path),
            "the lowest relocated segment; the startup loaded no relocated segment into DS "
            f"within {STARTUP_BUDGET:,} instructions", None)


def say_dgroup(exe_path, paragraph, how, where):
    print(f"emuverify.py: {Path(exe_path).name}: DGROUP 0x{paragraph:04x}, {how}"
          + (f" (at {where})" if where else ""), file=sys.stderr)


class Entry:
    """A function outside the segment the image starts in: where to run it.

    `segment` is CS as the emulator maps the image (at IMAGE_SEG), `offset`
    is IP, and `far` says it returns with RETF, so it is entered with a far
    return address and finds its arguments past CS as well as IP."""

    def __init__(self, segment, offset, far):
        self.segment, self.offset, self.far = segment, offset, far

    def __repr__(self):
        return f"Entry({self.segment:04x}:{self.offset:04x}{', far' if self.far else ''})"


def entries_from_functions_json(path, exe=None, accept_drift=False):
    """Function locations from the pipeline's export, for a binary with no map.

    Names are the Ghidra placeholders, so a match here transfers a name *to*
    this binary rather than confirming one it already has. Given `exe`, the
    export is refused if it was made from a different file: offsets from one
    build run against another are profiles of the wrong code.

    An entry is a whole segment:offset, put through the verified load mapping
    (loadimage.locate_entries). A function in the segment the image starts in
    is an offset into the image, run as it always was. One in another segment
    is an Entry, run at its own segment:offset -- reading the offset alone ran
    the code at that offset in the first segment instead (measured on four of
    five real programs; adventur's 1f77:0010 profiled whatever is at 1000:0010).
    """
    data = evidence.load_functions(path, exe, "emuverify.py", accept_drift)
    where, how, load = loadimage.locate_entries(path, data, exe or (data.get("target") or {}).get("path"))
    if how != "verified" and any(w["segment"] != load for w in where.values()):
        print(f"emuverify.py: note: no verified loadimage.json beside {path}; entries "
              f"outside segment 0x{load:04x} were placed by segment * 16 + offset",
              file=sys.stderr)
    out = {}
    for f in data["functions"]:
        if f.get("thunk") or f["entry"] not in where:
            continue
        w = where[f["entry"]]
        if w["segment"] == load:
            out.setdefault(f["entry"], w["image_offset"])
        else:
            mnemonics = set(f.get("mnemonics") or [])
            far = "RETF" in mnemonics and "RET" not in mnemonics
            out.setdefault(f["entry"], Entry(IMAGE_SEG + w["segment"] - load, w["offset"], far))
    return out


class Emulator:
    def __init__(self, exe, symbols_source, dgroup=None, accept_drift=False):
        self.image = load_image(exe)
        if str(symbols_source).lower().endswith(".json"):
            self.symbols = entries_from_functions_json(symbols_source, exe,
                                                       accept_drift)
            if dgroup is not None:
                self.dgroup = dgroup
            else:
                self.dgroup, how, where = locate_dgroup(exe)
                say_dgroup(exe, self.dgroup, how, where)
        else:
            self.symbols, layout = map_entries(symbols_source, exe, self.image)
            if dgroup is not None:
                self.dgroup = dgroup
            else:
                self.dgroup, how = dgroup_from_map(symbols_source, layout)
                say_dgroup(exe, self.dgroup, how, None)
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)

    def run(self, offset, args, max_insns=MAX_INSNS):
        """Execute one function. Returns an observation dict, or None if it
        could not be run to completion.

        `offset` is an offset into the image, for a function in the segment
        the image starts in, run as this always has; or an Entry, for one in
        another segment. An Entry runs at its own CS:IP. Its return cannot be
        caught at the sentinel -- a near return lands at CS:SENTINEL_IP in
        its own segment -- so it is caught as it happens instead: the first
        return taken with SP back at the return address pushed for it."""
        entry = offset if isinstance(offset, Entry) else None
        cs = entry.segment if entry else IMAGE_SEG
        ip = entry.offset if entry else offset
        uc = Uc(UC_ARCH_X86, UC_MODE_16)
        uc.mem_map(0, MEM_SIZE)
        uc.mem_write(IMAGE_BASE, bytes(self.image))
        uc.mem_write(IMAGE_BASE + SENTINEL_IP, b"\xF4")     # HLT at the sentinel

        ds = self.dgroup + IMAGE_SEG
        uc.reg_write(UC_X86_REG_CS, cs)
        uc.reg_write(UC_X86_REG_DS, ds)
        uc.reg_write(UC_X86_REG_ES, ds)
        uc.reg_write(UC_X86_REG_SS, ds)                     # small model
        uc.reg_write(UC_X86_REG_BP, 0)
        uc.reg_write(UC_X86_REG_FLAGS, 0x0202)

        dbase = ds << 4
        sp = STACK_TOP
        for value in reversed(args):                        # cdecl, right to left
            sp -= 2
            uc.mem_write(dbase + sp, struct.pack("<H", value & 0xFFFF))
        if entry and entry.far:
            sp -= 2                                         # a far call pushes CS too
            uc.mem_write(dbase + sp, struct.pack("<H", IMAGE_SEG))
        sp -= 2
        uc.mem_write(dbase + sp, struct.pack("<H", SENTINEL_IP))
        uc.reg_write(UC_X86_REG_SP, sp)
        return_sp = sp

        # "budget" and "aborted" are different outcomes and must not be
        # conflated: running out of instructions is what a non-returning
        # function does and still yields usable evidence, while a CPU fault
        # means the run was meaningless.
        state = {"calls": 0, "writes": set(), "reads": set(), "insns": 0,
                 "done": False, "aborted": None, "budget": False}

        def on_code(mu, address, size, _):
            state["insns"] += 1
            if state["insns"] > max_insns:
                state["budget"] = True
                mu.emu_stop()
                return
            if entry:
                ip = address - (mu.reg_read(UC_X86_REG_CS) << 4)
            else:
                ip = address - IMAGE_BASE
            try:
                code = mu.mem_read(address, min(15, size + 14))
            except UcError:
                return
            insn = next(self.md.disasm(bytes(code), address), None)
            if insn is None:
                return
            if entry and insn.mnemonic.startswith("ret") \
                    and mu.reg_read(UC_X86_REG_SP) == return_sp:
                state["returned"] = True
                mu.emu_stop()
                return
            if insn.mnemonic.startswith("call"):
                # Skip the call. Both implementations of a function make the
                # same calls in the same order, so a counter-derived stub
                # return keeps them comparable without executing the callee.
                state["calls"] += 1
                mu.reg_write(UC_X86_REG_AX, (0x1234 + state["calls"] * 7) & 0xFFFF)
                mu.reg_write(UC_X86_REG_IP, (ip + insn.size) & 0xFFFF)

        def on_intr(mu, intno, _):
            pass                                            # never reach hardware

        def on_write(mu, access, address, size, value, _):
            off = address - dbase
            if 0 <= off < FRAME_GUARD:                      # a global, not the frame
                state["writes"].add((off, size, value & 0xFFFF))

        def on_read(mu, access, address, size, value, _):
            # Which globals a function *reads* is nearly as identifying as
            # what it writes, and it rescues the large class of routines that
            # only inspect state. Without this, 80 of 173 functions were
            # behaviourally indistinguishable; with it, far fewer.
            off = address - dbase
            if 0 <= off < FRAME_GUARD:
                state["reads"].add((off, size))

        uc.hook_add(UC_HOOK_CODE, on_code)
        uc.hook_add(UC_HOOK_INTR, on_intr)
        uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
        uc.hook_add(UC_HOOK_MEM_READ, on_read)

        try:
            uc.emu_start((cs << 4) + ip, IMAGE_BASE + SENTINEL_IP,
                         timeout=2_000_000, count=0)
        except UcError as e:
            state["aborted"] = str(e)

        # emu_start stops *before* executing the `until` address, so the code
        # hook never fires there. Completion has to be read from IP afterwards.
        if entry:
            state["done"] = state.get("returned", False)
        elif (uc.reg_read(UC_X86_REG_IP) & 0xFFFF) == SENTINEL_IP:
            state["done"] = True

        if not state["done"] and not state["budget"]:
            return None                 # a fault, not a long-running function

        if not state["done"]:
            # The function never returned: an interrupt handler, a longjmp
            # target, or a main loop. Those are exactly the functions worth
            # identifying, so rather than discard them, compare what they
            # touched within the budget.
            #
            # Only the *set* of global offsets is kept -- no values, no counts,
            # no registers. Two builds of one function run a different number
            # of loop iterations in the same instruction budget, so anything
            # count-dependent would differ for reasons that say nothing about
            # what the function is.
            return {
                "partial": True,
                "ax": None, "dx": None, "calls": None,
                "writes": tuple(sorted({off for off, _, _ in state["writes"]})),
                "reads": tuple(sorted({off for off, _ in state["reads"]})),
            }

        return {
            "partial": False,
            "ax": uc.reg_read(UC_X86_REG_AX),
            "dx": uc.reg_read(UC_X86_REG_DX),
            "calls": state["calls"],
            "writes": tuple(sorted(state["writes"])),
            "reads": tuple(sorted(state["reads"])),
        }

    def profile(self, offset):
        """Observations across every input vector, or None if unrunnable."""
        obs = []
        for vec in VECTORS:
            r = self.run(offset, vec)
            if r is None:
                return None
            obs.append(r)
        return obs


MIN_PARTIAL_TOUCHES = 4     # a partial profile below this identifies nothing


def is_partial(obs):
    return any(o.get("partial") for o in obs)


def signature(obs):
    return tuple((o["ax"], o["dx"], o["calls"], o["writes"], o["reads"])
                 for o in obs)


def informative(obs):
    """True when the function did something an observer could distinguish.

    A routine that ignores its arguments, touches no globals and returns a
    constant is behaviourally identical to every other such routine. Calling
    those a match would be arithmetic, not evidence.
    """
    if is_partial(obs):
        # A non-returning function has no return value to compare, so the only
        # evidence is which globals it touched. Demand enough of them that the
        # set means something.
        touched = set()
        for o in obs:
            touched.update(o["writes"])
            touched.update(o["reads"])
        return len(touched) >= MIN_PARTIAL_TOUCHES
    if any(o["writes"] or o["reads"] for o in obs):
        return True
    outputs = {(o["ax"], o["dx"], o["calls"]) for o in obs}
    return len(outputs) > 1


def compare(a_emu, b_emu, a_offsets, b_offsets, progress=None):
    a_prof, b_prof = {}, {}
    for label, emu, offsets, store in (("A", a_emu, a_offsets, a_prof),
                                       ("B", b_emu, b_offsets, b_prof)):
        for i, (name, off) in enumerate(offsets.items()):
            if progress and i % 25 == 0:
                progress(f"profiling {label} {i}/{len(offsets)}")
            obs = emu.profile(off)
            if obs is not None:
                store[name] = obs

    index = {}
    for name, obs in b_prof.items():
        if informative(obs):
            index.setdefault(signature(obs), []).append(name)

    matches, ambiguous, uninformative, partial_matches = [], [], [], []
    for name, obs in a_prof.items():
        if not informative(obs):
            uninformative.append(name)
            continue
        hits = index.get(signature(obs), [])
        if len(hits) == 1:
            matches.append((name, hits[0]))
            if is_partial(obs):
                partial_matches.append(name)
        elif len(hits) > 1:
            ambiguous.append((name, hits))
    return {
        "profiled_a": len(a_prof), "profiled_b": len(b_prof),
        "matches": matches, "ambiguous": ambiguous,
        "uninformative": uninformative,
        # A partial profile compares only which globals were touched, because
        # the function never returned. Reported separately: it is weaker
        # evidence than a completed run, even when it is exact.
        "partial_matches": partial_matches,
    }


def main():
    # `sweep` is a subcommand; everything else is the comparison, whose
    # command line is unchanged: four positional arguments.
    if len(sys.argv) > 1 and sys.argv[1] == "sweep":
        import sweep
        return sweep.main(sys.argv[2:])
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe_a")
    ap.add_argument("map_a", help="linker map, or a functions.json from the pipeline")
    ap.add_argument("exe_b")
    ap.add_argument("map_b", help="linker map, or a functions.json from the pipeline")
    ap.add_argument("--dgroup-a", help="data segment paragraph for A, if known")
    ap.add_argument("--dgroup-b", help="data segment paragraph for B, if known")
    ap.add_argument("--limit", type=int, help="only the first N functions of each")
    ap.add_argument("--json", help="write results here")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--accept-profile-drift", action="store_true",
                    help="read functions.json although the handshake.json beside it "
                         "says it drifted; announced on stderr")
    args = ap.parse_args()

    a = Emulator(args.exe_a, args.map_a,
                 int(args.dgroup_a, 0) if args.dgroup_a else None,
                 args.accept_profile_drift)
    b = Emulator(args.exe_b, args.map_b,
                 int(args.dgroup_b, 0) if args.dgroup_b else None,
                 args.accept_profile_drift)

    a_offsets = dict(list(a.symbols.items())[:args.limit] if args.limit
                     else a.symbols.items())
    b_offsets = dict(list(b.symbols.items())[:args.limit] if args.limit
                     else b.symbols.items())

    def progress(msg):
        if not args.quiet:
            print(f"  {msg}", file=sys.stderr)

    res = compare(a, b, a_offsets, b_offsets, progress)

    print(f"functions profiled : {res['profiled_a']} in A, {res['profiled_b']} in B")
    print(f"unique matches     : {len(res['matches'])}"
          + (f" ({len(res['partial_matches'])} from non-returning functions)"
             if res.get("partial_matches") else ""))
    print(f"ambiguous          : {len(res['ambiguous'])}")
    print(f"uninformative      : {len(res['uninformative'])}")

    # When both sides carry real symbol names, agreement is checkable. When one
    # side is a functions.json its "names" are Ghidra placeholders, so the
    # comparison is meaningless and reporting a precision would be a fiction.
    checkable = not (str(args.map_a).lower().endswith(".json")
                     or str(args.map_b).lower().endswith(".json"))
    if res["matches"] and checkable:
        correct = sum(1 for x, y in res["matches"] if x == y)
        wrong = len(res["matches"]) - correct
        print(f"\nboth maps carry names, so the answer is checkable:")
        print(f"  correct   : {correct}")
        print(f"  incorrect : {wrong}")
        print(f"  precision : {correct / max(1, len(res['matches'])):.3f}")
        if wrong:
            print("\n  mismatches:")
            for x, y in res["matches"]:
                if x != y:
                    print(f"    {x} -> {y}")
    elif res["matches"]:
        print("\nnames carried across (first 20):")
        for x, y in res["matches"][:20]:
            print(f"  {x:<22} -> {y}")

    if args.json:
        Path(args.json).write_text(json.dumps(res, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
