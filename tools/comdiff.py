#!/usr/bin/env python3
"""
comdiff.py -- Compare two .COM programs routine by routine.

Why this exists
---------------
bindiff.py compares two builds against a linker map and emuverify.py runs
the functions of two MZ executables; both refuse a .COM, which has neither a
header nor a map. Moon Bugs (Windmill Software, 1983) shares its keyboard
handler, its RLE decompressor and its reboot routine with Rollo, from the
same company and year, and the agent naming it had to write its own script
to find that out. Every Windmill game will ask the same question, so the
toolkit answers it.

What it reads
-------------
Each program is the .COM and the listing comrec.py wrote for it. The listing
is assembled with NASM first and refused unless the result is the .COM byte
for byte: a listing made from another file, or edited since, compares the
wrong code. From the listing come its labels -- every address comrec found
code at -- and the targets of its calls. comrec's own walk is then run from
those labels over the .COM, which reproduces the instructions the listing
holds, pinned ones included (a pinned instruction is written as `db` but is
still an instruction), and that is checked against the listing's own
instruction lines.

What a routine is
-----------------
A routine starts at the program's entry, at a call target, or at an address
comrec decoded code from although nothing in the listing branches there -- an
interrupt handler installed by writing the vector table, a callback, a
dispatch target. The targets of a jump table read by `jmp word [...]` are the
cases of the routine that jumps, not routines. A routine runs to the end of
the last instruction before the next routine starts; data between its
instructions (a string after a call, a table) is part of its bytes.

So one routine reached only by a jump from another is part of the routine
before it, on both sides alike. Units defined from labels instead -- every
label a routine -- cut one routine into its branch targets, and a match
between two fragments of a loop says little about the routines they sit in.

How a pair is classified
------------------------
For each routine of the second program (the one being studied), the first is
searched for a counterpart, and the best kind found is the answer:

  byte-identical          the same bytes, data between the instructions too
  instruction-identical   the same instructions in the same order, where only
                          numbers may differ: immediates, absolute addresses
                          and displacements, the targets of calls and jumps
                          that leave the routine. A branch inside the routine
                          must land on the same instruction. A displacement
                          off BP is a stack frame slot and must agree.
  similar                 the best resemblance score (difflib's ratio over
                          the instruction sequences, numbers abstracted) at or
                          above --similar
  no counterpart          nothing reaches the threshold

Routines shorter than --min-bytes (12) are listed as too small and not
classified: a 3-byte `mov al, 1 / ret` matches dozens of others and means
nothing. Several counterparts of the same kind are all listed.

An instruction-identical pair also lists the numbers that differ, as pairs.
The memory ones map a global of one program onto its counterpart in the
other, which is how a name carries across.

Confirmed by emulation
----------------------
An instruction-identical pair is a claim that two routines compute the same
thing with different addresses. Where unicorn is available each such pair is
run, as emuverify.py runs MZ functions: both routines alone, from identical
registers, four vectors, calls skipped with the same stub return, interrupts
recorded and skipped, a budget of instructions. Two things are different
here, because the programs are different:

  * Memory is not the program's. Each byte is given a value the first time
    the routine touches it, chosen by the order of first touches, so the
    routine that reads [0x13c7] first in one program and [0x1ebd] first in the
    other reads the same value from both. What is compared is that renaming:
    the n-th address touched must be touched in the same way on both sides.
  * A value may differ by one of the differences between the pair's numbers
    and still agree, because an address loaded into a register and stepped
    through a table differs by exactly that much.

The result is confirmed (every vector agrees), differs (with the first
difference), or not run (a fault, or a segment the harness cannot place).
Byte-identical pairs are not run: the same bytes are the same instructions.

What it does not do
-------------------
It does not follow a routine into its callees, so two routines that call
different code are confirmed on their own instructions only. It takes .COM
files; an MZ goes to bindiff.py or emuverify.py. It reports resemblance as a
score and never as a match: only the two identical kinds are claims.

Usage:
    python comdiff.py A.COM A.asm B.COM B.asm
    python comdiff.py ROLLO.COM rollo.asm MOONBUGS.COM moonbugs.asm --json diff.json
    python comdiff.py A.COM A.asm B.COM B.asm --evidence diff-envelope.json
"""

import argparse
import difflib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import comrec  # noqa: E402  (its walk, its segments, its NASM lookup)
import evidence  # noqa: E402

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
except ImportError:  # pragma: no cover
    print("comdiff: capstone is required (pip install capstone)", file=sys.stderr)
    raise

MIN_BYTES = 12            # Kimi's floor in compare-with-rollo.py, kept so the
                          # counts can be set side by side
SIMILAR = 0.85            # and its threshold for "partial"

LABEL = re.compile(r"^L_([0-9A-Fa-f]{5}):", re.M)
SEGMENT = re.compile(r"^; ---- file 0x([0-9A-Fa-f]+), addresses relative to "
                     r"0x([0-9A-Fa-f]+) ----", re.M)
BRANCH_REF = re.compile(r"^\s+(\w+)\s+(?:strict (?:near|short) )?L_([0-9A-Fa-f]{5})\b",
                        re.M)


class Refused(Exception):
    """A precondition the comparison cannot do without; the message says
    what to do next."""


# ---------------------------------------------------------------- reading

def _assemble(asm, nasm):
    """The listing's bytes and {source line: file offset}, from NASM itself."""
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "out.bin"
        lst = Path(td) / "out.lst"
        try:
            r = subprocess.run([nasm, "-f", "bin", "-o", str(out), "-l", str(lst), str(asm)],
                               capture_output=True, text=True, timeout=comrec.NASM_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise Refused(f"nasm did not finish assembling {asm} in "
                          f"{comrec.NASM_TIMEOUT} s")
        if r.returncode != 0:
            raise Refused(f"{asm} does not assemble: {r.stderr.strip()[:300]}\n"
                          f"  regenerate it with comrec.py")
        offsets = {}
        for raw in lst.read_text(encoding="latin-1", errors="replace").splitlines():
            m = re.match(r"\s*(\d+)\s+([0-9A-F]{8})\s+[0-9A-F]", raw)
            if m:
                offsets.setdefault(int(m.group(1)) - 1, int(m.group(2), 16))
        return out.read_bytes(), offsets


class Program:
    """One .COM, the listing comrec wrote for it, and its routines."""

    def __init__(self, com, asm, nasm=None):
        self.com, self.asm = Path(com), Path(asm)
        self.image = self.com.read_bytes()
        if self.image[:2] in (b"MZ", b"ZM"):
            raise Refused(f"{self.com} is an MZ executable; comdiff takes .COM files. "
                          f"Two builds of an MZ go to bindiff.py or emuverify.py")
        text = self.asm.read_text(encoding="latin-1")
        built, line_offsets = _assemble(self.asm, comrec.find_nasm(nasm))
        difference = comrec.compare_files(self.image, built)
        if difference is not None:
            raise Refused(f"{self.asm} does not rebuild {self.com}: {difference[1]}.\n"
                          f"  A listing of another file, or one edited since, compares the "
                          f"wrong code. Regenerate it: python tools/comrec.py {self.com} "
                          f"--out {self.asm}")

        specs = [f"0x{int(f, 16):X}:0x{int(b, 16):X}" for f, b in SEGMENT.findall(text)]
        # A listing for a plain .COM names one segment, file 0 at 0x100, which
        # is also what parse_segments assumes when it is given none.
        self.segments = comrec.parse_segments(
            [] if specs == ["0x0:0x100"] else specs, len(self.image))
        self.labels = {int(x, 16) for x in LABEL.findall(text)}
        branched, self.calls = set(), set()
        for mnemonic, target in BRANCH_REF.findall(text):
            if mnemonic in comrec.BRANCH:
                branched.add(int(target, 16))
                if mnemonic == "call":
                    self.calls.add(int(target, 16))

        walk = comrec.Reconstructor(str(self.com), self.segments, sorted(self.labels))
        walk.disassemble()
        self.decoded = {off: size for off, (size, _, _) in walk.decoded.items()}
        self._check_walk(text, line_offsets)
        # Cases, not routines: the targets of `jmp word [cs:reg + table]`. A
        # table read by `call word [...]` holds routines, and they stay starts.
        self.cases = set()
        for base, targets in walk.detect_jump_tables():
            if walk.table_dispatch.get(base) == "jmp":
                self.cases.update(targets)

        self.starts = {"entry": [], "call target": [], "nothing branches here": []}
        entry = 0 if 0 in self.decoded else None
        for off in sorted(self.labels & set(self.decoded)):
            if off == entry:
                self.starts["entry"].append(off)
            elif off in self.calls:
                self.starts["call target"].append(off)
            elif off not in branched and off not in self.cases:
                self.starts["nothing branches here"].append(off)
        self.routines = self._routines(sorted(o for v in self.starts.values() for o in v))
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)
        self.md.detail = True

    def _check_walk(self, text, line_offsets):
        """Every instruction line of the listing is an instruction of the walk.

        The walk runs from the listing's labels, so it reaches what comrec
        reached; this is the check that it did, rather than an assumption."""
        missing = []
        for i, line in enumerate(text.split("\n")):
            s = line.strip()
            if not s or s.startswith((";", "db ", "BITS", "ORG", "L_")) or s.endswith(":"):
                continue
            off = line_offsets.get(i)
            if off is not None and off not in self.decoded:
                missing.append((i + 1, off))
        if missing:
            line, off = missing[0]
            raise Refused(f"{self.asm}: {len(missing)} instruction lines are not where "
                          f"comrec's walk from the listing's labels puts instructions "
                          f"(first: line {line}, file 0x{off:05X}). The listing does not "
                          f"read as comrec's; regenerate it with comrec.py")

    def _routines(self, starts):
        out = []
        code = sorted(self.decoded)
        for i, start in enumerate(starts):
            nxt = starts[i + 1] if i + 1 < len(starts) else len(self.image)
            insns = [(o, self.decoded[o]) for o in code if start <= o < nxt]
            if not insns:
                continue
            end = max(o + s for o, s in insns)
            covered = set()
            for o, s in insns:
                covered.update(range(o, o + s))
            out.append({"start": start, "end": end, "insns": insns,
                        "data_bytes": sum(1 for b in range(start, end) if b not in covered)})
        return out

    def segment(self, off):
        return next(s for s in self.segments if s.file_start <= off < s.file_end)

    def instructions(self, routine):
        """Capstone's reading of each instruction, at its own address. The
        walk decoded exactly these bytes, so each one decodes again."""
        seg = self.segment(routine["start"])
        return [(off, next(self.md.disasm(self.image[off:off + size], seg.addr(off))))
                for off, size in routine["insns"]]


# ---------------------------------------------------------------- comparing

def shape(program, routine):
    """(exact form, fuzzy form, numbers) of every instruction in a routine.

    The exact form keeps where a branch inside the routine lands, as the
    index of the instruction there; the fuzzy one, used for the score, does
    not, so one inserted instruction does not make every later branch
    disagree. `numbers` holds, per instruction, the values the form left out,
    in order, so that two routines of the same shape can be paired value by
    value."""
    seg = program.segment(routine["start"])
    insns = program.instructions(routine)
    index = {off: i for i, (off, _) in enumerate(insns)}
    exact, fuzzy, numbers = [], [], []
    for off, insn in insns:
        ops_exact, ops_fuzzy, nums = [], [], []
        relative = insn.mnemonic in comrec.BRANCH and len(insn.operands) == 1
        for op in insn.operands:
            if op.type == X86_OP_REG:
                form = ("r", insn.reg_name(op.reg))
                ops_exact.append(form)
                ops_fuzzy.append(form)
            elif op.type == X86_OP_IMM and relative:
                addr = op.imm & 0xFFFFFFFF
                if addr > 0xFFFF:              # capstone sign-extends a wrapped target
                    addr = seg.base + ((addr - seg.base) & 0xFFFF)
                target = seg.file_off(addr) if seg.contains_addr(addr) else None
                if target is not None and routine["start"] <= target < routine["end"]:
                    at = index.get(target)
                    ops_exact.append(("to", at if at is not None else
                                      ("byte", target - routine["start"])))
                    ops_fuzzy.append(("to",))
                else:
                    ops_exact.append(("out",))
                    ops_fuzzy.append(("out",))
                    nums.append(("target", addr))
            elif op.type == X86_OP_IMM:
                ops_exact.append(("imm", op.size))
                ops_fuzzy.append(("imm", op.size))
                nums.append(("immediate", op.imm & 0xFFFF))
            elif op.type == X86_OP_MEM:
                m = op.mem
                seg_reg = insn.reg_name(m.segment) if m.segment else None
                base = insn.reg_name(m.base) if m.base else None
                idx = insn.reg_name(m.index) if m.index else None
                if base == "bp":
                    # [bp + 4] is an argument and [bp + 6] another one; that is
                    # not a relocated address, so it has to agree.
                    form = ("m", op.size, seg_reg, base, idx, m.disp)
                else:
                    form = ("m", op.size, seg_reg, base, idx)
                    nums.append(("address" if base is None and idx is None
                                 else "displacement", m.disp & 0xFFFF))
                ops_exact.append(form)
                ops_fuzzy.append(form)
        exact.append((insn.mnemonic, tuple(ops_exact)))
        fuzzy.append((insn.mnemonic, tuple(ops_fuzzy)))
        numbers.append(tuple(nums))
    return tuple(exact), tuple(fuzzy), numbers


def differing_numbers(nums_a, nums_b):
    """The (kind, a, b) pairs where two same-shaped routines' numbers differ."""
    out = []
    for xs, ys in zip(nums_a, nums_b):
        for (kind, a), (_, b) in zip(xs, ys):
            if a != b and (kind, a, b) not in out:
                out.append((kind, a, b))
    return out


def classify(a, b, min_bytes=MIN_BYTES, similar=SIMILAR):
    """Every routine of `b`, with its best counterpart in `a`."""
    a_shapes = {r["start"]: shape(a, r) for r in a.routines}
    by_bytes, by_exact = {}, {}
    for r in a.routines:
        if r["end"] - r["start"] < min_bytes:
            continue
        by_bytes.setdefault(a.image[r["start"]:r["end"]], []).append(r)
        by_exact.setdefault(a_shapes[r["start"]][0], []).append(r)
    candidates = [r for r in a.routines if r["end"] - r["start"] >= min_bytes]

    rows = []
    for r in b.routines:
        size = r["end"] - r["start"]
        row = {"b": r["start"], "b_end": r["end"], "bytes": size,
               "instructions": len(r["insns"]), "data_bytes": r["data_bytes"]}
        if size < min_bytes:
            row["status"] = "too small"
            rows.append(row)
            continue
        exact, fuzzy, nums = shape(b, r)
        same_bytes = by_bytes.get(b.image[r["start"]:r["end"]])
        same_insns = by_exact.get(exact)
        if same_bytes:
            row.update(status="byte-identical", a=[x["start"] for x in same_bytes], score=1.0)
        elif same_insns:
            row.update(status="instruction-identical", a=[x["start"] for x in same_insns],
                       score=1.0)
            first = same_insns[0]
            row["numbers"] = differing_numbers(a_shapes[first["start"]][2], nums)
            dr = [x for x in range(r["start"], r["end"])
                  if not any(o <= x < o + s for o, s in r["insns"])]
            da = [x for x in range(first["start"], first["end"])
                  if not any(o <= x < o + s for o, s in first["insns"])]
            row["data_same"] = bytes(b.image[x] for x in dr) == bytes(a.image[x] for x in da)
        else:
            # The true best, not only the best above the threshold: a routine
            # with no counterpart says how near the nearest one came. The two
            # bounds below never exceed the ratio, so skipping on them cannot
            # lose it.
            best, best_at = 0.0, []
            for c in candidates:
                other = a_shapes[c["start"]][1]
                ceiling = 2.0 * min(len(other), len(fuzzy)) / (len(other) + len(fuzzy))
                if ceiling < best:
                    continue
                m = difflib.SequenceMatcher(None, other, fuzzy, autojunk=False)
                if m.quick_ratio() < best:
                    continue
                score = m.ratio()
                if score > best:
                    best, best_at = score, [c["start"]]
                elif score == best and score > 0:
                    best_at.append(c["start"])
            if best >= similar:
                row.update(status="similar", a=best_at, score=round(best, 3))
            else:
                row.update(status="no counterpart", best_score=round(best, 3),
                           nearest=best_at)
        rows.append(row)
    return rows


# ---------------------------------------------------------------- emulation

try:
    from unicorn import (Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INTR,
                         UC_HOOK_INSN, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UcError)
    from unicorn.x86_const import (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX,
                                   UC_X86_REG_DX, UC_X86_REG_SI, UC_X86_REG_DI,
                                   UC_X86_REG_BP, UC_X86_REG_SP, UC_X86_REG_IP,
                                   UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
                                   UC_X86_REG_SS, UC_X86_REG_FLAGS,
                                   UC_X86_INS_IN, UC_X86_INS_OUT)
    HAVE_UNICORN = True
except ImportError:  # pragma: no cover -- the comparison works without it
    HAVE_UNICORN = False

LOAD_SEG = 0x1000          # the .COM's PSP, as comrun and emuverify place it
DATA_SEG = 0x5000          # DS and ES: away from the code, so a write cannot
STACK_SEG = 0x7000         # land on an instruction the routine is running
STACK_TOP = 0xFF00
SENTINEL = 0xFFF0          # the return address that means "it returned"
BUDGET = 50_000            # emuverify's MAX_INSNS
FLAGS_COMPARED = 0x08C1    # CF, ZF, SF, OF: what a routine returns a status in
REGS = (("ax", "UC_X86_REG_AX"), ("bx", "UC_X86_REG_BX"), ("cx", "UC_X86_REG_CX"),
        ("dx", "UC_X86_REG_DX"), ("si", "UC_X86_REG_SI"), ("di", "UC_X86_REG_DI"),
        ("bp", "UC_X86_REG_BP"))

# Hand-written routines take their arguments in registers, not on a stack, so
# a vector sets all seven. emuverify's reasoning holds for the values: zero
# and one make code branch on emptiness, 0xFFFF is -1 and a large bound, and
# modest values keep pointer arguments near memory the routine plausibly uses.
VECTORS = [
    (0, 0, 0, 0, 0, 0, 0),
    (1, 2, 3, 4, 5, 6, 7),
    (0xFFFF, 1, 0, 7, 0x10, 0x20, 0x30),
    (0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700),
]


def fill(n):
    """The value of the n-th byte a routine touches. Varied, so that two reads
    of different bytes rarely agree by accident; the same on both sides."""
    return ((n + 1) * 0x9E3779B1 >> 13) & 0xFF


def run_routine(program, routine, regs):
    """One run of one routine. Returns its observation, or None for a fault."""
    seg = program.segment(routine["start"])
    delta = 0x100 + seg.file_start - seg.base
    if delta & 0xF:
        return {"end": "not run: its segment does not start on a paragraph"}
    cs = LOAD_SEG + (delta >> 4)
    lo = (cs << 4) + seg.addr(routine["start"])
    hi = (cs << 4) + seg.addr(routine["end"])
    calls = {(cs << 4) + seg.addr(off): insn.size for off, insn in program.instructions(routine)
             if insn.mnemonic in ("call", "lcall")}

    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, 0x110000)
    uc.mem_write((LOAD_SEG << 4) + 0x100, program.image)
    for (_, name), value in zip(REGS, regs):
        uc.reg_write(globals()[name], value)
    uc.reg_write(UC_X86_REG_CS, cs)
    uc.reg_write(UC_X86_REG_DS, DATA_SEG)
    uc.reg_write(UC_X86_REG_ES, DATA_SEG)
    uc.reg_write(UC_X86_REG_SS, STACK_SEG)
    uc.reg_write(UC_X86_REG_FLAGS, 0x0202)
    # FLAGS, CS and the sentinel, so that ret, retf and iret all come back to
    # the same place.
    sp = STACK_TOP - 6
    uc.mem_write((STACK_SEG << 4) + sp, bytes([SENTINEL & 0xFF, SENTINEL >> 8,
                                               cs & 0xFF, cs >> 8, 0x02, 0x02]))
    uc.reg_write(UC_X86_REG_SP, sp)

    touched = {}
    for a in range((STACK_SEG << 4) + sp, (STACK_SEG << 4) + STACK_TOP):
        touched[a] = len(touched)
    state = {"events": [], "insns": 0, "end": None, "ins": 0, "calls": 0}

    def first_touch(address, size, give_value):
        for a in range(address, address + size):
            if a not in touched:
                touched[a] = len(touched)
                if give_value:
                    uc.mem_write(a, bytes([fill(touched[a])]))
        return touched[address]

    def on_code(mu, address, size, _):
        state["insns"] += 1
        if state["insns"] > BUDGET:
            state["end"] = "budget"
            mu.emu_stop()
            return
        if not lo <= address < hi:
            state["events"].append(("left",))
            state["end"] = "left the routine"
            mu.emu_stop()
            return
        if address in calls:
            # Skipped, as emuverify skips calls: the callee is the other
            # program's business. Same stub return on both sides, in order.
            state["calls"] += 1
            state["events"].append(("call",))
            mu.reg_write(UC_X86_REG_AX, (0x1234 + state["calls"] * 7) & 0xFFFF)
            mu.reg_write(UC_X86_REG_IP, (address - (mu.reg_read(UC_X86_REG_CS) << 4)
                                         + calls[address]) & 0xFFFF)

    def on_intr(mu, number, _):
        state["events"].append(("int", number, (mu.reg_read(UC_X86_REG_AX) >> 8) & 0xFF))

    def on_in(mu, port, size, _):
        state["ins"] += 1
        state["events"].append(("in", port))
        return (0x5A + 0x11 * state["ins"]) & (0xFF if size == 1 else 0xFFFF)

    def on_out(mu, port, size, value, _):
        state["events"].append(("out", port, value))

    def on_read(mu, access, address, size, value, _):
        state["events"].append(("r", first_touch(address, size, True), size))

    def on_write(mu, access, address, size, value, _):
        state["events"].append(("w", first_touch(address, size, False), size,
                                value & ((1 << (8 * size)) - 1)))

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_INTR, on_intr)
    uc.hook_add(UC_HOOK_INSN, on_in, None, 1, 0, UC_X86_INS_IN)
    uc.hook_add(UC_HOOK_INSN, on_out, None, 1, 0, UC_X86_INS_OUT)
    uc.hook_add(UC_HOOK_MEM_READ, on_read)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    try:
        uc.emu_start(lo, (cs << 4) + SENTINEL, count=BUDGET + 1)
    except UcError as e:
        return None if state["end"] is None else _finish(uc, state)
    if state["end"] is None:
        ip = uc.reg_read(UC_X86_REG_IP)
        state["end"] = "returned" if ip == SENTINEL else f"stopped at IP 0x{ip:04X}"
    return _finish(uc, state)


def _finish(uc, state):
    regs = {name: uc.reg_read(globals()[const]) for name, const in REGS}
    regs["sp"] = uc.reg_read(UC_X86_REG_SP)
    regs["flags"] = uc.reg_read(UC_X86_REG_FLAGS) & FLAGS_COMPARED
    return {"end": state["end"], "events": state["events"], "regs": regs}


FRAME_BYTES = 6


def _byte(n, size):
    where = "the return frame" if n < FRAME_BYTES else f"touched byte #{n}"
    return f"{size} byte{'s' if size > 1 else ''} at {where}"


def _same(a, b, deltas, bits=16):
    mask = (1 << bits) - 1
    return a == b or ((b - a) & mask) in {d & mask for d in deltas}


def first_difference(oa, ob, deltas):
    """None when two observations agree under the pair's differences."""
    if oa["end"] != ob["end"]:
        return f"one {oa['end']}, the other {ob['end']}"
    for i, (ea, eb) in enumerate(zip(oa["events"], ob["events"])):
        if ea[0] != eb[0]:
            return f"event {i}: {ea[0]} against {eb[0]}"
        kind = ea[0]
        # A byte is named by the order it was first touched in: #0 is the
        # first, and the return frame's six bytes are #0 to #5.
        if kind == "r" and ea != eb:
            return (f"event {i}: one reads {_byte(ea[1], ea[2])}, the other "
                    f"{_byte(eb[1], eb[2])}")
        if kind == "w":
            if ea[1:3] != eb[1:3]:
                return (f"event {i}: one writes {_byte(ea[1], ea[2])}, the other "
                        f"{_byte(eb[1], eb[2])}")
            if not _same(ea[3], eb[3], deltas, 8 * ea[2]):
                return f"event {i}: writes 0x{ea[3]:X} against 0x{eb[3]:X}"
        if kind == "in" and not _same(ea[1], eb[1], deltas):
            return f"event {i}: reads port 0x{ea[1]:X} against 0x{eb[1]:X}"
        if kind == "out" and not (_same(ea[1], eb[1], deltas) and _same(ea[2], eb[2], deltas)):
            return (f"event {i}: port 0x{ea[1]:X} <- 0x{ea[2]:X} against "
                    f"port 0x{eb[1]:X} <- 0x{eb[2]:X}")
        if kind == "int" and not (_same(ea[1], eb[1], deltas, 8) and ea[2] == eb[2]):
            return f"event {i}: INT {ea[1]:02X}h AH={ea[2]:02X} against INT {eb[1]:02X}h AH={eb[2]:02X}"
    if len(oa["events"]) != len(ob["events"]):
        return f"{len(oa['events'])} events against {len(ob['events'])}"
    for name in oa["regs"]:
        a, b = oa["regs"][name], ob["regs"][name]
        if name == "flags":
            if a != b:
                return f"flags 0x{a:04X} against 0x{b:04X}"
        elif not _same(a, b, deltas):
            return f"{name} 0x{a:04X} against 0x{b:04X}"
    return None


def _acts(event):
    """Whether an event says anything about what the routine does.

    Every routine reads its own return frame on the way out, and one that
    only jumps elsewhere has done nothing either: as emuverify leaves the
    stack frame out of what makes a profile informative, these leave the
    frame out."""
    if event[0] == "left":
        return False
    if event[0] in ("r", "w"):
        return event[1] >= FRAME_BYTES
    return True


def confirm(a, ra, b, rb, numbers):
    """Run an instruction-identical pair on every vector; what came of it."""
    deltas = {(y - x) & 0xFFFF for _, x, y in numbers}
    informative = False
    for k, vector in enumerate(VECTORS):
        oa, ob = run_routine(a, ra, vector), run_routine(b, rb, vector)
        for o in (oa, ob):
            if o is None:
                return {"result": "not run", "why": f"a fault on vector {k}"}
            if o["end"].startswith("not run"):
                return {"result": "not run", "why": o["end"][9:]}
        why = first_difference(oa, ob, deltas)
        if why:
            return {"result": "differs", "vector": k, "why": why}
        changed = any(oa["regs"][n] != v for (n, _), v in zip(REGS, vector))
        informative = informative or any(map(_acts, oa["events"])) or changed
    if not informative:
        return {"result": "uninformative",
                "why": "touched nothing and changed no register on any vector"}
    return {"result": "confirmed", "vectors": len(VECTORS)}


# ---------------------------------------------------------------- the whole run

def compare(com_a, asm_a, com_b, asm_b, min_bytes=MIN_BYTES, similar=SIMILAR,
            emulate=True, nasm=None):
    """The comparison as data: both programs described, every routine of B
    classified, and the instruction-identical pairs run when unicorn is here."""
    a, b = Program(com_a, asm_a, nasm), Program(com_b, asm_b, nasm)
    rows = classify(a, b, min_bytes, similar)
    ran = emulate and HAVE_UNICORN
    if ran:
        by_start = {r["start"]: r for r in a.routines}
        b_start = {r["start"]: r for r in b.routines}
        for row in rows:
            if row["status"] != "instruction-identical":
                continue
            row["emulation"] = confirm(a, by_start[row["a"][0]], b, b_start[row["b"]],
                                       row["numbers"])

    def describe(p):
        return {"file": str(p.com), "listing": str(p.asm), "sha256":
                evidence.sha256_file(p.com), "bytes": len(p.image),
                "routines": len(p.routines),
                "considered": sum(1 for r in p.routines if r["end"] - r["start"] >= min_bytes),
                "starts": {k: len(v) for k, v in p.starts.items()},
                "jump_table_cases": len(p.cases)}

    statuses = ("byte-identical", "instruction-identical", "similar", "no counterpart",
                "too small")
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in statuses}
    emulation = None
    if ran:
        outcomes = [r["emulation"]["result"] for r in rows if "emulation" in r]
        emulation = {k: outcomes.count(k) for k in
                     ("confirmed", "differs", "uninformative", "not run")}
    return {"a": describe(a), "b": describe(b), "min_bytes": min_bytes,
            "similar_threshold": similar, "counts": counts,
            "emulation": emulation,
            "emulation_skipped": None if ran else
            ("not asked for" if not emulate else "unicorn is not installed"),
            "pairs": rows}


LIMITATIONS = [
    "A routine runs from one entry -- the program's entry, a call target, or code "
    "nothing in the listing branches to -- to the last instruction before the next. A "
    "routine reached only by a jump from another is part of the one before it.",
    "Similar is a resemblance score over instruction sequences with their numbers "
    "abstracted; it is not equivalence. Only the two identical kinds are claims.",
    "Emulation runs each routine alone with calls skipped and memory given values in "
    "the order the routine first touches it: it confirms the two routines compute the "
    "same thing from the same inputs, not that the programs use them the same way.",
    "Byte-identical routines are not run: the same bytes are the same instructions, "
    "though their callees may differ.",
]


def envelope(result):
    """The comparison in the evidence envelope of knowledge/17-evidence.md,
    about the second program -- the one being studied."""
    def hexed(row):
        out = dict(row)
        for k in ("b", "b_end"):
            out[k] = f"0x{row[k]:05X}"
        for k in ("a", "nearest"):
            if k in row:
                out[k] = [f"0x{x:05X}" for x in row[k]]
        if "numbers" in row:
            out["numbers"] = [{"kind": k, "a": f"0x{x:X}", "b": f"0x{y:X}"}
                              for k, x, y in row["numbers"]]
        return out

    pairs = [hexed(r) for r in result["pairs"]]
    items = [{"kind": "listing-rebuilds",
              "claim": f"{Path(side['listing']).name} assembles to "
                       f"{Path(side['file']).name} byte for byte",
              "location": {"file": side["file"]}, "value": side["sha256"]}
             for side in (result["a"], result["b"])]
    for p in pairs:
        if p["status"] not in ("byte-identical", "instruction-identical"):
            continue
        item = {"kind": p["status"],
                "claim": f"{p['b']} is {p['status']} to {', '.join(p['a'])}",
                "location": {"file_offset": p["b"], "end": p["b_end"]},
                "value": p["a"]}
        if "emulation" in p:
            item["detail"] = f"emulation: {p['emulation']['result']}"
            if p["emulation"]["result"] == "differs":
                item["level"] = "warn"
        items.append(item)
    unknowns = [f"{p['b']} and {p['a'][0]} have the same instructions but behave "
                f"differently on vector {p['emulation']['vector']}: "
                f"{p['emulation']['why']}. Is the difference in the numbers, or in "
                f"what they point at?"
                for p in pairs if p.get("emulation", {}).get("result") == "differs"]
    limitations = list(LIMITATIONS)
    if result["emulation_skipped"]:
        limitations.append(f"Instruction-identical pairs were not run: "
                           f"{result['emulation_skipped']}.")
    body = {k: v for k, v in result.items() if k != "pairs"}
    body["pairs"] = pairs
    return evidence.envelope("comdiff", evidence.target_identity(result["b"]["file"]),
                             status="ok", result=body, evidence=items,
                             limitations=limitations, unknowns=unknowns)


def report(result, show=40):
    """The comparison as a person reads it."""
    lines = []
    say = lines.append
    for label, side in (("A", result["a"]), ("B", result["b"])):
        st = side["starts"]
        say(f"{label}: {side['file']}  ({side['bytes']:,} bytes)")
        say(f"   listing {side['listing']} rebuilds it byte for byte")
        say(f"   {side['routines']} routines: {st['entry']} entry, {st['call target']} "
            f"call targets, {st['nothing branches here']} that nothing branches to; "
            f"{side['jump_table_cases']} jump-table targets read as cases")
        say(f"   {side['considered']} of them {result['min_bytes']} bytes or more")
    c = result["counts"]
    say("")
    say(f"each routine of B against A (at least {result['min_bytes']} bytes; similar "
        f"from {result['similar_threshold']:.2f}):")
    for k in ("byte-identical", "instruction-identical", "similar", "no counterpart"):
        say(f"   {k:<22} {c[k]:>4}")
    say(f"   {'too small':<22} {c['too small']:>4}   (not classified)")
    if result["emulation"]:
        e = result["emulation"]
        say("")
        say(f"instruction-identical pairs run under emulation: {e['confirmed']} confirmed, "
            f"{e['differs']} differ, {e['uninformative']} uninformative, "
            f"{e['not run']} not run")
    else:
        say("")
        say(f"instruction-identical pairs not run: {result['emulation_skipped']}")
    say("")
    shown = [r for r in result["pairs"]
             if r["status"] in ("byte-identical", "instruction-identical", "similar")]
    shown.sort(key=lambda r: (("byte-identical", "instruction-identical",
                               "similar").index(r["status"]), r["b"]))
    for r in shown[:show]:
        others = ", ".join(f"0x{x:05X}" for x in r["a"][:3]) + \
            (f" (+{len(r['a']) - 3})" if len(r["a"]) > 3 else "")
        tail = ""
        if r["status"] == "similar":
            tail = f"  score {r['score']:.3f}"
        elif "emulation" in r:
            tail = f"  emulation: {r['emulation']['result']}"
            if r["emulation"]["result"] in ("differs", "not run"):
                tail += f" ({r['emulation']['why']})"
        say(f"   B 0x{r['b']:05X} {r['bytes']:>5} B  {r['status']:<21} A {others}{tail}")
    if len(shown) > show:
        say(f"   ... {len(shown) - show} more (--json has them all)")
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("com_a", help="the program you know")
    ap.add_argument("asm_a", help="its comrec listing")
    ap.add_argument("com_b", help="the program you are reading")
    ap.add_argument("asm_b", help="its comrec listing")
    ap.add_argument("--min-bytes", type=int, default=MIN_BYTES,
                    help=f"routines shorter than this are not classified (default {MIN_BYTES})")
    ap.add_argument("--similar", type=float, default=SIMILAR,
                    help=f"the score from which a routine is called similar "
                         f"(default {SIMILAR})")
    ap.add_argument("--no-emulate", action="store_true",
                    help="do not run the instruction-identical pairs")
    ap.add_argument("--nasm", help="path to nasm; defaults to $NASM, then PATH")
    ap.add_argument("--json", metavar="FILE", help="write every pair as JSON")
    ap.add_argument("--evidence", metavar="FILE",
                    help="write the evidence envelope (knowledge/17-evidence.md); - for stdout")
    ap.add_argument("--show", type=int, default=40, help="pairs to print (default 40)")
    args = ap.parse_args()
    try:
        result = compare(args.com_a, args.asm_a, args.com_b, args.asm_b, args.min_bytes,
                         args.similar, not args.no_emulate, args.nasm)
    except Refused as e:
        print(f"comdiff: {e}", file=sys.stderr)
        return 2
    if args.evidence != "-":
        for line in report(result, args.show):
            print(line)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
        print(f"\nwrote {args.json}")
    if args.evidence:
        evidence.write(envelope(result), args.evidence)
    return 0


if __name__ == "__main__":
    sys.exit(main())
