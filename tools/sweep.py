#!/usr/bin/env python3
"""
sweep.py -- Run one routine of the original program on every input of a
domain, and compare a candidate with it, case by case.

This is the engine of `python tools/emuverify.py sweep`, and has no command
line of its own.

Why this exists
---------------
emuverify.py decides whether two functions are the same by running both on
four input vectors chosen to make them branch. That is right for its job,
carrying names between binaries, where more vectors measurably made it worse.
It does not answer a different question: does a port compute exactly what the
original computes? A web port of a 1984 game reimplements the original's
arithmetic, and the places it goes wrong -- a product that should wrap at 16
bits, a shift that should be unsigned, a comparison one step off -- are single
inputs nobody thinks to try. The DX-Ball case study that came with rea settled
one such routine by running the original x86 on every screen position from 0
to 640 at five scales, 3,205 cases, against the new code.

A sweep does that. The domain is written down; every case in it runs on the
original under emulation and on the candidate; the first input where they
disagree is printed, with what each side did.

How a case runs on the original
-------------------------------
  * The load image is mapped at segment 0x1000, as in emuverify.py, with its
    relocations applied, so a routine that reloads DS from a relocated word
    finds the same DGROUP as the sweep set up.
  * DS = ES = SS = DGROUP, SP = 0xFF00 inside it; the other registers are 0
    and FLAGS is 0x0202 at the start of every case.
  * The arguments are pushed right to left (cdecl), one 16-bit word each, two
    for a 32-bit one, then the return address. A far routine also gets CS.
    It is far when the export says it ends in RETF and never in RET, or when
    --far says so.
  * The case ends at the routine's return: the first RET or RETF taken with
    SP back at the return address pushed for it.
  * Calls are skipped, as in emuverify.py, and answer with a stub in AX: the
    n-th call made in a case returns (0x1234 + 7n) & 0xFFFF, unless the
    domain's `stubs` names another value for that n. Each call is recorded
    with its target and the words on the stack at the call.
  * Interrupts are skipped, as in emuverify.py.
  * A divide fault -- DIV or IDIV by zero, or a quotient that does not fit,
    such as -32768 / -1 -- ends the case with the outcome `divide`. It is an
    outcome to compare, not a failure of the tool. More than --budget
    instructions ends it as `hang`, and any other CPU exception or emulator
    error as `cpu`; both say where.
  * The CPU is an 8088 unless --cpu 386 says otherwise. Unicorn divides as a
    386 does, and the one difference that matters is IDIV's: an 8088 also
    raises the divide fault when the quotient is exactly -32768 (a word
    divide) or -128 (a byte divide), which a 386 returns. Under --cpu 8088 a
    hook on every IDIV works the quotient out first and ends the case as
    `divide` on those two. The games this toolkit was built on ran on 8088s.

Memory is put back after every case: every byte a case wrote, and every byte
the sweep wrote for it, returns to what the image holds.

The domain
----------
A JSON file:

    {
      "args": [
        {"name": "a", "range": [-300, 300]},
        {"name": "b", "list": [1, 3, 128]},
        {"name": "x", "set": "int16"}
      ],
      "globals": [
        {"name": "g_limit", "offset": "0x0000", "size": 2, "list": [-60, 10]},
        {"name": "g_hits",  "offset": "0x0004", "value": 5},
        {"name": "g_under", "offset": "0x0006"}
      ],
      "compare": ["ax", "writes", "calls"],
      "callees": {"helper": {"original": "1000:00a1", "candidate": "1000:0041",
                             "args": 2}},
      "stubs": [100, null],
      "max_cases": 100000,
      "seed": 7
    }

  args       In the order the C declaration has them. Each is a `range`
             [lo, hi] with an optional `step`, a `list`, or a named `set`:
             int8, uint8, int16, uint16, int32, uint32. `size` is 2 (one
             word on the stack) or 4 (two); a 32-bit set implies 4.
  globals    Words at DGROUP offsets. One with a range, list or set is swept
             like an argument; one with `value` is preset to it before every
             case; one with neither is only named, so that the writes to it
             can be compared by name. `size` is 1, 2 or 4 (default 2);
             `signed` says how the candidate sees a value it was not given;
             `candidate_offset` is where a binary candidate keeps it.
  compare    Any of `ax`, `dx`, `dx:ax`, `carry`, `writes`, `calls`.
             Default: ax, writes, calls. A divide fault, a hang or a CPU
             fault is always compared.
  callees    Names for call targets, segment:offset as functions.json writes
             them, one address per side; `args` is how many words to record
             at the call. A call to a target not listed is named by its
             address and records `call_args` words (default 0).
  stubs      AX for the first, second, ... call of a case; null keeps the
             default.
  max_cases, seed
             See below. --max-cases and --seed override them.

Exhaustive or sampled
---------------------
The domain is the product of every swept argument and global. When it holds
at most max_cases cases, all of them run, in order -- the first dimension
slowest -- and the sweep says "exhaustive". Otherwise it says "sampled", with
the seed, and runs every boundary value of every dimension: min, max, 0, +-1,
the powers of two with one either side, which takes in the sign boundaries.
Every combination of those when there are at most max_cases of them, or else
each boundary value once with the other dimensions at boundary values the
seed picks; then seeded random cases up to max_cases. A list domain's every
value is a boundary value. A sampled sweep is never called exhaustive.

The candidate contract
----------------------
Python, `path/to/ref.py:function_name`, imported into this process:

    def muldiv(args, ctx):
        a, b, c = args
        ...
        return {"ax": quotient}

JavaScript, `path/to/port.mjs:functionName`, run by one Node process for the
whole sweep (sweep_harness.mjs), which reads cases as JSON lines on stdin and
writes results on stdout:

    export function muldiv([a, b, c], ctx) { ...; return { ax: quotient }; }

Both receive:

  args          one number per argument, as the domain writes it: an int16
                argument arrives as -32768..32767, a uint16 one as 0..65535.
  ctx.globals   read only: every declared global's value for this case --
                the swept or preset value as the domain writes it, otherwise
                what the image holds (signed if the global says `signed`).
  ctx.call(target, ...args)
                record a call the routine makes and get its stub. `target`
                is a name from `callees`, or an address for one not listed.

Both return an object -- a bare number means {ax: number} -- with any of:

  ax, dx        16-bit; compared modulo 65536, so -1 and 65535 are the same
  "dx:ax"       a 32-bit result, instead of ax and dx
  carry         0 or 1 (or a boolean)
  writes        {name: value} for the globals the routine changed, each
                compared modulo 2 ** (8 * size); a global not mentioned keeps
                its ctx.globals value. A byte no global names is "0x0123".
  fault         "divide", "hang" or "cpu" -- what the original did instead of
                returning. Nothing else is compared on such a case. In
                Python a ZeroDivisionError counts as "divide".

A case the candidate takes longer than --case-timeout over (default 10 s) is
the outcome `hang` on the candidate side, compared like any other. A Python
candidate is interrupted inside its own loop; a Node process is stuck in
the case, so it is killed and a new one takes the cases after it -- once.
The second time a Node process stops answering, the sweep is blocked.

A field the domain compares and the candidate leaves out is a divergence,
named as such, and so is a fraction where the machine holds an integer -- a
port that divides without Math.trunc. A field the contract does not know, or
a value that is not a number, stops the sweep: those are nearly always a
misspelling. Any other exception is the candidate's answer for that case,
and a divergence.

Writes are compared as their effect: the final value of every declared
global, and every other byte of DGROUP the original changed, below the stack
frame at 0xF000.

A binary candidate (`--candidate-exe REBUILT.EXE --candidate-entry
SEG:OFF`) runs exactly as the original does, with its own DGROUP, its own
global offsets and its own callee addresses.

Coverage
--------
Every instruction the original executes, across the whole sweep, is
recorded. With the pipeline's functions.json (--functions), the routine's
`body` says which instructions it has; the sweep reports the share it
exercised and lists the ranges it never reached. A sweep that agrees on every
case but reached half the routine has proved half a routine, and says so.

What it does not do
-------------------
Follow calls, raise interrupts, or see self-modifying code (an instruction is
decoded once, the first time it runs). It compares the outputs it was told
to; reads, the flags other than carry, and registers other than AX and DX are
not compared. Of the ways an 8088 differs from the 386 Unicorn emulates, only
IDIV's refusal of -32768 and -128 is modelled; knowledge/18-oracle-sweeps.md
says how a candidate should model it too.
"""

import importlib.util
import itertools
import json
import platform
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
from collections import deque
from math import prod
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import emuverify  # noqa: E402
import evidence  # noqa: E402

from capstone import Cs, CS_ARCH_X86, CS_MODE_16  # noqa: E402
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG  # noqa: E402
from unicorn import (Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE,  # noqa: E402
                     UC_HOOK_INTR, UC_HOOK_MEM_WRITE, UcError)
from unicorn.x86_const import (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX,  # noqa: E402
                               UC_X86_REG_DX, UC_X86_REG_SI, UC_X86_REG_DI,
                               UC_X86_REG_BP, UC_X86_REG_SP, UC_X86_REG_IP,
                               UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
                               UC_X86_REG_SS, UC_X86_REG_FLAGS,
                               UC_X86_REG_AL, UC_X86_REG_AH, UC_X86_REG_BL,
                               UC_X86_REG_BH, UC_X86_REG_CL, UC_X86_REG_CH,
                               UC_X86_REG_DL, UC_X86_REG_DH)

IMAGE_SEG = emuverify.IMAGE_SEG
IMAGE_BASE = emuverify.IMAGE_BASE
SENTINEL_IP = emuverify.SENTINEL_IP
STACK_TOP = emuverify.STACK_TOP
FRAME_GUARD = emuverify.FRAME_GUARD
MEM_SIZE = emuverify.MEM_SIZE
HARNESS = Path(__file__).resolve().parent / "sweep_harness.mjs"

COMPARABLE = ("ax", "dx", "dx:ax", "carry", "writes", "calls")
DEFAULT_COMPARE = ["ax", "writes", "calls"]
RESULT_FIELDS = {"ax", "dx", "dx:ax", "carry", "writes", "fault"}
FAULTS = ("divide", "hang", "cpu")
CHUNK = 512                 # cases handed to a candidate at a time
SHOW_GROUP_EXAMPLES = 3

SETS = {"int8": (-0x80, 0x7F, 2), "uint8": (0, 0xFF, 2),
        "int16": (-0x8000, 0x7FFF, 2), "uint16": (0, 0xFFFF, 2),
        "int32": (-0x80000000, 0x7FFFFFFF, 4), "uint32": (0, 0xFFFFFFFF, 4)}

REGISTERS = {"ax": UC_X86_REG_AX, "bx": UC_X86_REG_BX, "cx": UC_X86_REG_CX,
             "dx": UC_X86_REG_DX, "si": UC_X86_REG_SI, "di": UC_X86_REG_DI,
             "bp": UC_X86_REG_BP, "sp": UC_X86_REG_SP, "cs": UC_X86_REG_CS,
             "ds": UC_X86_REG_DS, "es": UC_X86_REG_ES, "ss": UC_X86_REG_SS}
BYTE_REGISTERS = {"al": UC_X86_REG_AL, "ah": UC_X86_REG_AH, "bl": UC_X86_REG_BL,
                  "bh": UC_X86_REG_BH, "cl": UC_X86_REG_CL, "ch": UC_X86_REG_CH,
                  "dl": UC_X86_REG_DL, "dh": UC_X86_REG_DH}

CPUS = ("8088", "386")
# The quotient an 8088's IDIV refuses and a 386's returns, by operand size.
REFUSED_BY_8088 = {2: -0x8000, 1: -0x80}


class Blocked(Exception):
    """The sweep cannot start, and what to do about it."""


def default_stub(n):
    """What the n-th call of a case returns (n counts from 1): emuverify's."""
    return (0x1234 + n * 7) & 0xFFFF


def stub_for(stubs, n):
    value = stubs[n - 1] if n <= len(stubs) else None
    return default_stub(n) if value is None else value & 0xFFFF


def number(value, what):
    if isinstance(value, bool):
        raise Blocked(f"{what}: {value!r} is not a number")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            pass
    raise Blocked(f"{what}: {value!r} is not a number")


def address(text, what):
    try:
        seg, off = str(text).split(":")
        return int(seg, 16), int(off, 16)
    except ValueError:
        raise Blocked(f"{what}: {text!r} is not segment:offset in hex, e.g. 1000:004a")


def seg_off(seg, off):
    return f"{seg & 0xFFFF:04x}:{off & 0xFFFF:04x}"


# ---------------------------------------------------------------- the domain

class Dimension:
    """The values one argument or one global takes."""

    def __init__(self, name, of, lo=None, hi=None, step=1, values=None, label=""):
        self.name, self.of, self.label = name, of, label
        self.lo, self.hi, self.step, self.values = lo, hi, step, values

    @property
    def count(self):
        if self.values is not None:
            return len(self.values)
        return (self.hi - self.lo) // self.step + 1

    def value(self, i):
        return self.values[i] if self.values is not None else self.lo + i * self.step

    def random(self, rng):
        return self.value(rng.randrange(self.count))

    def boundary(self):
        """min, max, 0, +-1, and every power of two with one either side --
        which includes the sign boundaries -- that lie in the domain. Every
        value of a list."""
        if self.values is not None:
            return list(self.values)
        picks = {self.lo, self.hi, self.lo + self.step, self.hi - self.step, 0, 1, -1}
        for k in range(1, 32):
            p = 1 << k
            picks.update((p - 1, p, p + 1, -p - 1, -p, -p + 1))
        return sorted(v for v in picks
                      if self.lo <= v <= self.hi and (v - self.lo) % self.step == 0)

    def describe(self):
        return {"name": self.name, "of": self.of, "values": self.label, "count": self.count,
                "boundary": self.boundary()}


def fits(value, size):
    return -(1 << (8 * size - 1)) <= value < (1 << (8 * size))


def parse_dimension(name, of, obj, size, what):
    """A Dimension from a range, list or set, or None when obj has none."""
    kinds = [k for k in ("range", "list", "set") if k in obj]
    if len(kinds) > 1:
        raise Blocked(f"{what}: give one of range, list or set, not {' and '.join(kinds)}")
    if not kinds:
        return None
    kind = kinds[0]
    if kind == "set":
        if obj["set"] not in SETS:
            raise Blocked(f"{what}: set {obj['set']!r} is not one of {', '.join(SETS)}")
        lo, hi, _ = SETS[obj["set"]]
        dim = Dimension(name, of, lo, hi, 1, label=obj["set"])
    elif kind == "range":
        bounds = obj["range"]
        if not isinstance(bounds, list) or len(bounds) != 2:
            raise Blocked(f"{what}: range is [lo, hi], inclusive")
        lo, hi = (number(v, what) for v in bounds)
        step = number(obj.get("step", 1), what)
        if hi < lo or step < 1:
            raise Blocked(f"{what}: range [{lo}, {hi}] step {step} holds no values")
        dim = Dimension(name, of, lo, hi, step,
                        label=f"range {lo}..{hi}" + (f" step {step}" if step != 1 else ""))
    else:
        values = [number(v, what) for v in obj["list"]]
        if not values:
            raise Blocked(f"{what}: the list is empty")
        if len(set(values)) != len(values):
            raise Blocked(f"{what}: the list repeats a value")
        dim = Dimension(name, of, values=values, label=f"list of {len(values)}")
    for v in (dim.values if dim.values is not None else (dim.lo, dim.hi)):
        if not fits(v, size):
            raise Blocked(f"{what}: {v} does not fit in {size} bytes")
    return dim


class Global:
    def __init__(self, name, offset, candidate_offset, size, signed, dimension, value):
        self.name, self.offset, self.candidate_offset = name, offset, candidate_offset
        self.size, self.signed, self.dimension, self.value = size, signed, dimension, value

    def mask(self):
        return (1 << (8 * self.size)) - 1


class Spec:
    """The domain file, checked."""

    def __init__(self, path, max_cases=None, seed=None):
        self.path = Path(path)
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise Blocked(f"cannot read the domain {path}: {e}")
        if not isinstance(raw, dict):
            raise Blocked(f"{path}: the domain is a JSON object")
        known = {"args", "globals", "compare", "callees", "stubs", "call_args",
                 "max_cases", "seed"}
        unknown = sorted(set(raw) - known)
        if unknown:
            raise Blocked(f"{path}: unknown field(s) {', '.join(unknown)}; "
                          f"the domain's fields are {', '.join(sorted(known))}")
        self.args, self.arg_sizes = [], []
        names = set()
        for i, a in enumerate(raw.get("args") or []):
            name = a.get("name") or f"arg{i}"
            what = f"{path}: argument {name}"
            size = a.get("size") or (SETS[a["set"]][2] if a.get("set") in SETS else 2)
            if size not in (2, 4):
                raise Blocked(f"{what}: size is 2 or 4")
            dim = parse_dimension(name, "argument", a, size, what)
            if dim is None:
                raise Blocked(f"{what}: give a range, a list or a set")
            if name in names:
                raise Blocked(f"{what}: the name is used twice")
            names.add(name)
            self.args.append(dim)
            self.arg_sizes.append(size)
        self.globals = []
        for g in raw.get("globals") or []:
            name = g.get("name")
            what = f"{path}: global {name}"
            if not name or name in names:
                raise Blocked(f"{what}: every global needs a name of its own")
            if "offset" not in g:
                raise Blocked(f"{what}: give its DGROUP offset")
            names.add(name)
            size = g.get("size", 2)
            if size not in (1, 2, 4):
                raise Blocked(f"{what}: size is 1, 2 or 4")
            offset = number(g["offset"], what)
            cand = number(g.get("candidate_offset", offset), what)
            dim = parse_dimension(name, "global", g, size, what)
            value = number(g["value"], what) if "value" in g else None
            if dim is not None and value is not None:
                raise Blocked(f"{what}: a global is swept or preset, not both")
            if value is not None and not fits(value, size):
                raise Blocked(f"{what}: {value} does not fit in {size} bytes")
            self.globals.append(Global(name, offset, cand, size, bool(g.get("signed")),
                                       dim, value))
        self.compare = list(raw.get("compare") or DEFAULT_COMPARE)
        for f in self.compare:
            if f not in COMPARABLE:
                raise Blocked(f"{path}: cannot compare {f!r}; choose from {', '.join(COMPARABLE)}")
        self.callees = {}
        for name, c in (raw.get("callees") or {}).items():
            what = f"{path}: callee {name}"
            for side in ("original", "candidate"):
                if side in c:
                    address(c[side], what)
            self.callees[name] = {"original": c.get("original"), "candidate": c.get("candidate"),
                                  "args": number(c.get("args", 0), what)}
        self.call_args = number(raw.get("call_args", 0), f"{path}: call_args")
        self.stubs = [None if s is None else number(s, f"{path}: stubs")
                      for s in (raw.get("stubs") or [])]
        self.max_cases = number(max_cases if max_cases is not None
                                else raw.get("max_cases", 100_000), f"{path}: max_cases")
        self.seed = number(seed if seed is not None else raw.get("seed", 1), f"{path}: seed")
        if self.max_cases < 1:
            raise Blocked(f"{path}: max_cases must be at least 1")
        self.dimensions = self.args + [g.dimension for g in self.globals if g.dimension]
        if not self.dimensions:
            raise Blocked(f"{path}: nothing to sweep -- give at least one argument "
                          f"or a global with a range, list or set")

    def callee_names(self, side):
        """{"ssss:oooo": (name, words)} for one side."""
        out = {}
        for name, c in self.callees.items():
            if c.get(side):
                seg, off = address(c[side], name)
                out[seg_off(seg, off)] = (name, c["args"])
        return out


def plan(spec):
    """(mode, cases, info): cases is an iterator of value tuples, one value
    per dimension, in the order they run."""
    dims = spec.dimensions
    full = prod(d.count for d in dims)
    if full <= spec.max_cases:
        cases = itertools.product(*[[d.value(i) for i in range(d.count)] for d in dims])
        return "exhaustive", cases, {"full_product": full, "planned": full}

    rng = random.Random(spec.seed)
    edges = [d.boundary() for d in dims]
    if prod(len(e) for e in edges) <= spec.max_cases:
        boundary = list(itertools.product(*edges))
        rule = "every combination of boundary values"
    else:
        boundary, seen = [], set()
        for i, values in enumerate(edges):
            for v in values:
                case = tuple(v if j == i else rng.choice(edges[j]) for j in range(len(dims)))
                if case not in seen:
                    seen.add(case)
                    boundary.append(case)
        rule = "each boundary value once, the others at boundary values the seed picks"
    if len(boundary) > spec.max_cases:
        raise Blocked(f"max_cases {spec.max_cases} is below the {len(boundary)} boundary "
                      f"cases of this domain; raise it (--max-cases) or narrow the domain")

    def cases():
        seen = set(boundary)
        yield from boundary
        made, tries = len(boundary), 0
        while made < spec.max_cases and tries < 20 * spec.max_cases:
            tries += 1
            case = tuple(d.random(rng) for d in dims)
            if case not in seen:
                seen.add(case)
                made += 1
                yield case
    return "sampled", cases(), {"full_product": full, "boundary_cases": len(boundary),
                                "boundary_rule": rule, "planned": spec.max_cases}


class Case:
    """One input: the argument words for the stack, the globals' bytes, and
    what a Python or JavaScript candidate is told."""

    def __init__(self, spec, case_number, values, initial):
        self.number = case_number
        it = iter(values)
        self.args = [next(it) for _ in spec.args]
        swept = {g.name: next(it) for g in spec.globals if g.dimension}
        self.inputs = dict(zip([d.name for d in spec.args], self.args))
        self.inputs.update(swept)
        self.words = []
        for v, size in zip(self.args, spec.arg_sizes):
            self.words.append(v & 0xFFFF)
            if size == 4:
                self.words.append((v >> 16) & 0xFFFF)
        self.presets = {}        # name -> value written before the case
        self.view = {}           # name -> what the candidate is told
        for g in spec.globals:
            if g.dimension:
                value = swept[g.name]
            elif g.value is not None:
                value = g.value
            else:
                value = None
            if value is not None:
                self.presets[g.name] = value
                self.view[g.name] = value
            else:
                self.view[g.name] = initial[g.name]


# ---------------------------------------------------------------- the emulator

class Insn:
    __slots__ = ("kind", "size", "form", "text", "number")

    def __init__(self, kind, size, form, text, number=None):
        self.kind, self.size, self.form, self.text, self.number = kind, size, form, text, number


def call_form(insn):
    """How to find a call's target when it runs."""
    ops = insn.operands
    if insn.mnemonic == "call" and ops and ops[0].type == X86_OP_IMM:
        return ("near", ops[0].imm & 0xFFFF)
    if insn.mnemonic == "lcall" and len(ops) == 2 and ops[0].type == X86_OP_IMM:
        return ("far", ops[0].imm & 0xFFFF, ops[1].imm & 0xFFFF)
    if ops and ops[0].type == X86_OP_REG:
        return ("near-reg", insn.reg_name(ops[0].reg))
    if ops and ops[0].type == X86_OP_MEM:
        m = ops[0].mem
        return ("far-mem" if insn.mnemonic == "lcall" else "near-mem",
                insn.reg_name(m.segment) if m.segment else None,
                insn.reg_name(m.base) if m.base else None,
                insn.reg_name(m.index) if m.index else None, m.disp)
    return ("unknown",)


def idiv_form(insn):
    """(size, operand) for a word or byte IDIV, where the operand is ("reg",
    name) or ("mem", segment, base, index, disp); None for any other size,
    which an 8088 does not have."""
    ops = insn.operands
    if not ops or ops[0].size not in REFUSED_BY_8088:
        return None
    op = ops[0]
    if op.type == X86_OP_REG:
        return op.size, ("reg", insn.reg_name(op.reg))
    if op.type == X86_OP_MEM:
        m = op.mem
        return op.size, ("mem", insn.reg_name(m.segment) if m.segment else None,
                         insn.reg_name(m.base) if m.base else None,
                         insn.reg_name(m.index) if m.index else None, m.disp)
    return None


def signed(value, bits):
    value &= (1 << bits) - 1
    return value - (1 << bits) if value >> (bits - 1) else value


class CaseState:
    __slots__ = ("insns", "end", "where", "calls", "writes", "executed", "trace",
                 "pending_int")

    def __init__(self, executed, trace):
        self.insns, self.end, self.where = 0, None, None
        self.calls, self.writes = [], []
        self.executed, self.trace = executed, trace
        self.pending_int = None


class Program:
    """One routine of one MZ, loaded once and run case after case."""

    def __init__(self, exe, entry, load_segment, side, spec, dgroup=None, far=None,
                 record=None, budget=emuverify.MAX_INSNS, cpu="8088"):
        self.exe, self.side, self.spec, self.budget = Path(exe), side, spec, budget
        self.load_segment = load_segment
        if cpu not in CPUS:
            raise Blocked(f"--cpu {cpu}: one of {', '.join(CPUS)}")
        self.cpu = cpu
        data = self.exe.read_bytes()
        if data[:2] not in (b"MZ", b"ZM"):
            raise Blocked(f"{exe}: not an MZ executable")
        self.image = relocated_image(data, emuverify.load_image(exe))

        if dgroup is not None:
            self.dgroup, self.dgroup_how, self.dgroup_at = dgroup, "given", None
        else:
            try:
                self.dgroup, self.dgroup_how, at = emuverify.locate_dgroup(exe)
            except SystemExit as e:
                raise Blocked(f"{e}; pass the data segment paragraph with "
                              f"{'--dgroup' if side == 'original' else '--candidate-dgroup'}")
            # locate_dgroup writes the address at segment 0x1000; say it in
            # the same terms as the entry.
            self.dgroup_at = None if at is None else \
                seg_off(int(at[:4], 16) - IMAGE_SEG + load_segment, int(at[5:], 16))
        self.ds = IMAGE_SEG + self.dgroup
        self.dbase = self.ds << 4

        seg, off = entry
        rel = seg - load_segment
        if rel < 0 or (rel << 4) + off >= len(self.image):
            raise Blocked(f"{exe}: {seg_off(seg, off)} is not inside the load image "
                          f"(load segment 0x{load_segment:04x}); give the entry as "
                          f"functions.json writes it, or pass --load-segment")
        self.entry = (seg, off)
        self.cs = IMAGE_SEG + rel
        self.ip = off
        self.md = Cs(CS_ARCH_X86, CS_MODE_16)
        self.md.detail = True
        if far is not None:
            self.far, self.far_how = far, "given"
        elif record is not None:
            mnemonics = set(record.get("mnemonics") or [])
            self.far = "RETF" in mnemonics and "RET" not in mnemonics
            self.far_how = "functions.json: " + ("RETF and no RET" if self.far else "not RETF only")
        else:
            self.far, self.far_how = self._first_return_is_far()

        self.callees = spec.callee_names(side)
        self.cache = {}
        self.pristine = bytearray(MEM_SIZE)
        self.pristine[IMAGE_BASE:IMAGE_BASE + len(self.image)] = self.image
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, MEM_SIZE)
        self.uc.mem_write(0, bytes(self.pristine))
        self.dirty = []
        self.state = None
        self.uc.hook_add(UC_HOOK_CODE, self._on_code)
        self.uc.hook_add(UC_HOOK_INTR, self._on_intr)
        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._on_write)
        # The CPU as it is before any case, put back at the start of each.
        # One emulator serves the whole sweep, and a fault ended with
        # emu_stop leaves it believing it is still delivering that exception:
        # measured, the next divide fault arrived as interrupt 8, a double
        # fault, and the one after as nothing at all. Restoring this costs
        # 0.4 microseconds and the next fault arrives as interrupt 0 again.
        self.fresh = self.uc.context_save()

    def _first_return_is_far(self):
        """Without an export: decode straight on from the entry and take the
        first return, for want of anything better."""
        start = ((self.cs - IMAGE_SEG) << 4) + self.ip
        for insn in self.md.disasm(self.image[start:start + 4096], self.ip):
            if insn.mnemonic in ("ret", "retf"):
                return (insn.mnemonic == "retf",
                        f"the first return decoded from the entry is {insn.mnemonic.upper()}")
        return False, "no return decoded from the entry; entered as near"

    def global_offset(self, g):
        return g.offset if self.side == "original" else g.candidate_offset

    def initial(self, g):
        """A global's value in the image, as the candidate sees it."""
        at = self.dbase + self.global_offset(g)
        value = int.from_bytes(self.pristine[at:at + g.size], "little")
        if g.signed and value >> (8 * g.size - 1):
            value -= 1 << (8 * g.size)
        return value

    # -- hooks ---------------------------------------------------------------

    def _decode(self, linear, cs):
        insn = self.cache.get(linear)
        if insn is not None:
            return insn
        try:
            code = bytes(self.uc.mem_read(linear, 15))
        except UcError:
            return None
        ip = linear - (cs << 4)
        found = next(self.md.disasm(code, ip), None)
        if found is None:
            insn = Insn(None, 1, None, "(undecodable)")
        else:
            text = f"{found.mnemonic} {found.op_str}".strip()
            m = found.mnemonic
            if m in ("call", "lcall"):
                insn = Insn("call", found.size, call_form(found), text)
            elif m in ("ret", "retf"):
                insn = Insn("ret", found.size, None, text)
            elif m in ("div", "idiv"):
                insn = Insn("div", found.size, idiv_form(found) if m == "idiv" else None, text)
            elif m == "int":
                insn = Insn("int", found.size, None, text, found.operands[0].imm & 0xFF)
            elif m == "int3":
                insn = Insn("int", found.size, None, text, 3)
            elif m == "into":
                insn = Insn("int", found.size, None, text, 4)
            else:
                insn = Insn(None, found.size, None, text)
        self.cache[linear] = insn
        return insn

    def _on_code(self, uc, linear, size, _):
        st = self.state
        st.insns += 1
        if st.insns > self.budget:
            cs = uc.reg_read(UC_X86_REG_CS)
            st.end, st.where = "hang", (cs, linear - (cs << 4))
            uc.emu_stop()
            return
        if st.executed is not None:
            st.executed.add(linear)
        cs = uc.reg_read(UC_X86_REG_CS)
        if st.trace is not None:
            st.trace.append((cs, linear))
        insn = self._decode(linear, cs)
        kind = insn.kind if insn else None
        st.pending_int = insn.number if kind == "int" else None
        if kind == "ret":
            if uc.reg_read(UC_X86_REG_SP) == self.return_sp:
                st.end = "return"
                uc.emu_stop()
        elif kind == "call":
            self._skip_call(uc, cs, linear - (cs << 4), insn)
        elif kind == "div" and insn.form and self.cpu == "8088":
            refused = self._refused_by_8088(uc, *insn.form)
            if refused is not None:
                st.end = f"divide: an 8088 refuses the quotient {refused}"
                st.where = (cs, linear - (cs << 4))
                uc.emu_stop()

    def _refused_by_8088(self, uc, size, operand):
        """The quotient, when this IDIV's is the one an 8088 refuses and a 386
        returns; else None. Division by zero and a quotient out of range on
        both are left to Unicorn, which faults on them itself."""
        if operand[0] == "reg":
            reg = (BYTE_REGISTERS if size == 1 else REGISTERS)[operand[1]]
            divisor = signed(uc.reg_read(reg), 8 * size)
        else:
            _, segment, base, index, disp = operand
            ea = disp
            for r in (base, index):
                if r:
                    ea += uc.reg_read(REGISTERS[r])
            ea &= 0xFFFF
            if segment is None:
                segment = "ss" if base == "bp" else "ds"
            raw = bytes(uc.mem_read((uc.reg_read(REGISTERS[segment]) << 4) + ea, size))
            divisor = signed(int.from_bytes(raw, "little"), 8 * size)
        if divisor == 0:
            return None
        if size == 2:
            dividend = signed((uc.reg_read(UC_X86_REG_DX) << 16) | uc.reg_read(UC_X86_REG_AX), 32)
        else:
            dividend = signed(uc.reg_read(UC_X86_REG_AX), 16)
        quotient = abs(dividend) // abs(divisor)        # IDIV truncates toward zero
        if (dividend < 0) != (divisor < 0):
            quotient = -quotient
        return quotient if quotient == REFUSED_BY_8088[size] else None

    def _skip_call(self, uc, cs, ip, insn):
        st = self.state
        target = self._target(uc, cs, insn.form)
        name, words = self.callees.get(target, (target, self.spec.call_args))
        sp = uc.reg_read(UC_X86_REG_SP)
        ss = uc.reg_read(UC_X86_REG_SS)
        stack = bytes(uc.mem_read((ss << 4) + sp, 2 * words)) if words else b""
        args = [stack[i] | (stack[i + 1] << 8) for i in range(0, len(stack), 2)]
        st.calls.append([name, args])
        uc.reg_write(UC_X86_REG_AX, stub_for(self.spec.stubs, len(st.calls)))
        uc.reg_write(UC_X86_REG_IP, (ip + insn.size) & 0xFFFF)

    def _target(self, uc, cs, form):
        """The call's target, segment:offset as functions.json writes it."""
        kind = form[0]
        if kind == "near":
            seg, off = cs, form[1]
        elif kind == "far":
            seg, off = form[1], form[2]
        elif kind == "near-reg":
            seg, off = cs, uc.reg_read(REGISTERS[form[1]])
        elif kind in ("near-mem", "far-mem"):
            _, segment, base, index, disp = form
            ea = disp
            for r in (base, index):
                if r:
                    ea += uc.reg_read(REGISTERS[r])
            ea &= 0xFFFF
            if segment is None:
                segment = "ss" if base == "bp" else "ds"
            where = (uc.reg_read(REGISTERS[segment]) << 4) + ea
            raw = bytes(uc.mem_read(where, 4))
            off = raw[0] | (raw[1] << 8)
            seg = (raw[2] | (raw[3] << 8)) if kind == "far-mem" else cs
        else:
            return "unknown"
        return seg_off(seg - IMAGE_SEG + self.load_segment, off)

    def _on_intr(self, uc, intno, _):
        st = self.state
        cs, ip = uc.reg_read(UC_X86_REG_CS), uc.reg_read(UC_X86_REG_IP)
        if st.pending_int == intno or self._int_ends_at(cs, ip, intno):
            st.pending_int = None               # INT n: skipped, as in emuverify
            return
        # A fault leaves IP on the instruction that raised it: measured, an
        # IDIV by zero arrives here as interrupt 0 with IP on the IDIV.
        insn = self._decode((cs << 4) + ip, cs)
        st.where = (cs, ip)
        if intno == 0 and insn is not None and insn.kind == "div":
            st.end = "divide"
        else:
            st.end = f"cpu: exception {intno}"
        uc.emu_stop()

    def _int_ends_at(self, cs, ip, intno):
        """Whether the instruction just before CS:IP is INT intno (CD nn, or
        CC for INT 3): a software interrupt, whose IP is past it."""
        try:
            before = bytes(self.uc.mem_read((cs << 4) + ip - 2, 2))
        except UcError:
            return False
        return before == bytes((0xCD, intno)) or (intno == 3 and before[1] == 0xCC)

    def _on_write(self, uc, access, linear, size, value, _):
        self.dirty.append((linear, size))
        off = linear - self.dbase
        if 0 <= off < FRAME_GUARD:
            self.state.writes.append((off, size))

    # -- one case ------------------------------------------------------------

    def run(self, case, executed=None, trace=None):
        uc = self.uc
        uc.context_restore(self.fresh)
        for linear, size in self.dirty:
            uc.mem_write(linear, bytes(self.pristine[linear:linear + size]))
        self.dirty = []
        for g in self.spec.globals:
            if g.name in case.presets:
                at = self.dbase + self.global_offset(g)
                uc.mem_write(at, (case.presets[g.name] & g.mask()).to_bytes(g.size, "little"))
                self.dirty.append((at, g.size))
        sp = STACK_TOP
        frame = [SENTINEL_IP] + ([IMAGE_SEG] if self.far else []) + case.words
        sp -= 2 * len(frame)
        uc.mem_write(self.dbase + sp, b"".join(w.to_bytes(2, "little") for w in frame))
        self.dirty.append((self.dbase + sp, 2 * len(frame)))
        self.return_sp = sp
        for reg in (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX,
                    UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP):
            uc.reg_write(reg, 0)
        for reg in (UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
            uc.reg_write(reg, self.ds)
        uc.reg_write(UC_X86_REG_CS, self.cs)
        uc.reg_write(UC_X86_REG_SP, sp)
        uc.reg_write(UC_X86_REG_FLAGS, 0x0202)
        st = self.state = CaseState(executed, trace)
        try:
            uc.emu_start((self.cs << 4) + self.ip, IMAGE_BASE + SENTINEL_IP, count=0)
        except UcError as e:
            cs, ip = uc.reg_read(UC_X86_REG_CS), uc.reg_read(UC_X86_REG_IP)
            st.end, st.where = f"cpu: {e}", (cs, ip)
        if st.end is None:
            cs, ip = uc.reg_read(UC_X86_REG_CS), uc.reg_read(UC_X86_REG_IP)
            st.end, st.where = "cpu: stopped without returning", (cs, ip)
        return self._outcome(st)

    def _where(self, where):
        cs, ip = where
        return seg_off(cs - IMAGE_SEG + self.load_segment, ip)

    def _outcome(self, st):
        if st.end != "return":
            kind = st.end.split(":")[0]
            return {"fault": kind, "detail": st.end, "at": self._where(st.where),
                    "instructions": st.insns}
        uc = self.uc
        out = {"fault": None, "ax": uc.reg_read(UC_X86_REG_AX), "dx": uc.reg_read(UC_X86_REG_DX),
               "carry": uc.reg_read(UC_X86_REG_FLAGS) & 1, "calls": st.calls,
               "instructions": st.insns}
        final, named = {}, set()
        for g in self.spec.globals:
            at = self.dbase + self.global_offset(g)
            final[g.name] = int.from_bytes(bytes(uc.mem_read(at, g.size)), "little")
            named.update(range(self.global_offset(g), self.global_offset(g) + g.size))
        for off, size in st.writes:
            for o in range(off, off + size):
                if o in named or o >= FRAME_GUARD:
                    continue
                now = bytes(uc.mem_read(self.dbase + o, 1))[0]
                if now != self.pristine[self.dbase + o]:
                    final[f"0x{o:04x}"] = now
        out["writes"] = final
        return out

    def disassemble(self, cs, linear):
        insn = self._decode(linear, cs)
        return insn.text if insn else "(unreadable)"


def relocated_image(data, image):
    """The load image with IMAGE_SEG added to every relocated word, as DOS
    would add the load segment."""
    image = bytearray(image)
    count, table = struct.unpack_from("<H", data, 6)[0], struct.unpack_from("<H", data, 24)[0]
    for i in range(count):
        off, seg = struct.unpack_from("<HH", data, table + i * 4)
        pos = (seg << 4) + off
        if pos + 2 <= len(image):
            word = struct.unpack_from("<H", image, pos)[0]
            struct.pack_into("<H", image, pos, (word + IMAGE_SEG) & 0xFFFF)
    return bytes(image)


# ---------------------------------------------------------------- candidates

class BinaryCandidate:
    kind = "binary"

    def __init__(self, program):
        self.program = program
        self.processes = 0

    def describe(self):
        p = self.program
        return {"kind": "binary", "exe": str(p.exe), "entry": seg_off(*p.entry),
                "far": p.far, "far_how": p.far_how, "dgroup": f"0x{p.dgroup:04x}",
                "dgroup_how": p.dgroup_how,
                "dgroup_set_at": p.dgroup_at, "runtime": "the same emulation as the original"}

    def evaluate(self, cases):
        return [self.program.run(c) for c in cases]

    def close(self):
        pass


class ContractError(Exception):
    """A candidate answered outside the contract; the sweep stops."""


class PythonContext:
    def __init__(self, view, stubs):
        self.globals = types.MappingProxyType(dict(view))
        self.calls = []
        self._stubs = stubs

    def call(self, target, *args):
        self.calls.append([str(target), list(args)])
        return stub_for(self._stubs, len(self.calls))


CASE_TIMEOUT = 10.0         # seconds a candidate may take over one case


class CandidateTimeout(BaseException):
    """Raised into a Python candidate that has run past the case timeout. A
    BaseException, so that a candidate's own `except Exception` cannot
    swallow it."""


class Watchdog:
    """Fires when one case has run past its deadline.

    Arming is two attribute stores a case, so that it costs nothing a sweep
    of 65,536 cases would notice; a thread polls the deadline a few times a
    second. What firing does is the candidate's: interrupt a Python
    candidate's loop, or kill a Node process that stopped answering."""

    POLL = 0.05

    def __init__(self, seconds, fire):
        self.seconds, self.fire = seconds, fire
        self.armed = None                   # (token, deadline), or None
        self.fired = None                   # the token it last fired for
        self.lock = threading.Lock()
        threading.Thread(target=self._watch, daemon=True).start()

    def arm(self, token):
        self.armed = (token, time.monotonic() + self.seconds)

    def disarm(self):
        with self.lock:
            self.armed = None

    def _watch(self):
        while True:
            time.sleep(self.POLL)
            armed = self.armed
            if armed is None or time.monotonic() < armed[1]:
                continue
            with self.lock:
                if self.armed is armed:     # still the same case, still running
                    self.armed = None
                    self.fired = armed[0]
                    self.fire(armed[0])


def interrupt(thread_id, exc):
    """Raise `exc` in another thread at its next bytecode, or with exc None,
    cancel one not yet raised."""
    import ctypes
    ctypes.pythonapi.PyThreadState_SetAsyncExc(
        ctypes.c_ulong(thread_id), ctypes.py_object(exc) if exc else None)


class PythonCandidate:
    """A Python callable, called in this process.

    A case that runs past the case timeout is interrupted by an exception
    raised into the candidate's own loop, and answers `hang`. That reaches a
    loop written in Python; a candidate blocked inside a C call -- a
    time.sleep, a regular expression -- is not interrupted until the call
    returns."""
    kind = "python"

    def __init__(self, source, stubs, case_timeout=CASE_TIMEOUT):
        path, _, name = source.rpartition(":")
        if not path or not name:
            raise Blocked(f"--candidate {source}: give path/to/ref.py:function_name")
        self.path, self.name, self.stubs = Path(path), name, stubs
        if not self.path.is_file():
            raise Blocked(f"--candidate: no file {self.path}")
        sys.path.insert(0, str(self.path.resolve().parent))
        spec = importlib.util.spec_from_file_location(f"sweep_candidate_{self.path.stem}",
                                                      self.path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as e:  # noqa: BLE001 -- whatever the candidate raises
            raise Blocked(f"--candidate: importing {self.path} raised {type(e).__name__}: {e}")
        self.fn = getattr(module, name, None)
        if not callable(self.fn):
            raise Blocked(f"--candidate: {self.path} has no function {name}")
        self.processes = 0
        self.case_timeout, self.hangs = case_timeout, 0
        self.thread = threading.get_ident()
        self.watchdog = Watchdog(case_timeout,
                                 lambda token: interrupt(self.thread, CandidateTimeout))

    def describe(self):
        return {"kind": "python", "source": str(self.path), "function": self.name,
                "runtime": f"Python {platform.python_version()}, in this process",
                "case_timeout": self.case_timeout, "hangs": self.hangs}

    def evaluate(self, cases):
        return [self._one(c) for c in cases]

    def _one(self, case):
        ctx = PythonContext(case.view, self.stubs)
        answer = None
        try:
            try:
                self.watchdog.arm(case.number)
                try:
                    answer = {"result": self.fn(list(case.args), ctx), "calls": ctx.calls}
                except ZeroDivisionError:
                    answer = {"result": {"fault": "divide"}, "calls": ctx.calls}
                except Exception as e:  # noqa: BLE001 -- the candidate's answer for this case
                    answer = {"error": f"{type(e).__name__}: {e}", "calls": ctx.calls}
            finally:
                self.watchdog.disarm()
                if self.watchdog.fired == case.number and answer is not None:
                    # It fired as the case returned: cancel the exception if
                    # it is still on its way. If it already arrived, the
                    # except below keeps the answer the case gave.
                    interrupt(self.thread, None)
        except CandidateTimeout:
            pass
        if answer is None:
            self.hangs += 1
            answer = {"result": {"fault": "hang"}, "calls": ctx.calls,
                      "timeout": f"no answer in {self.case_timeout:g} s"}
        return answer

    def close(self):
        pass


class NodeCandidate:
    """One Node process for the whole sweep: cases go in as JSON lines, and
    results come back the same way, in order.

    A case that runs past the case timeout answers `hang`. Node is stuck in
    it, so the process is killed and a new one takes the cases after it --
    once. The second time a process stops answering, by a hang or by dying,
    the sweep is blocked: a port that loops on many inputs would otherwise
    cost a timeout and a Node start for every one of them."""
    kind = "javascript"
    RESTARTS = 1

    def __init__(self, source, stubs, case_timeout=CASE_TIMEOUT):
        path, _, name = source.rpartition(":")
        if not path or not name:
            raise Blocked(f"--candidate {source}: give path/to/port.mjs:functionName")
        self.path, self.name, self.stubs = Path(path), name, stubs
        if not self.path.is_file():
            raise Blocked(f"--candidate: no file {self.path}")
        self.node = shutil.which("node")
        if not self.node:
            raise Blocked("node is not on PATH; a JavaScript candidate needs Node.js 16 or "
                          "later (measured on 22.17.0)")
        self.version = subprocess.run([self.node, "--version"], capture_output=True,
                                      text=True).stdout.strip()
        # stderr to a file, not a pipe: nothing reads it while the sweep
        # runs, and a full pipe would stop Node mid-sweep.
        self.errors = tempfile.TemporaryFile(mode="w+", encoding="utf-8")
        self.case_timeout, self.hangs, self.restarts = case_timeout, 0, 0
        self.pids, self.proc = set(), None
        self.watchdog = Watchdog(case_timeout, self._kill)
        self._start()

    def _start(self):
        self.proc = subprocess.Popen(
            [self.node, str(HARNESS), str(self.path.resolve()), self.name,
             json.dumps(self.stubs)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.errors,
            text=True, encoding="utf-8", bufsize=1)
        self.watchdog.arm("start")
        ready = self._line()
        self.watchdog.disarm()
        if not ready or not ready.get("ready"):
            why = (ready or {}).get("error") or self._stderr() or \
                f"no answer in {self.case_timeout:g} s"
            self.close()
            raise Blocked(f"--candidate: Node could not load {self.path}:{self.name}: {why}")
        self.pids.add(ready["pid"])

    def _kill(self, token):
        try:
            self.proc.kill()
        except OSError:
            pass

    def _line(self):
        """The next answer, or None when the process is gone."""
        line = self.proc.stdout.readline()
        return json.loads(line) if line else None

    def _stderr(self):
        self.errors.seek(0)
        return self.errors.read().strip()[-800:]

    def _restart(self, case, why):
        if self.restarts >= self.RESTARTS:
            err = self._stderr()
            raise Blocked(f"the Node process for {self.path} stopped answering at case "
                          f"{case} ({why}), and it had been restarted once already"
                          + (f": {err}" if err else "")
                          + f"; find out why the port does not return there, or raise "
                            f"--case-timeout if it is only slow")
        self.restarts += 1
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self._start()

    def describe(self):
        return {"kind": "javascript", "source": str(self.path), "function": self.name,
                "runtime": f"Node {self.version}, one process for the sweep",
                "processes": len(self.pids), "case_timeout": self.case_timeout,
                "hangs": self.hangs, "restarts": self.restarts}

    def _feed(self, cases):
        # A thread writes while this one reads: on Linux a pipe's buffer is
        # 64 KB and Node's stdout to a pipe is synchronous, so writing a whole
        # chunk before reading any of it could leave both sides waiting.
        proc = self.proc

        def feed():
            try:
                for c in cases:
                    proc.stdin.write(json.dumps({"id": c.number, "args": c.args,
                                                 "globals": c.view}) + "\n")
                proc.stdin.flush()
            except (OSError, ValueError):
                pass                        # the process was killed under it
        writer = threading.Thread(target=feed, daemon=True)
        writer.start()
        return writer

    def evaluate(self, cases):
        out, pending = [], list(cases)
        while pending:
            writer = self._feed(pending)
            rest = []
            for i, c in enumerate(pending):
                self.watchdog.arm(c.number)
                answer = self._line()
                self.watchdog.disarm()
                if answer is None and self.watchdog.fired == c.number:
                    self.hangs += 1
                    out.append({"result": {"fault": "hang"}, "calls": [],
                                "timeout": f"no answer in {self.case_timeout:g} s"})
                    self._restart(c.number, f"no answer in {self.case_timeout:g} s")
                    rest = pending[i + 1:]
                    break
                if answer is None:
                    self._restart(c.number, "the process exited")
                    rest = pending[i:]      # it never answered this one
                    break
                if answer.get("id") != c.number:
                    raise Blocked(f"the Node harness answered case {answer.get('id')} "
                                  f"where case {c.number} was due")
                self.pids.add(answer.get("pid"))
                out.append(answer)
                if self.watchdog.fired == c.number:
                    # The deadline passed just as the answer came: the process
                    # was killed after answering. Not a hang; start another.
                    self.restarts -= 1
                    self._restart(c.number, "killed after answering")
                    rest = pending[i + 1:]
                    break
            writer.join(timeout=10)
            pending = rest
        return out

    def close(self):
        try:
            self.proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=10)
        self.errors.close()


def value_of(v, mask, what, case):
    """A number a candidate returned, as the machine would hold it. A
    fraction -- a port that forgot Math.trunc -- is kept as text, so it
    differs from what the original holds and shows as a divergence at that
    input. Something that is not a number at all breaks the contract."""
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ContractError(f"case {case.number}: {what} is {v!r}, not a number")
    if isinstance(v, float):
        if not v.is_integer():
            return f"{v!r}, not an integer"
        v = int(v)
    return v & mask


def calls_of(answer, case):
    """[target, [16-bit args]] for each call a candidate made: Python's
    context records [target, args], the Node harness {target, args}."""
    out = []
    for c in answer.get("calls") or []:
        target, args = (c["target"], c["args"]) if isinstance(c, dict) else c
        out.append([str(target), [value_of(a, 0xFFFF, f"an argument to {target}", case)
                                  for a in args]])
    return out


def candidate_outcome(answer, spec, case):
    """A Python or JavaScript candidate's answer, in the original's terms."""
    if "error" in answer:
        return {"fault": None, "error": answer["error"], "calls": calls_of(answer, case)}
    result = answer.get("result")
    if isinstance(result, bool) or result is None:
        raise ContractError(f"case {case.number}: the candidate returned {result!r}; "
                            f"return a number (AX) or an object")
    if isinstance(result, (int, float)):
        result = {"ax": result}
    if not isinstance(result, dict):
        raise ContractError(f"case {case.number}: the candidate returned a "
                            f"{type(result).__name__}; return a number or an object")
    unknown = sorted(set(result) - RESULT_FIELDS)
    if unknown:
        raise ContractError(f"case {case.number}: the candidate returned field(s) "
                            f"{', '.join(unknown)}, which the contract does not have; it "
                            f"has {', '.join(sorted(RESULT_FIELDS))}")
    fault = result.get("fault")
    if fault is not None:
        if fault not in FAULTS:
            raise ContractError(f"case {case.number}: fault {fault!r} is not one of "
                                f"{', '.join(FAULTS)}")
        return {"fault": fault}

    def word(key, bits=16):
        return value_of(result.get(key), (1 << bits) - 1, key, case)

    out = {"fault": None, "ax": word("ax"), "dx": word("dx"), "dx:ax": word("dx:ax", 32),
           "carry": None if "carry" not in result else int(bool(result["carry"])),
           "calls": calls_of(answer, case)}
    writes = result.get("writes") or {}
    if not isinstance(writes, dict):
        raise ContractError(f"case {case.number}: writes is not an object of name: value")
    final = {}
    sizes = {g.name: g for g in spec.globals}
    for g in spec.globals:
        final[g.name] = case.view[g.name] & g.mask()
    for key, v in writes.items():
        if key in sizes:
            final[key] = value_of(v, sizes[key].mask(), f"writes[{key!r}]", case)
        elif key.lower().startswith("0x"):
            final[f"0x{int(key, 16):04x}"] = value_of(v, 0xFF, f"writes[{key!r}]", case)
        else:
            raise ContractError(f"case {case.number}: writes names {key!r}, which is not a "
                                f"global of the domain (or a byte, as \"0x0123\")")
    out["writes"] = final
    return out


# ---------------------------------------------------------------- comparing

def view(outcome, compare):
    """The compared part of an outcome."""
    if outcome.get("fault"):
        return {"fault": outcome["fault"]}
    if outcome.get("error"):
        return {"fault": None, "error": outcome["error"]}
    v = {"fault": None}
    for f in compare:
        if f == "dx:ax":
            if outcome.get("dx:ax") is not None:
                v[f] = outcome["dx:ax"]
            elif isinstance(outcome.get("ax"), int) and isinstance(outcome.get("dx"), int):
                v[f] = (outcome["dx"] << 16) | outcome["ax"]
            else:
                v[f] = None
        else:
            v[f] = outcome.get(f)
    return v


def differences(original, candidate, compare):
    a, b = view(original, compare), view(candidate, compare)
    if "error" in b:
        return ["error"]
    if a["fault"] or b["fault"]:
        return [] if a["fault"] == b["fault"] else ["fault"]
    return [f for f in compare if a.get(f) != b.get(f)]


def show(outcome, compare, before=None):
    """One line for a person. `before` is each global's value as the case
    began: writes are compared as every global's final value, but a global
    that did not change is left out of the line."""
    before = before or {}
    if outcome.get("error"):
        return f"raised {outcome['error']}"
    if outcome.get("fault"):
        at = f" at {outcome['at']}" if outcome.get("at") else ""
        # Said only of the fault a 386 would not raise, so that a person
        # reading one side's fault and the other side's -32768 sees why.
        why = (outcome.get("detail") or "").partition("divide: ")[2]
        return f"{outcome['fault']} fault{at}" + (f" ({why})" if why else "")
    parts = []
    v = view(outcome, compare)
    for f in compare:
        x = v.get(f)
        if x is None:
            parts.append(f"{f} (not given)")
        elif isinstance(x, str):
            parts.append(f"{f}={x}")
        elif f in ("ax", "dx"):
            parts.append(f"{f}=0x{x:04x} ({x - 0x10000 if x & 0x8000 else x})")
        elif f == "dx:ax":
            parts.append(f"dx:ax=0x{x:08x}")
        elif f == "carry":
            parts.append(f"carry={x}")
        elif f == "writes":
            changed = [f"{k}={'0x%x' % w if isinstance(w, int) else w}"
                       for k, w in x.items() if before.get(k) != w]
            parts.append("writes " + (" ".join(changed) or "nothing changed"))
        elif f == "calls":
            parts.append("calls " + (" ".join(f"{t}({', '.join(hex(a) for a in args)})"
                                              for t, args in x) or "none"))
    return ", ".join(parts)


def record(case, original, candidate, fields, spec):
    compare = spec.compare
    before = {g.name: case.view[g.name] & g.mask() for g in spec.globals}
    return {"case": case.number, "inputs": case.inputs, "fields": fields,
            "original": view(original, compare), "candidate": view(candidate, compare),
            "original_at": original.get("at"), "text": {
                "original": show(original, compare, before),
                "candidate": show(candidate, compare, before)}}


# ---------------------------------------------------------------- coverage

def body_of(functions_path, exe, entry, accept_drift):
    """(record, ranges in emulator linear terms, load segment), or a reason."""
    data = evidence.load_functions(functions_path, exe, "emuverify.py sweep", accept_drift)
    load = int(((data.get("observed_profile") or {}).get("load_segment") or "0x1000"), 16)
    want = seg_off(*entry)
    for f in data.get("functions") or []:
        if f.get("entry", "").lower() == want:
            body = f.get("body") or {}
            if not body.get("ranges"):
                return f, None, load, (f"{functions_path} has no body for {want}: it was "
                                       f"exported before prompt 03; re-run tools/pipeline.ps1")
            shift = IMAGE_BASE - (load << 4)
            ranges = [(int(r["start_linear"], 16) + shift, int(r["end_linear"], 16) + shift)
                      for r in body["ranges"]]
            return f, ranges, load, None
    return None, None, load, f"{functions_path} has no function at {want}"


def coverage(program, ranges, executed):
    """Which of the body's instructions the sweep ran, and the runs it did not."""
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    insns = []              # (linear, size)
    for lo, hi in ranges:
        start = lo - IMAGE_BASE
        for insn in md.disasm(program.image[start:hi - IMAGE_BASE + 1], lo):
            insns.append((insn.address, insn.size))
    body = {a for a, _ in insns}
    ran = [a for a, _ in insns if a in executed]
    unreached, run = [], None
    for a, size in insns + [(None, 0)]:
        if a is not None and a not in executed and (run is None or run[1] + 1 == a):
            run = [a if run is None else run[0], a + size - 1, (run[2] if run else 0) + 1]
            continue
        if run is not None:
            unreached.append(run)
            run = None
        if a is not None and a not in executed:
            run = [a, a + size - 1, 1]
    outside = sorted(executed - body)
    load = program.load_segment

    def where(linear):
        seg = program.cs - IMAGE_SEG + load
        return seg_off(seg, linear - (program.cs << 4))
    return {
        "available": True, "instructions": len(insns), "exercised": len(ran),
        "percent": round(100.0 * len(ran) / len(insns), 1) if insns else 0.0,
        "unreached": [{"start": where(lo), "end": where(hi), "instructions": n}
                      for lo, hi, n in unreached],
        "executed_outside_body": len(outside),
        "outside_body": [where(a) for a in outside[:20]],
    }


# ---------------------------------------------------------------- the sweep

LIMITATIONS = [
    "Calls are not followed: each is skipped and answers with a stub in AX, so the callee's "
    "own behaviour is outside the comparison, and a callee that cleans its own stack "
    "(pascal) leaves the caller's stack as cdecl would not.",
    "Interrupts are skipped, as in emuverify.py: an INT does nothing, so a routine that "
    "depends on DOS or the BIOS is compared with that dependency removed.",
    "Each instruction is decoded once, the first time it runs, so self-modifying code is "
    "seen as it first was.",
    "Only the compared outputs are compared: memory the routine reads, flags other than "
    "carry, and registers other than AX and DX are not.",
    "Writes at DGROUP offsets from 0xF000 up are taken for the stack frame and not compared.",
    "A Python candidate past the case timeout is interrupted between bytecodes: a loop "
    "written in Python stops, but one blocked inside a C call (a sleep, a regular "
    "expression) runs on until the call returns.",
]

# What the sweep's CPU means for DIV and IDIV, said third among the above.
DIVIDE_LIMITATION = {
    "8088": "The CPU is an 8088 in one respect only: IDIV raises the divide fault on a "
            "quotient of exactly -32768 (a word divide) or -128 (a byte divide), as an 8088 "
            "does and a 386 does not. In every other respect DIV and IDIV are Unicorn's, "
            "which divides as a 386 does.",
    "386": "Unicorn implements DIV and IDIV as a later x86 does, and --cpu 386 leaves them "
           "so. An 8088 also raises the divide fault when IDIV's quotient is exactly the most "
           "negative value (-32768 for a word, -128 for a byte); this sweep does not.",
}


def limitations(cpu):
    return LIMITATIONS[:2] + [DIVIDE_LIMITATION[cpu]] + LIMITATIONS[2:]


def run_sweep(args, progress=None):
    """The envelope for one sweep. Raises Blocked when it cannot start."""
    spec = Spec(args.domain, args.max_cases, args.seed)
    entry = address(args.entry, "the original's entry")

    record_, ranges, load, why = None, None, None, None
    if args.functions:
        record_, ranges, load, why = body_of(args.functions, args.exe, entry,
                                             args.accept_profile_drift)
    if args.load_segment is not None:
        load = number(args.load_segment, "--load-segment")
    if load is None:
        load = IMAGE_SEG
    far = True if args.far else (False if args.near else None)
    original = Program(args.exe, entry, load, "original", spec,
                       dgroup=number(args.dgroup, "--dgroup") if args.dgroup else None,
                       far=far, record=record_, budget=args.budget, cpu=args.cpu)

    if args.candidate_exe:
        if not args.candidate_entry:
            raise Blocked("--candidate-exe needs --candidate-entry SEG:OFF")
        cprog = Program(args.candidate_exe, address(args.candidate_entry, "--candidate-entry"),
                        number(args.candidate_load_segment, "--candidate-load-segment")
                        if args.candidate_load_segment else load,
                        "candidate", spec,
                        dgroup=number(args.candidate_dgroup, "--candidate-dgroup")
                        if args.candidate_dgroup else None, far=far, budget=args.budget,
                        cpu=args.cpu)
        candidate = BinaryCandidate(cprog)
    elif args.candidate:
        suffix = args.candidate.rpartition(":")[0].lower()
        if suffix.endswith(".py"):
            candidate = PythonCandidate(args.candidate, spec.stubs, args.case_timeout)
        elif suffix.endswith((".mjs", ".js", ".cjs")):
            candidate = NodeCandidate(args.candidate, spec.stubs, args.case_timeout)
        else:
            raise Blocked(f"--candidate {args.candidate}: a .py or .mjs file and a function "
                          f"name after a colon; a rebuilt binary goes in --candidate-exe")
    else:
        raise Blocked("give a candidate: --candidate ref.py:fn, --candidate port.mjs:fn, "
                      "or --candidate-exe REBUILT.EXE --candidate-entry SEG:OFF")

    initial = {g.name: original.initial(g) for g in spec.globals}
    mode, values, info = plan(spec)
    executed = set()
    compare = spec.compare
    agree = 0
    fault_kinds = {}
    run = 0
    first = None
    groups = {}
    contract = None
    started = last_said = time.perf_counter()
    try:
        numbered = (Case(spec, i + 1, v, initial) for i, v in enumerate(values))
        while True:
            chunk = list(itertools.islice(numbered, CHUNK))
            if not chunk:
                break
            answers = candidate.evaluate(chunk)
            for case, answer in zip(chunk, answers):
                o = original.run(case, executed=executed)
                if candidate.kind == "binary":
                    c = answer
                else:
                    try:
                        c = candidate_outcome(answer, spec, case)
                    except ContractError as e:
                        contract = str(e)
                        break
                run += 1
                fields = differences(o, c, compare)
                if not fields:
                    agree += 1
                    if o.get("fault"):
                        fault_kinds[o["fault"]] = fault_kinds.get(o["fault"], 0) + 1
                    continue
                entry_record = record(case, o, c, fields, spec)
                if first is None:
                    first = entry_record
                for f in fields:
                    g = groups.setdefault(f, {"cases": 0, "examples": []})
                    g["cases"] += 1
                    if len(g["examples"]) < SHOW_GROUP_EXAMPLES:
                        g["examples"].append(entry_record)
                if not args.all:
                    break
            if contract or (first is not None and not args.all):
                break
            # Say how far it has got every few seconds. A sweep of a million
            # cases that prints nothing looks exactly like one that hung
            # (knowledge/16-emulator-driven-exploration.md).
            now = time.perf_counter()
            if progress and now - last_said > 5:
                progress(f"{run:,} of {info['planned']:,} cases, {now - started:.0f} s")
                last_said = now
    finally:
        described = candidate.describe()
        candidate.close()
    seconds = time.perf_counter() - started
    if contract:
        raise Blocked(f"the candidate broke the contract at {contract}")

    trace = None
    if first is not None and args.trace_on_divergence:
        case = Case(spec, first["case"], [first["inputs"][d.name] for d in spec.dimensions],
                    initial)
        ring = deque(maxlen=args.trace_on_divergence)
        original.run(case, trace=ring)
        trace = [{"at": seg_off(cs - IMAGE_SEG + load, linear - (cs << 4)),
                  "instruction": original.disassemble(cs, linear)} for cs, linear in ring]

    if ranges is not None:
        cov = coverage(original, ranges, executed)
    else:
        cov = {"available": False, "reason": why or "no functions.json given (--functions), "
                                                     "so there is no body to measure against",
               "executed": len(executed)}

    diverging_cases = run - agree
    status = "verified" if diverging_cases == 0 else "mismatch"
    planned = info.get("planned")
    result = {
        "original": {"exe": str(original.exe), "entry": seg_off(*entry), "far": original.far,
                     "far_how": original.far_how, "dgroup": f"0x{original.dgroup:04x}",
                     "dgroup_how": original.dgroup_how, "dgroup_set_at": original.dgroup_at,
                     "load_segment": f"0x{load:04x}"},
        "candidate": described,
        "cpu": args.cpu,
        "domain": {"spec": str(spec.path), "dimensions": [d.describe() for d in spec.dimensions],
                   "fixed_globals": {g.name: g.value for g in spec.globals if g.value is not None},
                   "full_product": info["full_product"]},
        "mode": mode, "seed": spec.seed if mode == "sampled" else None,
        "max_cases": spec.max_cases,
        "boundary_cases": info.get("boundary_cases"), "boundary_rule": info.get("boundary_rule"),
        "planned": planned, "cases_run": run,
        "stopped_at_first_divergence": first is not None and not args.all and run < planned,
        "compared": compare, "agree": agree, "diverge": diverging_cases,
        "faults_on_both_sides": fault_kinds,
        "first_divergence": first,
        "divergence_groups": groups if args.all else None,
        "coverage": cov,
        "trace": trace,
    }
    items = []
    if first is not None:
        items.append({"kind": "sweep-divergence",
                      "claim": f"case {first['case']}: {', '.join(first['fields'])} differs",
                      "location": {"address": seg_off(*entry), "case": first["case"]},
                      "value": {"inputs": first["inputs"], "original": first["original"],
                                "candidate": first["candidate"]},
                      "level": "mismatch"})
    if cov["available"]:
        items.append({"kind": "sweep-coverage",
                      "claim": f"{cov['exercised']} of {cov['instructions']} instructions of "
                               f"the body exercised",
                      "location": {"address": seg_off(*entry)},
                      "value": {"percent": cov["percent"]}})
        for u in cov["unreached"]:
            items.append({"kind": "unreached-range",
                          "claim": f"{u['start']}..{u['end']} never ran",
                          "location": {"address": u["start"], "end": u["end"]},
                          "value": {"instructions": u["instructions"]}})
    items.append({"kind": "dgroup", "claim": f"DGROUP 0x{original.dgroup:04x}",
                  "location": {"address": original.dgroup_at} if original.dgroup_at else {},
                  "value": {"how": original.dgroup_how}})
    unknowns = []
    if mode == "sampled":
        unknowns.append(f"What does the routine do on the {info['full_product'] - run:,} "
                        f"inputs of the domain this sampled sweep did not run (seed "
                        f"{spec.seed})?")
    if cov["available"]:
        for u in cov["unreached"]:
            unknowns.append(f"Which input reaches {u['start']}..{u['end']} "
                            f"({u['instructions']} instructions)? No case of this sweep did.")
    else:
        unknowns.append(f"How much of the routine did the sweep exercise? {cov['reason']}.")
    env = evidence.envelope("emuverify sweep", evidence.target_identity(original.exe),
                            status=status, result=result, evidence=items,
                            limitations=limitations(args.cpu), unknowns=unknowns)
    return env, seconds


def summary(env, seconds=None):
    r = env["result"]
    o, c = r["original"], r["candidate"]
    out = []
    dg = f"DGROUP {o['dgroup']} ({o['dgroup_how']}" + \
        (f", at {o['dgroup_set_at']})" if o.get("dgroup_set_at") else ")")
    out.append(f"original   {Path(o['exe']).name} {o['entry']}, "
               f"{'far' if o['far'] else 'near'}; {dg}")
    if c["kind"] == "binary":
        cdg = f"DGROUP {c['dgroup']} ({c['dgroup_how']}" + \
            (f", at {c['dgroup_set_at']})" if c.get("dgroup_set_at") else ")")
        out.append(f"candidate  {Path(c['exe']).name} {c['entry']}, "
                   f"{'far' if c['far'] else 'near'}; {cdg}")
    else:
        out.append(f"candidate  {Path(c['source']).name}:{c['function']} ({c['runtime']})")
    dims = ", ".join(f"{d['name']} {d['values']}" for d in r["domain"]["dimensions"])
    out.append(f"domain     {dims}; {r['domain']['full_product']:,} cases in all")
    how = "exhaustive" if r["mode"] == "exhaustive" else \
        f"sampled, seed {r['seed']}: {r['boundary_cases']:,} boundary ({r['boundary_rule']}), " \
        f"the rest random"
    out.append(f"cases      {r['cases_run']:,} run of {r['planned']:,} ({how})")
    out.append(f"compared   {', '.join(r['compared'])}, and faults")
    out.append("cpu        " + ("8088: IDIV faults on a quotient of -32768 or -128"
                                if r["cpu"] == "8088" else
                                "386: IDIV returns a quotient of -32768 or -128, which an "
                                "8088 refuses"))
    faults = "; ".join(f"{n:,} {k} faults on both sides"
                       for k, n in r["faults_on_both_sides"].items())
    out.append(f"agree      {r['agree']:,}" + (f" ({faults})" if faults else ""))
    if r["diverge"]:
        out.append(f"diverge    {r['diverge']:,}"
                   + (" (stopped at the first; --all for the rest)"
                      if r["stopped_at_first_divergence"] else ""))
    cov = r["coverage"]
    if cov["available"]:
        out.append(f"coverage   {cov['exercised']} of {cov['instructions']} instructions in the "
                   f"body ({cov['percent']}%)")
        for u in cov["unreached"]:
            out.append(f"             never reached: {u['start']}..{u['end']} "
                       f"({u['instructions']} instruction{'s' if u['instructions'] != 1 else ''})")
        if cov["executed_outside_body"]:
            out.append(f"             and {cov['executed_outside_body']} instructions run outside "
                       f"the body: {', '.join(cov['outside_body'][:5])}")
    else:
        out.append(f"coverage   not measured: {cov['reason']}")
    if seconds is not None and r["cases_run"]:
        out.append(f"time       {seconds:.2f} s, {r['cases_run'] / seconds:,.0f} cases/s")
    first = r["first_divergence"]
    if first:
        out.append("")
        out.append(f"first divergence, case {first['case']}:")
        out.append(f"  input      {' '.join(f'{k}={v}' for k, v in first['inputs'].items())}")
        out.append(f"  original   {first['text']['original']}")
        out.append(f"  candidate  {first['text']['candidate']}")
        out.append(f"  differs    {', '.join(first['fields'])}")
    if r.get("divergence_groups"):
        out.append("")
        out.append("divergences by field:")
        for field, g in r["divergence_groups"].items():
            out.append(f"  {field}: {g['cases']:,} cases, e.g.")
            for e in g["examples"]:
                out.append(f"    case {e['case']}: "
                           f"{' '.join(f'{k}={v}' for k, v in e['inputs'].items())}: "
                           f"{e['text']['original']} / {e['text']['candidate']}")
    if r.get("trace"):
        out.append("")
        out.append(f"the original's last {len(r['trace'])} instructions on case {first['case']}:")
        for t in r["trace"]:
            out.append(f"  {t['at']}  {t['instruction']}")
    out.append("")
    if env["status"] == "verified":
        how = "exhaustive" if r["mode"] == "exhaustive" else f"sampled, seed {r['seed']}"
        body = f"{cov['percent']}% of the body exercised" if cov["available"] \
            else "no body to measure coverage against"
        out.append(f"VERIFIED over {r['cases_run']} cases ({how}), {body}")
    else:
        inputs = " ".join(f"{k}={v}" for k, v in first["inputs"].items())
        out.append(f"MISMATCH at case {first['case']}: {inputs}: {', '.join(first['fields'])} "
                   f"differs -- original {first['text']['original']}; "
                   f"candidate {first['text']['candidate']}")
    return "\n".join(out)


def parser(prog="emuverify.py sweep"):
    """The command line's argument parser: the MCP server parses its own
    arguments with it, so a sweep there has exactly the command line's
    defaults."""
    import argparse
    ap = argparse.ArgumentParser(prog=prog, description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", help="the original program")
    ap.add_argument("entry", help="the routine, segment:offset as functions.json writes it")
    ap.add_argument("--domain", required=True, help="the domain, a JSON file")
    ap.add_argument("--candidate", help="ref.py:function or port.mjs:function")
    ap.add_argument("--candidate-exe", help="a rebuilt binary to compare instead")
    ap.add_argument("--candidate-entry", help="the routine in --candidate-exe, segment:offset")
    ap.add_argument("--candidate-load-segment",
                    help="the load segment --candidate-entry is written against "
                         "(default: the original's)")
    ap.add_argument("--functions", help="the pipeline's functions.json for the original: "
                                        "the routine's body, for coverage")
    ap.add_argument("--load-segment", help="the load segment the entry is written against "
                                           "(default: functions.json's, else 0x1000; 0 for a "
                                           "linker map's addresses)")
    ap.add_argument("--dgroup", help="the original's data segment paragraph, if known")
    ap.add_argument("--candidate-dgroup", help="the same for --candidate-exe")
    side = ap.add_mutually_exclusive_group()
    side.add_argument("--far", action="store_true", help="enter the routine with a far call")
    side.add_argument("--near", action="store_true", help="enter it with a near call")
    ap.add_argument("--max-cases", type=int, help="override the domain's max_cases")
    ap.add_argument("--seed", type=int, help="override the domain's seed")
    ap.add_argument("--budget", type=int, default=emuverify.MAX_INSNS,
                    help=f"instructions per case before it counts as a hang "
                         f"(default {emuverify.MAX_INSNS})")
    ap.add_argument("--cpu", choices=CPUS, default="8088",
                    help="8088 (default): IDIV also faults on a quotient of exactly -32768 "
                         "or -128, as the machines these games ran on did. 386: as Unicorn "
                         "divides, which returns them. Both sides of a binary candidate run "
                         "on the same CPU")
    ap.add_argument("--all", action="store_true",
                    help="run every case and group the divergences by field")
    ap.add_argument("--case-timeout", type=float, default=CASE_TIMEOUT, metavar="SECONDS",
                    help=f"how long a Python or JavaScript candidate may take over one case "
                         f"before it counts as a hang (default {CASE_TIMEOUT:g})")
    ap.add_argument("--trace-on-divergence", type=int, metavar="N", default=0,
                    help="the last N instructions the original ran on the first divergent case")
    ap.add_argument("--evidence", help="write the envelope here, or '-' for stdout")
    ap.add_argument("--quiet", action="store_true", help="no progress lines on stderr")
    ap.add_argument("--accept-profile-drift", action="store_true",
                    help="read functions.json although its handshake.json says it drifted")
    return ap


def main(argv, prog="emuverify.py sweep"):
    args = parser(prog).parse_args(argv)

    def progress(msg):
        if not args.quiet:
            print(f"  {msg}", file=sys.stderr, flush=True)

    try:
        env, seconds = run_sweep(args, progress)
    except Blocked as e:
        env = evidence.envelope("emuverify sweep",
                                evidence.target_identity(args.exe) if Path(args.exe).is_file()
                                else None, status="blocked",
                                result={"reason": str(e)}, limitations=limitations(args.cpu))
        if args.evidence:
            evidence.write(env, args.evidence)
        print(f"emuverify.py sweep: {e}", file=sys.stderr)
        return 3
    if args.evidence:
        evidence.write(env, args.evidence)
    if args.evidence != "-":
        print(summary(env, seconds))
    return 0 if env["status"] == "verified" else 1
