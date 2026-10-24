#!/usr/bin/env python3
"""Checks for comdiff.py, the routine-by-routine comparison of two .COM files.

The fixtures are two sibling programs written for the purpose (fixtures/),
related the way Moon Bugs is to Rollo: cmpb.asm's header lists what each of
its routines is to cmpa.asm, and every line of that table is checked here --
the kind, the counterpart, and for an instruction-identical pair whether
running both confirms it. Both are assembled with NASM and reconstructed
with comrec.py, so the comparison reads exactly what a user's listings hold.

Then the refusals: a listing that does not rebuild its file, and an MZ.

Usage:
    python tests/comdiff/regress.py [--nasm PATH]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

CASES = []


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


class Built:
    """Both fixtures assembled, reconstructed, and their labels' offsets."""

    def __init__(self, nasm, work):
        self.nasm, self.work = nasm, work
        self.com, self.asm, self.at = {}, {}, {}
        for name in ("cmpa", "cmpb"):
            src = HERE / "fixtures" / f"{name}.asm"
            com, lst = work / f"{name}.com", work / f"{name}.lst"
            subprocess.run([nasm, "-f", "bin", "-o", str(com), "-l", str(lst), str(src)],
                           check=True)
            asm = work / f"{name}-comrec.asm"
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "comrec.py"), str(com),
                                "--out", str(asm), "--nasm", nasm],
                               capture_output=True, text=True)
            if "BYTE-IDENTICAL" not in r.stdout:
                raise SystemExit(f"comrec did not rebuild {name}: {r.stdout[-400:]}")
            self.com[name], self.asm[name] = com, asm
            self.at[name] = labels(lst)


def labels(lst):
    """{label: file offset} from NASM's listing: a label line carries no
    offset, so it takes the next line's."""
    out, pending = {}, []
    for raw in lst.read_text(encoding="latin-1").splitlines():
        # The bytes column carries relocations in brackets: `A1[D100]`.
        m = re.match(r"\s*\d+\s+([0-9A-F]{8})\s+[0-9A-F]\S*\s+(?:(\w+):)?", raw)
        if m:
            for name in pending + ([m.group(2)] if m.group(2) else []):
                out[name] = int(m.group(1), 16)
            pending = []
            continue
        m = re.match(r"\s*\d+\s+(\w+):", raw)
        if m:
            pending.append(m.group(1))
    return out


B = None          # set in main()
RESULT = None


def row(name):
    at = B.at["cmpb"][name]
    for r in RESULT["pairs"]:
        if r["b"] == at:
            return r
    raise AssertionError(f"no routine of B starts at {name} (0x{at:05X})")


def expect(name, status, counterpart=None):
    r = row(name)
    if r["status"] != status:
        raise AssertionError(f"{name}: {r['status']}, not {status}")
    if counterpart and B.at["cmpa"][counterpart] not in r.get("a", []):
        raise AssertionError(f"{name}: counterpart {r.get('a')}, not A's {counterpart}")
    return r


@case("the same bytes: byte-identical")
def _():
    r = expect("times_ten", "byte-identical", "times_ten")
    if r["score"] != 1.0 or "numbers" in r:
        raise AssertionError(f"{r}")
    return "times_ten, score 1.0"


@case("the same instructions with moved globals: confirmed by running both")
def _():
    r = expect("accumulate", "instruction-identical", "accumulate")
    if r["emulation"]["result"] != "confirmed":
        raise AssertionError(f"emulation: {r['emulation']}")
    return "confirmed on 4 vectors"


@case("the numbers that differ map A's globals onto B's")
def _():
    r = row("accumulate")
    want = [("address", B.at["cmpa"][g] + 0x100, B.at["cmpb"][g] + 0x100)
            for g in ("counter", "step", "result")]
    have = [tuple(n) for n in r["numbers"]]
    missing = [w for w in want if w not in have]
    if missing:
        raise AssertionError(f"missing {missing}; have {have}")
    return f"{len(want)} globals paired, and the callee's address"


@case("the same instructions, a different count: emulation says they differ")
def _():
    r = expect("find_key", "instruction-identical", "find_key")
    e = r["emulation"]
    if e["result"] != "differs" or "return frame" not in e["why"]:
        raise AssertionError(f"emulation: {e}")
    return e["why"]


@case("one instruction inserted: similar, with its score")
def _():
    r = expect("halve_twice", "similar", "halve_twice")
    if not 0.85 <= r["score"] < 1.0:
        raise AssertionError(f"score {r['score']}")
    return f"score {r['score']}"


@case("a routine only B has: no counterpart")
def _():
    r = expect("beep", "no counterpart")
    if r["best_score"] >= 0.85:
        raise AssertionError(f"best score {r['best_score']}")
    return f"nearest scored {r['best_score']}"


@case("a three-byte routine is too small to classify")
def _():
    expect("one", "too small")
    return "one"


@case("a switch's cases are part of it, not routines")
def _():
    starts = {r["b"] for r in RESULT["pairs"]}
    cases = [B.at["cmpb"][f"case{i}"] for i in range(4)]
    if starts & set(cases):
        raise AssertionError(f"cases read as routines: {sorted(starts & set(cases))}")
    r = expect("pick", "instruction-identical", "pick")
    if r["data_same"]:
        raise AssertionError("the table moved, so its words cannot be the same")
    if RESULT["b"]["jump_table_cases"] != 4:
        raise AssertionError(f"{RESULT['b']['jump_table_cases']} cases counted")
    return "4 cases inside pick; its table differs, its instructions do not"


@case("a handler nothing branches to is a routine, and iret ends it")
def _():
    r = expect("tick", "instruction-identical", "tick")
    if RESULT["b"]["starts"]["nothing branches here"] != 1:
        raise AssertionError(f"starts: {RESULT['b']['starts']}")
    if r["emulation"]["result"] != "confirmed":
        raise AssertionError(f"emulation: {r['emulation']}")
    return "tick, confirmed"


@case("the entry: calls to other routines are numbers, the rest agrees")
def _():
    r = expect("start", "instruction-identical", "start")
    kinds = {n[0] for n in r["numbers"]}
    if "target" not in kinds:
        raise AssertionError(f"numbers {r['numbers']}")
    return "instruction-identical, call targets differ"


@case("every row is accounted for")
def _():
    c = RESULT["counts"]
    want = {"byte-identical": 1, "instruction-identical": 5, "similar": 1,
            "no counterpart": 1, "too small": 1}
    if c != want:
        raise AssertionError(f"counts {c}")
    e = RESULT["emulation"]
    if e != {"confirmed": 4, "differs": 1, "uninformative": 0, "not run": 0}:
        raise AssertionError(f"emulation {e}")
    return "1 / 5 / 1 / 1 / 1; 4 confirmed, 1 differs"


@case("a program against itself: every routine byte-identical to itself")
def _():
    import comdiff
    res = comdiff.compare(B.com["cmpa"], B.asm["cmpa"], B.com["cmpa"], B.asm["cmpa"],
                          emulate=False, nasm=B.nasm)
    wrong = [r for r in res["pairs"] if r["status"] not in ("byte-identical", "too small")
             or (r["status"] == "byte-identical" and r["b"] not in r["a"])]
    if wrong:
        raise AssertionError(f"{len(wrong)} rows: {wrong[:2]}")
    return f"{res['counts']['byte-identical']} of {res['a']['considered']}"


@case("without emulation the pairs say why they were not run")
def _():
    import comdiff
    res = comdiff.compare(B.com["cmpa"], B.asm["cmpa"], B.com["cmpb"], B.asm["cmpb"],
                          emulate=False, nasm=B.nasm)
    if res["emulation"] is not None or res["emulation_skipped"] != "not asked for" \
            or any("emulation" in r for r in res["pairs"]):
        raise AssertionError(f"{res['emulation']}, {res['emulation_skipped']}")
    return "not asked for"


@case("a listing that does not rebuild its file is refused")
def _():
    import comdiff
    bad = B.work / "cmpb-changed.com"
    data = bytearray(B.com["cmpb"].read_bytes())
    data[B.at["cmpb"]["times_ten"]] ^= 0xFF
    bad.write_bytes(bytes(data))
    try:
        comdiff.compare(B.com["cmpa"], B.asm["cmpa"], bad, B.asm["cmpb"], nasm=B.nasm)
    except comdiff.Refused as e:
        if "does not rebuild" not in str(e) or "comrec" not in str(e):
            raise AssertionError(f"message: {e}")
        return "refused, and told to regenerate it"
    raise AssertionError("compared a listing of another file")


@case("an MZ is refused, with where to take it")
def _():
    import comdiff
    mz = B.work / "x.exe"
    mz.write_bytes(b"MZ" + bytes(62))
    try:
        comdiff.compare(mz, B.asm["cmpa"], B.com["cmpb"], B.asm["cmpb"], nasm=B.nasm)
    except comdiff.Refused as e:
        if "bindiff.py or emuverify.py" not in str(e):
            raise AssertionError(f"message: {e}")
        return "refused"
    raise AssertionError("compared an MZ")


@case("the envelope: identical pairs as evidence, the one that differs unknown")
def _():
    import comdiff
    env = comdiff.envelope(RESULT)
    kinds = [e["kind"] for e in env["evidence"]]
    if env["status"] != "ok" or kinds.count("listing-rebuilds") != 2 \
            or kinds.count("instruction-identical") != 5 or kinds.count("byte-identical") != 1:
        raise AssertionError(f"status {env['status']}, kinds {kinds}")
    if len(env["unknowns"]) != 1 or "behave differently" not in env["unknowns"][0]:
        raise AssertionError(f"unknowns {env['unknowns']}")
    json.dumps(env)
    return f"{len(env['evidence'])} items, 1 unknown"


# ---------------------------------------------------------------- the rules, one at a time
#
# The cases above run two whole programs. These check each rule on the bytes
# that test it, through programs read from bytes alone: a list of chunks,
# code or ("data", bytes), decoded linearly, cut into routines at `starts`.

def synthetic(*chunks, starts=(0,), segments=()):
    import comdiff
    import comrec
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    p = comdiff.Program.__new__(comdiff.Program)
    p.com = p.asm = Path("synthetic")
    image, code = b"", []
    for chunk in chunks:
        if isinstance(chunk, tuple):
            image += chunk[1]
        else:
            code.append((len(image), len(image) + len(chunk)))
            image += chunk
    p.image = image
    p.segments = comrec.parse_segments(list(segments), len(image))
    walker = Cs(CS_ARCH_X86, CS_MODE_16)
    p.decoded = {}
    for lo, hi in code:
        seg = p.segment(lo)
        for insn in walker.disasm(image[lo:hi], seg.addr(lo)):
            p.decoded[seg.file_off(insn.address)] = insn.size
    p.md = Cs(CS_ARCH_X86, CS_MODE_16)
    p.md.detail = True
    p.routines = p._routines(sorted(starts))
    return p


def routine_at(p, start):
    return next(r for r in p.routines if r["start"] == start)


NOP, RET = b"\x90", b"\xC3"


@case("shape: every operand form, and the numbers it leaves out")
def _():
    import comdiff
    p = synthetic(bytes.fromhex(
        "89D8"          # mov ax, bx
        "B005"          # mov al, 5
        "83C0FF"        # add ax, -1
        "B80180"        # mov ax, 0x8001
        "A13412"        # mov ax, [0x1234]
        "8B47FE"        # mov ax, [bx - 2]
        "8A4010"        # mov al, [bx + si + 0x10]
        "8B4604"        # mov ax, [bp + 4]
        "26A11000"      # mov ax, [es:0x10]
        "FF27"          # jmp word [bx]
        "9A78563412"    # lcall 0x1234:0x5678
        "CD21"          # int 0x21 -- one immediate operand, and not a branch
        "C3"))          # ret
    exact, fuzzy, numbers = comdiff.shape(p, p.routines[0])
    want = [("mov", (("r", "ax"), ("r", "bx"))),
            ("mov", (("r", "al"), ("imm", 1))),
            ("add", (("r", "ax"), ("imm", 2))),
            ("mov", (("r", "ax"), ("imm", 2))),
            ("mov", (("r", "ax"), ("m", 2, None, None, None))),
            ("mov", (("r", "ax"), ("m", 2, None, "bx", None))),
            ("mov", (("r", "al"), ("m", 1, None, "bx", "si"))),
            ("mov", (("r", "ax"), ("m", 2, None, "bp", None, 4))),
            ("mov", (("r", "ax"), ("m", 2, "es", None, None))),
            ("jmp", (("m", 2, None, "bx", None),)),
            ("lcall", (("imm", 2), ("imm", 4))),
            ("int", (("imm", 1),)),
            ("ret", ())]
    want_numbers = [(), (("immediate", 5),), (("immediate", 0xFFFF),),
                    (("immediate", 0x8001),), (("address", 0x1234),),
                    (("displacement", 0xFFFE),), (("displacement", 0x10),), (),
                    (("address", 0x10),), (("displacement", 0),),
                    (("immediate", 0x1234), ("immediate", 0x5678)),
                    (("immediate", 0x21),), ()]
    if list(exact) != want or list(fuzzy) != want or numbers != want_numbers:
        raise AssertionError(f"exact {exact}\nnumbers {numbers}")
    return "13 forms and their numbers, exactly"


@case("shape: branches inside the routine by index, outside as numbers, wrapped too")
def _():
    import comdiff
    # A five-byte routine first, so that the one examined starts at 5 and a
    # landing in the middle of an instruction is counted from there.
    p = synthetic(NOP * 4 + RET, bytes.fromhex(
        "E8F9F0"        # 05  call 0xF201 -- below the call, so capstone wraps it
        "E845FF"        # 08  call 0x0050 -- below the segment's base
        "EB00"          # 0B  jmp short 0D, the next instruction
        "74F6"          # 0D  je 05, the routine's own start
        "EB05"          # 0F  jmp short 16, inside the add below
        "B80100"        # 11  mov ax, 1
        "81003412"      # 14  add word [bx + si], 0x1234
        "C3"),          # 18  ret
        starts=(0, 5))
    exact, fuzzy, numbers = comdiff.shape(p, routine_at(p, 5))
    want = [("call", (("out",),)), ("call", (("out",),)), ("jmp", (("to", 3),)),
            ("je", (("to", 0),)), ("jmp", (("to", ("byte", 17)),)),
            ("mov", (("r", "ax"), ("imm", 2))),
            ("add", (("m", 2, None, "bx", "si"), ("imm", 2))), ("ret", ())]
    want_fuzzy = [("call", (("out",),)), ("call", (("out",),)), ("jmp", (("to",),)),
                  ("je", (("to",),)), ("jmp", (("to",),)),
                  ("mov", (("r", "ax"), ("imm", 2))),
                  ("add", (("m", 2, None, "bx", "si"), ("imm", 2))), ("ret", ())]
    want_numbers = [(("target", 0xF201),), (("target", 0x0050),), (), (), (),
                    (("immediate", 1),), (("displacement", 0), ("immediate", 0x1234)), ()]
    if list(exact) != want or list(fuzzy) != want_fuzzy or numbers != want_numbers:
        raise AssertionError(f"exact {exact}\nfuzzy {fuzzy}\nnumbers {numbers}")
    return "to 3, to 0, to byte 17; targets 0xF201 and 0x0050"


@case("differing numbers: once each, in order, either way round, by value")
def _():
    import comdiff
    big_a, big_b = int("4660"), int("4660")        # equal, two objects
    a = [(("address", 0x10),), (("immediate", 5), ("address", 0x20)),
         (("address", 0x10),), (("immediate", big_a),)]
    b = [(("address", 0x30),), (("immediate", 5), ("address", 0x08)),
         (("address", 0x30),), (("immediate", big_b),)]
    got = comdiff.differing_numbers(a, b)
    if got != [("address", 0x10, 0x30), ("address", 0x20, 0x08)]:
        raise AssertionError(f"{got}")
    return "2 pairs"


@case("_same: equal, or apart by one of the differences, within the width")
def _():
    import comdiff
    s = comdiff._same
    checks = [(s(5, 5, set()), True), (s(5, 8, set()), False), (s(8, 5, set()), False),
              (s(5, 8, {3}), True), (s(8, 5, {3}), False), (s(8, 5, {0xFFFD}), True),
              (s(3, 7, {4}), True), (s(0, 0x8000, {0}), False), (s(5, 8, {2}), False),
              (s(5, 6, {0x0101}, 8), True), (s(5, 6, {0x0101}), False),
              (s(0, 0xFF, {0xFFFF}, 8), True), (s(0, 0xFF, {0xFFFF}), False)]
    wrong = [i for i, (got, want) in enumerate(checks) if got != want]
    if wrong:
        raise AssertionError(f"checks {wrong} wrong")
    return f"{len(checks)} cases"


def obs(end="returned", events=(), **regs):
    base = {n: 0 for n in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")}
    base["flags"] = 0
    base.update(regs)
    return {"end": end, "events": list(events), "regs": base}


@case("first_difference: every kind of difference, named exactly")
def _():
    import comdiff
    fd = comdiff.first_difference
    checks = [
        (fd(obs(), obs(), set()), None),
        (fd(obs("returned"), obs("left the routine"), set()),
         "one returned, the other left the routine"),
        (fd(obs("left the routine"), obs("returned"), set()),
         "one left the routine, the other returned"),
        (fd(obs(f"stopped at IP 0x{0x12:04X}"), obs(f"stopped at IP 0x{0x12:04X}"), set()),
         None),
        (fd(obs(events=[("r", 7, 2)]), obs(events=[("w", 7, 2, 0)]), set()),
         "event 0: r against w"),
        (fd(obs(events=[("w", 7, 2, 0)]), obs(events=[("r", 7, 2)]), set()),
         "event 0: w against r"),
        (fd(obs(events=[("r", 7, 2)]), obs(events=[("r", 9, 2)]), set()),
         "event 0: one reads 2 bytes at touched byte #7, the other 2 bytes at touched "
         "byte #9"),
        (fd(obs(events=[("r", 9, 1)]), obs(events=[("r", 7, 2)]), set()),
         "event 0: one reads 1 byte at touched byte #9, the other 2 bytes at touched "
         "byte #7"),
        (fd(obs(events=[("r", 0, 2)]), obs(events=[("r", 8, 1)]), set()),
         "event 0: one reads 2 bytes at the return frame, the other 1 byte at touched "
         "byte #8"),
        (fd(obs(events=[("w", 6, 2, 5)]), obs(events=[("w", 7, 2, 5)]), set()),
         "event 0: one writes 2 bytes at touched byte #6, the other 2 bytes at touched "
         "byte #7"),
        (fd(obs(events=[("w", 7, 1, 5)]), obs(events=[("w", 6, 2, 5)]), set()),
         "event 0: one writes 1 byte at touched byte #7, the other 2 bytes at touched "
         "byte #6"),
        (fd(obs(events=[("w", 6, 2, 5)]), obs(events=[("w", 6, 2, 7)]), set()),
         "event 0: writes 0x5 against 0x7"),
        (fd(obs(events=[("w", 6, 2, 5)]), obs(events=[("w", 6, 2, 7)]), {2}), None),
        # Byte writes compare in eight bits, word writes in sixteen.
        (fd(obs(events=[("w", 6, 1, 0x01)]), obs(events=[("w", 6, 1, 0x00)]), {0xFF}),
         None),
        (fd(obs(events=[("w", 6, 1, 0x00)]), obs(events=[("w", 6, 1, 0x80)]), {0x100}),
         "event 0: writes 0x0 against 0x80"),
        (fd(obs(events=[("w", 6, 2, 0x0001)]), obs(events=[("w", 6, 2, 0x0000)]),
            {0xFFFF}), None),
        (fd(obs(events=[("w", 6, 2, 0x0000)]), obs(events=[("w", 6, 2, 0x0080)]),
            {0x100}), "event 0: writes 0x0 against 0x80"),
        (fd(obs(events=[("in", 0x60)]), obs(events=[("in", 0x61)]), set()),
         "event 0: reads port 0x60 against 0x61"),
        (fd(obs(events=[("in", 0x60)]), obs(events=[("in", 0x61)]), {1}), None),
        (fd(obs(events=[("out", 0x20, 0x61)]), obs(events=[("out", 0x21, 0x61)]), set()),
         "event 0: port 0x20 <- 0x61 against port 0x21 <- 0x61"),
        (fd(obs(events=[("out", 0x20, 0x60)]), obs(events=[("out", 0x20, 0x61)]), set()),
         "event 0: port 0x20 <- 0x60 against port 0x20 <- 0x61"),
        (fd(obs(events=[("out", 0x20, 0x30)]), obs(events=[("out", 0x21, 0x61)]), {1}),
         "event 0: port 0x20 <- 0x30 against port 0x21 <- 0x61"),
        (fd(obs(events=[("out", 0x20, 0x30)]), obs(events=[("out", 0x21, 0x31)]), {1}),
         None),
        (fd(obs(events=[("out", 0x60, 0x20)]), obs(events=[("out", 0x60, 0x60)]), set()),
         "event 0: port 0x60 <- 0x20 against port 0x60 <- 0x60"),
        (fd(obs(events=[("out", 0x60, 0x20)]), obs(events=[("out", 0x20, 0x20)]), set()),
         "event 0: port 0x60 <- 0x20 against port 0x20 <- 0x20"),
        (fd(obs(events=[("int", 0x21, 0x09)]), obs(events=[("int", 0x21, 0x02)]), set()),
         "event 0: INT 21h AH=09 against INT 21h AH=02"),
        (fd(obs(events=[("int", 0x21, 0x02)]), obs(events=[("int", 0x21, 0x09)]), {7}),
         "event 0: INT 21h AH=02 against INT 21h AH=09"),
        (fd(obs(events=[("int", 0x10, 0)]), obs(events=[("int", 0x21, 0)]), set()),
         "event 0: INT 10h AH=00 against INT 21h AH=00"),
        (fd(obs(events=[("int", 0x21, 0)]), obs(events=[("int", 0x20, 0)]), {0xFF}), None),
        (fd(obs(events=[("int", 0x00, 0)]), obs(events=[("int", 0x80, 0)]), {0x100}),
         "event 0: INT 00h AH=00 against INT 80h AH=00"),
        (fd(obs(events=[("call",), ("in", 0x60)]), obs(events=[("call",), ("in", 0x64)]),
            set()), "event 1: reads port 0x60 against 0x64"),
        (fd(obs(events=[("call",), ("call",)]), obs(events=[("call",)] * 3), set()),
         "2 events against 3"),
        (fd(obs(events=[("call",)] * 3), obs(events=[("call",)] * 2), set()),
         "3 events against 2"),
        (fd(obs(events=[("call",)] * 300), obs(events=[("call",)] * 300), set()), None),
        (fd(obs(ax=1), obs(ax=2), set()), "ax 0x0001 against 0x0002"),
        (fd(obs(ax=1), obs(ax=2), {1}), None),
        (fd(obs(si=1), obs(si=2), {1}), None),
        (fd(obs(sp=0xFF00), obs(sp=0xFEFE), set()), "sp 0xFF00 against 0xFEFE"),
        (fd(obs(flags=0x0001), obs(flags=0x0041), {0x40}), "flags 0x0001 against 0x0041"),
        (fd(obs(flags=0x0041), obs(flags=0x0001), set()), "flags 0x0041 against 0x0001"),
        (fd(obs(flags=int("2049")), obs(flags=int("2049")), set()), None),
    ]
    wrong = [(i, got, want) for i, (got, want) in enumerate(checks) if got != want]
    if wrong:
        raise AssertionError(f"{len(wrong)} wrong, first: {wrong[0]}")
    return f"{len(checks)} cases, every message exact"


@case("_acts: the return frame and a bare departure say nothing")
def _():
    import comdiff
    checks = [(("r", 0, 2), False), (("r", 5, 1), False), (("r", 6, 1), True),
              (("r", 7, 1), True),
              (("w", 5, 2, 0), False), (("w", 6, 2, 0), True), (("left",), False),
              (("call",), True), (("in", 0x60), True), (("out", 0x20, 0x20), True),
              (("int", 0x21, 0), True)]
    wrong = [e for e, want in checks if comdiff._acts(e) != want]
    if wrong:
        raise AssertionError(f"wrong for {wrong}")
    return f"{len(checks)} events"


def pair_confirm(code_a, code_b, starts=(0,), segments=()):
    import comdiff
    a = synthetic(code_a, starts=starts, segments=segments)
    b = synthetic(code_b, starts=starts, segments=segments)
    ra, rb = a.routines[-1], b.routines[-1]
    numbers = comdiff.differing_numbers(comdiff.shape(a, ra)[2], comdiff.shape(b, rb)[2])
    return comdiff.confirm(a, ra, b, rb, numbers)


@case("confirm: a routine that does nothing is uninformative, not confirmed")
def _():
    got = pair_confirm(NOP * 11 + RET, NOP * 11 + RET)
    if got != {"result": "uninformative",
               "why": "touched nothing and changed no register on any vector"}:
        raise AssertionError(f"{got}")
    return "uninformative"


@case("confirm: one changed register is something, whichever way it moved")
def _():
    down = pair_confirm(bytes.fromhex("31F6") + NOP * 9 + RET,        # xor si, si
                        bytes.fromhex("31F6") + NOP * 9 + RET)
    up = pair_confirm(bytes.fromhex("BEFFFF") + NOP * 8 + RET,       # mov si, 0xFFFF
                      bytes.fromhex("BEFFFF") + NOP * 8 + RET)
    want = {"result": "confirmed", "vectors": 4}
    if down != want or up != want:
        raise AssertionError(f"xor: {down}; mov: {up}")
    return "both confirmed"


@case("confirm: an address that differs by the pair's own difference agrees")
def _():
    got = pair_confirm(bytes.fromhex("BE3512") + NOP * 8 + RET,      # mov si, 0x1235
                       bytes.fromhex("BE3212") + NOP * 8 + RET)      # mov si, 0x1232
    if got != {"result": "confirmed", "vectors": 4}:
        raise AssertionError(f"{got}")
    return "0xFFFD apart, confirmed"


@case("confirm: a fault, and a segment off a paragraph, are not run")
def _():
    fault = pair_confirm(bytes.fromhex("0F0B") + NOP * 9 + RET,      # ud2
                         bytes.fromhex("0F0B") + NOP * 9 + RET)
    # The second segment starts at file 3 with base 0: CS would have to be
    # 0x100 + 3 bytes above the PSP, which is no paragraph.
    code = NOP * 3 + bytes.fromhex("31F6") + NOP * 9 + RET
    odd = pair_confirm(code, code, starts=(0, 3), segments=["0x3:0x0"])
    if fault != {"result": "not run", "why": "a fault on vector 0"}:
        raise AssertionError(f"fault: {fault}")
    if odd != {"result": "not run", "why": "its segment does not start on a paragraph"}:
        raise AssertionError(f"segment: {odd}")
    return "both say why"


def classified(a_chunks, b_chunks, similar=0.85):
    """classify() on two synthetic programs, each a five-byte routine at 0
    (too small to count) and its routines after; {start: row} for B."""
    import comdiff
    a = synthetic(NOP * 4 + RET, *a_chunks[0], starts=(0,) + a_chunks[1])
    b = synthetic(NOP * 4 + RET, *b_chunks[0], starts=(0,) + b_chunks[1])
    return {r["b"]: r for r in comdiff.classify(a, b, similar=similar)}


INC, DEC = b"\x40", b"\x48"            # inc ax, dec ax: one byte, one token each
ADD_SI = bytes.fromhex("81003412")     # add word [bx + si], 0x1234: four bytes
ADD_DI = bytes.fromhex("81013412")     # the same into [bx + di]


@case("classify: A's routines under the minimum are no counterparts")
def _():
    # The same shape in both, but A's is 11 bytes and B's 12.
    rows = classified(([bytes.fromhex("8A4704") + NOP * 7 + RET], (5,)),
                      ([bytes.fromhex("8A873412") + NOP * 7 + RET], (5,)))
    want = {"status": "no counterpart", "best_score": 0.0, "nearest": []}
    got = {k: rows[5].get(k) for k in want}
    if rows[0]["status"] != "too small" or got != want:
        raise AssertionError(f"{rows}")
    return "no counterpart, nearest scored 0.0"


@case("classify: a routine of exactly the minimum is a candidate, rounded to 3 places")
def _():
    rows = classified(([bytes.fromhex("8A873412") + NOP * 6 + INC + RET], (5,)),
                      ([bytes.fromhex("8A873412") + NOP * 7 + RET], (5,)))
    want = {"status": "similar", "a": [5], "score": 0.889}
    got = {k: rows[5].get(k) for k in want}
    if got != want:
        raise AssertionError(f"{rows[5]}")
    return "similar to the 12-byte routine, 0.889"


@case("classify: the best counterpart wins, ties are all listed, in order")
def _():
    # c1 0.833, c2 three tokens (too short to beat it: skipped, not the
    # end of the search), c3 and c4 0.917 each, and c5 last: c3's tokens in
    # another order, so that no quick bound rules it out and only its ratio,
    # 0.833, puts it below them.
    c1, c2 = INC * 9 + DEC * 2 + RET, ADD_SI * 3
    c3 = c4 = INC * 10 + DEC + RET
    c5 = RET + INC * 10 + DEC
    starts = (5, 17, 29, 41, 53)
    rows = classified(([c1, c2, c3, c4, c5], starts), ([INC * 11 + RET], (5,)))
    want = {"status": "similar", "a": [29, 41], "score": 0.917}
    got = {k: rows[5].get(k) for k in want}
    if got != want:
        raise AssertionError(f"{rows[5]}")
    near = classified(([c1, c2], (5, 17)), ([INC * 11 + RET], (5,)))[5]
    if (near["status"], near["best_score"], near["nearest"]) != ("no counterpart", 0.833, [5]):
        raise AssertionError(f"{near}")
    return "c3 and c4 at 0.917; without them, 0.833 nearest"


@case("classify: the same instructions but for a branch's landing: similar at 1.0")
def _():
    # jmp short over one byte, against one onto the next instruction: the
    # fuzzy forms agree, the exact ones do not. Two such candidates tie.
    a = bytes.fromhex("EB01") + INC * 10 + RET
    rows = classified(([a, a], (5, 18)), ([bytes.fromhex("EB00") + INC * 10 + RET], (5,)))
    want = {"status": "similar", "a": [5, 18], "score": 1.0}
    got = {k: rows[5].get(k) for k in want}
    if got != want:
        raise AssertionError(f"{rows[5]}")
    return "1.0 twice, not instruction-identical"


@case("classify: a long routine's commonest instruction still counts")
def _():
    # Two hundred of one instruction, and nothing rarer in common to anchor
    # a match: difflib's junk rule, on for 200 items or more, would drop the
    # common one and score the pair 0. B leaves by a near jump back to 0.
    rows = classified(([DEC + INC * 200 + RET], (5,)),
                      ([INC * 200 + bytes.fromhex("E930FF")], (5,)))
    if rows[5].get("status") != "similar" or rows[5].get("score") != 0.993:
        raise AssertionError(f"{rows[5]}")
    return "0.993"


@case("shape: a call that wraps to 0xFFFF lands there, not at 0")
def _():
    import comdiff
    p = synthetic(bytes.fromhex("E8FCFE") + NOP * 8 + RET)   # call 0xFFFF from 0x100
    _, _, numbers = comdiff.shape(p, p.routines[0])
    if numbers[0] != (("target", 0xFFFF),):
        raise AssertionError(f"{numbers[0]}")
    # The same in a segment based at 0, where the call's own segment holds
    # address 0: wrapped wrongly, -1 would land on the routine's first byte.
    p = synthetic(NOP * 16, bytes.fromhex("E8FCFF") + NOP * 8 + RET,
                  starts=(0, 16), segments=["0x10:0x0"])
    exact, _, numbers = comdiff.shape(p, routine_at(p, 16))
    if exact[0] != ("call", (("out",),)) or numbers[0] != (("target", 0xFFFF),):
        raise AssertionError(f"{exact[0]}, {numbers[0]}")
    return "0xFFFF, from a segment at 0x100 and one at 0"


@case("classify: a score exactly at the threshold is similar")
def _():
    rows = classified(([ADD_SI * 3 + ADD_DI + RET], (5,)), ([ADD_SI * 4 + RET], (5,)),
                      similar=0.8)
    if (rows[5].get("status"), rows[5].get("score")) != ("similar", 0.8):
        raise AssertionError(f"{rows[5]}")
    return "0.8 at 0.8"


@case("classify: nothing in common scores 0, with no nearest")
def _():
    # B's routine ends in a jump back to the routine before it, so it shares
    # not even a ret with A's.
    rows = classified(([INC * 11 + RET], (5,)), ([DEC * 11 + bytes.fromhex("EBE8")], (5,)))
    got = (rows[5].get("status"), rows[5].get("best_score"), rows[5].get("nearest"))
    if got != ("no counterpart", 0.0, []):
        raise AssertionError(f"{rows[5]}")
    return "0.0, nearest []"


@case("classify: several twins: the numbers are against the first")
def _():
    one = bytes.fromhex("A11111") + NOP * 8 + RET
    two = bytes.fromhex("A12222") + NOP * 8 + RET
    rows = classified(([one, two], (5, 17)), ([bytes.fromhex("A13333") + NOP * 8 + RET], (5,)))
    r = rows[5]
    if (r.get("status"), r.get("a"), r.get("score"), r.get("numbers")) != \
            ("instruction-identical", [5, 17], 1.0, [("address", 0x1111, 0x3333)]):
        raise AssertionError(f"{r}")
    return "against 0x1111, the first"


@case("classify: the data between instructions is compared, and only it")
def _():
    # add ax, bx is 01 D8 in A and 03 C3 in B -- the same instruction --
    # and the address differs: neither is data. The two bytes after the jump
    # are, and they decide.
    def prog(add, addr, data):
        return ([bytes.fromhex(add + "A1" + addr + "EB02"), ("data", data), NOP * 3 + RET], (5,))
    same = classified(prog("01D8", "3412", b"XY"), prog("03C3", "7856", b"XY"))[5]
    diff = classified(prog("01D8", "3412", b"XY"), prog("03C3", "7856", b"AY"))[5]
    if (same.get("status"), same.get("data_same"), diff.get("data_same")) != \
            ("instruction-identical", True, False) or same["data_bytes"] != 2:
        raise AssertionError(f"same {same}\ndiff {diff}")
    return "XY and XY the same, XY and AY not"


def main():
    global B, RESULT
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nasm", default=os.environ.get("NASM") or shutil.which("nasm"))
    args = ap.parse_args()
    if not args.nasm or not Path(args.nasm).exists():
        print("NASM not found (pass --nasm, set NASM, or put it on PATH)")
        return 77
    import comdiff
    with tempfile.TemporaryDirectory() as td:
        B = Built(args.nasm, Path(td))
        RESULT = comdiff.compare(B.com["cmpa"], B.asm["cmpa"], B.com["cmpb"], B.asm["cmpb"],
                                 nasm=args.nasm)
        failures = 0
        for name, fn in CASES:
            try:
                print(f"  PASS  {name:<72} {fn()}")
            except AssertionError as e:
                print(f"  FAIL  {name:<72} {e}")
                failures += 1
    print()
    if failures:
        print(f"{failures} of {len(CASES)} checks failed.")
        return 1
    print(f"All {len(CASES)} comdiff checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
