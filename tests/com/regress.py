#!/usr/bin/env python3
"""
regress.py -- Check that comrec.py still rebuilds .COM files exactly.

The claim comrec makes is narrow and absolute: the .asm it writes assembles
back to a file identical to the one it read. That is rung 1b of the
verification ladder in knowledge/07-extended-reconstruction.md -- the whole
linked image, not per-function comparison; not "looks right", not "behaves the
same", but the same bytes. A test either confirms it or the tool
is broken, so this suite reassembles every fixture with NASM and compares
SHA-256.

Byte-identity alone is a low bar, though: emitting the whole file as `db`
lines would pass. So each fixture also carries a floor for how much of it must
come back as instructions, and a list of things the output has to contain.
Those are what catch a regression that is still technically correct but has
stopped being a decompilation.

The claim has a second half: when the rebuild is not identical, comrec says
so and names the first byte that differs. Two fixtures exist for that alone
(REFUSALS): programs comrec cannot rebuild, where every instruction matches its
own encoding and the file still differs, so only its last check -- the
whole-file comparison -- can catch it. The byte it names is checked against an
independent rebuild of the attempt it leaves behind.

The fixtures are written here rather than taken from a real game because games
from the period are still under copyright. They reproduce the patterns that
made a real reconstruction hard -- ParaTrooper's measured figures are recorded
in CASE-STUDY.md.

Usage:
    python tests/com/regress.py [--nasm PATH]
"""

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
COMREC = ROOT / "tools" / "comrec.py"
FIXTURES = HERE / "fixtures"

# name -> (floor for the share of the file that must come back as
#          instructions, substrings that must appear in the source or in
#          comrec's own report)
#
# The floors sit a little under what the tools currently achieve, so a real
# regression trips them while ordinary variation does not. They are low in
# absolute terms because these fixtures are mostly data -- farstub is 543
# bytes of which 480 are padding between the stub and the code it jumps to.
# A percentage of the whole file measures the fixture, not the tool, which is
# exactly why comrec reports the code region separately.
EXPECTATIONS = {
    "plain": (
        30.0,
        ["db 'A plain COM file, one segment, nothing clever.",
         "db 'Press Q to quit.'",
         # The message must not be disassembled as code: the walk has to stop
         # at the DOS exit that precedes it.
         "mov ax, 0x4c00"],
    ),
    "farstub": (
        7.0,
        ["detected from the entry stub",       # the split was found
         "% of the code region",               # and reported separately
         "db 'Reached the second segment.'",
         "ds:0x0002",                          # DS bias resolved
         "; ---- file 0x0200, addresses relative to 0x0000 ----"],
    ),
    # The same split, with the stub hidden behind a jump over a title banner
    # the way Zaxxon (1984) hides its. The needles are farstub's, because the
    # result has to be the same; what differs is only that offset 0 holds a
    # jump rather than the stub. Evaluating from offset 0 and stopping there
    # recovered nine instructions of Zaxxon's 20,736 bytes.
    "jmpstub": (
        7.0,
        ["detected from the entry stub",
         "db 'Reached the second segment.'",
         "ds:0x0002",
         "; ---- file 0x0200, addresses relative to 0x0000 ----"],
    ),
    "encodings": (
        30.0,
        ["strict word",                        # long immediate form recovered
         "; mov dx, ax"],                      # direction-bit alternate pinned
    ),
    # An interrupt handler is reachable only through the vector table. Nothing
    # branches to it, so recursive descent cannot find it and the gap sweep is
    # deliberately blocked from rescuing it -- see the fixture. These three
    # instructions coming back as code means the vector install was read.
    "interrupt": (
        45.0,
        ["INT 09h -> file",                    # reported, from comrec's output
         "in al, 0x60",                        # inside the handler
         "out 0x20, al",                       # the end-of-interrupt
         "iret"],
    ),
    # The same handler, installed through a base register with DS pointed at
    # zero instead of an absolute `[es:slot]` write -- the way Zaxxon does it.
    # No `es:` appears anywhere in the install, so matching the absolute form
    # alone finds nothing and the handler stays in the file as data.
    "timer": (
        60.0,
        ["INT 1Ch -> file",                    # reported, from comrec's output
         "inc al",                             # inside the handler
         "iret"],
    ),
    # Routines reached only through a table of addresses. Both hidden ones
    # coming back proves the table was read; `three` staying out (see
    # FORBIDDEN) proves the second table, whose first word is a data pointer,
    # stopped the reader instead of sending it into artwork.
    "jumptable": (
        50.0,
        ["jump tables : cs:0x",                # reported, from comrec's output
         "-> 2 targets",                       # the 0xFFFF ended it
         "mov dl, 0x41",                       # inside the first routine
         "mov dl, 0x42"],                      # inside the second
    ),
    # An MZ that is really a .COM wearing a header: one segment, an entry stub
    # that sets the segment registers once. comrec must strip the header and
    # reconstruct the *image*. Getting that wrong is silent -- treating the
    # header as code still rebuilds the file exactly and still prints
    # BYTE-IDENTICAL -- so the needle is an address. L_00002 can only appear if
    # the entry came from CS:IP with the header already off.
    "mzsingle": (
        60.0,
        ["MZ, 512-byte header stripped",       # reported, from comrec's output
         "L_00002:",                           # the entry, addressed from 0
         "int 0x21"],
    ),
    # An MZ that took the .COM route but whose header sets CS != 0, so the
    # code lives partway into the image and every `cs:` reference in that code
    # is offset from the CS base rather than flat. Alley Cat (1984) is the
    # game this covers: seven per-phase handlers behind `jmp word [cs:bx +
    # 0x250]` stayed data because the walker read the displacement as flat.
    # 'M' and 'Z' come back only if the CS-prefixed dispatch is followed.
    "mzdispatchcs": (
        6.0,                                   # the file is mostly zero-fill data
        ["MZ, 512-byte header stripped",
         "-> image offset 0x1000",             # entry landed above the data pad
         "jump tables : cs:0x",                # reported, from comrec's output
         "-> 2 targets",
         "mov dl, 0x4d",                       # 'M' inside the first handler
         "mov dl, 0x5a"],                      # 'Z' inside the second
    ),
    # An indirect jump ends recursive descent. Both hidden states are reachable
    # only through the pointer, and the second only after the first has been
    # reached -- so finding `mov dl, 0x42` proves the detection iterated rather
    # than taking one pass. The gap sweep is blocked from rescuing either.
    "dispatch": (
        40.0,
        ["jmp [0x", "-> 0x",                   # reported, from comrec's output
         "mov dl, 0x41",                       # inside the first state
         "mov dl, 0x42",                       # inside the second
         # Reached through a pointer at [9]. Capstone prints a one-digit
         # address with no 0x, so an 0x-only pattern skips the instruction
         # without saying so -- nine routines lost on Zaxxon that way.
         "mov dl, 0x43"],                      # inside the third
    ),
    # The compiler's own `switch`: the table is the jump's displacement and the
    # register is the index. Read as decimal, `0x...` did not match the pattern
    # at all and the pass reported nothing -- Karateka has six of these. All
    # three arms coming back proves the displacement was read as the table.
    "indexed": (
        40.0,
        ["jump tables : cs:0x",                # reported, from comrec's output
         "-> 3 targets",
         "mov dl, 0x41",
         "mov dl, 0x42",
         "mov dl, 0x43"],
    ),
    # A `switch` table sitting directly behind the arms it names, with nothing
    # anywhere pointing at it -- so detect_jump_tables cannot find it and the
    # gap sweep vetoes the run over the `insw` the table's own bytes contain.
    # All three arms coming back proves the table was read backwards from the
    # end of the run; `never_a` staying out (see FORBIDDEN) proves a table with
    # no code in front of it was refused.
    # 16.5% of the file comes back without the pass and 38.1% with it, so the
    # floor separates the two rather than merely being cleared.
    "casetable": (
        35.0,
        ["mov dl, 0x41",                       # inside the first arm
         "mov dl, 0x42",                       # inside the second
         "mov dl, 0x43"],                      # inside the third
    ),
}


# Some of what a fixture proves is an *absence*: a walk that stopped where it
# should have. Nothing else here can express that, and a rule with no test for
# its refusal case is only half tested -- the half that costs nothing to get
# wrong.
FORBIDDEN = {
    "jumptable": ["mov dl, 0x43"],   # behind a data pointer; must stay data
    # A well-formed case table with no function in front of it. Every content
    # test passes and it must still be refused: what the pass is entitled to
    # claim is a run the sweep would have taken but for its tail, not a table
    # found anywhere.
    "casetable": ["mov dl, 0x58"],
}


# Fixtures comrec cannot rebuild, and must say so from its last check: every
# instruction matched its own encoding, and the file still differs. name ->
# (the bytes the file holds once, where the rebuild first differs; whether the
# rebuild's byte there is above the original's). One of each direction, so a
# comparison that only notices a larger byte, or only a smaller one, misses
# the difference in one of them.
REFUSALS = {
    "fneni": (b"\xDB\xE0", True),       # CLD (FC) where the original has DB
    "fndisi": (b"\xDB\xE1", False),     # MOV AX (B8) where the original has DB
}
LAST_CHECK = re.compile(r"FAILED: byte 0x([0-9A-F]+) differs though every "
                        r"instruction matched its original encoding")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def nasm_build(nasm, src, out):
    r = subprocess.run([nasm, "-f", "bin", "-o", str(out), str(src)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"nasm failed on {src}:\n{r.stderr}")


def run_case(nasm, name, workdir):
    src = FIXTURES / f"{name}.asm"
    original = workdir / f"{name}.com"
    nasm_build(nasm, src, original)

    asm = workdir / f"{name}.rec.asm"
    r = subprocess.run([sys.executable, str(COMREC), str(original),
                        "--out", str(asm), "--nasm", nasm],
                       capture_output=True, text=True)
    stdout = r.stdout

    if r.returncode != 0 or "BYTE-IDENTICAL" not in stdout:
        return False, f"comrec did not report byte-identity\n{stdout}{r.stderr}"

    # Rebuild independently rather than trusting comrec's own account of it.
    rebuilt = workdir / f"{name}.rebuilt.com"
    nasm_build(nasm, asm, rebuilt)
    # For an MZ, the source covers the load image and comrec writes the header
    # out beside it. Reattaching it here is the whole claim: the artefact
    # compared has to be the file the user handed over, not the part of it that
    # happened to be convenient.
    header = asm.with_suffix(".mzheader")
    if header.exists():
        rebuilt.write_bytes(header.read_bytes() + rebuilt.read_bytes())
    if sha(rebuilt) != sha(original):
        return False, "rebuilt file differs from the original"

    floor, needles = EXPECTATIONS[name]
    m = re.search(r"bytes as code: [\d,]+ / [\d,]+\s+\(([\d.]+)% of file\)",
                  stdout)
    if not m:
        return False, "could not read the code fraction from comrec's output"
    pct = float(m.group(1))
    if pct < floor:
        return False, (f"only {pct:.1f}% of the file came back as instructions, "
                       f"floor is {floor:.1f}%")

    body = asm.read_text(encoding="latin-1") + stdout
    missing = [n for n in needles if n not in body]
    if missing:
        return False, "output is missing: " + "; ".join(repr(x) for x in missing)

    present = [n for n in FORBIDDEN.get(name, []) if n in body]
    if present:
        return False, ("output contains what it should have refused: "
                       + "; ".join(repr(x) for x in present))

    return True, f"byte-identical, {pct:.1f}% as instructions"


def first_difference(a, b):
    """Where two byte strings first differ, a shorter one differing at its end;
    None when they are the same. Written here, not borrowed from comrec."""
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    return None if len(a) == len(b) else min(len(a), len(b))


def run_refusal(nasm, name, workdir):
    """comrec must refuse the file, name the first byte that differs, and be
    right about it: the attempt it leaves behind is assembled here and
    compared with the original independently."""
    src = FIXTURES / f"{name}.asm"
    original = workdir / f"{name}.com"
    nasm_build(nasm, src, original)
    asm = workdir / f"{name}.rec.asm"
    r = subprocess.run([sys.executable, str(COMREC), str(original),
                        "--out", str(asm), "--nasm", nasm],
                       capture_output=True, text=True)
    stdout = r.stdout
    if r.returncode == 0 or "BYTE-IDENTICAL" in stdout:
        return False, f"comrec claimed a rebuild it cannot make\n{stdout}{r.stderr}"
    m = LAST_CHECK.search(stdout)
    if not m:
        return False, f"comrec refused, but not from its last check\n{stdout}{r.stderr}"
    named = int(m.group(1), 16)

    attempt = workdir / f"{name}.attempt.com"
    nasm_build(nasm, asm, attempt)
    data, built = original.read_bytes(), attempt.read_bytes()
    actual = first_difference(data, built)
    marker, above = REFUSALS[name]
    if data.count(marker) != 1:
        return False, f"{marker.hex()} is in the fixture {data.count(marker)} times, not once"
    where = data.find(marker)
    if (named, actual) != (where, where):
        return False, (f"comrec named byte 0x{named:X}; the attempt first differs at "
                       f"{actual if actual is None else hex(actual)}, the 8087 "
                       f"instruction is at 0x{where:X}")
    if (built[where] > data[where]) != above:
        return False, (f"the rebuild has {built[where]:02X} where the original has "
                       f"{data[where]:02X}: not the direction this fixture is for")
    return True, (f"refused: byte 0x{named:X} differs (rebuild {built[where]:02X}, "
                  f"original {data[where]:02X}), {len(data) - len(built)} bytes short")


def first_mismatch_cases():
    """The two outcomes no fixture reaches: a rebuild that is the original cut
    short, and one longer than it. NASM never emits more than its listing
    shows, and the 8087 fixtures differ before they end."""
    sys.path.insert(0, str(ROOT / "tools"))
    import comrec
    r = comrec.Reconstructor.__new__(comrec.Reconstructor)
    r.image, r.tail = bytes([0x10, 0x20, 0x30]), b""
    cases = [(bytes([0x10, 0x20, 0x30]), None, "identical"),
             (bytes([0x10, 0x20]), 2, "cut short"),
             (bytes([0x10, 0x20, 0x30, 0x40]), 3, "one byte longer"),
             (bytes([0x10, 0x21, 0x30]), 1, "a larger byte"),
             (bytes([0x10, 0x1F, 0x30]), 1, "a smaller byte"),
             (b"", 0, "empty")]
    wrong = [f"{why}: {got!r}, not {want!r}" for built, want, why in cases
             if (got := r.first_mismatch(built)) != want]
    # With bytes after the image, they are part of what the source must give.
    r.tail = bytes([0x40, 0x50])
    for built, want, why in ((bytes([0x10, 0x20, 0x30, 0x40, 0x50]), None, "image and tail"),
                             (bytes([0x10, 0x20, 0x30]), 3, "the image alone"),
                             (bytes([0x10, 0x20, 0x30, 0x40, 0x51]), 4, "the tail's last byte")):
        if (got := r.first_mismatch(built)) != want:
            wrong.append(f"{why}: {got!r}, not {want!r}")
    if wrong:
        return False, "; ".join(wrong)
    return True, (f"{len(cases) + 3} cases: identical, shorter, longer, larger, smaller, "
                  f"empty; with a tail, whole, without it, its last byte")


def compare_files_cases():
    """The comparison BYTE-IDENTICAL rests on, by hand: the rebuilt file
    against the whole original, length included."""
    sys.path.insert(0, str(ROOT / "tools"))
    import comrec
    original = bytes([0x4D, 0x5A, 0x00, 0x7F])
    cases = [(original, None, "the same"),
             (original[:3], 3, "cut short by one byte"),
             (original + b"\x00", 4, "one byte more"),
             (bytes([0x4D, 0x5A, 0x01, 0x7F]), 2, "a byte larger"),
             (bytes([0x4D, 0x5A, 0x00, 0x7E]), 3, "the last byte smaller"),
             (b"", 0, "nothing")]
    wrong = []
    for rebuilt, want, why in cases:
        got = comrec.compare_files(original, rebuilt)
        if (got if got is None else got[0]) != want:
            wrong.append(f"{why}: {got!r}, not at {want!r}")
    if comrec.compare_files(b"", b"") is not None:
        wrong.append("two empty files differ")
    if wrong:
        return False, "; ".join(wrong)
    return True, f"{len(cases) + 1} cases: same, shorter, longer, larger, smaller, empty"


def appended_case(nasm, workdir):
    """An MZ with bytes after its load image is rebuilt whole: comrec says so
    only after comparing all of the file, and the suite's own rebuild agrees."""
    original = workdir / "appended.exe"
    nasm_build(nasm, FIXTURES / "mzsingle.asm", original)
    image = original.read_bytes()
    tail = bytes((i * 37 + 11) & 0xFF for i in range(100)) + b"FBOV and more after it"
    original.write_bytes(image + tail)
    asm = workdir / "appended.rec.asm"
    r = subprocess.run([sys.executable, str(COMREC), str(original), "--out", str(asm),
                        "--nasm", nasm], capture_output=True, text=True)
    total = len(image) + len(tail)
    if r.returncode != 0 or "BYTE-IDENTICAL" not in r.stdout or \
            f"all {total:,} bytes the same" not in r.stdout:
        return False, f"comrec did not rebuild it whole\n{r.stdout}{r.stderr}"
    rebuilt = workdir / "appended.rebuilt"
    nasm_build(nasm, asm, rebuilt)
    whole = asm.with_suffix(".mzheader").read_bytes() + rebuilt.read_bytes()
    if whole != original.read_bytes():
        return False, f"the suite's own rebuild is {len(whole)} bytes, not the file's {total}"
    source = asm.read_text(encoding="latin-1")
    span = f"file 0x{len(image):X}..0x{total - 1:X}, {len(tail):,} bytes"
    if span not in source:
        return False, f"the source does not say where the bytes after the image are ({span})"
    return True, f"{total} of {total} bytes, {len(tail)} of them after the image"


def claim_case(nasm, workdir):
    """A route that compares less than the whole file cannot reach the claim:
    a round trip that reports success with a source leaving out the bytes
    after the image is refused by the final comparison."""
    sys.path.insert(0, str(ROOT / "tools"))
    import comrec
    original = workdir / "short-claim.exe"
    nasm_build(nasm, FIXTURES / "mzsingle.asm", original)
    original.write_bytes(original.read_bytes() + bytes(64))
    real_run = comrec.Reconstructor.run

    def image_only(self, nasm_path, max_rounds=150):
        source, last, rounds, err = real_run(self, nasm_path, max_rounds)
        self.tail = b""                       # the source, rebuilt without them
        return self.emit(), last, rounds, None
    comrec.Reconstructor.run = image_only
    try:
        report, code = comrec.reconstruct(original, workdir / "short-claim.asm", nasm=nasm)
    finally:
        comrec.Reconstructor.run = real_run
    lines = "\n".join(report["lines"])
    if code == 0 or report["byte_identical"] or "BYTE-IDENTICAL" in lines:
        return False, f"a rebuild of the image alone was called identical\n{lines}"
    if "the rebuilt file is not the original" not in (report["error"] or ""):
        return False, f"refused, but not by the whole-file comparison: {report['error']}"
    return True, report["error"]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nasm", default=None)
    args = ap.parse_args()

    nasm = args.nasm or os.environ.get("NASM")
    if not nasm:
        from shutil import which
        nasm = which("nasm")
    if not nasm or not Path(nasm).exists():
        raise SystemExit("nasm not found. Pass --nasm PATH, set NASM, or put "
                         "nasm on PATH.")

    failures = 0
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        for name in sorted(EXPECTATIONS):
            try:
                ok, detail = run_case(nasm, name, work)
            except SystemExit as e:
                ok, detail = False, str(e)
            print(f"  {'PASS' if ok else 'FAIL'}  {name:<12} {detail}")
            if not ok:
                failures += 1
        for name in sorted(REFUSALS):
            try:
                ok, detail = run_refusal(nasm, name, work)
            except SystemExit as e:
                ok, detail = False, str(e)
            print(f"  {'PASS' if ok else 'FAIL'}  {name:<12} {detail}")
            if not ok:
                failures += 1
        others = [("last check", first_mismatch_cases),
                  ("whole file", compare_files_cases),
                  ("appended", lambda: appended_case(nasm, work)),
                  ("short claim", lambda: claim_case(nasm, work))]
        for name, fn in others:
            try:
                ok, detail = fn()
            except SystemExit as e:
                ok, detail = False, str(e)
            print(f"  {'PASS' if ok else 'FAIL'}  {name:<12} {detail}")
            if not ok:
                failures += 1

    total = len(EXPECTATIONS) + len(REFUSALS) + len(others)
    print()
    if failures:
        print(f"{failures} of {total} cases failed.")
        return 1
    print(f"All {len(EXPECTATIONS)} .COM fixtures rebuild byte-identically; "
          f"{len(REFUSALS)} it cannot rebuild are refused at the right byte; "
          f"an MZ with bytes after its image is rebuilt whole; the comparisons' "
          f"edges hold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
