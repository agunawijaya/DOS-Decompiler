#!/usr/bin/env python3
"""
regress.py -- Check that the packer-header readers in unpack.py still read,
and that an EXEPACK file of either header layout unpacks to the program that
was packed.

Why this suite is different from the others
-------------------------------------------
`tests/com/` builds its fixtures with NASM and `tests/sopwith/` builds a whole
program. Producing a packed executable the same way means running LZEXE or
Microsoft LINK, which are someone else's software and not redistributable,
and the packed files this was developed against are commercial games.

So the header readers are tested against byte blocks assembled here from the
documented layouts, plus the field values observed in a real file. That half
covers the layout, the arithmetic and the refusal cases. The refusal cases are
the point of it: a header reader that accepts anything is worse than none,
because a wrong entry point sends a disassembler into the middle of a routine
and everything after it inherits the error.

EXEPACK, end to end
-------------------
EXEPACK's format is documented well enough to write, so this suite writes it.
`pack()` below packs tests/unpack/fixtures/program.asm -- four segments,
eight relocations, two of them past the first 64 KB -- in EXEPACK's format,
around fixtures/stub.asm, a decompressor written for these tests in both
header layouts (16 bytes, and 18 with skip_len). unpack.py then has to read
the layout from the stub's instructions, run the stub, decode the image a
second time without it, find the two agree, and write an MZ whose image,
relocations, entry and stack are the program's. The unpacked file is run
under comrun and must print what the program prints, which it does only if
every relocation landed on the right word.

What this cannot show is that Microsoft's own stub is read right; that is
measured on a real file (knowledge/00-scope.md, Unpacking). These cases need
NASM and capstone, and skip, saying so, without them.

Usage:
    python tests/unpack/regress.py
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import unpack                                             # noqa: E402


def mz(cs, ip, hdr_paras=2, sig_at_1c=b"\0\0\0\0", tail=b""):
    """The smallest MZ header that the readers look at, plus a body."""
    h = bytearray(hdr_paras * 16)
    h[0:2] = b"MZ"
    struct.pack_into("<HHHHHHHHHHHH", h, 2,
                     0, 0, 0, hdr_paras, 0, 0xFFFF, 0, 0, 0, ip, cs, 0x1C)
    h[0x1C:0x20] = sig_at_1c
    return bytes(h) + tail


# --- LZEXE ------------------------------------------------------------------
# The values are the ones measured in The Oregon Trail (MECC, 1990): the stub
# sits at segment 0x130F, the compressed-size word agrees with it, and the
# original entry is 0000:010A.
def lzexe_file(packed_paras=0x130F, cs0=0x0000, ip0=0x010A,
               ss=0x274A, sp=0x9C40, sig=b"LZ91"):
    hdr_paras = 2
    stub_at = hdr_paras * 16 + (packed_paras << 4)
    body = bytearray(stub_at - hdr_paras * 16 + 32)
    struct.pack_into("<8H", body, stub_at - hdr_paras * 16,
                     ip0, cs0, sp, ss, packed_paras, 0x11A4, 0x0ED8, 0x0E06)
    return mz(packed_paras, 0x0E, hdr_paras, sig, bytes(body))


CASES = []


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


@case("LZEXE 0.91: entry, stack and version are read")
def _():
    d = lzexe_file()
    got = unpack.lzexe_header(d, 32, 0x130F)
    assert got is not None, "returned nothing"
    assert (got["cs"] << 4) + got["ip"] == 0x10A, f"entry {got}"
    assert (got["ss"], got["sp"]) == (0x274A, 0x9C40), f"stack {got}"
    assert got["version"] == "LZ91", got["version"]
    return "entry 0x10A, SS:SP 274A:9C40"


@case("LZEXE 0.90 is accepted as well")
def _():
    got = unpack.lzexe_header(lzexe_file(sig=b"LZ90"), 32, 0x130F)
    assert got is not None and got["version"] == "LZ90"
    return "accepted"


@case("refused: the signature is absent")
def _():
    d = lzexe_file(sig=b"\0\0\0\0")
    assert unpack.lzexe_header(d, 32, 0x130F) is None
    return "refused, as it must"


@case("refused: the compressed-size word disagrees with the stub segment")
def _():
    # This is the cross-check that makes the read evidence rather than
    # assumption. A file merely *containing* the bytes LZ91 must not be able to
    # hand a disassembler an entry point.
    d = lzexe_file(packed_paras=0x130F)
    body = bytearray(d)
    struct.pack_into("<H", body, 32 + (0x130F << 4) + 8, 0x1234)
    assert unpack.lzexe_header(bytes(body), 32, 0x130F) is None
    return "refused, as it must"


@case("refused: the stub would be past the end of the file")
def _():
    d = lzexe_file()[:100]
    assert unpack.lzexe_header(d, 32, 0x130F) is None
    return "refused, as it must"


# --- EXEPACK ----------------------------------------------------------------
def exepack_blob():
    """(bytes, offset of the stub): EXEPACK's 16-byte header, ending in "RB",
    directly before its stub. tests/evidence wraps it in an MZ header for
    triage, so the file triage refuses is one these readers accept."""
    blob = bytearray(0x400)
    at = 0x200
    struct.pack_into("<HHHHHHH", blob, at - 16,
                     0x06B2, 0x0000, 0x1000, 0x0120, 0x0800, 0x0700, 0x0900)
    blob[at - 2:at] = b"RB"
    return bytes(blob), at


@case("EXEPACK: the 16 bytes before the stub are read")
def _():
    blob, at = exepack_blob()
    got = unpack.exepack_header(blob, at)
    assert got is not None, "returned nothing"
    assert (got["cs"] << 4) + got["ip"] == 0x6B2, got
    assert got["dest_paragraphs"] == 0x900, got
    return "entry 0x6B2 -- the value the heuristic missed"


@case("EXEPACK refused: no RB marker")
def _():
    blob = bytearray(0x400)
    assert unpack.exepack_header(bytes(blob), 0x200) is None
    return "refused, as it must"


# --- EXEPACK, packed here ---------------------------------------------------
# fixtures/stub.asm moves each pointer to an offset of 0x8000 or more before a
# command, so no run may be longer than this.
MAX_RUN = 0x7FF0
# A fill costs four bytes; a run of equal bytes this long is worth one.
FILL_FROM = 6


class Skip(Exception):
    """A case that cannot run on this machine, and why."""


def mz_parts(data):
    """(image, relocations as (segment, offset), (cs, ip), (ss, sp)) of an MZ."""
    last, pages, nrel, hdr, _mn, _mx, ss, sp, _ck, ip, cs, relo = \
        struct.unpack_from("<12H", data, 2)
    end = (pages - 1) * 512 + (last or 512)
    relocs = [struct.unpack_from("<HH", data, relo + 4 * i)[::-1] for i in range(nrel)]
    return data[hdr * 16:end], relocs, (cs, ip), (ss, sp)


def runs_of(image, start):
    """image[start:] as EXEPACK's runs, in file order: ("fill", value, count)
    for FILL_FROM or more equal bytes, ("copy", bytes) for the rest."""
    runs, i = [], start
    while i < len(image):
        j = i
        while j < len(image) and image[j] == image[i] and j - i < MAX_RUN:
            j += 1
        if j - i >= FILL_FROM:
            runs.append(("fill", image[i], j - i))
            i = j
            continue
        k = i
        while k < len(image) and k - i < MAX_RUN:
            m = k
            while m < len(image) and image[m] == image[k] and m - k < FILL_FROM:
                m += 1
            if m - k >= FILL_FROM:
                break
            k += 1
        runs.append(("copy", image[i:k]))
        i = k
    return runs


def in_place_safe(start, runs, image_len):
    """Whether these runs, after `start` bytes stored as they are, decompress
    in place: going backwards from both ends, the next byte written must never
    be below the next byte still to be read."""
    packed = start + sum(4 if r[0] == "fill" else len(r[1]) + 3 for r in runs)
    d, s = image_len - 1, packed - 1
    for r in reversed(runs):
        s -= 3
        if r[0] == "fill":
            s -= 1
            d -= r[2]
        else:
            if d < s:
                return False
            d -= len(r[1])
            s -= len(r[1])
        if d < s:
            return False
    return d == s == start - 1


def pack(program, stub, header_bytes):
    """`program`, an MZ, packed in EXEPACK's format around `stub` (built from
    fixtures/stub.asm with -DHEADER=header_bytes): the image compressed from
    its end, a prefix stored as it is where compressing would overtake the
    reading, 0xFF padding to a paragraph, then the stub's block -- header,
    code, the relocation table in sixteen 64 KB groups -- with CS:IP at its
    entry. Returns the packed file's bytes."""
    image, relocs, (cs, ip), (ss, sp) = mz_parts(program)
    image = image + b"\0" * (-len(image) % 16)
    runs = None
    for start in range(len(image) + 1):
        candidate = runs_of(image, start)
        if candidate and in_place_safe(start, candidate, len(image)):
            runs = candidate
            break
    assert runs is not None, "no prefix makes the image decompress in place"
    stream = bytearray(image[:start])
    for n, r in enumerate(runs):
        last = 1 if n == 0 else 0          # the first in the file is decoded last
        if r[0] == "fill":
            stream += bytes([r[1]]) + struct.pack("<H", r[2]) + bytes([0xB0 | last])
        else:
            stream += r[1] + struct.pack("<H", len(r[1])) + bytes([0xB2 | last])
    stream += b"\xFF" * (-len(stream) % 16)
    groups = [[] for _ in range(16)]
    for seg, off in relocs:
        linear = (seg << 4) + off
        groups[linear >> 16].append(linear & 0xFFFF)
    table = b"".join(struct.pack("<H", len(g)) + b"".join(struct.pack("<H", o) for o in g)
                     for g in groups)
    block = bytearray(stub + table)
    dest = len(image) // 16
    fields = [ip, cs, 0, len(block), sp, ss, dest] + ([1] if header_bytes == 18 else [])
    struct.pack_into(f"<{len(fields)}H", block, 0, *fields)
    assert block[header_bytes - 2:header_bytes] == b"RB", "the stub's header is not where expected"
    packed = bytes(stream) + bytes(block)
    block_paras = (len(block) + 15) // 16
    total = 32 + len(packed)
    stack_seg = dest + block_paras + 1     # above the block's copy past the image
    minalloc = max(0, stack_seg + 0x10 - (len(packed) + 15) // 16)
    header = struct.pack("<2s13H", b"MZ", total % 512, (total + 511) // 512, 0, 2, minalloc,
                         0xFFFF, stack_seg, 0x0100, 0, header_bytes, len(stream) // 16, 0x1C, 0)
    return header + b"\0" * (32 - len(header)) + packed


class Built:
    folder = None
    program = None
    packed = {}
    why_not = None


def find_nasm():
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    return nasm if nasm and Path(nasm).exists() else None


def built():
    """The program and both packed files, built once; Skip without NASM or
    capstone."""
    if Built.why_not:
        raise Skip(Built.why_not)
    if Built.program:
        return Built
    nasm = find_nasm()
    if not nasm:
        Built.why_not = "NASM not found (set NASM or put nasm on PATH)"
    elif unpack.Cs is None:
        Built.why_not = "capstone not importable: unpack.py reads EXEPACK's stub with it"
    if Built.why_not:
        raise Skip(Built.why_not)
    Built.folder = Path(tempfile.mkdtemp(prefix="unpack-regress-"))

    def nasm_build(src, out, *defines):
        r = subprocess.run([nasm, "-f", "bin", *(f"-D{d}" for d in defines), "-o", str(out),
                            str(src)], capture_output=True, text=True)
        assert r.returncode == 0, f"nasm could not build {src.name}: {r.stderr}"
        return out.read_bytes()

    Built.program = Built.folder / "program.exe"
    program = nasm_build(HERE / "fixtures" / "program.asm", Built.program)
    for layout in (16, 18):
        stub = nasm_build(HERE / "fixtures" / "stub.asm", Built.folder / f"stub{layout}.bin",
                          f"HEADER={layout}")
        path = Built.folder / f"packed{layout}.exe"
        path.write_bytes(pack(program, stub, layout))
        Built.packed[layout] = path
    return Built


def unpacked(layout):
    """unpack.py on one packed fixture: (file bytes, info)."""
    b = built()
    out, info = unpack.unpack(str(b.packed[layout]))
    assert out is not None, f"nothing unpacked: {info.get('problem') or info.get('stopped')}"
    return out, info


@case("EXEPACK packed here: the 18-byte layout read from its stub")
def _():
    data = built().packed[18].read_bytes()
    lay = unpack.exepack_layout(data, unpack.Header(data))
    assert lay and not lay["problem"], lay and lay["problem"]
    assert lay["layout"] == "the 18-byte layout, with skip_len", lay["layout"]
    assert lay["fields"]["skip_len"] == 0x0E and lay["header_bytes"] == 18, lay["fields"]
    assert any(w.startswith("skip_len at [0x0E]") for w in lay["why"]), lay["why"]
    return f"{len(lay['fields'])} fields, skip_len at [0x0E], each named with its instruction"


@case("EXEPACK packed here: the 16-byte layout read from its stub")
def _():
    data = built().packed[16].read_bytes()
    lay = unpack.exepack_layout(data, unpack.Header(data))
    assert lay and not lay["problem"], lay and lay["problem"]
    assert lay["layout"] == "the 16-byte layout", lay["layout"]
    assert "skip_len" not in lay["fields"] and lay["values"]["skip_len"] == 1, lay["fields"]
    return f"{len(lay['fields'])} fields, no skip_len (taken as 1)"


@case("both layouts unpack to the program: image, relocations, entry, stack")
def _():
    b = built()
    want_image, want_relocs, want_entry, want_stack = mz_parts(b.program.read_bytes())
    want_image = want_image + b"\0" * (-len(want_image) % 16)
    linear = sorted((s << 4) + o for s, o in want_relocs)
    for layout in (16, 18):
        out, info = unpacked(layout)
        image, relocs, entry, stack = mz_parts(out)
        assert image == want_image, f"{layout}: the image differs from the program's"
        got = sorted((s << 4) + o for s, o in relocs)
        assert got == linear, f"{layout}: relocations {got} against {linear}"
        assert (entry, stack) == (want_entry, want_stack), f"{layout}: {entry} {stack}"
        assert info["format"] == "Microsoft EXEPACK", info["format"]
    return (f"{len(want_image):,} bytes, {len(linear)} relocations (2 past 64 KB), "
            f"entry {want_entry[0]:04X}:{want_entry[1]:04X}, both layouts")


@case("the stub's own output and the static decode agree, byte for byte")
def _():
    for layout in (16, 18):
        _out, info = unpacked(layout)
        assert info["agreeing_bytes"] == info["compared_bytes"], \
            f"{layout}: {info['agreement']}, first difference at {info['first_difference']}"
        assert info["static"]["commands"] > 1, info["static"]
    return f"{info['agreement']} bytes, {info['static']['commands']} commands"


@case("the 18-byte header read as the 16-byte one: the 272-byte image of old")
def _():
    # unpack.exepack_header is the 16-byte reading every EXEPACK file once got.
    # On the 18-byte layout it takes skip_len for dest_len, and real_cs for
    # real_ip, which is the failure The Ancient Art of War exposed.
    data = built().packed[18].read_bytes()
    h = unpack.Header(data)
    old = unpack.exepack_header(data, h.hdr + (h.cs << 4) + h.ip)
    _, _, (cs, ip), _ = mz_parts(Built.program.read_bytes())
    assert old["dest_paragraphs"] == 1, old
    assert old["ip"] == cs, old
    return f"dest_len read as {old['dest_paragraphs']}: {old['dest_paragraphs'] * 16 + 0x100} bytes"


@case("the unpacked file runs, and every relocation is where it was")
def _():
    b = built()

    def printed(path):
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "comrun.py"), str(path),
                            "--budget", "200000"], capture_output=True, text=True)
        lines = r.stdout.splitlines()
        assert "  the program printed:" in lines, r.stdout + r.stderr
        return [l.strip() for l in lines[lines.index("  the program printed:") + 1:]
                if l.startswith("      ")]

    want = printed(b.program)
    assert len(want) == 5, want
    for layout in (16, 18):
        out, _ = unpacked(layout)
        path = b.folder / f"unpacked{layout}.exe"
        path.write_bytes(out)
        got = printed(path)
        assert got == want, f"{layout}: printed {got}"
    return f"{len(want)} lines, the same as the program's, from both"


@case("a stub that reads skip_len from the wrong place is refused, not guessed")
def _():
    data = bytearray(built().packed[18].read_bytes())
    h = unpack.Header(bytes(data))
    block = h.hdr + (h.cs << 4)
    read_skip = bytes([0x8B, 0x1E, 0x0E, 0x00])       # mov bx, [0x0E]
    at = data.find(read_skip, block)
    assert at != -1, "the stub's read of skip_len was not found"
    data[at + 2] = 0x10                                # mov bx, [0x10]: "RB"
    lay = unpack.exepack_layout(bytes(data), h)
    assert lay["problem"] and "past the header's" in lay["problem"], lay["problem"]
    path = Built.folder / "bad-skip.exe"
    path.write_bytes(data)
    _out, info = unpack.unpack(str(path))
    assert info.get("exepack_problem") == lay["problem"], info
    assert info.get("oep_offset") in (0, None), info
    return "the header is not used, and the dump's entry is left at 0"


@case("a damaged command byte: the stub never hands over, and nothing is written")
def _():
    data = bytearray(built().packed[18].read_bytes())
    h = unpack.Header(bytes(data))
    lay = unpack.exepack_layout(bytes(data), h)
    # The last command in the file is the first the stub reads.
    at = h.hdr + (h.cs - 1) * 16 + 0x0F
    while data[at] == 0xFF:
        at -= 1
    assert data[at] & 0xFE in (0xB0, 0xB2), hex(data[at])
    data[at] = 0xC4
    path = Built.folder / "bad-command.exe"
    path.write_bytes(data)
    out, info = unpack.unpack(str(path))
    assert out is None and "never reached" in info.get("problem", ""), info
    static, _, details = unpack.exepack_static(bytes(data), unpack.Header(bytes(data)), lay)
    assert static is None and "0xC4" in details["problem"], details
    return "both readings refuse it: " + details["problem"][:48] + "..."


@case("bytes past the packed image are carried past the new one, page-aligned")
def _():
    data = built().packed[18].read_bytes()
    h = unpack.Header(data)
    overlay = b"MZ" + bytes(range(256)) * 3
    path = Built.folder / "with-tail.exe"
    path.write_bytes(data + b"\0" * (h.pages * 512 - len(data)) + overlay)
    out, info = unpack.unpack(str(path))
    at = info["carried_at"]
    assert at % 512 == 0 and out[at:] == overlay, (at, len(out))
    image, *_ = mz_parts(out)
    last, pages = struct.unpack_from("<HH", out, 2)
    assert pages * 512 == at, (pages, at)
    return f"{len(overlay)} bytes at file 0x{at:X}, the root's page count times 512"


def main():
    failures = skipped = 0
    for name, fn in CASES:
        try:
            detail = fn()
            print(f"  PASS  {name:<58} {detail}")
        except Skip as e:
            print(f"  SKIP  {name:<58} {e}")
            skipped += 1
        except AssertionError as e:
            print(f"  FAIL  {name:<58} {e}")
            failures += 1
    if Built.folder:
        shutil.rmtree(Built.folder, ignore_errors=True)
    print()
    if failures:
        print(f"{failures} of {len(CASES)} checks failed.")
        return 1
    if skipped:
        print(f"All {len(CASES) - skipped} checks that ran pass; {skipped} skipped: "
              f"{Built.why_not}.")
        return 0
    print(f"All {len(CASES)} unpack checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
