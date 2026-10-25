#!/usr/bin/env python3
"""
unpack.py -- Recover the original program from a packed DOS executable, by
running the packer's own decompressor.

Why this exists
---------------
Compressing the executable was near-universal on commercial DOS releases from
the late 1980s. Of the period games lying around during this toolkit's
development, every commercial one was packed. A packed file defeats every
static tool here: the entry point is a decompressor, and decompiling it
produces something correct and useless.

Why emulation rather than a format-specific unpacker
-----------------------------------------------------
Writing an unpacker per format -- PKLITE, LZEXE, EXEPACK, DIET, and the
variants within each -- is a treadmill. But every packer, whatever its
algorithm, must do the same thing: reconstruct the original image in memory
and jump to it. So run it and take the result. One mechanism, any packer,
including ones nobody has documented.

The idea is old and well proven in the packing world; what makes it practical
here is that `unicorn` is already a dependency for `emuverify.py`.

How the original entry point is found
--------------------------------------
Execution starts at the decompressor. Every write into the image region is
recorded. The moment control reaches an address that this run has *written*,
the program is executing code that did not exist in the file -- that is the
unpacked program, and that address is its entry point.

EXEPACK, read twice
-------------------
EXEPACK's header comes in two layouts, 16 bytes and 18 (the second with a
`skip_len` word before "RB"), and which one a file has is not written down
anywhere but in its own stub. So the layout is read from the stub: the
offsets its instructions read the header at -- `add ax,[0x0C]` for the
destination's length, `mov cx,[0x06]` for the block it copies, `[0x0E]` for
skip_len when there is one, `jmp far cs:[0]` for the entry -- and the output
says which it found and why. Reading the 18-byte header as the 16-byte one put
every field one word late, and The Ancient Art of War (1987) came out 272
bytes long.

With the layout known, the image is decompressed twice: once by the stub
itself, under emulation, stopped where it hands over to the program, and once
statically, following the stub's commands in Python. The two are compared
byte for byte, relocations unapplied, and the agreement is printed as a
number. The relocation table is EXEPACK's own, read the way its stub reads
it, so the output is an MZ that loads, with the entry and stack the header
states; and bytes the packed file carried past its load image -- overlays
-- are carried past the new one, at the same page alignment.

Caveats, stated plainly
-----------------------
For every format but EXEPACK, the dump is for **analysis**, not necessarily
for running. Relocations are not reconstructed: the loader would normally
patch segment values, and recovering which words need patching would mean
tracking the decompressor's own relocation pass. Ghidra does not care -- it
wants the code.

DOS is stubbed, not emulated. Enough of INT 21h is answered to let a
decompressor resize its memory block and get on with it. A packer that does
something more elaborate will fail, and will say so rather than produce a
quietly wrong dump.

Reading EXEPACK's stub needs capstone; without it the stated header is not
used, and the dump is made as for a format that states nothing.

Usage:
    python unpack.py PACKED.EXE -o UNPACKED.EXE
    python unpack.py PACKED.EXE -o UNPACKED.EXE --trace
"""

import argparse
import struct
import sys
from pathlib import Path

try:
    from unicorn import (Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE,
                         UC_HOOK_INTR, UC_HOOK_MEM_WRITE, UcError)
    from unicorn.x86_const import (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX,
                                   UC_X86_REG_DX, UC_X86_REG_SP, UC_X86_REG_IP,
                                   UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
                                   UC_X86_REG_SS, UC_X86_REG_FLAGS)
except ImportError:  # pragma: no cover
    print("unpack: unicorn is required (pip install unicorn)", file=sys.stderr)
    raise

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG
except ImportError:  # only EXEPACK's stub is read with it; see exepack_layout
    Cs = None

MEM_SIZE = 0x110000
PSP_SEG = 0x0FF0             # a plausible PSP, image loads just above it
LOAD_SEG = 0x1000
LOAD_BASE = LOAD_SEG << 4
MAX_INSNS = 20_000_000       # decompressing a 60 KB image takes a few million
# Writing this quiet for this long means decompression is done.
WRITE_QUIET_INSNS = 200_000


def exepack_header(data, entry):
    """Read EXEPACK's own record of where the program really starts.

    When a packer states the answer, take it rather than infer it. EXEPACK
    keeps a 16-byte structure immediately before its decompressor, ending with
    the ASCII bytes "RB":

        +0  real_ip     +8  real_sp
        +2  real_cs    +10  real_ss
        +4  mem_start  +12  dest_len (paragraphs)
        +6  exepack_size            +14  "RB"

    Verified by packing a program with Microsoft LINK /EXEPACK and comparing:
    real_ip, real_cs, real_sp and real_ss all matched the unpacked build
    exactly, and dest_len matched its image size to within a paragraph.
    """
    if entry < 16 or data[entry - 2:entry] != b"RB":
        return None
    ip, cs, _mem, _size, sp, ss, dest = struct.unpack_from(
        "<HHHHHHH", data, entry - 16)
    return {"ip": ip, "cs": cs, "sp": sp, "ss": ss, "dest_paragraphs": dest}


# Where each field sits in the two layouts EXEPACK is known to use. Only for
# naming the layout found: the offsets used are the ones the stub reads.
EXEPACK_LAYOUTS = {
    "the 16-byte layout": {"real_ip": 0x00, "real_cs": 0x02, "exepack_size": 0x06,
                           "real_sp": 0x08, "real_ss": 0x0A, "dest_len": 0x0C},
    "the 18-byte layout, with skip_len": {"real_ip": 0x00, "real_cs": 0x02,
                                          "exepack_size": 0x06, "real_sp": 0x08,
                                          "real_ss": 0x0A, "dest_len": 0x0C,
                                          "skip_len": 0x0E},
}
# What each field is for, in the words the output uses.
EXEPACK_ROLES = {
    "dest_len": "the destination's length, added to the load segment",
    "exepack_size": "the length of the block the stub copies out of the way",
    "skip_len": "skip_len, subtracted from both ends of the decompression",
    "real_ss": "the program's SS, loaded into SS",
    "real_sp": "the program's SP, loaded into SP",
    "real_ip": "the program's IP, the far jump's offset",
    "real_cs": "the program's CS, relocated and jumped to",
}
# How far past the entry the stub is read for its far jump. The Ancient Art of
# War's is 0xEC bytes in, and its stub, header to error message, 301 bytes.
STUB_READ_LIMIT = 0x200


def _word_reg(name):
    return name in ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp")


def exepack_layout(data, h):
    """Where EXEPACK's header keeps each field, read from the stub that reads
    it. None when the entry is not preceded by "RB" (this is not EXEPACK).

    The stub is decoded from the entry to its far jump into the program, and
    each field is found by what the instruction reading it does with it, not
    by where it is assumed to be:

        add r16, [d]                 dest_len      the destination's end
        mov cx, [d]  (then rep movs) exepack_size  the block copied out of the way
        mov r, [d] ... sub x, r      skip_len      absent in the 16-byte layout
        mov r, [d] ... mov ss, r     real_ss
        mov r, [d] ... mov sp, r     real_sp
        add [d], r                   real_cs       relocated by the load segment
        jmp far [d]                  real_ip, and real_cs at d + 2
        mov si, imm                  the relocation table, at CS:imm

    A register keeps the field it was loaded from through add, sub, inc and
    dec, and loses it to anything else that writes it; `mov bx, 0 / jmp far
    cs:[bx]`, as Microsoft's stub ends, is read as `jmp far cs:[0]`. Every
    field found is checked against the header around it: inside it, before
    "RB", and the 16- and 18-byte layouts agreeing with the header's length.
    `problem` is set when they do not, and then nothing here is used."""
    block = h.hdr + (h.cs << 4)
    entry = block + h.ip
    if entry < 2 or data[entry - 2:entry] != b"RB":
        return None
    out = {"header_file_offset": block, "header_bytes": h.ip, "fields": {},
           "why": [], "relocation_table": None, "problem": None}
    if Cs is None:
        out["problem"] = ("capstone is not installed, and the layout is read from the "
                          "stub's instructions (pip install capstone)")
        return out
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    code = data[entry:min(len(data), entry + STUB_READ_LIMIT)]
    consts, loaded, copy_count, jumped = {}, {}, None, False
    fields, why = {}, {}

    def found(name, d, insn):
        if name not in fields:
            fields[name] = d
            why[name] = f"{insn.mnemonic} {insn.op_str} at CS:{insn.address:04X}"

    def absolute(insn, op):
        """The header offset a memory operand reads, if it reads a fixed one."""
        m = op.mem
        if m.index:
            return None
        if not m.base:
            return m.disp & 0xFFFF
        base = insn.reg_name(m.base)
        return (consts[base] + m.disp) & 0xFFFF if base in consts else None

    for insn in md.disasm(code, h.ip):
        ops = insn.operands
        mn = insn.mnemonic
        if mn == "ljmp" and ops and ops[0].type == X86_OP_MEM:
            d = absolute(insn, ops[0])
            if d is not None:
                found("real_ip", d, insn)
                found("real_cs", (d + 2) & 0xFFFF, insn)
            jumped = True
            break
        regs = [insn.reg_name(o.reg) if o.type == X86_OP_REG else None for o in ops]
        if len(ops) == 2 and ops[1].type == X86_OP_MEM and regs[0] and _word_reg(regs[0]):
            d = absolute(insn, ops[1])
            if mn == "add" and d is not None:
                found("dest_len", d, insn)
            elif mn == "mov" and d is not None:
                loaded[regs[0]] = (d, insn)
                if regs[0] == "cx":
                    copy_count = (d, insn)
                consts.pop(regs[0], None)
                continue
        if len(ops) == 2 and ops[0].type == X86_OP_MEM and regs[1] and mn == "add":
            d = absolute(insn, ops[0])
            if d is not None:
                found("real_cs_relocated", d, insn)
        if mn.startswith("rep") and copy_count is not None:
            found("exepack_size", copy_count[0], copy_count[1])
        if mn == "sub" and len(ops) == 2 and regs[1] in loaded:
            found("skip_len", loaded[regs[1]][0], loaded[regs[1]][1])
        if mn == "mov" and regs[0] in ("ss", "sp") and regs[1] in loaded:
            found("real_ss" if regs[0] == "ss" else "real_sp", loaded[regs[1]][0],
                  loaded[regs[1]][1])
        if mn == "mov" and regs[0] == "si" and len(ops) == 2 and ops[1].type == X86_OP_IMM:
            if ops[1].imm > h.ip:       # past the header; inside the block, checked below
                out["relocation_table"] = ops[1].imm
                why["relocation_table"] = f"{mn} {insn.op_str} at CS:{insn.address:04X}"
        if mn == "mov" and regs[0] and len(ops) == 2 and ops[1].type == X86_OP_IMM:
            consts[regs[0]] = ops[1].imm & 0xFFFF
            loaded.pop(regs[0], None)
            continue
        # Anything else that writes a register forgets what it held, except
        # arithmetic on itself, which keeps the field it came from.
        written = [insn.reg_name(r) for r in insn.regs_access()[1]]
        for r in written:
            consts.pop(r, None)
            if mn not in ("add", "sub", "inc", "dec"):
                loaded.pop(r, None)

    out["fields"] = {k: v for k, v in fields.items() if k != "real_cs_relocated"}
    out["why"] = [f"{name} at [0x{off:02X}] ({EXEPACK_ROLES[name]}): {why[name]}"
                  for name, off in sorted(out["fields"].items(), key=lambda kv: kv[1])]
    if out["relocation_table"] is not None:
        out["why"].append(f"relocation table at CS:0x{out['relocation_table']:X}: "
                          f"{why['relocation_table']}")
    if "real_cs_relocated" in fields and fields["real_cs_relocated"] != fields.get("real_cs"):
        out["problem"] = (f"the stub relocates the word at [0x{fields['real_cs_relocated']:02X}] "
                          f"but jumps through a CS at [0x{fields.get('real_cs', 0):02X}]")
    missing = [n for n in ("real_ip", "dest_len", "exepack_size", "real_ss", "real_sp")
               if n not in out["fields"]]
    if not jumped:
        out["problem"] = (f"no far jump through memory in the first {STUB_READ_LIMIT} bytes "
                          f"after the entry: not a stub this knows")
    elif missing:
        out["problem"] = ("the stub was not seen to read " + ", ".join(missing)
                          + ": not a stub this knows")
    elif out["relocation_table"] is None:
        out["problem"] = "the stub was not seen to point SI at a relocation table"
    if out["problem"]:
        return out
    # Every field inside the header, before its "RB".
    outside = [n for n, off in out["fields"].items() if off + 2 > h.ip - 2]
    if outside:
        out["problem"] = (f"the stub reads {', '.join(outside)} at or past the header's "
                          f"\"RB\" (CS:0x{h.ip - 2:X})")
        return out
    for name, offsets in EXEPACK_LAYOUTS.items():
        if offsets == out["fields"]:
            out["layout"] = name
            break
    else:
        out["layout"] = "a layout of its own"
    expected = {"the 16-byte layout": 0x10, "the 18-byte layout, with skip_len": 0x12}
    if out["layout"] in expected and expected[out["layout"]] != h.ip:
        out["problem"] = (f"the stub reads {out['layout']} but the entry is at CS:0x{h.ip:X}, "
                          f"so the header is {h.ip} bytes")
        return out
    out["values"] = {name: struct.unpack_from("<H", data, block + off)[0]
                     for name, off in out["fields"].items()}
    out["values"].setdefault("skip_len", 1)
    size = out["values"]["exepack_size"]
    out["block_ends_at_image_end"] = block + size == h.image_end
    if out["relocation_table"] >= size:
        out["problem"] = (f"the stub reads its relocation table at CS:0x{out['relocation_table']:X}, "
                          f"past the 0x{size:X}-byte block exepack_size gives")
    elif not out["block_ends_at_image_end"]:
        out["problem"] = (f"exepack_size 0x{size:X} from CS:0 (file 0x{block:X}) ends at file "
                          f"0x{block + size:X}, not at the end of the load image "
                          f"(0x{h.image_end:X})")
    return out


def exepack_static(data, h, layout):
    """Decompress an EXEPACK image without running anything, by following the
    stub's own commands, as it does: from the end backwards, `B0`/`B1` fill a
    run with one byte, `B2`/`B3` copy one, bit 0 marks the last, and up to 16
    bytes of 0xFF padding before the last command are skipped. Source and
    destination end skip_len paragraphs below the header and the destination's
    end, and the bytes below where they meet were stored as they are.

    Returns (image, relocations, details) with the relocations as (segment,
    offset) pairs, image-relative, read from the table the way the stub reads
    it: sixteen groups, one per 64 KB of the image, each a count and that many
    offsets; or (None, None, details) with details["problem"] saying why not.
    A relocation at offset 0xFFFF, which the stub patches through the next
    paragraph, is written as that paragraph's 0xFFEF: the same word."""
    v = layout["values"]
    cs, skip, dest = h.cs, v["skip_len"], v["dest_len"]
    details = {"problem": None}
    if skip < 1 or skip > cs or skip > dest:
        details["problem"] = f"skip_len {skip} leaves no data to decompress"
        return None, None, details
    mem = bytearray(max(len(h.image), dest * 16) + 16)
    mem[:len(h.image)] = h.image
    s = (cs - skip) * 16 + 0x0F
    padding = 0
    while padding < 16 and mem[s] == 0xFF:
        s -= 1
        padding += 1
    d = (dest - skip) * 16 + 0x0F
    commands = 0
    while True:
        if s < 2:
            details["problem"] = "the commands run off the start of the image"
            return None, None, details
        c = mem[s]
        count = mem[s - 2] | (mem[s - 1] << 8)
        s -= 3
        if c & 0xFE == 0xB0:
            value = mem[s]
            s -= 1
            if d - count + 1 < 0:
                details["problem"] = f"a fill of {count} bytes runs off the destination"
                return None, None, details
            mem[d - count + 1:d + 1] = bytes([value]) * count
            d -= count
        elif c & 0xFE == 0xB2:
            if d - count + 1 < 0 or s - count + 1 < 0:
                details["problem"] = f"a copy of {count} bytes runs off the image"
                return None, None, details
            for _ in range(count):          # byte by byte, as overlapping copies are
                mem[d] = mem[s]
                d -= 1
                s -= 1
        else:
            details["problem"] = (f"command byte 0x{c:02X} at image offset 0x{s + 3:X} is not "
                                  f"one EXEPACK's stub knows (it would print its error)")
            return None, None, details
        commands += 1
        if c & 1:
            break
    length = (dest - skip + 1) * 16
    details.update(commands=commands, padding=padding, source_left_at=s + 1,
                   destination_left_at=d + 1, image_bytes=length)
    relocations = []
    at = layout["header_file_offset"] + layout["relocation_table"]
    for group in range(16):
        if at + 2 > len(data):
            details["problem"] = "the relocation table runs past the end of the file"
            return None, None, details
        n = struct.unpack_from("<H", data, at)[0]
        at += 2
        for _ in range(n):
            if at + 2 > len(data):
                details["problem"] = "the relocation table runs past the end of the file"
                return None, None, details
            off = struct.unpack_from("<H", data, at)[0]
            at += 2
            seg = group * 0x1000
            if off == 0xFFFF:
                seg, off = seg + 1, 0xFFEF
            relocations.append((seg, off))
    details["relocation_table_file_end"] = at
    details["table_ends_at_image_end"] = at == h.image_end
    outside = [(s_, o) for s_, o in relocations if (s_ << 4) + o + 2 > length]
    if outside:
        details["problem"] = (f"{len(outside)} relocations patch words past the "
                              f"{length:,}-byte image")
        return None, None, details
    return bytes(mem[:length]), relocations, details


def lzexe_header(data, hdr, cs):
    """Read LZEXE's own record of where the program really starts.

    The same idea as `exepack_header` above, for the other packer that states
    the answer instead of leaving it to be inferred. LZEXE 0.90 and 0.91 put a
    sixteen-byte block at the *start* of their decompressor stub, and the MZ
    header's entry offset skips over it -- an LZEXE'd file has `IP = 0x0E`
    because the first fourteen bytes are this:

        +0  ip          +8  compressed size, in paragraphs
        +2  cs         +10  increase in size, in paragraphs
        +4  sp         +12  decompressor size
        +6  ss         +14  checksum

    `cs` and `ss` are relative to the load segment, exactly as in an MZ header.

    Two cross-checks pin the layout rather than trusting a field list, and both
    were run on The Oregon Trail (MECC, 1990), 81,896 bytes packed:

    * the compressed-size word reads 0x130F, and the packed file's own header
      says the stub lives at segment 0x130F -- which it must, because LZEXE
      places the stub immediately after the compressed data;
    * SS:SP resolves to 0x310E0 against an unpacked image of 0x311E0 bytes, so
      the stack sits 256 bytes below the top of the image, where a stack goes.

    The entry it gives for that program is 0x10A. The behavioural heuristic
    said 0x10F -- five bytes and one instruction later, which would have
    skipped the first of six far calls to unit initialisers and left the
    program half-initialised with nothing to indicate it.
    """
    if data[0x1C:0x20] not in (b"LZ91", b"LZ90"):
        return None
    at = hdr + (cs << 4)
    if at + 16 > len(data):
        return None
    ip, cs0, sp, ss, packed, _grow, _stub, _sum = struct.unpack_from(
        "<8H", data, at)
    # The stub sits directly after the compressed data, so its segment is the
    # compressed size. If those two disagree this is not the block we think.
    if packed != cs:
        return None
    return {"ip": ip, "cs": cs0, "sp": sp, "ss": ss,
            "version": data[0x1C:0x20].decode("ascii")}


class Header:
    def __init__(self, data):
        if data[:2] not in (b"MZ", b"ZM"):
            raise SystemExit("not an MZ executable")
        (self.last, self.pages, self.nreloc, self.hdr_paras, self.minalloc,
         self.maxalloc, self.ss, self.sp, _, self.ip, self.cs,
         self.reloc_off) = struct.unpack_from("<HHHHHHHHHHHH", data, 2)
        self.hdr = self.hdr_paras * 16
        self.image_end = ((self.pages - 1) * 512 + (self.last if self.last else 512)
                          if self.pages else len(data))
        self.image = data[self.hdr:self.image_end]
        self.relocs = []
        for i in range(self.nreloc):
            pos = self.reloc_off + i * 4
            if pos + 4 <= len(data):
                off, seg = struct.unpack_from("<HH", data, pos)
                self.relocs.append((seg, off))


def unpack(path, trace=False, max_insns=MAX_INSNS, use_header=True):
    data = Path(path).read_bytes()
    h = Header(data)
    # EXEPACK's layout is settled before anything runs, because it says where
    # the stub hands over: the emulation stops there, so the dump is what the
    # decompressor wrote and not what the program did after it.
    layout = exepack_layout(data, h) if use_header else None
    handoff = None
    if layout and not layout["problem"]:
        v = layout["values"]
        handoff = (((LOAD_SEG + v["real_cs"]) & 0xFFFF) << 4) + v["real_ip"]

    uc = Uc(UC_ARCH_X86, UC_MODE_16)
    uc.mem_map(0, MEM_SIZE)
    uc.mem_write(LOAD_BASE, bytes(h.image))

    # The stub's own relocations must be applied, exactly as DOS would: add the
    # load segment to each word the table points at. Without this the
    # decompressor jumps into nothing.
    for seg, off in h.relocs:
        addr = LOAD_BASE + (seg << 4) + off
        if addr + 2 <= MEM_SIZE:
            value = struct.unpack_from("<H", uc.mem_read(addr, 2), 0)[0]
            uc.mem_write(addr, struct.pack("<H", (value + LOAD_SEG) & 0xFFFF))

    # A minimal PSP: the decompressor may read the memory-size field at :0002.
    uc.mem_write((PSP_SEG << 4) + 2, struct.pack("<H", 0x9FFF))

    uc.reg_write(UC_X86_REG_CS, (LOAD_SEG + h.cs) & 0xFFFF)
    uc.reg_write(UC_X86_REG_IP, h.ip)
    uc.reg_write(UC_X86_REG_SS, (LOAD_SEG + h.ss) & 0xFFFF)
    uc.reg_write(UC_X86_REG_SP, h.sp)
    uc.reg_write(UC_X86_REG_DS, PSP_SEG)
    uc.reg_write(UC_X86_REG_ES, PSP_SEG)
    uc.reg_write(UC_X86_REG_FLAGS, 0x0202)

    # Segment arithmetic wraps, and packers exploit that. PKLITE writes
    # CS = 0xFFF0 -- minus sixteen paragraphs -- so that the entry lands at the
    # very start of the load image via the PSP. Computing LOAD_BASE + (cs << 4)
    # without wrapping puts it a megabyte away, outside mapped memory.
    start_seg = (LOAD_SEG + h.cs) & 0xFFFF
    start_ip = (start_seg << 4) + h.ip
    image_paras = max(1, len(h.image) // 16)
    # A decompressor's first act is often to copy *itself* somewhere safe and
    # jump to the copy. That is a jump into freshly written bytes and it is not
    # the original entry point. Two conditions separate the real thing:
    # a substantial fraction of the image must have been rewritten by then, and
    # control must land back inside the load area where the program belongs --
    # the relocated stub lives above it.
    min_written = max(16, image_paras // 4)
    image_top = LOAD_BASE + len(h.image) + 0x1000

    state = {"written": set(), "insns": 0, "oep": None, "ss": None, "sp": None,
             "stopped": None, "int21": 0, "rejected": 0,
             "cs": (LOAD_SEG + h.cs) & 0xFFFF, "last_new_write": 0,
             "candidates": []}

    def on_write(mu, access, address, size, value, _):
        # Page granularity: a decompressor writes byte by byte, and recording
        # every address individually is both slow and unnecessary.
        before = len(state["written"])
        for a in range(address, address + size, 16):
            state["written"].add(a >> 4)
        if len(state["written"]) != before:
            state["last_new_write"] = state["insns"]

    def on_code(mu, address, size, _):
        state["insns"] += 1
        if address == handoff:
            state["stopped"] = "reached the entry EXEPACK's header states"
            state["handoff"] = state["insns"]
            mu.emu_stop()
            return
        if state["insns"] > max_insns:
            state["stopped"] = "instruction budget exhausted"
            mu.emu_stop()
            return
        # Writing has stopped for a long stretch: decompression is finished and
        # whatever runs now is the program itself.
        if state["candidates"] and \
                state["insns"] - state["last_new_write"] > WRITE_QUIET_INSNS:
            state["stopped"] = "decompression finished (writing went quiet)"
            mu.emu_stop()
            return
        # Handing control to the unpacked program means leaving the
        # decompressor's segment, so CS changes. Jumps *within* the program
        # afterwards do not -- which matters, because once decompression is
        # done the whole image counts as "written" and a rule based on written
        # memory alone would fire on ordinary gameplay code.
        cs = mu.reg_read(UC_X86_REG_CS)
        cs_changed = cs != state["cs"]
        state["cs"] = cs
        if not cs_changed or state["insns"] <= 64:
            return
        if (address >> 4) not in state["written"] or abs(address - start_ip) <= 0x40:
            return
        if address >= image_top:
            state["rejected"] += 1      # the stub jumping into its own copy
            return
        # Record every candidate and keep running. Stopping at the first one
        # truncated the dump -- on a PKLITE-packed game the detection fired
        # before decompression had finished and the image came out nearly
        # empty. Decompression is over when writing stops, not when a jump
        # looks interesting, and the handoff to the program is the candidate
        # that sits closest to that moment.
        state["candidates"].append((state["insns"], address,
                                    mu.reg_read(UC_X86_REG_SS),
                                    mu.reg_read(UC_X86_REG_SP),
                                    len(state["written"])))

    def on_intr(mu, intno, _):
        if intno != 0x21:
            return
        state["int21"] += 1
        ah = (mu.reg_read(UC_X86_REG_AX) >> 8) & 0xFF
        if ah == 0x4A:                    # resize memory block -- always allow
            mu.reg_write(UC_X86_REG_BX, 0x9000)
            mu.reg_write(UC_X86_REG_FLAGS,
                         mu.reg_read(UC_X86_REG_FLAGS) & ~1)
        elif ah == 0x48:                  # allocate
            mu.reg_write(UC_X86_REG_AX, 0x9000)
            mu.reg_write(UC_X86_REG_FLAGS,
                         mu.reg_read(UC_X86_REG_FLAGS) & ~1)
        elif ah in (0x4C, 0x00):           # terminate -- the stub gave up
            state["stopped"] = f"program terminated via INT 21h AH={ah:02X}"
            mu.emu_stop()
        else:
            mu.reg_write(UC_X86_REG_FLAGS,
                         mu.reg_read(UC_X86_REG_FLAGS) & ~1)

    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)
    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_INTR, on_intr)

    try:
        uc.emu_start(start_ip, 0, timeout=120_000_000, count=0)
    except UcError as e:
        if state["oep"] is None:
            state["stopped"] = f"CPU fault: {e}"

    # The handoff to the program is the last control transfer into the image
    # before decompression finished. Candidates after that point are the
    # program running normally -- by then the whole image counts as "written".
    usable = [c for c in state["candidates"] if c[0] <= state["last_new_write"] + 1]
    chosen = (usable or state["candidates"])[-1] if state["candidates"] else None
    if chosen:
        state["oep"], state["ss"], state["sp"] = chosen[1], chosen[2], chosen[3]

    result = {
        "instructions": state["insns"],
        "candidates": len(state["candidates"]),
        "int21_calls": state["int21"],
        "paragraphs_written": len(state["written"]),
        "rejected_candidates": state["rejected"],
        "stopped": state["stopped"],
        "oep": state["oep"],
    }
    # An authoritative entry point beats a heuristic one. The emulation still
    # had to run -- it is what produced the decompressed image -- but where the
    # program starts is stated by the packer, not inferred from behaviour.
    if handoff is not None:
        return exepack_result(uc, data, h, layout, state, result)
    if layout is not None:
        # EXEPACK's "RB", with a stub that does not say how to read the
        # header. A header read on an assumption is how one layout came out
        # 272 bytes long, so nothing in it is used.
        result["exepack_problem"] = layout["problem"]
    lz = lzexe_header(data, h.hdr, h.cs) if use_header and layout is None else None
    if lz:
        # LZEXE states the entry and the stack but not the unpacked length, so
        # the extent still comes from watching where the decompressor wrote.
        result["format"] = "LZEXE " + lz["version"][2:].replace("9", "0.9", 1)
        result["oep_source"] = "packer header (authoritative)"
        result["oep_guess"] = (state["oep"] - LOAD_BASE
                               if state["oep"] is not None else None)
        oep = (lz["cs"] << 4) + lz["ip"]
        ss, sp = (LOAD_SEG + lz["ss"]) & 0xFFFF, lz["sp"]
        top = max(state["written"]) + 1
        size = min(MEM_SIZE - LOAD_BASE, (top << 4) - LOAD_BASE + 0x100)
    elif state["oep"] is not None:
        # The image is sound; the entry point is not.
        #
        # Locating an entry point generically was tried three ways: first jump
        # into written memory, then the same with a minimum-decompression
        # threshold, then requiring CS to change as well. On the EXEPACK
        # known-answer test all three returned 0x8B40 against a true 0x6B2.
        # Generic OEP recovery is the hard part of unpacking, which is why real
        # unpackers are written per format.
        #
        # So the guess is reported and deliberately NOT written into the
        # header. A wrong entry point is worse than none: it sends the
        # disassembler off into the middle of a routine and everything
        # downstream inherits the error. Entry is set to offset 0, and
        # anchors.py can find `main` structurally from the dump.
        result["format"] = "unrecognised"
        result["oep_source"] = "unknown -- header entry set to 0"
        result["oep_candidate"] = state["oep"] - LOAD_BASE
        oep = 0
        ss, sp = state["ss"], state["sp"]
        top = max(state["written"]) + 1
        size = min(MEM_SIZE - LOAD_BASE, (top << 4) - LOAD_BASE + 0x100)
    else:
        return None, result

    image = bytes(uc.mem_read(LOAD_BASE, size))
    result["unpacked_size"] = len(image)
    result["oep_offset"] = oep
    return build_mz(image, oep, ss, sp), result


def exepack_result(uc, data, h, layout, state, result):
    """The end of an EXEPACK unpack, once the emulation has stopped: the image
    the stub wrote against the one decoded statically, and an MZ around it
    with EXEPACK's own relocation table. Returns (file bytes or None, result).

    The image written is the emulated one, with the stub's relocations taken
    back off: it is what the packer's own code produced. The static decode is
    the second source, and the agreement between the two is the evidence that
    the layout was read right -- a field read one word late does not give two
    decoders the same 56 KB by accident."""
    v = layout["values"]
    entry = f"{v['real_cs']:04X}:{v['real_ip']:04X}"
    result.update({
        "format": "Microsoft EXEPACK", "oep_source": "packer header (authoritative)",
        "layout": layout["layout"], "header_bytes": layout["header_bytes"],
        "header_file_offset": layout["header_file_offset"],
        "layout_why": list(layout["why"]), "entry": entry,
        "relocation_table_file_offset": layout["header_file_offset"] + layout["relocation_table"],
        "stack": f"{v['real_ss']:04X}:{v['real_sp']:04X}",
        "oep_offset": (v["real_cs"] << 4) + v["real_ip"],
    })
    if not state.get("handoff"):
        result["problem"] = (f"the stub never reached the entry its header states, {entry}; "
                             f"the emulation stopped: {state['stopped']}")
        return None, result
    static, relocations, details = exepack_static(data, h, layout)
    result["static"] = details
    if static is None:
        # The stub ran and handed over, so its image is sound; what failed is
        # the second reading, and with it the relocation table. Write the
        # dump as this tool always did -- relocated, without a table -- and
        # say why the rest is missing.
        result["problem"] = f"the static decode failed ({details['problem']}), so the " \
                            f"relocation table was not rebuilt"
        top = (v["dest_len"] - v["skip_len"] + 1) * 16
        image = bytes(uc.mem_read(LOAD_BASE, min(MEM_SIZE - LOAD_BASE, top)))
        result["unpacked_size"] = len(image)
        return build_mz(image, result["oep_offset"], (LOAD_SEG + v["real_ss"]) & 0xFFFF,
                        v["real_sp"]), result
    length = len(static)
    emulated = bytearray(uc.mem_read(LOAD_BASE, length))
    for seg, off in relocations:
        at = (seg << 4) + off
        word = struct.unpack_from("<H", emulated, at)[0]
        struct.pack_into("<H", emulated, at, (word - LOAD_SEG) & 0xFFFF)
    differing = [i for i in range(length) if emulated[i] != static[i]]
    result.update({
        "compared_bytes": length, "agreeing_bytes": length - len(differing),
        "agreement": f"{length - len(differing)}/{length}",
        "first_difference": differing[0] if differing else None,
        "relocations": len(relocations), "unpacked_size": length,
    })
    out, placed = build_real_mz(bytes(emulated), relocations, v, h, data)
    result.update(placed)
    return out, result


def build_real_mz(image, relocations, v, h, data):
    """An MZ that loads: `image` behind a header with its relocation table,
    the entry and stack EXEPACK's header states, and enough memory for that
    stack. Whatever the packed file held past its load image is carried past
    this one, at the same page alignment: Microsoft's overlay manager finds
    its overlays by stepping from the start of the file in whole pages, the
    root's first (knowledge/01-dos-binaries.md, Overlays).

    The memory asked for is the packed file's own -- image and minalloc,
    which EXEPACK sized to hold the program -- less the image now on disk,
    and never less than reaches the stack. Returns (file bytes, what was
    placed where)."""
    count = len(relocations)
    hdr_size = (0x1C + 4 * count + 15) // 16 * 16
    total = hdr_size + len(image)
    paras = (len(image) + 15) // 16
    packed_paras = (len(h.image) + 15) // 16 + h.minalloc
    stack_paras = ((v["real_ss"] << 4) + v["real_sp"] + 15) // 16
    minalloc = min(0xFFFF, max(0, packed_paras - paras, stack_paras - paras))
    header = struct.pack("<2sHHHHHHHHHHHHH", b"MZ", total % 512, (total + 511) // 512,
                         count, hdr_size // 16, minalloc, h.maxalloc,
                         v["real_ss"], v["real_sp"], 0, v["real_ip"], v["real_cs"],
                         0x1C, 0)
    header += b"".join(struct.pack("<HH", off, seg) for seg, off in relocations)
    out = header + b"\x00" * (hdr_size - len(header)) + image
    placed = {"minalloc": minalloc, "past_image_bytes": max(0, len(data) - h.image_end),
              "carried_bytes": 0, "carried_at": None, "not_carried": 0}
    page_end = h.pages * 512
    if page_end < len(data):
        # Inside the last page, past the image: the loader reads it, nothing
        # owns it; EXEPACK leaves zeros there. Anything else is said, not moved.
        placed["not_carried"] = sum(1 for b in data[h.image_end:page_end] if b)
        out += b"\x00" * ((-len(out)) % 512)
        placed["carried_at"] = len(out)
        placed["carried_bytes"] = len(data) - page_end
        out += data[page_end:]
    return out, placed


def build_mz(image, oep, ss, sp):
    """Wrap a memory dump back into a loadable-looking MZ file.

    No relocation table: see the module docstring. Ghidra will load this and
    show the real code, which is the point.
    """
    hdr_paras = 2                       # 32 bytes, no relocation entries
    hdr_size = hdr_paras * 16
    total = hdr_size + len(image)
    pages = (total + 511) // 512
    last = total % 512

    cs, ip = divmod(oep, 16)
    # A near entry keeps CS small enough for any tool that assumes segment 0.
    if cs > 0xFFF:
        ip += (cs & 0xF) * 16
        cs &= ~0xF
    header = struct.pack(
        "<2sHHHHHHHHHHHH", b"MZ", last, pages, 0, hdr_paras, 0x0010, 0xFFFF,
        (ss - LOAD_SEG) & 0xFFFF if ss is not None else 0,
        sp if sp is not None else 0xFFFE,
        0, ip & 0xFFFF, cs & 0xFFFF, 0x001C)
    return header + b"\x00" * (hdr_size - len(header)) + image


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--max-insns", type=int, default=MAX_INSNS)
    ap.add_argument("--ignore-packer-header", action="store_true",
                    help="force the generic heuristic even when the format "
                         "states its entry point -- for testing the heuristic "
                         "against a known answer")
    args = ap.parse_args()

    out, info = unpack(args.exe, max_insns=args.max_insns,
                       use_header=not args.ignore_packer_header)

    print(f"instructions executed : {info['instructions']:,}")
    print(f"INT 21h calls handled : {info['int21_calls']}")
    print(f"paragraphs written    : {info['paragraphs_written']:,}")
    # A fault after the handoff is normal and harmless: the emulator carried on
    # into the unpacked program, which then tried to touch hardware that is not
    # there. The image was captured before that. Reporting it as the outcome
    # made a successful run look like a failure.
    outcome = info["stopped"]
    if out is not None and outcome and outcome.startswith("CPU fault"):
        outcome = ("decompression complete; the emulator then ran on into the "
                   "program and faulted, which is expected")
    print(f"outcome               : {outcome}")

    if info.get("layout"):
        print_exepack(info)
    if info.get("exepack_problem"):
        print(f"EXEPACK header        : not used: {info['exepack_problem']}")
    if out is None:
        if info.get("problem"):
            print(f"\n{info['problem']}. Nothing was written. --ignore-packer-header "
                  f"dumps what the decompressor wrote without the header's word on "
                  f"where the program starts.", file=sys.stderr)
            return 1
        print("\nNo unpacked entry point was reached. Either the file is not "
              "packed, or its decompressor needs more of DOS than this stubs "
              "out. Nothing was written.", file=sys.stderr)
        return 1

    print(f"format                : {info.get('format')}")
    print(f"original entry point  : offset 0x{info['oep_offset']:X}"
          + (f" ({info['entry']})" if info.get("entry") else "")
          + f"  [{info.get('oep_source')}]")
    if info.get("oep_guess") is not None and info["oep_guess"] != info["oep_offset"]:
        # Worth printing every time. It is the only place the heuristic gets
        # marked against an answer, and on the one file where both were
        # available it was wrong by one instruction.
        print(f"  (the behavioural heuristic would have said "
              f"0x{info['oep_guess']:X} -- "
              f"{info['oep_guess'] - info['oep_offset']:+d} bytes)")
    print(f"unpacked image        : {info['unpacked_size']:,} bytes")
    if info.get("oep_source", "").startswith("unknown"):
        print(f"\nNOTE: this format's entry point is not recovered. A "
              f"behavioural guess would have said "
              f"0x{info.get('oep_candidate', 0):X}, but on a known-answer test "
              f"the same rule was wrong (0x8B40 against a true 0x6B2), so it "
              f"is not written into the header -- a wrong entry point sends "
              f"the disassembler into the middle of a routine and everything "
              f"after inherits the error.\n"
              f"The image itself is sound. Load it and run "
              f"tools/anchors.py, which locates main from structure rather "
              f"than from the header.", file=sys.stderr)
    Path(args.output).write_bytes(out)
    print(f"\nwrote {args.output}")
    if info.get("relocations") is not None:
        print(f"An MZ that loads: its {info['relocations']} relocations are EXEPACK's own, "
              f"read from its table, and the entry and stack are its header's. Feed it "
              f"to tools/triage.py and the pipeline.")
        return 0
    print("This dump is for analysis. Relocations are not reconstructed, so it "
          "is not expected to run -- feed it to tools/triage.py and the "
          "pipeline.")
    return 0


def print_exepack(info):
    """What EXEPACK's stub said about its header, and how the two readings
    of the image agree."""
    print(f"header layout         : {info['layout']}, {info['header_bytes']} bytes at "
          f"CS:0 (file 0x{info['header_file_offset']:X}), read from the stub:")
    for line in info["layout_why"]:
        print(f"                        {line}")
    s = info.get("static") or {}
    if s.get("problem"):
        print(f"static decode         : failed: {s['problem']}")
    elif s:
        print(f"static decode         : {s['commands']} commands, {s['image_bytes']:,} bytes; "
              f"source and destination met at image offset 0x{s['source_left_at']:X}"
              + ("" if s["source_left_at"] == s["destination_left_at"] else
                 f" and 0x{s['destination_left_at']:X}")
              + f"; {s['padding']} bytes of 0xFF padding skipped")
    if info.get("compared_bytes"):
        n, same = info["compared_bytes"], info["agreeing_bytes"]
        line = (f"agreement             : {same:,} of {n:,} bytes ({100.0 * same / n:.3f}%) "
                f"between the stub's own output, stopped at its handoff, and the static "
                f"decode, relocations unapplied")
        if info["first_difference"] is not None:
            line += f"; the first difference at image offset 0x{info['first_difference']:X}"
        print(line)
        print(f"relocations           : {info['relocations']}, from the table at file "
              f"0x{info['relocation_table_file_offset']:X}, ending "
              + ("at the end of the load image" if s.get("table_ends_at_image_end") else
                 f"at file 0x{s.get('relocation_table_file_end', 0):X}, not at the end of "
                 f"the load image"))
        print(f"entry, stack          : {info['entry']}, {info['stack']}; minalloc "
              f"{info['minalloc']:,} paragraphs")
    if info.get("carried_bytes"):
        print(f"past the load image   : {info['carried_bytes']:,} bytes carried over, from "
              f"the packed file's page boundary to the new one at file "
              f"0x{info['carried_at']:X}"
              + (f"; {info['not_carried']} non-zero bytes between the packed image's "
                 f"end and its page boundary were not" if info["not_carried"] else ""))


if __name__ == "__main__":
    sys.exit(main())
