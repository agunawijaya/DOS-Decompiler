#!/usr/bin/env python3
"""
mzinfo.py -- Structural analysis of DOS MZ executables (16-bit real mode).

Step 1 of the decompilation workflow. Before any disassembler touches the file,
this establishes the facts every later stage depends on:

  * where the load image really starts and ends
  * the true entry point (CS:IP is relative to the load image, not the file)
  * which segments the program actually uses, recovered from the relocation
    table rather than guessed
  * whether there is data appended past the load image (overlays, embedded
    resources, packer payloads) -- a classic source of "the decompiler stopped
    early" confusion
  * heuristic detection of packers and of overlay managers

--json is what pipeline.ps1 reads, and its shape does not change. --evidence
writes the same facts as an evidence envelope (knowledge/17-evidence.md)
instead: each one with the file offset it was read from, tied to the file's
SHA-256, with what these checks cannot see written down beside them.

Usage:
    python mzinfo.py GAME.EXE            # human-readable report
    python mzinfo.py GAME.EXE --json     # machine-readable, for the pipeline
    python mzinfo.py GAME.EXE --evidence -   # the envelope alone, on stdout
"""

import argparse
import json
import struct
import sys
from collections import Counter
from pathlib import Path

import evidence

MZ_HEADER = "<2sHHHHHHHHHHHHH"  # 28 bytes through the overlay number
MZ_HEADER_SIZE = struct.calcsize(MZ_HEADER)

# Byte signatures of common DOS-era executable packers. If one of these appears
# near the entry point the file must be unpacked before decompilation: the
# decompiler would otherwise faithfully decompile the *decompressor*.
PACKER_SIGNATURES = {
    b"LZ91": "LZEXE 0.91",
    b"LZ09": "LZEXE 0.90",
    b"PKLITE": "PKLITE",
    b"diet": "DIET",
    b"EXEPACK": "Microsoft EXEPACK",
    b"aPLib": "aPLib",
    b"UPX!": "UPX",
}

# Microsoft overlay manager marker; also used by Borland's overlay scheme.
OVERLAY_SIGNATURES = {
    b"FBOV": "Borland/Microsoft overlay table (FBOV)",
    b"OVLM": "overlay manager marker (OVLM)",
}


class MZError(Exception):
    pass


def parse(path):
    data = Path(path).read_bytes()
    if len(data) < MZ_HEADER_SIZE:
        raise MZError(f"file too small to be an MZ executable ({len(data)} bytes)")

    (sig, last_page, pages, nreloc, hdr_paras, minalloc, maxalloc,
     ss, sp, checksum, ip, cs, reloc_off, overlay) = struct.unpack_from(
        MZ_HEADER, data, 0)

    if sig not in (b"MZ", b"ZM"):
        raise MZError(f"not an MZ executable (magic = {sig!r})")

    header_size = hdr_paras * 16
    # The load image length: (pages - 1) full 512-byte pages plus the bytes used
    # on the final page. last_page == 0 is a legal encoding meaning "full page".
    if pages == 0:
        image_end = len(data)
    else:
        image_end = (pages - 1) * 512 + (last_page if last_page else 512)

    image_start = header_size
    image_size = max(0, image_end - image_start)
    trailing = len(data) - image_end  # data beyond the declared load image

    entry_linear = image_start + (cs << 4) + ip
    stack_linear = image_start + (ss << 4) + sp

    relocs = []
    if nreloc:
        if reloc_off + nreloc * 4 > len(data):
            raise MZError("relocation table extends past end of file")
        for i in range(nreloc):
            off, seg = struct.unpack_from("<HH", data, reloc_off + i * 4)
            relocs.append({
                "index": i,
                "seg": seg,
                "off": off,
                "linear": image_start + (seg << 4) + off,
            })

    # Every relocation entry points at a 16-bit segment value stored in the load
    # image. Reading those values back tells us which segments the program
    # actually constructs at load time -- the most reliable segment inventory
    # available without executing anything.
    referenced = Counter()
    for r in relocs:
        if r["linear"] + 2 <= len(data):
            (value,) = struct.unpack_from("<H", data, r["linear"])
            r["value"] = value
            referenced[value] += 1
        else:
            r["value"] = None

    result = {
        "file": str(path),
        "file_size": len(data),
        "header": {
            "magic": sig.decode("ascii", "replace"),
            "bytes_on_last_page": last_page,
            "pages_512": pages,
            "relocations": nreloc,
            "header_paragraphs": hdr_paras,
            "header_size": header_size,
            "min_extra_paragraphs": minalloc,
            "max_extra_paragraphs": maxalloc,
            "initial_ss": ss,
            "initial_sp": sp,
            "checksum": checksum,
            "initial_ip": ip,
            "initial_cs": cs,
            "reloc_table_offset": reloc_off,
            "overlay_number": overlay,
        },
        "layout": {
            "image_start": image_start,
            "image_end": image_end,
            "image_size": image_size,
            "trailing_bytes": trailing,
            "entry_point_file_offset": entry_linear,
            "entry_point_cs_ip": f"{cs:04X}:{ip:04X}",
            "stack_ss_sp": f"{ss:04X}:{sp:04X}",
            "stack_file_offset": stack_linear,
            "min_memory_bytes": minalloc * 16,
            "max_memory_bytes": maxalloc * 16,
        },
        "relocations": relocs,
        "referenced_segments": [
            {"segment": s, "count": c} for s, c in sorted(referenced.items())
        ],
        "findings": [],
    }

    _analyze(data, result)
    return data, result


def _analyze(data, result):
    """Attach interpretation -- the part that saves time later."""
    f = result["findings"]
    h = result["header"]
    lay = result["layout"]
    ep = lay["entry_point_file_offset"]

    if lay["trailing_bytes"] > 0:
        f.append({
            "level": "warn" if lay["trailing_bytes"] > 64 else "info",
            "code": "trailing-data",
            "message": (
                f"{lay['trailing_bytes']} bytes exist past the declared load image. "
                "Small amounts are usually linker padding; large amounts mean "
                "overlays, appended data files, or a packer payload. The "
                "disassembler will not see this region unless told to."
            ),
        })

    if lay["stack_file_offset"] > lay["image_end"]:
        f.append({
            "level": "info",
            "code": "stack-above-image",
            "message": (
                "The initial stack sits above the load image, in memory DOS "
                "allocates at run time. Normal, but it means SS != DS-relative "
                "file data: do not map the stack into the disassembly."
            ),
        })

    n = h["relocations"]
    size_kb = result["file_size"] / 1024.0
    if n == 0:
        f.append({
            "level": "warn", "code": "no-relocations",
            "message": (
                "No relocations at all: either a .COM-style single-segment "
                "program linked as EXE, or a packed file. Check the packer scan."
            ),
        })
    elif n < 8 and size_kb > 16:
        # Verified against Sopwith: 2 relocations for a 60 KB image looks
        # alarming but is simply what small-model C produces. Code that never
        # forms a far pointer needs no fixups, so only the startup requires
        # them -- and both of Sopwith's sit within 0x30 bytes of the entry
        # point. Check that before suspecting anything worse.
        near_entry = sum(1 for r in result["relocations"]
                         if abs(r["linear"] - ep) < 0x40)
        if near_entry == n:
            f.append({
                "level": "info", "code": "few-relocations-small-model",
                "message": (
                    f"Only {n} relocations, and all of them sit next to the "
                    "entry point. This is the signature of a small- or "
                    "tiny-model program: the startup code loads DGROUP and the "
                    "stack segment, and nothing else ever needs a segment "
                    "fixup. Treat the binary as one code segment plus one data "
                    "group."
                ),
            })
        else:
            f.append({
                "level": "warn", "code": "few-relocations",
                "message": (
                    f"Only {n} relocations for a {size_kb:.0f} KB image, and "
                    "they are not all clustered at the entry point. A "
                    "multi-segment program of this size would need dozens. "
                    "Suspect either a packer, or code that computes segment "
                    "values at run time instead of letting the loader fix them "
                    "up -- the latter defeats automatic segment resolution and "
                    "the segments will have to be supplied by hand."
                ),
            })

    # Packer scan: check the whole file, but weight hits near the entry point.
    for sigbytes, name in PACKER_SIGNATURES.items():
        pos = data.find(sigbytes)
        if pos != -1:
            near = abs(pos - ep) < 0x200
            f.append({
                "level": "error" if near else "info",
                "code": "packer",
                "message": (
                    f"Packer signature {name!r} found at file offset 0x{pos:X}"
                    + (" -- adjacent to the entry point, so the file is almost "
                       "certainly packed and MUST be unpacked before "
                       "decompilation." if near else
                       " -- far from the entry point, possibly coincidental; "
                       "verify before acting on it.")
                ),
            })

    for sigbytes, name in OVERLAY_SIGNATURES.items():
        pos = data.find(sigbytes)
        if pos != -1:
            f.append({
                "level": "warn", "code": "overlay",
                "message": (
                    f"{name} found at file offset 0x{pos:X}. Overlaid code is "
                    "loaded on demand into a shared memory region, so several "
                    "different functions occupy the same addresses at different "
                    "times. Each overlay must be disassembled as its own "
                    "address space."
                ),
            })

    if h["overlay_number"] != 0:
        f.append({
            "level": "warn", "code": "overlay-number",
            "message": (
                f"Header overlay number is {h['overlay_number']}, not 0. This "
                "file is itself an overlay module, not a main program."
            ),
        })

    if h["max_extra_paragraphs"] == 0xFFFF:
        f.append({
            "level": "info", "code": "max-alloc",
            "message": (
                "maxalloc = 0xFFFF: the program asks DOS for all available "
                "memory. Typical of programs doing their own heap management "
                "(and of large-model C runtimes)."
            ),
        })

    # Segment inventory derived from relocation targets.
    segs = result["referenced_segments"]
    if segs:
        distinct = len(segs)
        f.append({
            "level": "info", "code": "segment-inventory",
            "message": (
                f"{distinct} distinct segment value(s) are written by the "
                "loader: " + ", ".join(f"{s['segment']:04X}h" for s in segs[:12])
                + ("..." if distinct > 12 else "")
                + ". These are load-image-relative paragraph numbers; add the "
                "program's load segment at run time. Use them as the initial "
                "segment map for the disassembler."
            ),
        })


def report(result):
    h, lay = result["header"], result["layout"]
    out = []
    A = out.append
    A(f"File            : {result['file']}")
    A(f"Size            : {result['file_size']} bytes")
    A("")
    A("-- MZ header ------------------------------------------------------")
    A(f"  magic                {h['magic']}")
    A(f"  header size          {h['header_size']} bytes ({h['header_paragraphs']} paragraphs)")
    A(f"  pages / last page    {h['pages_512']} / {h['bytes_on_last_page']}")
    A(f"  relocations          {h['relocations']} (table at 0x{h['reloc_table_offset']:04X})")
    A(f"  entry CS:IP          {lay['entry_point_cs_ip']}  -> file offset 0x{lay['entry_point_file_offset']:X}")
    A(f"  stack SS:SP          {lay['stack_ss_sp']}")
    A(f"  extra memory         min {lay['min_memory_bytes']:,} / max {lay['max_memory_bytes']:,} bytes")
    A(f"  overlay number       {h['overlay_number']}")
    A("")
    A("-- Layout ---------------------------------------------------------")
    A(f"  load image           0x{lay['image_start']:X} .. 0x{lay['image_end']:X}  ({lay['image_size']} bytes)")
    A(f"  trailing data        {lay['trailing_bytes']} bytes")
    A("")
    if result["referenced_segments"]:
        A("-- Segments referenced by relocations ------------------------------")
        for s in result["referenced_segments"]:
            A(f"  {s['segment']:04X}h   ({s['count']} relocation(s))")
        A("")
    if result["relocations"]:
        A("-- Relocation entries ---------------------------------------------")
        for r in result["relocations"][:32]:
            val = "----" if r["value"] is None else f"{r['value']:04X}"
            A(f"  [{r['index']:3d}] {r['seg']:04X}:{r['off']:04X}"
              f"  file 0x{r['linear']:06X}  patches segment value {val}h")
        if len(result["relocations"]) > 32:
            A(f"  ... {len(result['relocations']) - 32} more")
        A("")
    A("-- Findings -------------------------------------------------------")
    if not result["findings"]:
        A("  (nothing unusual)")
    for fi in result["findings"]:
        tag = {"info": "INFO ", "warn": "WARN ", "error": "ERROR"}[fi["level"]]
        A(f"  [{tag}] {fi['code']}")
        for line in _wrap(fi["message"], 66):
            A(f"          {line}")
    return "\n".join(out)


def _wrap(text, width):
    words, line, lines = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        lines.append(line)
    return lines


# True of every run, whatever the file: what these checks cannot see.
LIMITATIONS = [
    "Nothing is disassembled. Every finding comes from the header, the "
    "relocation table and byte searches.",
    "The segment inventory is read from the relocation table. A program that "
    "builds segment values at run time uses segments this does not list.",
    "Packer and overlay signatures are searched for anywhere in the file; a "
    "hit is evidence of the bytes, not of the packer. One far from the entry "
    "point is reported as possibly coincidental.",
]


def _unknown_for(f, result):
    """The question a finding leaves open, when it leaves one."""
    if f["code"] == "trailing-data" and f["level"] == "warn":
        return (f"what the {result['layout']['trailing_bytes']} bytes past the "
                f"load image are: overlays, appended data, or a packer's payload")
    if f["code"] == "few-relocations":
        return ("whether the program is packed, or builds its segment values "
                "at run time instead of letting the loader fix them up")
    if f["code"] == "no-relocations":
        return "whether this is a single-segment program or a packed one"
    if f["code"] == "packer" and f["level"] == "info":
        return "whether the packer signature far from the entry point is coincidental"
    return None


def _hex(v):
    return f"0x{v:x}"


def envelope(path):
    """The evidence envelope: the --json result, each finding as an evidence
    item, and what the header-level checks cannot see."""
    try:
        _, result = parse(path)
        target = evidence.target_identity(path)
    except MZError as e:
        target = evidence.target_identity(path)
        return evidence.envelope(
            "mzinfo", target, status="unsupported",
            result={"file": str(path), "error": str(e)},
            limitations=["Only MZ executables are read. A .COM has no header "
                         "for this to describe; see triage.py."])
    except OSError as e:
        return evidence.envelope(
            "mzinfo", {"path": str(Path(path).resolve()), "size": None,
                       "sha256": None},
            status="error", result={"file": str(path), "error": str(e)},
            limitations=["The file could not be read, so nothing about it "
                         "was established."])

    h, lay = result["header"], result["layout"]
    items = [
        {"kind": "magic", "claim": f"MZ signature {h['magic']!r}",
         "location": {"file_offset": "0x0"}, "value": h["magic"]},
        {"kind": "header-size",
         "claim": f"header of {h['header_size']} bytes "
                  f"({h['header_paragraphs']} paragraphs)",
         "location": {"file_offset": "0x8"}, "value": h["header_size"]},
        {"kind": "load-image",
         "claim": f"load image 0x{lay['image_start']:X}..0x{lay['image_end']:X} "
                  f"({lay['image_size']} bytes)",
         "location": {"file_offset": _hex(lay["image_start"]),
                      "file_end": _hex(lay["image_end"])},
         "value": {"pages_512": h["pages_512"],
                   "bytes_on_last_page": h["bytes_on_last_page"],
                   "image_size": lay["image_size"],
                   "trailing_bytes": lay["trailing_bytes"]}},
        {"kind": "entry-point",
         "claim": f"entry {lay['entry_point_cs_ip']} at file offset "
                  f"0x{lay['entry_point_file_offset']:X}",
         "location": {"file_offset": _hex(lay["entry_point_file_offset"])},
         "value": lay["entry_point_cs_ip"]},
        {"kind": "stack", "claim": f"stack {lay['stack_ss_sp']}",
         "location": {"file_offset": "0xe"}, "value": lay["stack_ss_sp"]},
        {"kind": "memory-request",
         "claim": f"extra memory min {lay['min_memory_bytes']:,} / max "
                  f"{lay['max_memory_bytes']:,} bytes",
         "location": {"file_offset": "0xa"},
         "value": {"min": lay["min_memory_bytes"], "max": lay["max_memory_bytes"]}},
        {"kind": "overlay-field", "claim": f"overlay number {h['overlay_number']}",
         "location": {"file_offset": "0x1a"}, "value": h["overlay_number"]},
        {"kind": "relocation-count",
         "claim": f"{h['relocations']} relocations, table at "
                  f"0x{h['reloc_table_offset']:04X}",
         "location": {"file_offset": _hex(h["reloc_table_offset"])},
         "value": h["relocations"]},
    ]
    for s in result["referenced_segments"]:
        items.append({"kind": "referenced-segment",
                      "claim": f"segment {s['segment']:04X}h is patched by "
                               f"{s['count']} relocation(s)",
                      "value": s})
    unknowns = []
    for f in result["findings"]:
        items.append({"kind": f["code"], "level": f["level"], "claim": f["code"],
                      "detail": f["message"]})
        question = _unknown_for(f, result)
        if question:
            unknowns.append(question)
    return evidence.envelope("mzinfo", target, status="ok", result=result,
                             evidence=items, limitations=LIMITATIONS,
                             unknowns=unknowns)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", help="DOS MZ executable")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    ap.add_argument("--evidence", metavar="FILE",
                    help="also write the evidence envelope here (knowledge/"
                         "17-evidence.md); '-' prints it instead of the report")
    args = ap.parse_args()
    if args.json and args.evidence == "-":
        ap.error("--json and --evidence - both want stdout; give --evidence a file")

    if args.evidence:
        env = envelope(args.exe)
        evidence.write(env, args.evidence)
        if args.evidence == "-":
            return 0 if env["status"] == "ok" else 2
        # stdout may be the --json the pipeline reads, so say it elsewhere.
        print(f"mzinfo: wrote {args.evidence}", file=sys.stderr)

    try:
        _, result = parse(args.exe)
    except (MZError, OSError) as e:
        print(f"mzinfo: {e}", file=sys.stderr)
        return 2

    if args.json:
        json.dump(result, sys.stdout, indent=2)
        print()
    else:
        print(report(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
