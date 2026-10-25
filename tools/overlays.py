#!/usr/bin/env python3
"""
overlays.py -- Microsoft LINK's overlays: list the modules appended to an MZ,
and write one view per module for the pipeline to analyse.

Why this exists
---------------
A program linked with overlays keeps most of its code out of memory and reads
it in when it is called. Microsoft LINK appends each overlay module to the
executable as an MZ of its own -- header, relocation table, image -- with its
overlay number at 0x1A of its header, each on the 512-byte page after the
one before. The overlay manager in the root finds module N the same way:
reading headers from the start of the file and stepping each one's page count
times 512 (read whole in The Ancient Art of War's manager; knowledge/
01-dos-binaries.md, Overlays). A call into an overlay is `int 3Fh` followed by
a byte and a word: which overlay segment, and the offset in it. Every module
loads at the same place, so their code shares addresses, and one flat
disassembly of the file is nonsense.

What it writes
--------------
A view per module: what memory holds while that module is resident. The
root's load image with the module's image at the overlay area, and both
relocation tables -- the root's, and the module's, whose segments are counted
from the program's start just as the root's are. Every byte of a view comes
from the root or from the module. A view is refused, and nothing written for
it, when the root's bytes there are not all zero (LINK leaves the area empty),
when the module does not fit inside the root's image, when a relocation of
the root patches a word inside the area, or when one of the module's patches
a word outside the module.

Where the area starts is read from the modules' own relocation tables: they
name link segments, and the lowest any module names is the area's first (all
six of The Ancient Art of War's name 0482). Modules whose tables are empty
say nothing about it; then --load-segment has to.

Beside each view goes its record, VIEW.view.json: an evidence envelope saying
which overlay it is, of which file, built from which root, and the checks it
passed. pipeline.ps1 finds it beside the view, checks that it describes the
file given, and the run's loadimage.json carries it.

What it does not do
-------------------
Read the overlay manager's tables, so it does not say which `int 3Fh` call
lands in which module, and Ghidra still decodes the three bytes after each
`int 3Fh` as instructions. The rest of the area after a module is zero in its
view; at run time it holds whatever a larger module left there. A packed root
has to be unpacked first (unpack.py carries the overlays across). Borland's
FBOV overlays are another format, not read here.

Usage:
    python overlays.py GAME.EXE
    python overlays.py GAME.EXE --json overlays.json
    python overlays.py GAME.EXE --views OUTDIR [--root UNPACKED.EXE] [--load-segment 0x482]
    python overlays.py --check-view VIEW.view.json VIEW.exe
"""

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402

INT3F = b"\xCD\x3F"
# What LINK's overlay manager reads from a module's header, and nothing else.
FIELDS = ("last", "pages", "relocations", "header_paragraphs", "minalloc", "maxalloc",
          "ss", "sp", "checksum", "ip", "cs", "relocation_table", "overlay")


class Refused(Exception):
    """A view that would not be what memory holds, and why."""


def header_at(data, at):
    """The MZ header at file offset `at` with its module's bounds, or None if
    there is not a whole one there."""
    if at < 0 or at + 0x1C > len(data) or data[at:at + 2] not in (b"MZ", b"ZM"):
        return None
    h = dict(zip(FIELDS, struct.unpack_from("<13H", data, at + 2)))
    if h["pages"] == 0 or h["last"] > 512:
        return None
    h["file_offset"] = at
    h["header_bytes"] = h["header_paragraphs"] * 16
    h["end"] = at + (h["pages"] - 1) * 512 + (h["last"] or 512)
    table_end = h["relocation_table"] + 4 * h["relocations"]
    if (h["header_bytes"] < 0x1C or h["end"] > len(data) or h["end"] < at + h["header_bytes"]
            or (h["relocations"] and table_end > h["header_bytes"])):
        return None
    return h


def module_parts(data, h):
    """(image, relocations as (segment, offset)) of the module whose header is h."""
    at = h["file_offset"]
    image = data[at + h["header_bytes"]:h["end"]]
    relocs = [struct.unpack_from("<HH", data, at + h["relocation_table"] + 4 * i)[::-1]
              for i in range(h["relocations"])]
    return image, relocs


def find(data):
    """The overlays appended to the MZ in `data`, walked as LINK's overlay
    manager walks them: from the start of the file, each header's page count
    times 512 to the next. A module is an MZ with a non-zero overlay number;
    the walk stops at the first thing that is not one.

    None if `data` is not an MZ; otherwise {"root", "modules", "after"}, where
    "after" is the bytes past the last module (or past the root, when there is
    none) and each module records its file range, image, relocations and the
    link segments they name."""
    root = header_at(data, 0)
    if root is None:
        return None
    modules = []
    at = root["pages"] * 512
    while True:
        h = header_at(data, at)
        if h is None or h["overlay"] == 0:
            break
        image, relocs = module_parts(data, h)
        h.update(image_bytes=len(image), segments=sorted({s for s, _ in relocs}),
                 image_sha256=hashlib.sha256(image).hexdigest())
        modules.append(h)
        at += h["pages"] * 512
    end = modules[-1]["end"] if modules else root["end"]
    return {"root": root, "modules": modules, "after": max(0, len(data) - end),
            "walk_ends_at": at}


def int3f_calls(image):
    """Every `int 3Fh` in a load image, as (image offset, the byte after it,
    the word after that): the overlay segment's index and the offset in it,
    as LINK's overlay calls carry them. Found by bytes, not by decoding, so
    one inside data is counted too."""
    out, at = [], image.find(INT3F)
    while at != -1:
        if at + 5 <= len(image):
            out.append((at, image[at + 2], struct.unpack_from("<H", image, at + 3)[0]))
        at = image.find(INT3F, at + 1)
    return out


def area_segment(modules):
    """The lowest link segment any module's relocations name, and how many
    modules name it; (None, 0) when no module has a relocation."""
    named = [m["segments"][0] for m in modules if m["segments"]]
    if not named:
        return None, 0
    low = min(named)
    return low, sum(1 for m in modules if low in m["segments"])


def build_view(root_data, module_data, module, area):
    """The root with `module`'s image at segment `area`: (view bytes, checks).
    Refused when that is not what memory would hold."""
    root = header_at(root_data, 0)
    if root is None:
        raise Refused("the root is not an MZ with a whole header")
    image = bytearray(root_data[root["header_bytes"]:root["end"]])
    root_relocs = module_parts(root_data, root)[1]
    mod_image, mod_relocs = module_parts(module_data, module)
    start, end = area * 16, area * 16 + len(mod_image)
    if end > len(image):
        raise Refused(f"overlay {module['overlay']} is {len(mod_image):,} bytes and does not "
                      f"fit: from segment {area:04X} it ends at image offset 0x{end:X}, past "
                      f"the root's image (0x{len(image):X})")
    used = [i for i in range(start, end) if image[i]]
    if used:
        raise Refused(f"the overlay area is not empty: the root holds {len(used)} non-zero "
                      f"bytes between image offsets 0x{start:X} and 0x{end:X}, the first at "
                      f"0x{used[0]:X}")
    inside = [(s, o) for s, o in root_relocs if start - 1 <= (s << 4) + o < end]
    if inside:
        s, o = inside[0]
        raise Refused(f"{len(inside)} of the root's relocations patch words in the overlay "
                      f"area, the first {s:04X}:{o:04X}")
    outside = [(s, o) for s, o in mod_relocs if not start <= (s << 4) + o <= end - 2]
    if outside:
        s, o = outside[0]
        raise Refused(f"{len(outside)} of overlay {module['overlay']}'s relocations patch words "
                      f"outside its image as placed at segment {area:04X}, the first "
                      f"{s:04X}:{o:04X}")
    image[start:end] = mod_image
    relocs = root_relocs + mod_relocs
    hdr = (0x1C + 4 * len(relocs) + 15) // 16 * 16
    total = hdr + len(image)
    fields = [root[f] for f in FIELDS]
    fields[0], fields[1], fields[2], fields[3] = total % 512, (total + 511) // 512, len(relocs), hdr // 16
    fields[11], fields[12] = 0x1C, 0
    header = b"MZ" + struct.pack("<13H", *fields)
    header += b"".join(struct.pack("<HH", o, s) for s, o in relocs)
    view = header + b"\0" * (hdr - len(header)) + bytes(image)
    checks = {"area_empty": True, "fits": True, "root_relocations_outside_area": True,
              "module_relocations_inside_module": True,
              "area": {"segment": f"{area:04X}", "image_start": start, "image_end": end},
              "relocations": {"root": len(root_relocs), "module": len(mod_relocs)}}
    return view, checks


def describe(path, found, root_path=None, root_found=None):
    """The listing as data: what --json writes and the report prints."""
    root = root_found["root"] if root_found else found["root"]
    image_start, image_end = root["header_bytes"], root["end"]
    root_data = Path(root_path or path).read_bytes()
    calls = int3f_calls(root_data[image_start:image_end])
    entry = image_start + (root["cs"] << 4) + root["ip"]
    packed = root_data[max(0, entry - 2):entry] == b"RB"
    area, naming = area_segment(found["modules"])
    out = {
        "file": str(path),
        "root": {"file": str(root_path or path), "image_bytes": image_end - image_start,
                 "pages": found["root"]["pages"], "relocations": root["relocations"],
                 "packed": packed},
        "modules": [{"overlay": m["overlay"], "file_offset": m["file_offset"],
                     "file_end": m["end"], "header_bytes": m["header_bytes"],
                     "image_bytes": m["image_bytes"], "relocations": m["relocations"],
                     "segments": [f"{s:04X}" for s in m["segments"]],
                     "entry": f"{m['cs']:04X}:{m['ip']:04X}",
                     "stack": f"{m['ss']:04X}:{m['sp']:04X}"} for m in found["modules"]],
        "bytes_after_last": found["after"],
        "load_segment": f"{area:04X}" if area is not None else None,
        "load_segment_source": (f"the lowest link segment any module's relocations name; "
                                f"{naming} of {len(found['modules'])} modules name it"
                                if area is not None else None),
        "int3f_calls": None if packed else len(calls),
        "int3f_indexes": None if packed else sorted({i for _, i, _ in calls}),
    }
    return out


def report(d):
    out = [f"File      : {d['file']}"]
    r = d["root"]
    out.append(f"Root      : {r['image_bytes']:,}-byte load image, {r['pages']} pages, "
               f"{r['relocations']} relocations" + (f" ({r['file']})" if r["file"] != d["file"] else "")
               + ("; packed with EXEPACK" if r["packed"] else ""))
    mods = d["modules"]
    if not mods:
        out.append("Overlays  : none -- no MZ with an overlay number on the page after the root")
        return "\n".join(out)
    out.append(f"Overlays  : {len(mods)}, found as LINK's overlay manager finds them: from the "
               f"start of the file, each header's page count times 512")
    out.append("   #  file range          header     image  relocations  link segments")
    for m in mods:
        out.append(f"  {m['overlay']:>2}  0x{m['file_offset']:05X}..0x{m['file_end'] - 1:05X}  "
                   f"{m['header_bytes']:>6,}  {m['image_bytes']:>8,}  {m['relocations']:>11,}  "
                   f"{' '.join(m['segments'])}")
    out.append(f"After the last: {d['bytes_after_last']:,} bytes")
    if d["load_segment"]:
        out.append(f"Overlay area: segment {d['load_segment']}, {d['load_segment_source']}")
    else:
        out.append("Overlay area: not known -- no module has a relocation; give --load-segment")
    if d["int3f_calls"] is None:
        out.append("int 3Fh   : the root is packed, so its overlay calls cannot be read until it "
                   "is unpacked (tools/unpack.py carries the overlays across)")
    else:
        idx = d["int3f_indexes"]
        out.append(f"int 3Fh   : {d['int3f_calls']} in the root's image, by bytes"
                   + (f"; overlay segment indexes {idx[0]}..{idx[-1]}" if idx else ""))
    return "\n".join(out)


LIMITATIONS = [
    "The overlay area's segment is the lowest link segment any module's relocations "
    "name, not read from the overlay manager's tables.",
    "The rest of the overlay area after this module is zero in the view; at run time "
    "it holds whatever a larger module left there.",
    "Which int 3Fh call lands in this module is in the overlay manager's tables, which "
    "are not read here; Ghidra decodes the three bytes after each int 3Fh as "
    "instructions.",
]


def write_views(path, out_dir, root_path=None, load_segment=None):
    """One view and its record per module. Returns [(overlay, view path or
    None, record path or reason)]."""
    data = Path(path).read_bytes()
    found = find(data)
    if found is None:
        raise SystemExit(f"{path} is not an MZ. overlays.py reads the overlays appended to one.")
    if not found["modules"]:
        raise SystemExit(f"{path} has no overlays: nothing on the page after its load image "
                         f"is an MZ with an overlay number.")
    root_data = Path(root_path).read_bytes() if root_path else data
    if header_at(root_data, 0) is None:
        raise SystemExit(f"{root_path or path}: the root is not an MZ with a whole header.")
    entry = header_at(root_data, 0)
    at = entry["header_bytes"] + (entry["cs"] << 4) + entry["ip"]
    if root_data[max(0, at - 2):at] == b"RB":
        raise SystemExit(f"the root of {path} is packed with EXEPACK, and a view of a packed "
                         f"root is the decompressor. Unpack it first: python tools/unpack.py "
                         f"\"{path}\" -o UNPACKED.EXE, then views of UNPACKED.EXE (the overlays "
                         f"come along), or --root UNPACKED.EXE.")
    area, naming = area_segment(found["modules"])
    source = (f"the lowest link segment any module's relocations name; {naming} of "
              f"{len(found['modules'])} modules name it")
    if load_segment is not None:
        area, source = load_segment, "--load-segment"
    if area is None:
        raise SystemExit("no module has a relocation, so nothing says where the overlay area "
                         "starts. Give it with --load-segment (in hex, e.g. 0x482).")
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = Path(path).stem
    target = evidence.target_identity(path)
    root_identity = evidence.target_identity(root_path) if root_path else target
    results = []
    for m in found["modules"]:
        try:
            view, checks = build_view(root_data, data, m, area)
        except Refused as e:
            results.append((m["overlay"], None, str(e)))
            continue
        view_path = out_dir / f"{stem}-overlay{m['overlay']}.exe"
        view_path.write_bytes(view)
        result = {
            "view": {"file": str(view_path.resolve()), "size": len(view),
                     "sha256": hashlib.sha256(view).hexdigest()},
            "overlay": m["overlay"],
            "source": {"file": target["path"], "sha256": target["sha256"]},
            "root": {"file": root_identity["path"], "sha256": root_identity["sha256"],
                     "unpacked": root_path is not None},
            "module": {"file_offset": m["file_offset"], "file_end": m["end"],
                       "header_bytes": m["header_bytes"], "image_bytes": m["image_bytes"],
                       "image_sha256": m["image_sha256"], "relocations": m["relocations"],
                       "segments": [f"{s:04X}" for s in m["segments"]]},
            "load_segment": f"{area:04X}", "load_segment_source": source,
            "built": ("the root's load image with this module's image at the load segment, "
                      "the root's relocation table and then the module's"),
            "checks": checks,
        }
        items = [
            {"kind": "overlay-module", "claim": f"overlay {m['overlay']} at file "
             f"0x{m['file_offset']:X}..0x{m['end'] - 1:X}",
             "location": {"file_offset": f"0x{m['file_offset']:x}"},
             "value": {"image_bytes": m["image_bytes"], "relocations": m["relocations"]}},
            {"kind": "overlay-area", "claim": f"loaded at segment {area:04X}",
             "value": {"segment": f"{area:04X}", "source": source}},
            {"kind": "view-check", "claim": "the area is empty in the root, the module fits, "
             "and no relocation crosses into the other's bytes", "value": checks},
        ]
        env = evidence.envelope("overlays", target, status="ok", result=result,
                                evidence=items, limitations=LIMITATIONS)
        record = view_path.with_suffix(".view.json")
        evidence.write(env, str(record))
        results.append((m["overlay"], view_path, record))
    return results


def check_view(record_path, view_path):
    """Whether VIEW.view.json describes this file: (ok, message)."""
    try:
        env = json.loads(Path(record_path).read_text(encoding="utf-8"))
        want = env["result"]["view"]["sha256"]
        overlay = env["result"]["overlay"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        return False, f"{record_path} is not a view record overlays.py wrote: {e}"
    got = evidence.sha256_file(view_path)
    if got != want:
        return False, (f"{record_path} describes a view with SHA-256 {want[:16]}..., and "
                       f"{view_path} is {got[:16]}...: not the file it was written for. Write "
                       f"the views again with overlays.py --views")
    return True, (f"overlay {overlay} of {env['result']['source']['file']}, at segment "
                  f"{env['result']['load_segment']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe", nargs="?", help="the MZ the overlays are appended to")
    ap.add_argument("--json", metavar="FILE", help="write the listing here")
    ap.add_argument("--views", metavar="DIR", help="write one view, and its record, per module")
    ap.add_argument("--root", metavar="EXE",
                    help="the root to build the views on, when the file's own is packed: "
                         "unpack.py's output")
    ap.add_argument("--load-segment", type=lambda t: int(t, 0), metavar="SEG",
                    help="where the overlay area starts, when no module's relocations say")
    ap.add_argument("--check-view", nargs=2, metavar=("RECORD", "VIEW"),
                    help="say whether a view record describes this view file (pipeline.ps1)")
    args = ap.parse_args()

    if args.check_view:
        ok, message = check_view(*args.check_view)
        print(f"overlay view: {message}" if ok else f"overlays: {message}",
              file=sys.stdout if ok else sys.stderr)
        return 0 if ok else 1
    if not args.exe:
        ap.error("give the executable, or --check-view")
    data = Path(args.exe).read_bytes()
    found = find(data)
    if found is None:
        print(f"overlays: {args.exe} is not an MZ.", file=sys.stderr)
        return 2
    root_found = find(Path(args.root).read_bytes()) if args.root else None
    d = describe(args.exe, found, args.root, root_found)
    print(report(d))
    if args.json:
        Path(args.json).write_text(json.dumps(d, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    if args.views:
        print("")
        refused = 0
        for overlay, view, record in write_views(args.exe, args.views, args.root,
                                                 args.load_segment):
            if view is None:
                refused += 1
                print(f"overlay {overlay}: not written: {record}")
            else:
                print(f"overlay {overlay}: {view.name}, record {Path(record).name}")
        if refused:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
