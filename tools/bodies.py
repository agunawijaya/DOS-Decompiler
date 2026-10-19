#!/usr/bin/env python3
"""
bodies.py -- Which bytes of an MZ program's code no function claims, and what
they look like.

Why this exists
---------------
`functions.json` used to give each function an entry and one `size`, and
every consumer assumed a function is one contiguous run of bytes it owns.
1980s code is not that tidy. A jump table sits in the middle of a function; a
compiler shares an epilogue; hand-written assembly jumps into the middle of a
neighbour; RecoverFunctions splits functions Ghidra ran together. Since
prompt 03 each function carries its `body` -- every address range, ends
inclusive -- and `body_overlaps` lists the bytes more than one function
claims. This reads both and says what they add up to.

The .COM route has asked the other half of the question for a long time:
which bytes of the code region did nothing claim, and are any of them code
nobody reached (knowledge/11-unreached-code.md)? This asks it of the MZ route.

What it reports
---------------
  code         the blocks holding at least one function's body, from the
               verified module layout in loadimage.json
  claimed      the bytes of those blocks some function's body covers, as a
               percentage
  shapes       functions whose body is not contiguous, bytes more than one
               function claims (from body_overlaps), and functions whose body
               does not contain their own entry
  unclaimed    every run no body covers, classified by residue.py, the rules
               comrec.py uses for its residue: padding, a table of near
               pointers into the code, text, repeated bytes, or "looks like
               code" -- decodes cleanly, every instruction plausible for an
               8088, for at least --min-instructions instructions, ending in a
               return or an unconditional jump. A run that is "other" as a
               whole is looked at again with the 00 and 90 padding at either
               end taken off, so code followed by alignment fill is still seen.

The last line says, in the .COM route's words, either "nothing unclaimed
looks like code" or which ranges do. Those are questions, not findings: the
envelope lists them under `unknowns`.

The bytes are the file's with DOS's fixups applied (loadimage.py's expected
load), which the load-image check verified are Ghidra's program.

What it does not do: decide anything is code, change the export, or resolve
an overlap. A body is the set of addresses Ghidra assigned to the function;
code a function runs inside another function's body is in body_overlaps and
counted once here, as the other function's.

Usage:
    python bodies.py out/functions.json [--exe GAME.EXE]
                     [--loadimage out/loadimage.json] [--evidence out/bodies.json]
                     [--min-instructions 3] [--show 40]

Exit codes: 0 ok, 3 blocked -- an export from before function bodies, or no
loadimage.json or executable to read the bytes from.
"""

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
except ImportError:  # pragma: no cover
    print("bodies: capstone is required (pip install capstone)", file=sys.stderr)
    raise

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402
import loadimage  # noqa: E402
import residue  # noqa: E402

# Bytes alignment fill is made of: zero, and NOP.
PADDING_BYTES = (0x00, 0x90)

# residue.py's names for a kind, in this route's words.
KIND_NAMES = {"zero": "padding", "text": "text", "table": "pointer table",
              "code": "looks like code", "other": "other"}

LIMITATIONS = [
    "A body is the set of addresses Ghidra 12.1.2 assigned to the function, "
    "which never overlaps another body (measured). Code a function runs inside "
    "another function's body is listed in body_overlaps, and counted once "
    "here, as claimed by the function whose body it is.",
    "The code is the blocks that hold at least one function's body. A block "
    "with code and no function is not counted; data inside a block that holds "
    "functions is, and is what the unclaimed list classifies.",
    "Unclaimed bytes are classified by how they look, with comrec.py's rules "
    "(residue.py). 'Looks like code' means it decodes cleanly and ends in a "
    "return or jump, not that anything runs it.",
    "Bytes are read from the file with DOS's fixups applied. They are the "
    "program Ghidra analysed only when the load image verified.",
]


class Blocked(Exception):
    """Something this needs is missing, and what to do about it."""


def seg_address(segment, linear):
    return f"{segment:04x}:{(linear - (segment << 4)) & 0xFFFF:04x}"


def merge(ranges):
    """Sorted, merged, inclusive (lo, hi) ranges."""
    out = []
    for lo, hi in sorted(ranges):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def subtract(ranges, holes):
    """The parts of `ranges` not in `holes`; both merged and inclusive."""
    out = []
    for lo, hi in ranges:
        at = lo
        for hlo, hhi in holes:
            if hhi < at or hlo > hi:
                continue
            if hlo > at:
                out.append((at, hlo - 1))
            at = max(at, hhi + 1)
        if at <= hi:
            out.append((at, hi))
    return out


def body_ranges(function):
    return [(int(r["start_linear"], 16), int(r["end_linear"], 16))
            for r in function["body"]["ranges"]]


class Bytes:
    """The module as DOS loads it, addressed by linear address."""

    def __init__(self, exe, load_segment):
        self.expected = loadimage.Expected(exe, load_segment)
        self.base = load_segment << 4

    def get(self, lo, hi):
        image = self.expected.relocated
        return image[lo - self.base:hi - self.base + 1]


def looks_like_code(md, data, address, min_instructions):
    """Decodes cleanly from its first byte to its last, every instruction
    plausible, at least `min_instructions` of them, and the last a return or
    an unconditional jump -- the shape of a routine nothing reaches."""
    insns = residue.decode_run(md, data, address)
    return (insns is not None and len(insns) >= min_instructions
            and insns[-1].mnemonic in residue.TRANSFER)


def kind_of(data, address, segment, in_code, md, min_instructions):
    """This route's name for what `data` looks like."""
    k = residue.kind(data, lambda w: in_code((segment << 4) + w),
                     lambda: looks_like_code(md, data, address, min_instructions))
    name = KIND_NAMES[k]
    if name == "other" and len(data) >= 2 and len(set(data)) == 1:
        name = "padding" if data[0] in PADDING_BYTES else "repeated bytes"
    return name


def classify(lo, hi, data, segment, in_code, md, min_instructions):
    """[(lo, hi, kind)] for one unclaimed run: the run whole, or split into
    its padding and what the padding surrounds when only that looks like
    something."""
    offset = (lo - (segment << 4)) & 0xFFFF
    whole = kind_of(data, offset, segment, in_code, md, min_instructions)
    if whole != "other":
        return [(lo, hi, whole)]
    a, b = 0, len(data)
    while a < b and data[a] in PADDING_BYTES:
        a += 1
    while b > a and data[b - 1] in PADDING_BYTES:
        b -= 1
    if a == b or (a, b) == (0, len(data)):
        return [(lo, hi, whole)]
    core = kind_of(data[a:b], offset + a, segment, in_code, md, min_instructions)
    if core == "other":
        return [(lo, hi, whole)]
    pieces = []
    if a:
        pieces.append((lo, lo + a - 1, "padding"))
    pieces.append((lo + a, lo + b - 1, core))
    if b < len(data):
        pieces.append((lo + b, hi, "padding"))
    return pieces


def describe(kind, data, segment, in_code, md):
    """A few words on what was seen, for the prose and the envelope."""
    if kind == "text":
        return repr(bytes(data[:40]).decode("latin-1")) + ("..." if len(data) > 40 else "")
    if kind == "pointer table":
        words = [data[i] | (data[i + 1] << 8) for i in range(0, len(data) - 1, 2)]
        inside = sum(1 for w in words if in_code((segment << 4) + w))
        return f"{len(words)} words, {inside} into the code"
    if kind in ("padding", "repeated bytes"):
        common, n = Counter(data).most_common(1)[0]
        return f"{common:02x} x{n}" if n == len(data) else f"mostly {common:02x}"
    if kind == "looks like code":
        insns = residue.decode_run(md, data, 0)
        return f"{len(insns)} instructions, ending {insns[-1].mnemonic}"
    return " ".join(f"{x:02x}" for x in data[:8]) + (" ..." if len(data) > 8 else "")


def analyse(functions_path, exe=None, loadimage_path=None, min_instructions=3,
            accept_drift=False):
    """The envelope for one export. Raises Blocked when it cannot be read."""
    functions_path = Path(functions_path)
    data = evidence.load_functions(functions_path, exe, "bodies.py", accept_drift)
    functions = data.get("functions") or []
    if not functions or any("body" not in f for f in functions):
        raise Blocked(f"{functions_path} has no function bodies: it was exported "
                      f"before ExportDecompiledC.java wrote them. Re-run "
                      f"tools/pipeline.ps1 on the executable.")
    record_path = Path(loadimage_path) if loadimage_path else \
        functions_path.parent / (data.get("load_image") or {}).get("record", "loadimage.json")
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
        layout = record["result"]
        load_segment = int(layout["load_segment"], 16)
        mappings = layout["mappings"]
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise Blocked(f"no usable loadimage.json at {record_path} ({e}); it holds "
                      f"the module layout. Run tools/pipeline.ps1, which writes it.")
    exe_path = Path(exe) if exe else Path((data.get("target") or {}).get("path") or "")
    if not exe_path.is_file():
        raise Blocked(f"cannot read the executable at {exe_path}; pass --exe.")
    image = Bytes(exe_path, load_segment)

    bodies = merge(r for f in functions for r in body_ranges(f))
    code_maps = [m for m in mappings
                 if any(lo <= m["linear_end_inclusive"] and hi >= m["linear_start"]
                        for lo, hi in bodies)]
    region = merge((m["linear_start"], m["linear_end_inclusive"]) for m in code_maps)

    def in_code(linear):
        return any(lo <= linear <= hi for lo, hi in region)

    def segment_of(linear):
        for m in code_maps:
            if m["linear_start"] <= linear <= m["linear_end_inclusive"]:
                return int(m["segment"], 16)
        return load_segment

    claimed = [(max(lo, rlo), min(hi, rhi)) for lo, hi in bodies
               for rlo, rhi in region if lo <= rhi and hi >= rlo]
    claimed = merge(claimed)
    code_bytes = sum(hi - lo + 1 for lo, hi in region)
    claimed_bytes = sum(hi - lo + 1 for lo, hi in claimed)

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    unclaimed = []
    for lo, hi in subtract(region, claimed):
        seg = segment_of(lo)
        raw = image.get(lo, hi)
        for plo, phi, kind in classify(lo, hi, raw, seg, in_code, md, min_instructions):
            part = raw[plo - lo:phi - lo + 1]
            unclaimed.append({
                "start": seg_address(seg, plo), "end": seg_address(seg, phi),
                "start_linear": f"0x{plo:x}", "end_linear": f"0x{phi:x}",
                "bytes": phi - plo + 1, "kind": kind,
                "detail": describe(kind, part, seg, in_code, md)})

    split = [{"entry": f["entry"], "name": f["name"],
              "ranges": len(f["body"]["ranges"]),
              "total_bytes": f["body"]["total_bytes"],
              "span_bytes": f["body"]["span_bytes"]}
             for f in functions if f["body"]["non_contiguous"]]
    outside = [{"entry": f["entry"], "name": f["name"]}
               for f in functions if f["body"]["available"]
               and not f["body"]["contains_entry"]]
    overlaps = data.get("body_overlaps") or []
    code_like = [u for u in unclaimed if u["kind"] == "looks like code"]
    by_kind = Counter()
    for u in unclaimed:
        by_kind[u["kind"]] += u["bytes"]

    result = {
        "functions_json": str(functions_path),
        "functions": len(functions),
        "origins": dict(sorted(Counter(f.get("origin", "unknown") for f in functions).items())),
        "code": {"bytes": code_bytes,
                 "blocks": [{"block": m["block"], "segment": m["segment"],
                             "start": seg_address(int(m["segment"], 16), m["linear_start"]),
                             "end": seg_address(int(m["segment"], 16),
                                                m["linear_end_inclusive"]),
                             "bytes": m["length"]} for m in code_maps]},
        "claimed_bytes": claimed_bytes,
        "claimed_percent": round(100.0 * claimed_bytes / code_bytes, 1) if code_bytes else 0.0,
        "non_contiguous": split,
        "overlaps": len(overlaps),
        "overlap_bytes": sum(o["bytes"] for o in overlaps),
        "entry_outside_body": outside,
        "unclaimed": unclaimed,
        "unclaimed_bytes": sum(u["bytes"] for u in unclaimed),
        "unclaimed_by_kind": dict(sorted(by_kind.items())),
        "looks_like_code": len(code_like),
        "min_instructions": min_instructions,
        "load_image": record.get("status"),
    }

    items = [{"kind": "code-claimed",
              "claim": f"{claimed_bytes:,} of {code_bytes:,} code bytes claimed "
                       f"by some function's body",
              "value": result["claimed_percent"]}]
    items += [{"kind": "non-contiguous-body", "claim": f"{s['name']} is {s['ranges']} ranges",
               "location": {"address": s["entry"]},
               "value": {"total_bytes": s["total_bytes"], "span_bytes": s["span_bytes"]}}
              for s in split]
    items += [{"kind": "body-overlap", "level": "warn",
               "claim": f"{o['bytes']} bytes claimed by "
                        f"{len({c['entry'] for c in o['functions']})} functions",
               "location": {"address": o["start"], "end": o["end"]},
               "value": [f"{c['entry']} {c['claim']}" for c in o["functions"]]}
              for o in overlaps]
    items += [{"kind": "entry-outside-body", "level": "warn",
               "claim": f"{o['name']}'s body does not contain its entry",
               "location": {"address": o["entry"]}} for o in outside]
    items += [{"kind": "unclaimed", "level": "warn" if u["kind"] == "looks like code" else "info",
               "claim": f"{u['bytes']} unclaimed bytes, {u['kind']}",
               "location": {"address": u["start"], "end": u["end"]},
               "value": u["kind"], "detail": u["detail"]} for u in unclaimed]
    unknowns = [f"is {u['start']}..{u['end']} ({u['bytes']} bytes) code that nothing "
                f"reaches? It decodes cleanly: {u['detail']}." for u in code_like]
    limitations = list(LIMITATIONS)
    if record.get("status") != "verified":
        limitations.append(f"The load image did not verify ({record.get('status')}), so "
                           f"the bytes read from the file may not be the program Ghidra "
                           f"analysed.")
    return evidence.envelope("bodies", evidence.target_identity(exe_path), status="ok",
                             result=result, evidence=items, limitations=limitations,
                             unknowns=unknowns)


def summary(env, show=40):
    """The prose report, line by line."""
    r = env["result"]
    out = [f"bodies: {Path(env['target']['path']).name}  ({r['functions']} functions, "
           f"load image {r['load_image']})"]
    blocks = ", ".join(f"{b['block']} {b['start']}..{b['end']}" for b in r["code"]["blocks"])
    out.append(f"code        : {r['code']['bytes']:,} bytes in "
               f"{len(r['code']['blocks'])} block(s) holding functions ({blocks})")
    out.append(f"claimed     : {r['claimed_bytes']:,} bytes by some function's body "
               f"({r['claimed_percent']}%)")
    out.append("origins     : " + ", ".join(f"{n} {o}" for o, n in r["origins"].items()))
    out.append(f"non-contiguous: {len(r['non_contiguous'])}")
    for s in r["non_contiguous"]:
        out.append(f"  {s['entry']}  {s['name']}  {s['ranges']} ranges, "
                   f"{s['total_bytes']} of {s['span_bytes']} bytes")
    out.append(f"claimed by more than one function: {r['overlaps']} range(s), "
               f"{r['overlap_bytes']} bytes (see body_overlaps)")
    for item in env["evidence"]:
        if item["kind"] == "body-overlap":
            out.append(f"  {item['location']['address']}..{item['location']['end']}  "
                       + "; ".join(item["value"]))
    if r["entry_outside_body"]:
        out.append("entry outside body: " + ", ".join(
            f"{o['entry']} {o['name']}" for o in r["entry_outside_body"]))
    else:
        out.append("entry outside body: none")
    kinds = ", ".join(f"{n:,} {k}" for k, n in sorted(r["unclaimed_by_kind"].items(),
                                                       key=lambda kv: -kv[1]))
    out.append(f"unclaimed   : {r['unclaimed_bytes']:,} bytes in {len(r['unclaimed'])} "
               f"range(s)" + (f": {kinds}" if kinds else ""))
    for u in r["unclaimed"][:show]:
        out.append(f"  {u['start']}..{u['end']}  {u['bytes']:>6,}  {u['kind']:<15} {u['detail']}")
    if len(r["unclaimed"]) > show:
        out.append(f"  ... and {len(r['unclaimed']) - show} more, every one in the envelope")
    code_like = [u for u in r["unclaimed"] if u["kind"] == "looks like code"]
    if code_like:
        listed = ", ".join(f"{u['start']}..{u['end']} ({u['bytes']} bytes)" for u in code_like)
        out.append(f"{len(code_like)} unclaimed range{'s' if len(code_like) != 1 else ''} "
                   f"look{'s' if len(code_like) == 1 else ''} like code: {listed}")
    else:
        out.append("nothing unclaimed looks like code")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("functions", help="functions.json from tools/pipeline.ps1")
    ap.add_argument("--exe", help="the executable it was made from; it is refused if "
                                  "functions.json describes another file. Default: the "
                                  "file recorded in functions.json")
    ap.add_argument("--loadimage", help="loadimage.json; default: the one beside "
                                        "functions.json")
    ap.add_argument("--evidence", help="write the envelope here, or '-' for stdout")
    ap.add_argument("--min-instructions", type=int, default=3,
                    help="instructions an unclaimed run must decode to before it "
                         "looks like code (default 3)")
    ap.add_argument("--show", type=int, default=40,
                    help="unclaimed ranges to list in the prose (default 40)")
    ap.add_argument("--accept-profile-drift", action="store_true",
                    help="read an export whose handshake.json says it drifted, and say so")
    args = ap.parse_args()
    try:
        env = analyse(args.functions, args.exe, args.loadimage, args.min_instructions,
                      args.accept_profile_drift)
    except Blocked as e:
        print(f"bodies: {e}", file=sys.stderr)
        return 3
    if args.evidence:
        evidence.write(env, args.evidence)
    if args.evidence != "-":
        for line in summary(env, args.show):
            print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
