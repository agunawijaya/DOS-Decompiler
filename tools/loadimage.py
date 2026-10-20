#!/usr/bin/env python3
"""
loadimage.py -- Check that Ghidra loaded what the MZ file says it should.

Why this exists
---------------
Everything after import trusts that Ghidra's program is the executable: the
same bytes, at the addresses the header implies, with every relocation
applied once per entry. Nothing checked it. A loader that drops part of the
image, maps a segment at the wrong place, or applies a fixup the wrong number
of times produces decompiled C that looks perfectly normal -- the silent kind
of failure knowledge/00-scope.md warns costs the most.

How it works
------------
  expected  From the file alone, what a correct load looks like: the load
            module's file range and digest, every relocation with the word it
            patches before and after the fixup, the entry point and stack, and
            anything appended after the declared image. Nothing from Ghidra.
            The header is parsed by mzinfo.py -- one parser for the format in
            the toolkit, and it needs nothing but the file -- and the bounds
            mzinfo does not check are checked here.
  observed  What DumpLoadImage.java wrote: every block, the file range behind
            each part of it, the bytes Ghidra holds, its copy of the file
            before and after fixups, the relocation table, the entry points.
  verify    One check per property, each with its expected and observed
            value. On a digest mismatch the first differing byte is found:
            its file offset, its address, and both values.

The expected load follows DOS, not Ghidra. DOS adds the load segment to the
word at every relocation entry in table order, so an entry listed twice adds
it twice, and a later entry sees what an earlier one wrote. And a header
whose bytes-on-last-page is 0 declares a full last page. Where Ghidra's
loader reads either differently, that is a mismatch to report, not a rule to
copy.

A relocated word differs from the file word by design. Every memory digest is
taken against the file with the fixups applied, never against the file as
stored, and the relocation checks hold each patched word to its value after
the fixup.

The two loads Ghidra 12.1.2 gets wrong are corrected before this runs, by
CorrectMzLoad.java, from `expected`'s output. `verify --corrections` records
what it corrected, so a clean load can be told from a corrected one, and
checks which script wrote the record -- but it does not believe the record:
the corrected program is compared with the file like any other.

What it does not do: run anything, or say what an uninitialised block will
hold at run time -- those are reported, not verified. It covers MZ only; a
.COM has no header for it to check and goes through comrec.py instead.

Usage:
    python loadimage.py expected GAME.EXE [--profile out/profile.json] [--evidence -]
    python loadimage.py verify GAME.EXE out/loadimage-observed \\
                        [--profile out/profile.json] [--evidence out/loadimage.json] \\
                        [--corrections out/load-corrections.json]
    python loadimage.py map out/loadimage.json --file 0x201
    python loadimage.py map out/loadimage.json --address 1000:0001
    python loadimage.py map out/loadimage.json --linear 0x10001

Exit codes: 0 verified (or, for `expected`, ok), 1 mismatch, 2 unsupported,
3 blocked -- no observed dump to compare against.
"""

import argparse
import hashlib
import json
import struct
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402
import mzinfo  # noqa: E402

DEFAULT_LOAD_SEGMENT = 0x1000      # analysis_profile.LOAD_SEGMENT, measured
DUMP_SCRIPT = Path(__file__).resolve().parent / "ghidra_scripts" / "DumpLoadImage.java"
HELPER_SCRIPT = Path(__file__).resolve().parent / "ghidra_scripts" / "LoadImageMap.java"
CORRECT_SCRIPT = Path(__file__).resolve().parent / "ghidra_scripts" / "CorrectMzLoad.java"

LIMITATIONS = [
    "The expected load is DOS's reading of the header, from documentation: a "
    "relocation entry adds the load segment once per entry, in table order, "
    "and bytes-on-last-page 0 means a full last page. It was not measured "
    "against a running DOS.",
    "Uninitialised blocks -- minalloc, a segment past the end of the image -- "
    "are reported but their contents are not verified: there are none in the "
    "file to verify against.",
    "Only what DumpLoadImage.java reported is compared. A property Ghidra "
    "keeps that the dump does not write -- comments, data types, references "
    "-- is not checked here.",
]


# Added when relocations.status_after_correction was used.
AFTER_CORRECTION_LIMITATION = (
    "A relocation inside the page CorrectMzLoad.java restored keeps the FAILURE "
    "record Ghidra wrote for it, because nothing in Ghidra's API rewrites a "
    "relocation record. That record was accepted, under "
    "relocations.status_after_correction, only because the word in memory is the "
    "value computed here from the file, it lies in a range the corrections record "
    "says was restored, and that record passed its provenance checks. The "
    "relocation table Ghidra keeps still says FAILURE for it.")


class Unsupported(Exception):
    """The file is not one this can say anything about, and why."""


class MapError(ValueError):
    """An address or offset that the load image does not map."""


def sha256(data):
    return hashlib.sha256(bytes(data)).hexdigest()


def seg_off(segment, offset):
    return f"{segment & 0xFFFF:04x}:{offset & 0xFFFF:04x}"


def parse_address(text):
    """'1000:0001' -> (segment, offset)."""
    try:
        seg, off = text.split(":")
        return int(seg, 16), int(off, 16)
    except ValueError:
        raise MapError(f"{text!r} is not an address of the form ssss:oooo")


# ---------------------------------------------------------------- expected

class Expected:
    """What a correct load of one file looks like, computed from the file."""

    def __init__(self, path, load_segment=DEFAULT_LOAD_SEGMENT):
        self.path = Path(path)
        self.load_segment = load_segment
        self.data = self.path.read_bytes()
        self._read()

    def _read(self):
        data = self.data
        try:
            _, mz = mzinfo.parse(self.path)
        except mzinfo.MZError as e:
            raise Unsupported(str(e))
        h = mz["header"]
        self.header_size = h["header_size"]
        pages, last = h["pages_512"], h["bytes_on_last_page"]
        self.pages, self.bytes_on_last_page = pages, last

        if self.header_size < 0x1C:
            raise Unsupported(f"the header is {self.header_size} bytes, smaller "
                              f"than the 28 its own fields take")
        if self.header_size > len(data):
            raise Unsupported(f"the header claims {self.header_size} bytes and the "
                              f"file is {len(data)}")
        if pages == 0:
            raise Unsupported("the header declares no pages: there is no load image")
        if last > 512:
            raise Unsupported(f"bytes on the last page is {last}, more than a page")
        # bytes_on_last_page 0 is DOS's way of saying the last page is full.
        self.image_end = (pages - 1) * 512 + (last if last else 512)
        if self.image_end > len(data):
            raise Unsupported(f"the header declares the image to end at file offset "
                              f"0x{self.image_end:x}, and the file is "
                              f"0x{len(data):x} bytes")
        if self.image_end <= self.header_size:
            raise Unsupported(f"the image ends at 0x{self.image_end:x}, inside the "
                              f"0x{self.header_size:x}-byte header")
        if h["relocations"] and h["reloc_table_offset"] < 0x1C:
            raise Unsupported(f"the relocation table starts at "
                              f"0x{h['reloc_table_offset']:x}, inside the header's "
                              f"own fields")

        self.module = data[self.header_size:self.image_end]
        size = len(self.module)
        self.relocations = []
        for r in mz["relocations"]:
            image_offset = (r["seg"] << 4) + r["off"]
            if image_offset + 2 > size:
                raise Unsupported(
                    f"relocation {r['index']} ({r['seg']:04X}:{r['off']:04X}) patches "
                    f"image offset 0x{image_offset:x}, past the {size}-byte image")
            self.relocations.append({"index": r["index"], "segment": r["seg"],
                                     "offset": r["off"],
                                     "image_offset": image_offset})

        cs, ip = h["initial_cs"], h["initial_ip"]
        entry_offset = (cs << 4) + ip
        if entry_offset >= size:
            raise Unsupported(f"the entry point {cs:04X}:{ip:04X} is image offset "
                              f"0x{entry_offset:x}, past the {size}-byte image")
        self.entry = {"cs": cs, "ip": ip, "image_offset": entry_offset,
                      "file_offset": self.header_size + entry_offset,
                      "linear": (self.load_segment << 4) + entry_offset,
                      "address": seg_off(self.load_segment + cs, ip)}
        ss, sp = h["initial_ss"], h["initial_sp"]
        stack_offset = (ss << 4) + sp
        self.stack = {"ss": ss, "sp": sp,
                      "segment": (self.load_segment + ss) & 0xFFFF,
                      "linear": (self.load_segment << 4) + stack_offset,
                      "address": seg_off(self.load_segment + ss, sp),
                      "inside_image": stack_offset < size}

        # DOS applies each entry in table order, adding the load segment to
        # whatever the word holds by then.
        relocated = bytearray(self.module)
        for r in self.relocations:
            t = r["image_offset"]
            word = struct.unpack_from("<H", relocated, t)[0]
            struct.pack_into("<H", relocated, t, (word + self.load_segment) & 0xFFFF)
        self.relocated = bytes(relocated)
        self.relocated_file = data[:self.header_size] + self.relocated + data[self.image_end:]

        counts = Counter(r["image_offset"] for r in self.relocations)
        for r in self.relocations:
            t = r["image_offset"]
            r["file_offset"] = self.header_size + t
            r["linear"] = (self.load_segment << 4) + t
            r["address"] = seg_off(self.load_segment + r["segment"], r["offset"])
            r["original_word"] = struct.unpack_from("<H", self.module, t)[0]
            r["relocated_word"] = struct.unpack_from("<H", self.relocated, t)[0]
            r["entries_for_this_word"] = counts[t]

    def linear_of_file_offset(self, file_offset):
        return (self.load_segment << 4) + file_offset - self.header_size

    def record(self):
        appended = None
        if self.image_end < len(self.data):
            tail = self.data[self.image_end:]
            appended = {"file_start": self.image_end,
                        "file_end_inclusive": len(self.data) - 1,
                        "size": len(tail), "sha256": sha256(tail),
                        "loaded": False}
        duplicates = sorted({r["address"] for r in self.relocations
                             if r["entries_for_this_word"] > 1})
        return {
            "file": str(self.path),
            "file_size": len(self.data),
            "load_segment": f"0x{self.load_segment:04x}",
            "header": {"size": self.header_size,
                       "sha256": sha256(self.data[:self.header_size]),
                       "pages": self.pages,
                       "bytes_on_last_page": self.bytes_on_last_page},
            "module": {"file_start": self.header_size,
                       "file_end_inclusive": self.image_end - 1,
                       "size": len(self.module),
                       "sha256": sha256(self.module),
                       "relocated_sha256": sha256(self.relocated),
                       "linear_start": self.linear_of_file_offset(self.header_size)},
            "relocations": self.relocations,
            "duplicated_relocations": duplicates,
            "entry": self.entry,
            "stack": self.stack,
            "appended": appended,
            "relocated_file_sha256": sha256(self.relocated_file),
        }


def dos_map(path, load_segment=DEFAULT_LOAD_SEGMENT):
    """A record map_address() can read, for a file nothing has analysed yet.

    loadimage.json's mappings are Ghidra's blocks, so they exist only after an
    import. This is what DOS itself does with the file: the load module at the
    load segment, cut into 64 KB windows so every byte has a segment:offset,
    and then the header's minalloc paragraphs -- allocated, with no file bytes
    behind them -- as uninitialised. Relocated words are listed as in the
    verified record. It is the expected load, from the header alone; once
    the pipeline has run, the verified loadimage.json is the one to read."""
    exp = Expected(path, load_segment)
    rec = exp.record()
    _, mz = mzinfo.parse(path)
    minalloc = mz["header"]["min_extra_paragraphs"]
    base = rec["module"]["linear_start"]
    size = rec["module"]["size"]
    mappings = []
    for start in range(0, size, 0x10000):
        end = min(start + 0x10000, size) - 1
        mappings.append({"block": f"load module +0x{start:x}",
                         "segment": f"{load_segment + (start >> 4):04x}",
                         "linear_start": base + start, "linear_end_inclusive": base + end,
                         "file_start": exp.header_size + start,
                         "file_end_inclusive": exp.header_size + end})
    # DOS rounds the module up to a paragraph and gives minalloc more.
    first_free = base + ((size + 15) // 16) * 16
    uninitialized = []
    if minalloc:
        uninitialized.append({"block": "minalloc", "linear_start": base + size,
                              "linear_end_inclusive": first_free + minalloc * 16 - 1})
    rec.update(mappings=mappings, uninitialized=uninitialized, source="expected")
    return rec


def expected_envelope(path, load_segment=DEFAULT_LOAD_SEGMENT, profile=None):
    try:
        exp = Expected(path, load_segment)
    except Unsupported as e:
        return evidence.envelope(
            "loadimage", evidence.target_identity(path), status="unsupported",
            result={"file": str(path), "reason": str(e)}, profile=profile,
            limitations=LIMITATIONS)
    record = exp.record()
    items = [{"kind": "load-module", "claim": f"load module, file 0x{exp.header_size:x}"
                                              f"..0x{exp.image_end - 1:x} inclusive",
              "location": {"file_offset": f"0x{exp.header_size:x}",
                           "file_end_inclusive": f"0x{exp.image_end - 1:x}"},
              "value": record["module"]["sha256"]}]
    for r in exp.relocations:
        items.append({"kind": "relocation",
                      "claim": f"relocation {r['index']} patches {r['address']}: "
                               f"0x{r['original_word']:04x} -> 0x{r['relocated_word']:04x}",
                      "location": {"file_offset": f"0x{r['file_offset']:x}"},
                      "value": {"original": r["original_word"],
                                "relocated": r["relocated_word"]}})
    unknowns = []
    if record["duplicated_relocations"]:
        unknowns.append("why the relocation table lists "
                        + ", ".join(record["duplicated_relocations"])
                        + " more than once: DOS adds the load segment once per entry")
    return evidence.envelope("loadimage", evidence.target_identity(path), status="ok",
                             result=record, evidence=items, profile=profile,
                             limitations=LIMITATIONS, unknowns=unknowns)


# ---------------------------------------------------------------- observed

class Observed:
    """DumpLoadImage.java's output: observed.json and the bytes beside it."""

    def __init__(self, folder):
        self.folder = Path(folder)
        path = self.folder / "observed.json" if self.folder.is_dir() else self.folder
        self.folder = path.parent
        self.json = json.loads(path.read_text(encoding="utf-8"))
        self._bytes = {}

    def __getitem__(self, key):
        return self.json[key]

    def get(self, key, default=None):
        return self.json.get(key, default)

    def dump(self, name):
        if name not in self._bytes:
            self._bytes[name] = (self.folder / name).read_bytes()
        return self._bytes[name]

    def block_bytes(self, block):
        return self.dump(block["dump"]) if block.get("dump") else None

    def file_bytes(self, which):
        fbs = self.json.get("file_bytes") or []
        return self.dump(fbs[0][f"{which}_dump"]) if fbs else None

    def file_mappings(self):
        """Every mapping with file bytes behind it: (block, mapping)."""
        for b in self.json["blocks"]:
            for m in b["mappings"]:
                if m["file_offset"] >= 0:
                    yield b, m

    def memory(self, block, mapping):
        data = self.block_bytes(block)
        if data is None:
            return None
        start = mapping["offset_in_block"]
        return data[start:start + mapping["length"]]


def mapping_segment(mapping):
    return parse_address(mapping["min"])[0]


def mapping_linear(mapping):
    seg, off = parse_address(mapping["min"])
    return (seg << 4) + off


# ---------------------------------------------------------------- verify

def first_difference(want, got, file_offset, linear=None, segment=None):
    """The first byte where two runs differ, located: its file offset, and
    its address when the runs are memory rather than the file. A byte one run
    lacks -- not loaded -- has an observed value of None."""
    for i in range(max(len(want), len(got))):
        w = want[i] if i < len(want) else None
        g = got[i] if i < len(got) else None
        if w != g:
            out = {"file_offset": f"0x{file_offset + i:x}",
                   "expected": None if w is None else f"0x{w:02x}",
                   "observed": None if g is None else f"0x{g:02x}"}
            if linear is not None:
                lin = linear + i
                out["linear"] = f"0x{lin:x}"
                out["address"] = seg_off(segment, lin - (segment << 4))
            return out
    return None


class Checks:
    def __init__(self):
        self.items = []

    def add(self, name, ok, expected, observed, detail=None, first_difference=None):
        item = {"name": name, "ok": bool(ok), "expected": expected,
                "observed": observed}
        if detail:
            item["detail"] = detail
        if first_difference:
            item["first_difference"] = first_difference
        self.items.append(item)
        return ok

    def first_failure(self):
        return next((c for c in self.items if not c["ok"]), None)


def expected_script_hashes(profile):
    """What DumpLoadImage.java and its helper should report of themselves:
    from the profile when there is one, else from this checkout."""
    dump = (profile or {}).get("load_image_dump") or {}
    return (dump.get("script_sha256") or evidence.source_sha256(DUMP_SCRIPT),
            dump.get("helper_sha256") or evidence.source_sha256(HELPER_SCRIPT))


def restored_ranges(record):
    """The linear ranges a corrections record says CorrectMzLoad.java mapped
    back in, ends inclusive. Taken from the record -- the one thing the
    verifier takes from it -- and used only to say which of Ghidra's FAILURE
    relocation records may be judged by relocations.status_after_correction."""
    return [(c["linear_start"], c["linear_end_inclusive"])
            for c in (record or {}).get("corrections", [])
            if c.get("kind") == "missing-last-page"
            and isinstance(c.get("linear_start"), int)
            and isinstance(c.get("linear_end_inclusive"), int)]


def compare(exp, obs, profile=None, restored=(), trusted=False):
    """Every check, in the order a reader should see them fail.

    `restored` and `trusted` come from the corrections record: the ranges it
    says were mapped back in, and whether its provenance checks passed."""
    c = Checks()
    want_script, want_helper = expected_script_hashes(profile)
    c.add("dumper.script_sha256", obs.get("script_sha256") == want_script,
          want_script, obs.get("script_sha256"),
          "which DumpLoadImage.java wrote the dump")
    c.add("dumper.helper_sha256", obs.get("helper_sha256") == want_helper,
          want_helper, obs.get("helper_sha256"))
    want_loader = (profile or {}).get("loader", "Old-style DOS Executable (MZ)")
    c.add("loader", obs.get("loader") == want_loader, want_loader, obs.get("loader"))
    want_seg = (profile or {}).get("load_segment", f"0x{exp.load_segment:04x}")
    c.add("load-segment", obs.get("load_segment") == want_seg, want_seg,
          obs.get("load_segment"),
          "the segment image byte 0 landed at, against the profile")

    data, hdr = exp.data, exp.header_size
    fbs = obs.get("file_bytes") or []
    original = obs.file_bytes("original")
    c.add("file.size", fbs and fbs[0]["size"] == len(data), len(data),
          fbs[0]["size"] if fbs else None, "Ghidra's copy of the file")
    c.add("file.original", original is not None and sha256(original) == sha256(data),
          sha256(data), sha256(original) if original is not None else None,
          first_difference=None if original is None or original == data else
          first_difference(data, original, 0))
    c.add("executable.sha256", obs.get("executable_sha256") == sha256(data),
          sha256(data), obs.get("executable_sha256"),
          "the hash Ghidra recorded at import")

    # The header, wherever Ghidra put it, must be outside the analysis
    # address space and unchanged.
    stray = []
    for b, m in obs.file_mappings():
        if b["segmented"]:
            continue
        lo, hi = m["file_offset"], m["file_offset"] + m["length"]
        if hi > hdr:
            stray.append(f"{b['name']} {m['min']} maps file 0x{lo:x}..0x{hi - 1:x}")
        elif obs.memory(b, m) != data[lo:hi]:
            stray.append(f"{b['name']} {m['min']} differs from the file")
    c.add("header.mapping", not stray, f"only file 0x0..0x{hdr - 1:x}, unchanged",
          stray or "as expected")

    # Coverage: the file-backed mappings in the analysis space must cover the
    # module exactly once -- no gap, no overlap, nothing outside it.
    segmented = sorted(((m["file_offset"], m["file_offset"] + m["length"], b, m)
                        for b, m in obs.file_mappings() if b["segmented"]),
                       key=lambda t: t[0])
    problems, at = [], hdr
    for lo, hi, b, m in segmented:
        if lo < at:
            problems.append(f"overlap at file 0x{lo:x}")
        elif lo > at:
            problems.append(f"file 0x{at:x}..0x{lo - 1:x} not loaded")
        if lo < hdr or hi > exp.image_end:
            problems.append(f"{b['name']} maps file 0x{lo:x}..0x{hi - 1:x}, "
                            f"outside the module")
        at = max(at, hi)
    if at < exp.image_end:
        problems.append(f"file 0x{at:x}..0x{exp.image_end - 1:x} not loaded")
    c.add("module.coverage", not problems,
          f"file 0x{hdr:x}..0x{exp.image_end - 1:x}, once",
          problems or "as expected",
          "every byte of the load module mapped once, and nothing else")

    c.add("module.as-stored",
          original is not None and sha256(original[hdr:exp.image_end]) == sha256(exp.module),
          sha256(exp.module),
          sha256(original[hdr:exp.image_end]) if original is not None else None,
          "the module bytes in Ghidra's copy of the file, before fixups")

    _relocation_checks(c, exp, obs, restored, trusted)

    loaded = bytearray(len(exp.module))
    filled = bytearray(len(exp.module))
    mapping_failures = 0
    for lo, hi, b, m in segmented:
        got = obs.memory(b, m)
        lin = mapping_linear(m)
        seg = mapping_segment(m)
        want_lin = exp.linear_of_file_offset(lo)
        label = f"mapping {b['name']} {m['min']}"
        c.add(f"{label}.address", lin == want_lin, f"0x{want_lin:x}", f"0x{lin:x}",
              f"file 0x{lo:x} must land at load segment * 16 + image offset")
        if got is None:
            c.add(f"{label}.digest", False, "initialised bytes", "none")
            continue
        lo_c, hi_c = max(lo, hdr), min(hi, exp.image_end)
        want = exp.relocated[lo_c - hdr:hi_c - hdr]
        mine = got[lo_c - lo:hi_c - lo]
        ok = want == mine
        mapping_failures += not ok
        c.add(f"{label}.digest", ok, sha256(want), sha256(mine),
              f"file 0x{lo_c:x}..0x{hi_c - 1:x} with fixups applied",
              None if ok else first_difference(want, mine, lo_c, lin + (lo_c - lo), seg))
        for i in range(lo_c, hi_c):
            loaded[i - hdr] = got[i - lo]
            filled[i - hdr] = 1

    whole_ok = bytes(loaded) == exp.relocated and all(filled)
    first = None
    if not whole_ok:
        for i, (w, g) in enumerate(zip(exp.relocated, loaded)):
            if w != g or not filled[i]:
                lin = exp.linear_of_file_offset(hdr + i)
                seg = _segment_for(segmented, hdr + i, exp.load_segment)
                first = first_difference(exp.relocated[i:i + 1],
                                         loaded[i:i + 1] if filled[i] else b"",
                                         hdr + i, lin, seg)
                break
    c.add("module.loaded", whole_ok, exp.record()["module"]["relocated_sha256"],
          sha256(loaded), "the module as it sits in memory, fixups applied",
          first)

    modified = obs.file_bytes("modified")
    c.add("file.modified",
          modified is not None and modified == exp.relocated_file,
          sha256(exp.relocated_file),
          sha256(modified) if modified is not None else None,
          "Ghidra's copy of the file after its fixups",
          None if modified is None or modified == exp.relocated_file else
          first_difference(exp.relocated_file, modified, 0))

    reaching = [f"{b['name']} {m['min']}" for b, m in obs.file_mappings()
                if m["file_offset"] + m["length"] > exp.image_end]
    c.add("overlay.excluded", not reaching,
          "nothing loaded from past file 0x%x" % (exp.image_end - 1),
          reaching or "nothing", "appended bytes stay outside the module")

    entries = obs.get("entry_points") or []
    entry_lin = [e["offset"] for e in entries]
    c.add("entry", exp.entry["linear"] in entry_lin,
          f"{exp.entry['address']} (0x{exp.entry['linear']:x})",
          [e["address"] for e in entries])
    stack = obs.get("stack") or {}
    want_stack = {"ss": exp.stack["segment"], "sp": exp.stack["sp"]}
    c.add("stack", stack == want_stack, want_stack, stack,
          "SS and SP as the loader set them at the entry")
    return c


def _segment_for(segmented, file_offset, load_segment):
    for lo, hi, b, m in segmented:
        if lo <= file_offset < hi:
            return mapping_segment(m)
    return load_segment


def _after_correction(c, exp, obs, blocks, restored, trusted):
    """FAILURE records CorrectMzLoad.java's restored page excuses, if any.

    Ghidra cannot apply a relocation whose word lies in the page its loader
    dropped, records it as FAILURE with no original bytes, and nothing in its
    API rewrites a relocation record. The corrector restores the page and the
    word, so the record is the only thing still wrong. Such a record is
    accepted only when all three hold: the word in memory is the value this
    verifier computes from the file, the address is inside a range the
    corrections record says it restored, and that record passed its
    provenance checks. Nothing else is taken from the record.

    Returns the excused records' linear addresses. The check is added only
    when there is a record for it to judge."""
    observed = obs.get("relocations") or []
    by_linear = {r["linear"]: r for r in exp.relocations}
    inside = [r for r in observed if r["status"] == "FAILURE"
              and any(lo <= r["offset"] and r["offset"] + 1 <= hi for lo, hi in restored)]
    if not inside:
        return set()
    problems, judged = [], []
    if not trusted:
        problems.append("the corrections record failed its provenance checks")
    for r in inside:
        e = by_linear.get(r["offset"])
        if e is None:
            problems.append(f"0x{r['offset']:x}: not a relocation the file declares")
            continue
        word = _memory_word(obs, blocks, r["offset"])
        if word != e["relocated_word"]:
            problems.append(f"{e['address']}: memory holds "
                            + (f"0x{word:04x}" if word is not None else "nothing")
                            + f", not 0x{e['relocated_word']:04x}")
        else:
            judged.append(f"{e['address']}: FAILURE, memory 0x{word:04x} as the file "
                          f"makes it, inside the restored page")
    c.add("relocations.status_after_correction", not problems,
          "each FAILURE record inside a page CorrectMzLoad.java restored holds the "
          "word the file makes, under a corrections record from this checkout",
          problems or judged,
          "Ghidra marks a relocation in the page its loader dropped FAILURE, and the "
          "record cannot be rewritten; the word is held to the file instead")
    return set() if problems else {r["offset"] for r in inside}


def _relocation_checks(c, exp, obs, restored=(), trusted=False):
    observed = obs.get("relocations") or []
    want = Counter(r["linear"] for r in exp.relocations)
    got = Counter(r["offset"] for r in observed)
    by_linear = {r["linear"]: r for r in exp.relocations}
    blocks = [(b, m) for b, m in obs.file_mappings() if b["segmented"]]

    def name(lin):
        r = by_linear.get(lin)
        return r["address"] if r else f"0x{lin:x}"

    missing = sorted(set(want) - set(got))
    extra = sorted(set(got) - set(want))
    c.add("relocations.set", not missing and not extra,
          sorted(name(x) for x in want),
          sorted(name(x) for x in got) if (missing or extra) else "as expected",
          "; ".join(filter(None, [
              ("missing " + ", ".join(name(x) for x in missing)) if missing else "",
              ("extra " + ", ".join(name(x) for x in extra)) if extra else ""])) or None)
    differ = {name(x): {"expected": want[x], "observed": got[x]}
              for x in set(want) & set(got) if want[x] != got[x]}
    c.add("relocations.multiplicity", not differ,
          {name(x): n for x, n in sorted(want.items()) if n > 1} or "one entry each",
          differ or "as expected", "entries per patched word")
    # Judged first, reported after the status check it qualifies.
    held = Checks()
    excused = _after_correction(held, exp, obs, blocks, restored, trusted)
    bad = [f"{r['address']} {r['status']}" for r in observed
           if r["status"] != "APPLIED" and r["offset"] not in excused]
    c.add("relocations.status", not bad,
          "every one APPLIED" + (", or excused below" if excused else ""),
          bad or "as expected")
    c.items.extend(held.items)

    wrong_original = []
    for r in observed:
        e = by_linear.get(r["offset"])
        if e is None or r["offset"] in excused:
            continue
        want_bytes = struct.pack("<H", e["original_word"]).hex()
        if (r.get("bytes") or "").lower() != want_bytes:
            wrong_original.append(f"{e['address']}: {r.get('bytes')} not {want_bytes}")
    c.add("relocations.original", not wrong_original,
          "each record's original bytes are the file's word",
          wrong_original or "as expected")

    # The word in memory, against its value after the fixup -- not the file's
    # word, which it differs from by design.
    wrong_word = []
    first = None
    seen = set()
    for r in exp.relocations:
        if r["linear"] in seen:
            continue                    # a duplicated entry: one word, said once
        seen.add(r["linear"])
        got_word = _memory_word(obs, blocks, r["linear"])
        if got_word != r["relocated_word"]:
            wrong_word.append(
                f"{r['address']}: 0x{got_word:04x} not 0x{r['relocated_word']:04x}"
                if got_word is not None else f"{r['address']}: not loaded")
            if first is None and got_word is not None:
                want_b = struct.pack("<H", r["relocated_word"])
                got_b = struct.pack("<H", got_word)
                first = first_difference(want_b, got_b, r["file_offset"], r["linear"],
                                         exp.load_segment + r["segment"])
    c.add("relocations.words", not wrong_word,
          "each patched word holds its value after every fixup to it",
          wrong_word or "as expected", None, first)


def _memory_word(obs, blocks, linear):
    out = []
    for at in (linear, linear + 1):
        for b, m in blocks:
            lo = mapping_linear(m)
            if lo <= at < lo + m["length"]:
                mem = obs.memory(b, m)
                if mem is None:
                    return None
                out.append(mem[at - lo])
                break
        else:
            return None
    return out[0] | (out[1] << 8)


def mapping_record(obs):
    """The verified mapping, as `map` uses it."""
    mappings, uninitialized = [], []
    for b in obs["blocks"]:
        if not b["segmented"]:
            continue
        for m in b["mappings"]:
            lin = mapping_linear(m)
            entry = {"block": b["name"], "segment": f"{mapping_segment(m):04x}",
                     "linear_start": lin, "linear_end_inclusive": lin + m["length"] - 1,
                     "length": m["length"]}
            if m["file_offset"] >= 0 and b["initialized"]:
                entry["file_start"] = m["file_offset"]
                entry["file_end_inclusive"] = m["file_offset"] + m["length"] - 1
                mappings.append(entry)
            else:
                uninitialized.append(entry)
    return {"mappings": mappings, "uninitialized": uninitialized}


def _corrector_checks(c, exp, corrections_path, profile):
    """Where load-corrections.json came from -- never what it says was done.

    The record is checked for provenance only: the CorrectMzLoad.java and
    helper in this checkout wrote it, about this file. Whether the corrected
    program is right is settled by every other check, against the file, as
    though no corrector existed."""
    try:
        record = json.loads(Path(corrections_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        c.add("corrector.record", False, "a readable load-corrections.json", str(e))
        return None
    want = (profile or {}).get("load_correction") or {}
    want_script = want.get("script_sha256") or evidence.source_sha256(CORRECT_SCRIPT)
    want_helper = want.get("helper_sha256") or evidence.source_sha256(HELPER_SCRIPT)
    c.add("corrector.script_sha256", record.get("script_sha256") == want_script,
          want_script, record.get("script_sha256"),
          "which CorrectMzLoad.java wrote the record")
    c.add("corrector.helper_sha256", record.get("helper_sha256") == want_helper,
          want_helper, record.get("helper_sha256"))
    c.add("corrector.target", record.get("target_sha256") == sha256(exp.data),
          sha256(exp.data), record.get("target_sha256"),
          "the corrections were made against this file")
    return record


def verify(exe, observed_folder, profile=None, corrections=None):
    """The envelope for one file and one dump. Status verified, mismatch,
    unsupported, or blocked when there is no dump to compare against.

    `corrections` is CorrectMzLoad.java's load-corrections.json, when it ran.
    Its corrections are recorded in the result -- so a reader can tell a
    clean load from a corrected one -- and its provenance is checked, but
    nothing in it is believed: the corrected program is compared with the
    file exactly as an uncorrected one would be."""
    load_segment = int((profile or {}).get("load_segment", "0x1000"), 16)
    target = evidence.target_identity(exe)
    try:
        exp = Expected(exe, load_segment)
    except Unsupported as e:
        return evidence.envelope(
            "loadimage", target, status="unsupported", profile=profile,
            result={"file": str(exe), "reason": str(e),
                    "first_failure": {"name": "expected.bounds", "detail": str(e)}},
            evidence=[{"kind": "load-check", "level": "unsupported",
                       "claim": "expected.bounds", "detail": str(e)}],
            limitations=LIMITATIONS)
    try:
        obs = Observed(observed_folder)
    except (OSError, ValueError) as e:
        return evidence.envelope(
            "loadimage", target, status="blocked", profile=profile,
            result={"file": str(exe), "reason": f"no observed dump to compare: {e}"},
            limitations=LIMITATIONS)

    # Where the record came from is settled first, because one check below
    # leans on it; its own checks are still reported last.
    provenance = Checks()
    record = _corrector_checks(provenance, exp, corrections, profile) if corrections else None
    trusted = record is not None and all(i["ok"] for i in provenance.items)
    checks = compare(exp, obs, profile, restored_ranges(record), trusted)
    checks.items.extend(provenance.items)
    status = "verified" if all(i["ok"] for i in checks.items) else "mismatch"
    result = exp.record()
    result.update(mapping_record(obs))
    result["observed"] = str(obs.folder)
    # null: the corrector did not run. 0: it ran and found nothing to correct.
    result["corrections"] = None if not corrections else \
        (record.get("count") if record else None)
    result["correction_record"] = str(corrections) if corrections else None
    result["corrections_made"] = (record or {}).get("corrections", [])
    result["checks"] = len(checks.items)
    result["failed"] = [i["name"] for i in checks.items if not i["ok"]]
    result["first_failure"] = checks.first_failure()
    items = []
    for i in checks.items:
        item = {"kind": "load-check", "claim": i["name"],
                "level": "ok" if i["ok"] else "mismatch",
                "value": {"expected": i["expected"], "observed": i["observed"],
                          "ok": i["ok"]}}
        if i.get("detail"):
            item["detail"] = i["detail"]
        if i.get("first_difference"):
            item["location"] = i["first_difference"]
        items.append(item)
    unknowns = []
    if result["duplicated_relocations"]:
        unknowns.append("why the relocation table lists "
                        + ", ".join(result["duplicated_relocations"])
                        + " more than once")
    limitations = list(LIMITATIONS)
    if any(i["name"] == "relocations.status_after_correction" for i in checks.items):
        limitations.append(AFTER_CORRECTION_LIMITATION)
    return evidence.envelope("loadimage", target, status=status, result=result,
                             evidence=items, profile=profile,
                             limitations=limitations, unknowns=unknowns)


# ---------------------------------------------------------------- map

def map_address(record, file_offset=None, linear=None, address=None):
    """Convert between a file offset, a linear address and segment:offset.

    `record` is the result of a verified envelope (loadimage.json's "result").
    Exactly one of the three is given. Returns all three, the canonical
    segment:offset -- the segment of the block Ghidra put the byte in --
    and notes: that other segment:offset spellings name the same byte, and,
    inside a relocated word, that memory holds a different value from the
    file. Raises MapError for anything the load image does not map.
    """
    given = [x is not None for x in (file_offset, linear, address)]
    if sum(given) != 1:
        raise MapError("give exactly one of a file offset, a linear address or "
                       "a segment:offset address")
    header, module = record["header"], record["module"]
    notes = []
    if file_offset is not None:
        if file_offset < 0 or file_offset >= record["file_size"]:
            raise MapError(f"file offset 0x{file_offset:x} is outside the "
                           f"{record['file_size']}-byte file")
        if file_offset < header["size"]:
            raise MapError(f"file offset 0x{file_offset:x} is in the MZ header "
                           f"(0x0..0x{header['size'] - 1:x}), which is not loaded "
                           f"into the program's address space")
        if file_offset > module["file_end_inclusive"]:
            raise MapError(f"file offset 0x{file_offset:x} is past the load image "
                           f"(which ends at 0x{module['file_end_inclusive']:x}): "
                           f"appended data, never loaded")
        m = next((m for m in record["mappings"]
                  if m["file_start"] <= file_offset <= m["file_end_inclusive"]), None)
        if m is None:
            raise MapError(f"file offset 0x{file_offset:x} is in the load image but "
                           f"Ghidra mapped no block to it")
        linear = m["linear_start"] + file_offset - m["file_start"]
    else:
        if address is not None:
            seg, off = parse_address(address)
            if off > 0xFFFF or seg > 0xFFFF:
                raise MapError(f"{address!r} is not a 16-bit segment:offset")
            linear = (seg << 4) + off
        m = next((m for m in record["mappings"]
                  if m["linear_start"] <= linear <= m["linear_end_inclusive"]), None)
        if m is None:
            u = next((u for u in record["uninitialized"]
                      if u["linear_start"] <= linear <= u["linear_end_inclusive"]), None)
            if u is not None:
                raise MapError(f"0x{linear:x} is in {u['block']}, which is "
                               f"uninitialised: allocated at load, with no file "
                               f"bytes behind it")
            raise MapError(f"0x{linear:x} is not mapped by any block")
        file_offset = m["file_start"] + linear - m["linear_start"]

    seg = int(m["segment"], 16)
    canonical = seg_off(seg, linear - (seg << 4))
    if address is not None and address.lower() != canonical:
        notes.append(f"{address} names the same byte as {canonical}, the address "
                     f"Ghidra uses")
    notes.append("other segment:offset pairs name this byte too -- any ssss:oooo "
                 "with ssss*16+oooo equal to the linear address")
    for r in record["relocations"]:
        if r["linear"] <= linear <= r["linear"] + 1:
            notes.append(f"inside the relocated word at {r['address']}: memory holds "
                         f"0x{r['relocated_word']:04x}, the file 0x{r['original_word']:04x}")
            break
    return {"file_offset": file_offset, "linear": linear, "address": canonical,
            "block": m["block"], "notes": notes}


def locate_entries(functions_path, data, exe, beside=True):
    """Where each function in a functions.json starts, in the file and in the
    load image: {entry: {"file_offset", "image_offset", "linear", "segment",
    "offset"}}, and how that was worked out.

    An entry is a segment:offset pair, and the segment is half of it. Reading
    the offset alone is right only for code in the segment the image starts
    in. So each entry goes through the verified mapping in the loadimage.json
    beside functions.json (`map_address`). Without a verified one -- an
    export from before prompt 02 -- it falls back to the same rule the
    mapping encodes, linear = segment * 16 + offset, with the export's own
    load segment, and says which it used. An entry the mapping does not cover
    is left out.

    beside=False skips the loadimage.json: for entries read from a linker map,
    whose segments are the image's own paragraphs, so the linear rule is
    exact, and a loadimage.json that happens to sit beside the map says
    nothing about them."""
    functions_path = Path(functions_path)
    record_name = (data.get("load_image") or {}).get("record", "loadimage.json")
    record = None
    try:
        if beside:
            env = json.loads((functions_path.parent / record_name).read_text(encoding="utf-8"))
            if env.get("status") == "verified":
                record = env["result"]
    except (OSError, ValueError, KeyError):
        record = None
    if record is not None:
        load = int(record["load_segment"], 16)
        how = "verified"
    else:
        load = int(((data.get("observed_profile") or {}).get("load_segment")
                    or "0x1000"), 16)
        header = struct.unpack_from("<H", Path(exe).read_bytes(), 8)[0] * 16
        how = "linear-rule"
    out = {}
    for f in data.get("functions") or []:
        entry = f["entry"]
        seg, off = parse_address(entry)
        linear = (seg << 4) + off
        if record is not None:
            try:
                file_offset = map_address(record, address=entry)["file_offset"]
            except MapError:
                continue
        else:
            file_offset = header + linear - (load << 4)
        out[entry] = {"file_offset": file_offset, "image_offset": linear - (load << 4),
                      "linear": linear, "segment": seg, "offset": off}
    return out, how, load


# ---------------------------------------------------------------- command line

def _read_profile(path):
    if not path:
        return None
    env = json.loads(Path(path).read_text(encoding="utf-8"))
    return env.get("profile") if "profile" in env else env


def _number(text):
    return int(text, 0)


def summary(env):
    status = env["status"]
    result = env["result"]
    n = result.get("corrections")
    after = ""
    if n:
        record = Path(result.get("correction_record") or "load-corrections.json").name
        after = f" after {n} correction{'' if n == 1 else 's'} (see {record})"
    if status == "verified":
        return [f"load image: verified{after}, {result['checks']} checks agree"]
    if status in ("unsupported", "blocked"):
        return [f"load image: {status}: {result['reason']}"]
    f = result["first_failure"]
    lines = [f"load image: mismatch{after}, {len(result['failed'])} of "
             f"{result['checks']} checks failed",
             f"first failing check: {f['name']}: expected {f['expected']}, "
             f"observed {f['observed']}"]
    if f.get("first_difference"):
        d = f["first_difference"]
        where = f"file {d['file_offset']}"
        if "address" in d:
            where += f", {d['address']} (linear {d['linear']})"
        lines.append(f"first differing byte: {where}: expected {d['expected']}, "
                     f"observed {d['observed']}")
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("expected", help="what a correct load of this file looks like")
    e.add_argument("exe")
    e.add_argument("--profile", help="profile.json, for the load segment")
    e.add_argument("--load-segment", type=_number, help="instead of the profile's")
    e.add_argument("--evidence", default="-", help="where to write the envelope")

    v = sub.add_parser("verify", help="compare it with what Ghidra loaded")
    v.add_argument("exe")
    v.add_argument("observed", help="DumpLoadImage.java's folder, or its observed.json")
    v.add_argument("--profile", help="profile.json from analysis_profile.py write")
    v.add_argument("--evidence", help="write the envelope here (loadimage.json)")
    v.add_argument("--corrections",
                   help="CorrectMzLoad.java's load-corrections.json, when it ran: "
                        "recorded, and its provenance checked, but not trusted")

    m = sub.add_parser("map", help="convert a file offset or an address")
    m.add_argument("record", help="loadimage.json from a verified run")
    m.add_argument("--file", type=_number, dest="file_offset")
    m.add_argument("--linear", type=_number)
    m.add_argument("--address")
    m.add_argument("--allow-unverified", action="store_true",
                   help="use the mapping of a run that did not verify")

    args = ap.parse_args()
    if args.cmd == "expected":
        profile = _read_profile(args.profile)
        seg = args.load_segment if args.load_segment is not None else \
            int((profile or {}).get("load_segment", "0x1000"), 16)
        env = expected_envelope(args.exe, seg, profile)
        evidence.write(env, args.evidence)
        return 0 if env["status"] == "ok" else 2

    if args.cmd == "verify":
        env = verify(args.exe, args.observed, _read_profile(args.profile),
                     args.corrections)
        if args.evidence:
            evidence.write(env, args.evidence)
        for line in summary(env):
            print(line)
        return {"verified": 0, "mismatch": 1, "unsupported": 2}.get(env["status"], 3)

    env = json.loads(Path(args.record).read_text(encoding="utf-8"))
    if env.get("status") != "verified" and not args.allow_unverified:
        print(f"loadimage: {args.record} is {env.get('status')}, not verified, so its "
              f"mapping is not to be trusted. Fix the load first, or pass "
              f"--allow-unverified.", file=sys.stderr)
        return 1
    try:
        out = map_address(env["result"], args.file_offset, args.linear, args.address)
    except MapError as err:
        print(f"loadimage: {err}", file=sys.stderr)
        return 1
    print(f"file 0x{out['file_offset']:x}  =  {out['address']}  =  linear "
          f"0x{out['linear']:x}  ({out['block']})")
    for note in out["notes"]:
        print(f"  {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
