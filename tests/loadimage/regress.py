#!/usr/bin/env python3
"""
regress.py -- Check that tools/loadimage.py tells a correct load from a wrong
one, that CorrectMzLoad.java puts right the two loads Ghidra gets wrong and
nothing else, and that the pipeline stops on a load that is still wrong.

The fixture is tests/loadimage/fixtures/segments.asm, assembled at test time in
nine variants: the good file, the same with bytes appended past the declared
image, a duplicated relocation entry, a header whose last page is full, both
of those at once, a full last page with a relocation inside it, and three
malformed headers. See the fixture for what each one exercises.

Without Ghidra
--------------
* The expected side, read back against values taken from the file
  independently -- struct reads of the header, not loadimage.py's own.
* Malformed headers, the three fixtures and five more made by editing bytes,
  must come back `unsupported` with the reason, and no traceback.
* A synthetic dump shaped like DumpLoadImage.java's -- blocks, mappings,
  relocation records -- built from a correct load must verify. That proves
  the comparison on its own, and lets every tamper case run anywhere.
* A relocated word differs from the file's word by design. A dump whose
  memory holds the file's word at a relocation, or the file exactly as
  stored, must be a mismatch naming relocations.words.
* Tampering -- one byte in one block, one relocation missing, one extra --
  must name the right check, and for the byte the exact first difference.
* `map` round-trips every initialised byte, file offset to address to file
  offset, and refuses the header, appended data and uninitialised memory.

* A corrections record is checked for where it came from and never believed:
  a wrong byte stays a mismatch however the record describes it.
* A FAILURE relocation record inside a restored page is excused only when
  the record's provenance holds, the address is in the range it restored,
  and the word in memory is the file's after the fixup -- each condition
  failed in turn must fail the run.

With Ghidra (skipped, and saying so, without it)
------------------------------------------------
* The pipeline on the two good variants must verify with 0 corrections, and
  their dumps must be the same, block for block, as Ghidra's own load.
* The duplicated relocation and the full last page must verify after one
  correction each, with the exact values recorded; the variant with both
  gets both. A full last page with a relocation in it gets the page and the
  fixup back, and verifies although Ghidra's record for that relocation
  still says FAILURE: relocations.status_after_correction holds the word to
  the file instead, and a word changed in memory fails it.
* tests/loadimage/fixtures/bigpage.asm, one segment just past 64 KB with a
  full last page, has its page restored at the page's own paragraph,
  because it does not fit in the segment of the block before it.
* With -NoLoadCorrection the two must stop exactly as they did in prompt 02;
  with -AllowLoadMismatch as well they must continue, say so, and record it.
* A dump tampered after correction is still a mismatch.
* The forced load-segment drift and a malformed header stop the pipeline.
* The tamper cases again on a dump Ghidra wrote, and `map` round-tripping
  every initialised byte of a verified Ghidra load.

Usage:
    python tests/loadimage/regress.py
    python tests/loadimage/regress.py --only "after correction"   # cases matching
"""

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TOOLS = ROOT / "tools"
FIXTURE = HERE / "fixtures" / "segments.asm"
# One segment past 64 KB, last page full: the page the corrector restores
# does not fit in the segment of the block before it.
BIGPAGE = HERE / "fixtures" / "bigpage.asm"
sys.path.insert(0, str(TOOLS))
import evidence                                          # noqa: E402
import loadimage                                         # noqa: E402

# name -> the -d flags it is assembled with
VARIANTS = {"plain": [], "APPENDED": ["APPENDED"], "DUPLICATED": ["DUPLICATED"],
            "FULL_LAST_PAGE": ["FULL_LAST_PAGE"],
            "BOTH": ["DUPLICATED", "FULL_LAST_PAGE"],
            "TAIL_RELOCATION": ["TAIL_RELOCATION"],
            "RELOC_TABLE_OUTSIDE": ["RELOC_TABLE_OUTSIDE"],
            "RELOC_TARGET_PAST": ["RELOC_TARGET_PAST"],
            "ENTRY_OUTSIDE": ["ENTRY_OUTSIDE"]}
LOAD = 0x1000

CASES = []


def case(name, ghidra=False):
    def wrap(fn):
        CASES.append((name, fn, ghidra))
        return fn
    return wrap


class Skip(Exception):
    pass


WORK = None
EXE = {}


def run(*args, env=None):
    env = dict(env if env is not None else os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable] + [str(a) for a in args],
                       capture_output=True, text=True, env=env)
    return r.returncode, r.stdout, r.stderr


def header(path):
    """The fields this suite checks against, read with struct, not loadimage."""
    data = Path(path).read_bytes()
    (_, last, pages, nreloc, paras, _, _, ss, sp, _, ip, cs, table, _) = \
        struct.unpack_from("<2sHHHHHHHHHHHHH", data, 0)
    relocs = [struct.unpack_from("<HH", data, table + 4 * i) for i in range(nreloc)]
    return {"data": data, "last": last, "pages": pages, "header": paras * 16,
            "ss": ss, "sp": sp, "ip": ip, "cs": cs,
            "relocs": [(seg, off) for off, seg in relocs]}


# ---------------------------------------------------------------- expected

@case("the expected side matches the header, read independently")
def _():
    h = header(EXE["plain"])
    exp = loadimage.Expected(EXE["plain"])
    rec = exp.record()
    end = (h["pages"] - 1) * 512 + h["last"]
    if (rec["module"]["file_start"], rec["module"]["file_end_inclusive"]) != \
            (h["header"], end - 1):
        raise AssertionError(f"module range {rec['module']}")
    if rec["module"]["sha256"] != hashlib.sha256(h["data"][h["header"]:end]).hexdigest():
        raise AssertionError("module digest")
    for r, (seg, off) in zip(rec["relocations"], h["relocs"]):
        at = h["header"] + seg * 16 + off
        word = struct.unpack_from("<H", h["data"], at)[0]
        if (r["file_offset"], r["original_word"], r["relocated_word"],
                r["linear"], r["address"]) != \
                (at, word, (word + LOAD) & 0xFFFF, LOAD * 16 + seg * 16 + off,
                 f"{LOAD + seg:04x}:{off:04x}"):
            raise AssertionError(f"relocation {r}")
    want_entry = (f"{LOAD + h['cs']:04x}:{h['ip']:04x}", LOAD * 16 + h["cs"] * 16 + h["ip"])
    if (rec["entry"]["address"], rec["entry"]["linear"]) != want_entry:
        raise AssertionError(f"entry {rec['entry']}")
    if rec["entry"]["image_offset"] == 0:
        raise AssertionError("the fixture's entry is meant not to be at offset 0")
    if (rec["stack"]["segment"], rec["stack"]["sp"]) != (LOAD + h["ss"], h["sp"]):
        raise AssertionError(f"stack {rec['stack']}")
    if rec["appended"] is not None or rec["duplicated_relocations"]:
        raise AssertionError("nothing appended, nothing duplicated in the plain file")
    return (f"module 0x{h['header']:x}..0x{end - 1:x}, {len(h['relocs'])} relocations, "
            f"entry {want_entry[0]}")


@case("appended bytes are reported, with their digest, outside the module")
def _():
    plain = loadimage.Expected(EXE["plain"]).record()
    rec = loadimage.Expected(EXE["APPENDED"]).record()
    data = Path(EXE["APPENDED"]).read_bytes()
    tail = data[plain["module"]["file_end_inclusive"] + 1:]
    app = rec["appended"]
    if not app or (app["file_start"], app["file_end_inclusive"], app["size"]) != \
            (len(data) - len(tail), len(data) - 1, len(tail)):
        raise AssertionError(f"appended {app}")
    if app["sha256"] != hashlib.sha256(tail).hexdigest() or app["loaded"]:
        raise AssertionError("appended digest, or reported as loaded")
    if rec["module"] != plain["module"]:
        raise AssertionError("appending changed the module")
    return f"file 0x{app['file_start']:x}..0x{app['file_end_inclusive']:x}, not loaded"


@case("a duplicated relocation is counted, and adds the load segment twice")
def _():
    rec = loadimage.Expected(EXE["DUPLICATED"]).record()
    dup = [r for r in rec["relocations"] if r["entries_for_this_word"] > 1]
    if rec["duplicated_relocations"] != ["1006:0016"] or len(dup) != 2:
        raise AssertionError(f"duplicates {rec['duplicated_relocations']}")
    if dup[0]["relocated_word"] != (dup[0]["original_word"] + 2 * LOAD) & 0xFFFF:
        raise AssertionError(f"word {dup[0]}")
    return (f"1006:0016 listed twice: 0x{dup[0]['original_word']:04x} -> "
            f"0x{dup[0]['relocated_word']:04x}, as FreeDOS and DOSBox apply it")


@case("bytes-on-last-page 0 is read as a full last page")
def _():
    h = header(EXE["FULL_LAST_PAGE"])
    rec = loadimage.Expected(EXE["FULL_LAST_PAGE"]).record()
    if h["last"] != 0 or h["pages"] != 2:
        raise AssertionError(f"the fixture should be 2 pages, last 0: {h['pages']}, {h['last']}")
    if rec["module"]["file_end_inclusive"] != 2 * 512 - 1:
        raise AssertionError(f"module ends at {rec['module']['file_end_inclusive']}")
    return "module to file 0x3ff, both pages"


def malformed():
    """(label, path, words the reason must contain)"""
    base = bytearray(Path(EXE["plain"]).read_bytes())
    made = []

    def edit(label, offset, fmt, value, words):
        data = bytearray(base)
        struct.pack_into(fmt, data, offset, value)
        p = WORK / f"bad-{label}.exe"
        p.write_bytes(data)
        made.append((label, p, words))

    edit("header-larger-than-file", 0x08, "<H", 0x0100, ["header claims"])
    edit("no-pages", 0x04, "<H", 0, ["no pages"])
    edit("last-page-too-long", 0x02, "<H", 600, ["more than a page"])
    edit("image-past-file", 0x04, "<H", 9, ["file is"])
    edit("table-in-fixed-fields", 0x18, "<H", 0x0010, ["inside the header"])
    text = WORK / "bad-not-mz.exe"
    text.write_bytes(b"not an executable at all, just text\r\n")
    made.append(("not-mz", text, ["not an MZ"]))
    made += [("RELOC_TABLE_OUTSIDE", EXE["RELOC_TABLE_OUTSIDE"], ["past end of file"]),
             ("RELOC_TARGET_PAST", EXE["RELOC_TARGET_PAST"], ["past the", "image"]),
             ("ENTRY_OUTSIDE", EXE["ENTRY_OUTSIDE"], ["entry point", "past the"])]
    return made


@case("malformed headers are unsupported, with the reason, and no traceback")
def _():
    cases = malformed()
    for label, path, words in cases:
        code, out, err = run(TOOLS / "loadimage.py", "expected", path)
        env = json.loads(out)
        reason = env["result"].get("reason", "")
        if code != 2 or env["status"] != "unsupported" or err.strip():
            raise AssertionError(f"{label}: exit {code}, {env['status']}, {err[-200:]!r}")
        if not all(w in reason for w in words):
            raise AssertionError(f"{label}: reason {reason!r} lacks {words}")
        code, out, err = run(TOOLS / "loadimage.py", "verify", path, WORK / "no-dump")
        if code != 2 or "unsupported" not in out or err.strip():
            raise AssertionError(f"{label} through verify: exit {code}, {out!r}, {err!r}")
    return f"{len(cases)} files, each with its reason"


# ------------------------------------------------- a dump without Ghidra

def synthetic_dump(exp, folder, memory=None, splits=None):
    """A dump shaped like DumpLoadImage.java's, of a load done right.

    One block per segment start in `splits` (image offsets, paragraph
    aligned), named as Ghidra's MZ loader names them, a HEADER block in a
    space of its own, and an uninitialised DATA block after the last.
    `memory` replaces the loaded bytes, to model a load done wrong."""
    folder.mkdir(parents=True, exist_ok=True)
    mem = bytes(exp.relocated if memory is None else memory)
    hdr, size = exp.header_size, len(exp.module)
    splits = sorted(set([0] + list(splits or [0x10, 0x40, 0x60]) + [size]))
    blocks = []
    for i, (lo, hi) in enumerate(zip(splits, splits[1:])):
        seg = LOAD + lo // 16
        name = f"block-{i:02d}.bin"
        (folder / name).write_bytes(mem[lo:hi])
        blocks.append({"index": i, "name": f"CODE_{i}", "space": "ram",
                       "segmented": True, "start": f"{seg:04x}:0000",
                       "start_offset": LOAD * 16 + lo, "size": hi - lo,
                       "initialized": True, "sha256": loadimage.sha256(mem[lo:hi]),
                       "dump": name,
                       "mappings": [{"min": f"{seg:04x}:0000", "min_offset": LOAD * 16 + lo,
                                     "offset_in_block": 0, "length": hi - lo,
                                     "file_offset": hdr + lo}]})
    last = blocks[-1]
    seg = int(last["start"][:4], 16)
    top = size - (seg - LOAD) * 16
    blocks.append({"index": len(blocks), "name": "DATA", "space": "ram",
                   "segmented": True, "start": f"{seg:04x}:{top:04x}",
                   "start_offset": LOAD * 16 + size, "size": 256, "initialized": False,
                   "mappings": [{"min": f"{seg:04x}:{top:04x}",
                                 "min_offset": LOAD * 16 + size, "offset_in_block": 0,
                                 "length": 256, "file_offset": -1}]})
    (folder / "header.bin").write_bytes(exp.data[:hdr])
    blocks.append({"index": len(blocks), "name": "HEADER", "space": "HEADER",
                   "segmented": False, "start": "HEADER::00000000", "start_offset": 0,
                   "size": hdr, "initialized": True, "dump": "header.bin",
                   "sha256": loadimage.sha256(exp.data[:hdr]),
                   "mappings": [{"min": "HEADER::00000000", "min_offset": 0,
                                 "offset_in_block": 0, "length": hdr, "file_offset": 0}]})
    modified = exp.data[:hdr] + mem + exp.data[exp.image_end:]
    (folder / "file-original.bin").write_bytes(exp.data)
    (folder / "file-modified.bin").write_bytes(modified)
    observed = {
        "schema": "dos-decompiler/loadimage-observed/1",
        "script_sha256": evidence.source_sha256(loadimage.DUMP_SCRIPT),
        "helper_sha256": evidence.source_sha256(loadimage.HELPER_SCRIPT),
        "loader": "Old-style DOS Executable (MZ)", "load_segment": "0x1000",
        "executable_sha256": loadimage.sha256(exp.data), "header_size": hdr,
        "stack": {"ss": exp.stack["segment"], "sp": exp.stack["sp"]},
        "entry_points": [{"address": exp.entry["address"], "offset": exp.entry["linear"]}],
        "file_bytes": [{"index": 0, "filename": exp.path.name, "file_offset": 0,
                        "size": len(exp.data),
                        "original_sha256": loadimage.sha256(exp.data),
                        "modified_sha256": loadimage.sha256(modified),
                        "original_dump": "file-original.bin",
                        "modified_dump": "file-modified.bin"}],
        "blocks": blocks,
        "relocations": [{"address": r["address"], "offset": r["linear"],
                         "status": "APPLIED", "type": 0, "length": 2,
                         "bytes": struct.pack("<H", r["original_word"]).hex(),
                         "values": [r["segment"], r["offset"]]}
                        for r in exp.relocations],
    }
    (folder / "observed.json").write_text(json.dumps(observed, indent=1), encoding="utf-8")
    return folder


def verified(exe, folder):
    env = loadimage.verify(exe, folder)
    return env, env["result"].get("first_failure")


@case("a correct load, laid out as Ghidra lays one out, verifies")
def _():
    exp = loadimage.Expected(EXE["plain"])
    env, first = verified(EXE["plain"], synthetic_dump(exp, WORK / "synthetic-good"))
    if env["status"] != "verified":
        raise AssertionError(f"{env['status']}: {first}")
    app = loadimage.Expected(EXE["APPENDED"])
    env2, first = verified(EXE["APPENDED"], synthetic_dump(app, WORK / "synthetic-appended"))
    if env2["status"] != "verified":
        raise AssertionError(f"appended: {env2['status']}: {first}")
    return f"{env['result']['checks']} checks, and the appended variant too"


@case("a relocated word that holds the file's value is a mismatch, by design")
def _():
    exp = loadimage.Expected(EXE["plain"])
    r = exp.relocations[3]                             # the far pointer in DATA
    memory = bytearray(exp.relocated)
    memory[r["image_offset"]:r["image_offset"] + 2] = struct.pack("<H", r["original_word"])
    env, first = verified(EXE["plain"], synthetic_dump(exp, WORK / "unrelocated-one", memory))
    if env["status"] != "mismatch" or first["name"] != "relocations.words" \
            or r["address"] not in str(first["observed"]):
        raise AssertionError(f"one word left as the file has it: {first}")
    env, first = verified(EXE["plain"],
                          synthetic_dump(exp, WORK / "as-stored", exp.module))
    failed = env["result"]["failed"]
    if env["status"] != "mismatch" or first["name"] != "relocations.words" \
            or "module.loaded" not in failed:
        raise AssertionError(f"the file as stored: {failed}")
    return (f"{r['address']} holding 0x{r['original_word']:04x} fails; so does the "
            f"file exactly as stored ({len(failed)} checks)")


def tamper_byte(folder):
    """Flip one byte of the largest initialised block, away from any
    relocated word. Returns what the first difference must be."""
    obs = json.loads((folder / "observed.json").read_text(encoding="utf-8"))
    blocks = [b for b in obs["blocks"] if b["segmented"] and b["initialized"]]
    block = max(blocks, key=lambda b: b["size"])
    m = block["mappings"][0]
    seg, off = loadimage.parse_address(m["min"])
    lin0 = seg * 16 + off
    touched = set()
    for r in obs["relocations"]:
        touched |= {r["offset"], r["offset"] + 1}
    i = next(i for i in range(2, m["length"]) if lin0 + i not in touched)
    path = folder / block["dump"]
    data = bytearray(path.read_bytes())
    before = data[m["offset_in_block"] + i]
    data[m["offset_in_block"] + i] ^= 0x5A
    path.write_bytes(data)
    block["sha256"] = hashlib.sha256(data).hexdigest()
    (folder / "observed.json").write_text(json.dumps(obs, indent=1), encoding="utf-8")
    lin = lin0 + i
    return {"check": f"mapping {block['name']} {m['min']}.digest",
            "first_difference": {"file_offset": f"0x{m['file_offset'] + i:x}",
                                 "expected": f"0x{before:02x}",
                                 "observed": f"0x{before ^ 0x5A:02x}",
                                 "linear": f"0x{lin:x}",
                                 "address": f"{seg:04x}:{lin - seg * 16:04x}"}}


def tamper_relocation(folder, mode):
    obs = json.loads((folder / "observed.json").read_text(encoding="utf-8"))
    relocations = obs["relocations"]
    if mode == "missing":
        gone = relocations.pop(1)
        named = gone["address"]
    else:
        extra = dict(relocations[0])
        extra["offset"] = relocations[0]["offset"] + 8
        seg, off = loadimage.parse_address(extra["address"])
        extra["address"] = f"{seg:04x}:{off + 8:04x}"
        relocations.append(extra)
        named = f"0x{extra['offset']:x}"
    (folder / "observed.json").write_text(json.dumps(obs, indent=1), encoding="utf-8")
    return named


def run_tampers(exe, saved, label):
    """The three tamper cases on a copy of `saved`. Returns what was found."""
    found = []
    folder = WORK / f"tamper-byte-{label}"
    shutil.copytree(saved, folder)
    want = tamper_byte(folder)
    env, first = verified(exe, folder)
    if env["status"] != "mismatch" or first["name"] != want["check"]:
        raise AssertionError(f"byte: first failing {first and first['name']}, "
                             f"wanted {want['check']}")
    if first.get("first_difference") != want["first_difference"]:
        raise AssertionError(f"byte: {first.get('first_difference')} != "
                             f"{want['first_difference']}")
    d = want["first_difference"]
    found.append(f"byte at file {d['file_offset']} ({d['address']}): "
                 f"{d['expected']} -> {d['observed']}")
    for mode in ("missing", "extra"):
        folder = WORK / f"tamper-{mode}-{label}"
        shutil.copytree(saved, folder)
        named = tamper_relocation(folder, mode)
        env, first = verified(exe, folder)
        if env["status"] != "mismatch" or first["name"] != "relocations.set" \
                or f"{mode} {named}" not in (first.get("detail") or ""):
            raise AssertionError(f"{mode} relocation: {first}")
        found.append(f"{mode} relocation {named}")
    return found


@case("tampering with a dump names the right check, and the exact byte")
def _():
    exp = loadimage.Expected(EXE["plain"])
    saved = synthetic_dump(exp, WORK / "synthetic-saved")
    return "; ".join(run_tampers(EXE["plain"], saved, "synthetic"))


@case("a dump missing part of the module, or from another dumper, is a mismatch")
def _():
    exp = loadimage.Expected(EXE["plain"])
    folder = synthetic_dump(exp, WORK / "synthetic-gap")
    obs = json.loads((folder / "observed.json").read_text(encoding="utf-8"))
    gone = obs["blocks"].pop(2)                        # one segment never loaded
    (folder / "observed.json").write_text(json.dumps(obs), encoding="utf-8")
    env, first = verified(EXE["plain"], folder)
    m = gone["mappings"][0]
    hole = f"file 0x{m['file_offset']:x}..0x{m['file_offset'] + m['length'] - 1:x} not loaded"
    if env["status"] != "mismatch" or first["name"] != "module.coverage" \
            or hole not in first["observed"]:
        raise AssertionError(f"gap: {first}")

    folder = synthetic_dump(exp, WORK / "synthetic-dumper")
    obs = json.loads((folder / "observed.json").read_text(encoding="utf-8"))
    obs["script_sha256"] = "0" * 64                    # an older DumpLoadImage.java
    (folder / "observed.json").write_text(json.dumps(obs), encoding="utf-8")
    env, first = verified(EXE["plain"], folder)
    if env["status"] != "mismatch" or first["name"] != "dumper.script_sha256":
        raise AssertionError(f"dumper: {first}")
    return f"{hole}; and a dump by another DumpLoadImage.java refused first"


# ---------------------------------------------------------------- map

def round_trip(record):
    """Every initialised byte: file offset -> address -> file offset."""
    n = 0
    for m in record["mappings"]:
        for f in range(m["file_start"], m["file_end_inclusive"] + 1):
            there = loadimage.map_address(record, file_offset=f)
            back = loadimage.map_address(record, address=there["address"])
            again = loadimage.map_address(record, linear=there["linear"])
            if (back["file_offset"], again["file_offset"]) != (f, f):
                raise AssertionError(f"file 0x{f:x} -> {there['address']} -> "
                                     f"0x{back['file_offset']:x}")
            n += 1
    module = record["module"]
    if n != module["size"]:
        raise AssertionError(f"{n} bytes mapped of a {module['size']}-byte module")
    return n


@case("map round-trips every initialised byte, and refuses what is not loaded")
def _():
    exp = loadimage.Expected(EXE["APPENDED"])
    env = loadimage.verify(EXE["APPENDED"], synthetic_dump(exp, WORK / "synthetic-map"))
    record = env["result"]
    n = round_trip(record)

    def refused(words, **query):
        try:
            loadimage.map_address(record, **query)
        except loadimage.MapError as e:
            if not all(w in str(e) for w in words):
                raise AssertionError(f"{query}: {e}")
            return
        raise AssertionError(f"{query} was mapped")

    refused(["MZ header"], file_offset=0x10)
    refused(["appended data"], file_offset=record["appended"]["file_start"])
    refused(["uninitialised"], linear=record["uninitialized"][0]["linear_start"])
    refused(["not mapped"], linear=0x90000)
    refused(["outside the"], file_offset=10 ** 6)

    r = record["relocations"][3]
    seg, off = loadimage.parse_address(r["address"])
    alias = f"{seg - 1:04x}:{off + 16:04x}"
    out = loadimage.map_address(record, address=alias)
    notes = " ".join(out["notes"])
    if out["address"] != r["address"] or "names the same byte" not in notes \
            or "relocated word" not in notes:
        raise AssertionError(f"{alias}: {out}")
    return f"{n} bytes both ways; {alias} is {r['address']}, inside a relocated word"


@case("a corrections record is checked for where it came from, and never believed")
def _():
    exp = loadimage.Expected(EXE["plain"])
    r = exp.relocations[3]
    memory = bytearray(exp.relocated)
    memory[r["image_offset"]] ^= 0x01                   # a word left wrong
    folder = synthetic_dump(exp, WORK / "corrector-claims", memory)
    record = {"schema": "dos-decompiler/load-corrections/1",
              "script_sha256": evidence.source_sha256(loadimage.CORRECT_SCRIPT),
              "helper_sha256": evidence.source_sha256(loadimage.HELPER_SCRIPT),
              "target_sha256": loadimage.sha256(exp.data), "count": 1, "notes": [],
              "corrections": [{"kind": "duplicated-relocation", "address": r["address"],
                               "before": "0x0000", "after": f"0x{r['relocated_word']:04x}"}]}
    claims = WORK / "corrector-claims.json"
    claims.write_text(json.dumps(record), encoding="utf-8")
    env = loadimage.verify(EXE["plain"], folder, corrections=claims)
    if env["status"] != "mismatch" or env["result"]["first_failure"]["name"] != \
            "relocations.words" or env["result"]["corrections"] != 1:
        raise AssertionError(f"a record claiming the word was fixed: {env['result']['failed']}")
    good = synthetic_dump(exp, WORK / "corrector-good")
    for field, value, check in (("script_sha256", "0" * 64, "corrector.script_sha256"),
                                ("target_sha256", "1" * 64, "corrector.target")):
        bad = dict(record, **{field: value})
        claims.write_text(json.dumps(bad), encoding="utf-8")
        env = loadimage.verify(EXE["plain"], good, corrections=claims)
        if env["status"] != "mismatch" or env["result"]["failed"] != [check]:
            raise AssertionError(f"{field}: {env['result']['failed']}")
    claims.write_text(json.dumps(dict(record, count=0, corrections=[])), encoding="utf-8")
    env = loadimage.verify(EXE["plain"], good, corrections=claims)
    if env["status"] != "verified" or env["result"]["corrections"] != 0:
        raise AssertionError(f"a clean record on a clean dump: {env['result']['failed']}")
    return ("a wrong word stays wrong whatever the record says; a record from "
            "another corrector or file is refused")


@case("a FAILURE record in the restored page passes only on all three conditions")
def _():
    # TAIL_RELOCATION: a relocation at file 0x212, inside the second page, the
    # page Ghidra's loader drops. A dump of a correct load, except that the
    # record Ghidra writes for that relocation says FAILURE with no bytes,
    # as Ghidra 12.1.2 was measured to write it.
    exp = loadimage.Expected(EXE["TAIL_RELOCATION"])
    data = EXE["TAIL_RELOCATION"].read_bytes()
    hdr = struct.unpack_from("<H", data, 8)[0] * 16
    tail_linear = LOAD * 16 + 0x212 - hdr
    word = struct.unpack_from("<H", data, 0x212)[0] + LOAD      # what DOS makes it
    page = (LOAD * 16 + 0x200 - hdr, LOAD * 16 + 0x3FF - hdr)  # the second page

    def dump(name, memory=None, failures=(tail_linear,)):
        folder = synthetic_dump(exp, WORK / name, memory)
        obs = json.loads((folder / "observed.json").read_text(encoding="utf-8"))
        for r in obs["relocations"]:
            if r["offset"] in failures:
                r.update(status="FAILURE", length=0, bytes=None)
        (folder / "observed.json").write_text(json.dumps(obs), encoding="utf-8")
        return folder

    def record(name, **changes):
        rec = {"schema": "dos-decompiler/load-corrections/1",
               "script_sha256": evidence.source_sha256(loadimage.CORRECT_SCRIPT),
               "helper_sha256": evidence.source_sha256(loadimage.HELPER_SCRIPT),
               "target_sha256": loadimage.sha256(data), "count": 1, "notes": [],
               "corrections": [{"kind": "missing-last-page", "linear_start": page[0],
                                "linear_end_inclusive": page[1]}]}
        rec.update(changes)
        path = WORK / f"{name}.json"
        path.write_text(json.dumps(rec), encoding="utf-8")
        return path

    def check(env, name):
        return next((i for i in env["evidence"] if i["claim"] == name), None)

    good = dump("after-good")
    env = loadimage.verify(EXE["TAIL_RELOCATION"], good, corrections=record("rec-good"))
    held = check(env, "relocations.status_after_correction")
    if env["status"] != "verified" or not held or not held["value"]["ok"] \
            or f"memory 0x{word:04x}" not in str(held["value"]["observed"]) \
            or not any("FAILURE record" in t for t in env["limitations"]):
        raise AssertionError(f"all three hold: {env['status']}, {env['result']['failed']}, {held}")
    # Without a corrections record nothing is excused, and there is no check.
    env = loadimage.verify(EXE["TAIL_RELOCATION"], good)
    if env["result"]["failed"] != ["relocations.status", "relocations.original"] \
            or check(env, "relocations.status_after_correction"):
        raise AssertionError(f"no record: {env['result']['failed']}")
    # A record from another corrector: provenance fails, so nothing is excused.
    env = loadimage.verify(EXE["TAIL_RELOCATION"], good,
                           corrections=record("rec-other", script_sha256="0" * 64))
    if env["result"]["failed"] != ["relocations.status", "relocations.status_after_correction",
                                   "relocations.original", "corrector.script_sha256"]:
        raise AssertionError(f"another corrector: {env['result']['failed']}")
    # A FAILURE outside the restored range stays a failure, whatever the record.
    first = exp.relocations[0]["linear"]
    env = loadimage.verify(EXE["TAIL_RELOCATION"],
                           dump("after-outside", failures=(tail_linear, first)),
                           corrections=record("rec-good2"))
    if env["result"]["failed"] != ["relocations.status", "relocations.original"] \
            or not check(env, "relocations.status_after_correction")["value"]["ok"]:
        raise AssertionError(f"FAILURE outside: {env['result']['failed']}")
    # The word in memory wrong: the check fails, and names both values.
    memory = bytearray(exp.relocated)
    memory[tail_linear - LOAD * 16] ^= 0x01
    env = loadimage.verify(EXE["TAIL_RELOCATION"], dump("after-word", memory),
                           corrections=record("rec-good3"))
    held = check(env, "relocations.status_after_correction")
    want = f"memory holds 0x{word ^ 0x01:04x}, not 0x{word:04x}"
    if env["status"] != "mismatch" or held["value"]["ok"] or want not in str(held["value"]["observed"]):
        raise AssertionError(f"wrong word: {env['result']['failed']}, {held}")
    return (f"0x{word:04x} at {exp.relocations[-1]['address']} excused; not without a "
            f"record, from another corrector, outside the page, or with the word wrong")


# ---------------------------------------------------------------- Ghidra

def ghidra_ready():
    ghidra = os.environ.get("GHIDRA_HOME")
    java = os.environ.get("JAVA_HOME")
    pwsh = shutil.which("pwsh")
    if not ghidra or not any((Path(ghidra) / "support" / n).exists()
                             for n in ("analyzeHeadless.bat", "analyzeHeadless")):
        return None, "Ghidra not found (set GHIDRA_HOME)"
    if not java or not Path(java).exists():
        return None, "JDK not found (set JAVA_HOME)"
    if not pwsh:
        return None, "pwsh not found; pipeline.ps1 needs PowerShell 7"
    return (ghidra, java, pwsh), None


GHIDRA = None
PIPELINES = {}


def pipeline(variant, *extra, drift=None):
    """Run pipeline.ps1 on one variant once; later calls reuse the result."""
    key = (variant,) + extra + ((f"drift={drift}",) if drift else ())
    if key in PIPELINES:
        return PIPELINES[key]
    ghidra, java, pwsh = GHIDRA
    folder = WORK / "pipeline" / "-".join(k.replace("=", "_") for k in key)
    folder.mkdir(parents=True, exist_ok=True)
    exe = folder / "SEGMENTS.EXE"
    shutil.copy(EXE[variant], exe)
    env = dict(os.environ, PYTHON=sys.executable)
    env.pop("DOS_DECOMPILER_FORCE_DRIFT", None)
    if drift:
        env["DOS_DECOMPILER_FORCE_DRIFT"] = drift
    r = subprocess.run([pwsh, "-NoProfile", "-File", str(TOOLS / "pipeline.ps1"),
                        "-Exe", str(exe), "-OutDir", str(folder / "out"),
                        "-Ghidra", ghidra, "-JavaHome", java] + list(extra),
                       capture_output=True, text=True, env=env)
    PIPELINES[key] = (r.returncode, r.stdout + r.stderr, exe, folder / "out")
    return PIPELINES[key]


def record_of(out):
    return json.loads((out / "loadimage.json").read_text(encoding="utf-8"))


def functions_of(out):
    return json.loads((out / "functions.json").read_text(encoding="utf-8"))


def raw_dump(variant):
    """Ghidra's own load of a variant, dumped: import without analysis, no
    corrector, then DumpLoadImage.java -- what the pipeline saw before this
    prompt added the corrector."""
    ghidra, java, pwsh = GHIDRA
    folder = WORK / "raw" / variant
    (folder / "proj").mkdir(parents=True, exist_ok=True)
    exe = folder / "SEGMENTS.EXE"
    shutil.copy(EXE[variant], exe)
    script = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    headless = str(Path(ghidra) / "support" / script)
    env = dict(os.environ, JAVA_HOME=java)
    for args in (["-import", str(exe), "-overwrite", "-noanalysis"],
                 ["-process", exe.name, "-noanalysis", "-readOnly", "-scriptPath",
                  str(TOOLS / "ghidra_scripts"), "-postScript", "DumpLoadImage.java",
                  str(folder)]):
        subprocess.run([headless, str(folder / "proj"), "t"] + args,
                       capture_output=True, text=True, env=env)
    return folder / "loadimage-observed"


def dump_shape(folder):
    """Everything in a dump that describes the load -- not the scripts'
    own hashes, which differ by design between dumper and corrector runs."""
    obs = json.loads((folder / "observed.json").read_text(encoding="utf-8"))
    fbs = [{k: f[k] for k in ("size", "original_sha256", "modified_sha256")}
           for f in obs["file_bytes"]]
    return {"blocks": obs["blocks"], "relocations": obs["relocations"],
            "file_bytes": fbs, "entry_points": obs["entry_points"],
            "stack": obs["stack"], "load_segment": obs["load_segment"]}


def corrections_of(out):
    return json.loads((out / "load-corrections.json").read_text(encoding="utf-8"))


@case("the good fixtures verify with 0 corrections, and the same dump as Ghidra's",
      ghidra=True)
def _():
    found = []
    for variant in ("plain", "APPENDED"):
        code, log, exe, out = pipeline(variant)
        if code != 0:
            raise AssertionError(f"{variant}: exit {code}\n{log[-1500:]}")
        env = record_of(out)
        fj = functions_of(out)
        if env["status"] != "verified" or env["result"]["corrections"] != 0 \
                or "load image: verified, " not in log:
            raise AssertionError(f"{variant}: {env['status']}, corrections "
                                 f"{env['result'].get('corrections')}")
        if fj.get("load_image") != {"status": "verified", "corrections": 0,
                                    "mismatch_allowed": False, "record": "loadimage.json"}:
            raise AssertionError(f"{variant}: functions.json load_image {fj.get('load_image')}")
        if corrections_of(out)["corrections"]:
            raise AssertionError(f"{variant}: the record lists corrections")
        raw = dump_shape(raw_dump(variant))
        if dump_shape(out / "loadimage-observed") != raw:
            raise AssertionError(f"{variant}: the corrector changed a clean load")
        found.append(f"{variant}: {env['result']['checks']} checks, "
                     f"{len(raw['blocks'])} blocks as Ghidra loaded them")
    return "; ".join(found)


# What the corrector must record, exactly, measured on Ghidra 12.1.2.
PAGE_CORRECTION = {
    "kind": "missing-last-page", "file_start": 0x200, "file_end_inclusive": 0x3FF,
    "linear_start": 0x101C0, "linear_end_inclusive": 0x103BF, "address": "1006:0160",
    "before": "not loaded",
    "after": "file 0x200..0x3ff mapped at 1006:0160, joined to CODE_3",
    "uninitialized_moved": "DATA 1006:0160 size 256 -> DATA 1006:0360 size 256",
    "fixups": []}
DUPLICATE_CORRECTION = {
    "kind": "duplicated-relocation", "address": "1006:0016", "linear": 0x10076,
    "file_offset": 0xB6, "entries": 2, "relocation_records": 2,
    "before": "0x1004", "after": "0x2004"}


@case("the two loads Ghidra gets wrong verify after correction, exactly recorded",
      ghidra=True)
def _():
    wants = {"FULL_LAST_PAGE": [PAGE_CORRECTION],
             "DUPLICATED": [DUPLICATE_CORRECTION]}
    for variant, want in wants.items():
        code, log, exe, out = pipeline(variant)
        line = "load image: verified after 1 correction (see load-corrections.json)"
        if code != 0 or line not in log:
            raise AssertionError(f"{variant}: exit {code}\n{log[-1500:]}")
        env = record_of(out)
        if env["status"] != "verified" or env["result"]["corrections"] != 1 \
                or env["result"]["corrections_made"] != want:
            raise AssertionError(f"{variant}: {env['status']}, "
                                 f"{env['result'].get('corrections_made')}")
        if corrections_of(out)["corrections"] != want:
            raise AssertionError(f"{variant}: load-corrections.json {corrections_of(out)}")
        load = functions_of(out).get("load_image")
        if load != {"status": "verified", "corrections": 1, "mismatch_allowed": False,
                    "record": "loadimage.json"}:
            raise AssertionError(f"{variant}: functions.json load_image {load}")
    return ("page: file 0x200..0x3ff mapped at 1006:0160, joined to CODE_3; "
            "duplicate: 1006:0016 0x1004 -> 0x2004")


@case("a file with both divergences gets both corrections", ghidra=True)
def _():
    code, log, exe, out = pipeline("BOTH")
    env = record_of(out)
    made = env["result"]["corrections_made"]
    if code != 0 or env["status"] != "verified" or made != [PAGE_CORRECTION,
                                                            DUPLICATE_CORRECTION]:
        raise AssertionError(f"exit {code}, {env['status']}, {made}\n{log[-1000:]}")
    if "load image: verified after 2 corrections (see load-corrections.json)" not in log:
        raise AssertionError("prose does not say 2 corrections")
    return "2 corrections, the page and the duplicate, and verified"


@case("a relocation inside the restored page verifies, through "
      "relocations.status_after_correction", ghidra=True)
def _():
    # A relocation inside the dropped page: the corrector restores the page
    # and the fixup in memory, but the record Ghidra wrote for it says
    # FAILURE, and nothing in the program API rewrites a relocation record.
    # The verifier accepts that record only on its own terms, and says so.
    code, log, exe, out = pipeline("TAIL_RELOCATION")
    env = record_of(out)
    fixups = env["result"]["corrections_made"][0]["fixups"]
    if code != 0 or env["status"] != "verified" or env["result"]["corrections"] != 1:
        raise AssertionError(f"exit {code}, {env['status']}, {env['result']['failed']}")
    if fixups != [{"address": "1006:0172", "file_offset": 0x212, "entries": 1,
                   "before": "0x0004", "after": "0x1004"}]:
        raise AssertionError(f"fixups {fixups}")
    held = next((i for i in env["evidence"]
                 if i["claim"] == "relocations.status_after_correction"), None)
    if not held or held["value"]["observed"] != [
            "1006:0172: FAILURE, memory 0x1004 as the file makes it, inside the restored page"]:
        raise AssertionError(f"the check: {held}")
    if not any("FAILURE record" in t for t in env["limitations"]):
        raise AssertionError("the limitation is not in the envelope")
    obs = json.loads((out / "loadimage-observed" / "observed.json").read_text(encoding="utf-8"))
    if [r["status"] for r in obs["relocations"] if r["address"] == "1006:0172"] != ["FAILURE"]:
        raise AssertionError("Ghidra's record no longer says FAILURE; the check is moot")
    if "load image: verified after 1 correction" not in log:
        raise AssertionError("prose")
    return ("Ghidra's record still FAILURE; 1006:0172 holds 0x1004 as the file makes it; "
            f"{env['result']['checks']} checks agree")


@case("a word changed in memory inside the restored page fails that check", ghidra=True)
def _():
    code, log, exe, out = pipeline("TAIL_RELOCATION")
    folder = WORK / "tamper-tail-word"
    shutil.copytree(out / "loadimage-observed", folder)
    obs = json.loads((folder / "observed.json").read_text(encoding="utf-8"))
    block = next(b for b in obs["blocks"] if b["name"] == "CODE_3")
    m = block["mappings"][0]
    at = m["offset_in_block"] + 0x212 - m["file_offset"]       # 1006:0172, file 0x212
    data = bytearray((folder / block["dump"]).read_bytes())
    data[at] ^= 0x01
    (folder / block["dump"]).write_bytes(data)
    env = loadimage.verify(exe, folder, corrections=out / "load-corrections.json")
    held = next(i for i in env["evidence"] if i["claim"] == "relocations.status_after_correction")
    if env["status"] != "mismatch" or held["value"]["ok"] \
            or held["value"]["observed"] != ["1006:0172: memory holds 0x1005, not 0x1004"]:
        raise AssertionError(f"{env['status']}: {held}")
    return f"{held['value']['observed'][0]}; failed {env['result']['failed'][:3]}"


@case("a page that does not fit the segment before it is restored at its own paragraph",
      ghidra=True)
def _():
    # bigpage.asm: header 64 bytes, 129 pages, bytes-on-last-page 0. Ghidra
    # maps (129 - 1) * 512 = 0x10000 bytes of file, image 0..0xFFBF in one
    # block at 1000:0000, so the last page is file 0x10000..0x101FF, linear
    # 0x10000 + 0x10000 - 0x40 = 0x1FFC0 -- offset 0xFFC0 in segment 0x1000,
    # whose 512 bytes would run past 0xFFFF. Its own paragraph is 1FFC:0000.
    code, log, exe, out = pipeline("BIGPAGE")
    env = record_of(out)
    made = env["result"]["corrections_made"]
    want = [{"kind": "missing-last-page", "file_start": 0x10000, "file_end_inclusive": 0x101FF,
             "linear_start": 0x1FFC0, "linear_end_inclusive": 0x201BF, "address": "1ffc:0000",
             "before": "not loaded",
             "after": "file 0x10000..0x101ff mapped at 1ffc:0000, joined to CODE_0",
             # minalloc's 256 bytes, from right after Ghidra's block to right
             # after the restored page; 2000:01c0 is how Ghidra spells 0x201C0.
             "uninitialized_moved": "DATA 1000:ffc0 size 256 -> DATA 2000:01c0 size 256",
             "fixups": []}]
    if code != 0 or env["status"] != "verified" or made != want:
        raise AssertionError(f"exit {code}, {env['status']}, {env['result']['failed']}, {made}")
    return f"1ffc:0000, joined to CODE_0; verified, {env['result']['checks']} checks agree"


@case("with -NoLoadCorrection the two stop exactly as they did in prompt 02",
      ghidra=True)
def _():
    # The lines prompt 02 printed, copied from its report.
    wants = {"DUPLICATED": [
                 "load image: mismatch, 4 of 28 checks failed",
                 "first failing check: relocations.words: expected each patched word "
                 "holds its value after every fixup to it, observed "
                 "['1006:0016: 0x1004 not 0x2004']",
                 "first differing byte: file 0xb7, 1006:0017 (linear 0x10077): "
                 "expected 0x20, observed 0x10"],
             "FULL_LAST_PAGE": [
                 "load image: mismatch, 2 of 28 checks failed",
                 "first failing check: module.coverage: expected file 0x40..0x3ff, "
                 "once, observed ['file 0x200..0x3ff not loaded']"]}
    for variant, lines in wants.items():
        code, log, exe, out = pipeline(variant, "-NoLoadCorrection")
        missing = [l for l in lines if l not in log]
        if code == 0 or missing or "stopping before anything is built on it" not in log:
            raise AssertionError(f"{variant}: exit {code}, missing {missing}\n{log[-1500:]}")
        if (out / "functions.json").exists() or (out / "load-corrections.json").exists():
            raise AssertionError(f"{variant}: exported, or corrected")
        if "Load correction skipped (-NoLoadCorrection)" not in log:
            raise AssertionError(f"{variant}: the skip is not announced")
    return "both mismatches, line for line"


@case("-AllowLoadMismatch goes on, says so, and records it in functions.json",
      ghidra=True)
def _():
    code, log, exe, out = pipeline("FULL_LAST_PAGE", "-NoLoadCorrection",
                                   "-AllowLoadMismatch")
    if code != 0 or "LOAD IMAGE NOT VERIFIED (mismatch)" not in log:
        raise AssertionError(f"exit {code}\n{log[-1500:]}")
    fj = functions_of(out)
    if fj.get("load_image") != {"status": "mismatch", "corrections": None,
                                "mismatch_allowed": True, "record": "loadimage.json"}:
        raise AssertionError(f"functions.json load_image {fj.get('load_image')}")
    if fj["observed_profile"]["load_correction"]["ran"] is not False:
        raise AssertionError("observed_profile says the corrector ran")
    rc, _, err = run(TOOLS / "anchors.py", out / "functions.json", "--exe", exe)
    if rc != 0 or "did not verify (mismatch)" not in err or "module.coverage" not in err:
        raise AssertionError(f"anchors.py: exit {rc}, {err!r}")
    return "continued, corrections null, mismatch_allowed, and anchors.py warns"


@case("a dump tampered after correction is still a mismatch", ghidra=True)
def _():
    code, log, exe, out = pipeline("FULL_LAST_PAGE")
    folder = WORK / "tamper-after-correction"
    shutil.copytree(out / "loadimage-observed", folder)
    obs = json.loads((folder / "observed.json").read_text(encoding="utf-8"))
    block = next(b for b in obs["blocks"] if b["name"] == "CODE_3")
    m = block["mappings"][0]
    at = 0x300 - m["file_offset"]                      # inside the restored page
    data = bytearray((folder / block["dump"]).read_bytes())
    before = data[m["offset_in_block"] + at]
    data[m["offset_in_block"] + at] ^= 0x33
    (folder / block["dump"]).write_bytes(data)
    env = loadimage.verify(exe, folder, corrections=out / "load-corrections.json")
    first = env["result"]["first_failure"]
    d = first.get("first_difference") or {}
    if env["status"] != "mismatch" or not first["name"].endswith(".digest") \
            or d.get("file_offset") != "0x300" \
            or d.get("expected") != f"0x{before:02x}" \
            or d.get("observed") != f"0x{before ^ 0x33:02x}":
        raise AssertionError(f"{env['status']}: {first}")
    if env["result"]["corrections"] != 1:
        raise AssertionError("the corrections record was not read")
    return (f"file 0x300 {d['expected']} -> {d['observed']} at {d['address']}, "
            f"despite the record of 1 correction")


@case("a profile expecting another load segment stops at the load-image check, "
      "and nothing is corrected under it", ghidra=True)
def _():
    # BOTH, so there is something the corrector would otherwise correct: under
    # segment 0x2000 it would write 0x4004 into a word DOS loads at 0x1000
    # as 0x2004, and map the page 0x10000 bytes away.
    code, log, exe, out = pipeline("BOTH", drift="load_segment=0x2000")
    want = "first failing check: load-segment: expected 0x2000, observed 0x1000"
    if code == 0 or want not in log or "[5/6]" in log:
        raise AssertionError(f"exit {code}\n{log[-1500:]}")
    record = corrections_of(out)
    refusal = "Ghidra loaded the image at segment 0x1000, the expected record at 0x2000"
    if record["count"] != 0 or record["corrections"] or \
            not any(n.startswith(refusal) for n in record["notes"]):
        raise AssertionError(f"count {record['count']}, notes {record['notes']}")
    return ("load-segment: expected 0x2000, observed 0x1000, before analysis ran; "
            "0 corrections: " + record["notes"][0])


@case("the pipeline stops on a malformed header as unsupported", ghidra=True)
def _():
    code, log, exe, out = pipeline("ENTRY_OUTSIDE")
    if code == 0 or "load image: unsupported" not in log or "entry point" not in log:
        raise AssertionError(f"exit {code}\n{log[-1500:]}")
    return "unsupported: " + next(l.strip() for l in log.splitlines()
                                  if "load image: unsupported" in l)[:90]


@case("tampering with a dump Ghidra wrote names the right check, and the byte",
      ghidra=True)
def _():
    code, log, exe, out = pipeline("plain")
    return "; ".join(run_tampers(exe, out / "loadimage-observed", "ghidra"))


@case("map round-trips every initialised byte of a verified Ghidra load", ghidra=True)
def _():
    code, log, exe, out = pipeline("APPENDED")
    env = record_of(out)
    n = round_trip(env["result"])
    code, text, _ = run(TOOLS / "loadimage.py", "map", out / "loadimage.json",
                        "--file", hex(env["result"]["entry"]["file_offset"]))
    if code != 0 or env["result"]["entry"]["address"] not in text:
        raise AssertionError(f"map --file on the entry: {text!r}")
    return f"{n} bytes, file -> address -> file"


def main():
    global WORK, GHIDRA
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    if not nasm or not Path(nasm).exists():
        print("loadimage regress: nasm not found (set NASM); the fixtures cannot "
              "be assembled")
        return 77
    GHIDRA, why = ghidra_ready()

    WORK = Path(tempfile.mkdtemp(prefix="loadimage-regress-"))
    failures = skipped = 0
    try:
        for v, defines in VARIANTS.items():
            out = WORK / f"{v}.exe"
            flags = [f"-d{d}" for d in defines]
            r = subprocess.run([nasm, "-f", "bin"] + flags + ["-o", str(out), str(FIXTURE)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(f"FAIL  nasm could not build {v}:\n{r.stderr}")
                return 1
            EXE[v] = out
        out = WORK / "BIGPAGE.exe"
        r = subprocess.run([nasm, "-f", "bin", "-o", str(out), str(BIGPAGE)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FAIL  nasm could not build bigpage:\n{r.stderr}")
            return 1
        EXE["BIGPAGE"] = out
        only = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else None
        for name, fn, needs_ghidra in CASES:
            if only and only not in name:
                continue
            if needs_ghidra and GHIDRA is None:
                print(f"  SKIP  {name:<74} skipped: {why}")
                skipped += 1
                continue
            try:
                print(f"  PASS  {name:<74} {fn()}")
            except Skip as e:
                print(f"  SKIP  {name:<74} {e}")
                skipped += 1
            except AssertionError as e:
                print(f"  FAIL  {name:<74} {e}")
                failures += 1
    finally:
        shutil.rmtree(WORK, ignore_errors=True)

    print()
    if only:
        print(f"--only {only!r}: {failures} failed")
        return 1 if failures else 0
    if failures:
        print(f"{failures} of {len(CASES)} load-image checks failed.")
        return 1
    if skipped:
        print(f"{len(CASES) - skipped} load-image checks pass; {skipped} skipped.")
        return 0
    print(f"All {len(CASES)} load-image checks pass, {sum(c[2] for c in CASES)} "
          f"of them through Ghidra.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
