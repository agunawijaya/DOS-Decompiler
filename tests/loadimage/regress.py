#!/usr/bin/env python3
"""
regress.py -- Check that tools/loadimage.py tells a correct load from a wrong
one, and that the pipeline stops on a wrong one.

The fixture is tests/loadimage/fixtures/segments.asm, assembled at test time in
seven variants: the good file, the same with bytes appended past the declared
image, a duplicated relocation entry, a header whose last page is full, and
three malformed headers. See the fixture for what each one exercises.

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

With Ghidra (skipped, and saying so, without it)
------------------------------------------------
* The pipeline on the two good variants must verify.
* On the duplicated relocation and the full last page it must stop, naming
  the first failing check; with -AllowLoadMismatch it must continue, say so,
  and record it in functions.json. On a malformed header it must stop with
  unsupported.
* The tamper cases again, on a dump Ghidra itself wrote.
* `map` round-trips every initialised byte of the real verified record.

Usage:
    python tests/loadimage/regress.py
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
sys.path.insert(0, str(TOOLS))
import evidence                                          # noqa: E402
import loadimage                                         # noqa: E402

VARIANTS = ("plain", "APPENDED", "DUPLICATED", "FULL_LAST_PAGE",
            "RELOC_TABLE_OUTSIDE", "RELOC_TARGET_PAST", "ENTRY_OUTSIDE")
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


@case("the pipeline verifies both good fixtures", ghidra=True)
def _():
    found = []
    for variant in ("plain", "APPENDED"):
        code, log, exe, out = pipeline(variant)
        if code != 0:
            raise AssertionError(f"{variant}: exit {code}\n{log[-1500:]}")
        env = record_of(out)
        fj = json.loads((out / "functions.json").read_text(encoding="utf-8"))
        if env["status"] != "verified" or "load image: verified" not in log:
            raise AssertionError(f"{variant}: {env['status']}, {env['result'].get('first_failure')}")
        if fj.get("load_image") != {"status": "verified", "mismatch_allowed": False,
                                    "record": "loadimage.json"}:
            raise AssertionError(f"{variant}: functions.json load_image {fj.get('load_image')}")
        found.append(f"{variant} {env['result']['checks']} checks")
    return ", ".join(found)


@case("the pipeline stops on a load that differs, naming the first failing check",
      ghidra=True)
def _():
    wants = {"DUPLICATED": ("relocations.words", "1006:0016: 0x1004 not 0x2004"),
             "FULL_LAST_PAGE": ("module.coverage", "file 0x200..0x3ff not loaded")}
    found = []
    for variant, (check, words) in wants.items():
        code, log, exe, out = pipeline(variant)
        if code == 0 or f"first failing check: {check}" not in log or words not in log:
            raise AssertionError(f"{variant}: exit {code}\n{log[-1500:]}")
        if "stopping before anything is built on it" not in log:
            raise AssertionError(f"{variant}: no stop message")
        if (out / "functions.json").exists():
            raise AssertionError(f"{variant}: the pipeline went on to export")
        found.append(f"{variant}: {check} ({words})")
    return "; ".join(found)


@case("-AllowLoadMismatch goes on, says so, and records it in functions.json",
      ghidra=True)
def _():
    code, log, exe, out = pipeline("FULL_LAST_PAGE", "-AllowLoadMismatch")
    if code != 0 or "LOAD IMAGE NOT VERIFIED (mismatch)" not in log:
        raise AssertionError(f"exit {code}\n{log[-1500:]}")
    fj = json.loads((out / "functions.json").read_text(encoding="utf-8"))
    if fj.get("load_image") != {"status": "mismatch", "mismatch_allowed": True,
                                "record": "loadimage.json"}:
        raise AssertionError(f"functions.json load_image {fj.get('load_image')}")
    rc, _, err = run(TOOLS / "anchors.py", out / "functions.json", "--exe", exe)
    if rc != 0 or "did not verify (mismatch)" not in err or "module.coverage" not in err:
        raise AssertionError(f"anchors.py: exit {rc}, {err!r}")
    return "continued, functions.json says mismatch_allowed, and anchors.py warns"


@case("a profile expecting another load segment stops at the load-image check",
      ghidra=True)
def _():
    code, log, exe, out = pipeline("plain", drift="load_segment=0x2000")
    want = "first failing check: load-segment: expected 0x2000, observed 0x1000"
    if code == 0 or want not in log or "[4/5]" in log:
        raise AssertionError(f"exit {code}\n{log[-1500:]}")
    return "load-segment: expected 0x2000, observed 0x1000, before recovery ran"


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
        for v in VARIANTS:
            out = WORK / f"{v}.exe"
            flags = [] if v == "plain" else [f"-d{v}"]
            r = subprocess.run([nasm, "-f", "bin"] + flags + ["-o", str(out), str(FIXTURE)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(f"FAIL  nasm could not build {v}:\n{r.stderr}")
                return 1
            EXE[v] = out
        for name, fn, needs_ghidra in CASES:
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
