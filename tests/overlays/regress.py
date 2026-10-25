#!/usr/bin/env python3
"""
regress.py -- Check that tools/overlays.py finds Microsoft LINK's overlays
where LINK's overlay manager finds them, builds each view from the root and
the module and nothing else, refuses a view that would not be what memory
holds, and that the pipeline verifies a view and records which one it is.

The fixture is tests/overlays/fixtures/overlaid.asm: a root with an overlay
area in its image and its own INT 3Fh overlay manager, and two overlay
modules after it in LINK's format, the second with two segments. Everything
expected below is read from the assembled file with struct, or from the
fixture's own labels, not from overlays.py.

Without Ghidra
--------------
* The modules are found by walking headers a page count at a time from the
  start of the file, with their file ranges, images and relocations; the
  overlay area is the lowest link segment their relocations name.
* Each view is the root's image with the module's bytes at the area, and the
  root's relocation table followed by the module's; the header keeps the
  root's entry and stack.
* A view is refused when the area holds anything, when the module does not
  fit, when a root relocation patches the area, or when a module relocation
  falls outside the module; and with no module relocations, until
  --load-segment is given. A packed root is refused with the way to unpack.
* The view's record names the overlay, and --check-view tells its view from
  any other file.
* triage and mzinfo report the modules instead of "bytes past the load
  image", and survey says so beside the executable.

With Ghidra (skipped, and saying so, without it)
------------------------------------------------
* pipeline.ps1 on each view: the load image verifies, the handshake verifies,
  and loadimage.json's overlay_view says which overlay it is, from the record
  found beside the view. A record of another file stops the run.

Usage:
    python tests/overlays/regress.py
    python tests/overlays/regress.py --only view
"""

import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
import overlays  # noqa: E402
import mzinfo  # noqa: E402
import survey  # noqa: E402
import triage  # noqa: E402

FIXTURE = HERE / "fixtures" / "overlaid.asm"
CASES = []
WORK = None
EXE = None
GHIDRA = None


class Skip(Exception):
    pass


def case(name, needs_ghidra=False):
    def wrap(fn):
        CASES.append((name, fn, needs_ghidra))
        return fn
    return wrap


def header(data, at):
    """The 13 header words at `at`, by struct, independently of overlays.py."""
    f = struct.unpack_from("<13H", data, at + 2)
    names = ("last", "pages", "nrel", "hdr", "minalloc", "maxalloc", "ss", "sp", "csum",
             "ip", "cs", "relo", "ovl")
    h = dict(zip(names, f))
    h["end"] = at + (h["pages"] - 1) * 512 + (h["last"] or 512)
    h["image"] = data[at + h["hdr"] * 16:h["end"]]
    h["relocs"] = [struct.unpack_from("<HH", data, at + h["relo"] + 4 * i)[::-1]
                   for i in range(h["nrel"])]
    return h


def labels():
    """The fixture's labels, from NASM's listing: name -> file offset. A label
    on a line of its own takes the address of the next line that has one."""
    import re
    out, pending = {}, []
    for line in (WORK / "overlaid.lst").read_text(encoding="latin-1").splitlines():
        addr = re.match(r"\s*\d+\s+([0-9A-F]{8})\s", line)
        label = re.search(r"^\s*\d+\s+(?:[0-9A-F]{8}\s+\S+\s+)?(\w+):", line)
        if label and not addr:
            pending.append(label.group(1))
            continue
        if addr:
            for name in pending + ([label.group(1)] if label else []):
                out[name] = int(addr.group(1), 16)
            pending = []
    return out


# ---------------------------------------------------------------- without Ghidra

@case("modules found a page count at a time from the start of the file")
def _():
    data = EXE.read_bytes()
    root = header(data, 0)
    found = overlays.find(data)
    want, at = [], root["pages"] * 512
    while at + 0x1C <= len(data) and data[at:at + 2] == b"MZ":
        h = header(data, at)
        want.append((h["ovl"], at, h["end"], len(h["image"]), len(h["relocs"])))
        at += h["pages"] * 512
    got = [(m["overlay"], m["file_offset"], m["end"], m["image_bytes"], m["relocations"])
           for m in found["modules"]]
    assert got == want and len(got) == 2, f"{got} against {want}"
    assert [m["overlay"] for m in found["modules"]] == [1, 2], got
    return ", ".join(f"#{o} at 0x{a:X} ({n} bytes, {r} relocations)" for o, a, _, n, r in got)


@case("the overlay area is the lowest link segment the modules' relocations name")
def _():
    data = EXE.read_bytes()
    found = overlays.find(data)
    area, naming = overlays.area_segment(found["modules"])
    lab = labels()
    want = (lab["area_start"] - lab["root_image"]) // 16
    assert area == want and naming == 2, (area, want, naming)
    second = sorted({s for m in found["modules"] for s in m["segments"]})
    assert len(second) == 2, second
    return f"segment {area:04X}, named by both modules; module 2 adds {second[1]:04X}"


@case("int 3Fh calls counted in the root, with the module and offset after each")
def _():
    data = EXE.read_bytes()
    root = header(data, 0)
    calls = overlays.int3f_calls(root["image"])
    assert [i for _, i, _ in calls] == [1, 2, 1], calls
    lab = labels()
    assert calls[1][2] == lab["ov2_hello"] - lab["ov2_image"], calls
    return f"{len(calls)} calls, to modules 1, 2, 1"


@case("a view is the root's image with the module in place, and both tables")
def _():
    data = EXE.read_bytes()
    root = header(data, 0)
    out = WORK / "views"
    results = overlays.write_views(str(EXE), str(out))
    assert [r[0] for r in results] == [1, 2] and all(r[1] for r in results), results
    area = overlays.area_segment(overlays.find(data)["modules"])[0]
    for n, view_path, _record in results:
        mod = header(data, 0x600 if n == 1 else 0x800)
        assert mod["ovl"] == n, mod["ovl"]
        want = bytearray(root["image"])
        want[area * 16:area * 16 + len(mod["image"])] = mod["image"]
        view = header(view_path.read_bytes(), 0)
        assert view["image"] == bytes(want), f"view {n}: image differs"
        assert view["relocs"] == root["relocs"] + mod["relocs"], f"view {n}: relocations"
        for f in ("ip", "cs", "ss", "sp", "minalloc", "maxalloc"):
            assert view[f] == root[f], f"view {n}: {f} {view[f]} against {root[f]}"
        assert view["ovl"] == 0 and view["end"] == len(view_path.read_bytes()), view["ovl"]
    return f"2 views, {len(root['image'])}-byte images, root's entry and stack kept"


@case("the view record names the overlay, and tells its view from another file")
def _():
    out = WORK / "views"
    record = out / "OVERLAID-overlay2.view.json"
    env = json.loads(record.read_text(encoding="utf-8"))
    r = env["result"]
    assert env["tool"] == "overlays" and r["overlay"] == 2, (env["tool"], r["overlay"])
    assert r["checks"]["area_empty"] and r["checks"]["fits"], r["checks"]
    assert r["module"]["relocations"] == 2 and r["source"]["sha256"] == \
        overlays.evidence.sha256_file(EXE), r["module"]
    ok, why = overlays.check_view(str(record), str(out / "OVERLAID-overlay2.exe"))
    assert ok and "overlay 2" in why, why
    ok, why = overlays.check_view(str(record), str(out / "OVERLAID-overlay1.exe"))
    assert not ok and "not the file it was written for" in why, why
    return "overlay 2, its checks, and a refusal for the other view"


def refused(fn):
    try:
        fn()
    except overlays.Refused as e:
        return str(e)
    raise AssertionError("not refused")


@case("refused: the area holds something in the root")
def _():
    data = bytearray(EXE.read_bytes())
    found = overlays.find(bytes(data))
    area = overlays.area_segment(found["modules"])[0]
    root = header(bytes(data), 0)
    data[root["hdr"] * 16 + area * 16 + 7] = 0x90
    why = refused(lambda: overlays.build_view(bytes(data), bytes(data), found["modules"][0], area))
    assert "not empty" in why and f"0x{area * 16 + 7:X}" in why, why
    return why[:70] + "..."


@case("refused: a module that does not fit, or relocations outside it")
def _():
    data = EXE.read_bytes()
    found = overlays.find(data)
    root = header(data, 0)
    last = (len(root["image"]) - 16) // 16
    why = refused(lambda: overlays.build_view(data, data, found["modules"][0], last))
    assert "does not fit" in why, why
    area = overlays.area_segment(found["modules"])[0]
    why2 = refused(lambda: overlays.build_view(data, data, found["modules"][1], area + 1))
    assert "outside its image" in why2, why2
    return "past the image; and one paragraph off, its relocations fall outside"


@case("refused: a root relocation inside the area")
def _():
    data = bytearray(EXE.read_bytes())
    found = overlays.find(bytes(data))
    area = overlays.area_segment(found["modules"])[0]
    root = header(bytes(data), 0)
    # Point the root's second relocation at the area's first word.
    struct.pack_into("<HH", data, root["relo"] + 4, 0, area)
    why = refused(lambda: overlays.build_view(bytes(data), bytes(data), found["modules"][0], area))
    assert "root's relocations patch words in the overlay area" in why, why
    return why[:70] + "..."


@case("no module relocations: the area is not guessed, --load-segment gives it")
def _():
    data = bytearray(EXE.read_bytes())
    for at in (0x600, 0x800):
        struct.pack_into("<H", data, at + 6, 0)        # no relocations
    path = WORK / "bare" / "OVERLAID.EXE"
    path.parent.mkdir()
    path.write_bytes(data)
    try:
        overlays.write_views(str(path), str(WORK / "bare" / "views"))
        raise AssertionError("views written without knowing the area")
    except SystemExit as e:
        assert "--load-segment" in str(e), e
    area = overlays.area_segment(overlays.find(EXE.read_bytes())["modules"])[0]
    results = overlays.write_views(str(path), str(WORK / "bare" / "views"), load_segment=area)
    env = json.loads(Path(results[0][2]).read_text(encoding="utf-8"))
    assert env["result"]["load_segment_source"] == "--load-segment", env["result"]
    return "refused, then written, the record saying the segment was given"


@case("a packed root is refused for views, with the way to unpack it")
def _():
    data = bytearray(EXE.read_bytes())
    root = header(bytes(data), 0)
    entry = root["hdr"] * 16 + (root["cs"] << 4) + root["ip"]
    data[entry - 2:entry] = b"RB"
    path = WORK / "packed" / "OVERLAID.EXE"
    path.parent.mkdir()
    path.write_bytes(data)
    try:
        overlays.write_views(str(path), str(WORK / "packed" / "views"))
        raise AssertionError("views of a packed root were written")
    except SystemExit as e:
        assert "unpack.py" in str(e) and "--root" in str(e), e
    d = overlays.describe(str(path), overlays.find(bytes(data)))
    assert d["root"]["packed"] and d["int3f_calls"] is None, d["root"]
    return "refused, naming unpack.py and --root; its int 3Fh calls not counted"


@case("triage and mzinfo report the modules, not bytes past the image")
def _():
    observations, decisions = [], []
    r = triage.analyse(str(EXE), observations, decisions)
    titles = [t for _, t, _ in r["findings"]]
    assert "2 Microsoft LINK overlays after the load image" in titles, titles
    assert not any("bytes past the load image" in t for t in titles), titles
    assert r["verdict"] == {"in_scope": True, "confidence": "low"}, r["verdict"]
    ov = next(o for o in observations if o["kind"] == "overlay-modules")
    assert ov["value"]["int3f_calls"] == 3 and len(ov["value"]["modules"]) == 2, ov["value"]
    env = triage.envelope(str(EXE))
    assert any("Borland's FBOV" in x for x in env["limitations"]), env["limitations"]
    _, m = mzinfo.parse(EXE)
    codes = [f["code"] for f in m["findings"]]
    assert "overlay-modules" in codes and "trailing-data" not in codes, codes
    assert [x["overlay"] for x in m["overlays"]["modules"]] == [1, 2], m["overlays"]
    return "in scope with low confidence; mzinfo's JSON gains overlays"


@case("survey says so beside the executable")
def _():
    folder = WORK / "survey"
    folder.mkdir()
    shutil.copy(EXE, folder / "OVERLAID.EXE")
    s = survey.survey(str(folder))
    e = s["executables"][0]
    assert e.get("linked_overlays") == 2, e
    text = survey.report(s)
    assert "2 Microsoft LINK overlays appended" in text, text
    return "2 overlays, in the report and the JSON"


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


def pipeline(exe, out):
    ghidra, java, pwsh = GHIDRA
    env = dict(os.environ, PYTHON=sys.executable)
    r = subprocess.run([pwsh, "-NoProfile", "-File", str(TOOLS / "pipeline.ps1"),
                        "-Exe", str(exe), "-OutDir", str(out), "-Ghidra", ghidra,
                        "-JavaHome", java], capture_output=True, text=True, env=env)
    return r.returncode, r.stdout + r.stderr


@case("pipeline.ps1 on each view: verified, and loadimage.json says which overlay",
      needs_ghidra=True)
def _():
    lines = []
    area = overlays.area_segment(overlays.find(EXE.read_bytes())["modules"])[0]
    for n in (1, 2):
        view = WORK / "views" / f"OVERLAID-overlay{n}.exe"
        out = WORK / f"pipeline{n}"
        code, log = pipeline(view, out)
        assert code == 0, f"view {n}: exit {code}\n{log[-1500:]}"
        load = json.loads((out / "loadimage.json").read_text(encoding="utf-8"))
        hand = json.loads((out / "handshake.json").read_text(encoding="utf-8"))
        assert load["status"] == "verified" and hand["status"] == "verified", \
            (load["status"], hand["status"])
        ov = load["result"]["overlay_view"]
        assert ov["overlay"] == n and ov["load_segment"] == f"{area:04X}", ov
        assert any(i["kind"] == "overlay-view" for i in load["evidence"]), load["evidence"]
        assert (out / "overlay-view.json").exists(), "the record was not copied"
        assert f"overlay {n} of" in log, log[-800:]
        lines.append(f"view {n}: {load['result']['checks']} checks")
    return "; ".join(lines) + "; both handshakes verified"


@case("a view record of another file stops the pipeline", needs_ghidra=True)
def _():
    folder = WORK / "mixed"
    folder.mkdir()
    shutil.copy(WORK / "views" / "OVERLAID-overlay1.exe", folder / "OVERLAID-overlay1.exe")
    shutil.copy(WORK / "views" / "OVERLAID-overlay2.view.json",
                folder / "OVERLAID-overlay1.view.json")
    code, log = pipeline(folder / "OVERLAID-overlay1.exe", folder / "out")
    assert code != 0 and "does not describe" in log and "not the file it was written for" in log, \
        f"exit {code}: {log[-800:]}"
    assert not (folder / "out" / "functions.json").exists(), "it went on to export"
    return "stopped before import, saying why"


def main():
    global WORK, EXE, GHIDRA
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    if not nasm or not Path(nasm).exists():
        print("overlays regress: nasm not found (set NASM); the fixture cannot be assembled")
        return 77
    GHIDRA, why = ghidra_ready()
    only = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else None
    WORK = Path(tempfile.mkdtemp(prefix="overlays-regress-"))
    failures = skipped = 0
    try:
        EXE = WORK / "OVERLAID.EXE"
        r = subprocess.run([nasm, "-f", "bin", "-l", str(WORK / "overlaid.lst"), "-o", str(EXE),
                            str(FIXTURE)], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FAIL  nasm could not build the fixture:\n{r.stderr}")
            return 1
        for name, fn, needs_ghidra in CASES:
            if only and only not in name:
                continue
            if needs_ghidra and GHIDRA is None:
                print(f"  SKIP  {name:<76} skipped: {why}")
                skipped += 1
                continue
            try:
                print(f"  PASS  {name:<76} {fn()}")
            except Skip as e:
                print(f"  SKIP  {name:<76} {e}")
                skipped += 1
            except AssertionError as e:
                print(f"  FAIL  {name:<76} {e}")
                failures += 1
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
    print()
    if failures:
        print(f"{failures} of {len(CASES)} overlay checks failed.")
        return 1
    if skipped:
        print(f"{len(CASES) - skipped} overlay checks pass; {skipped} skipped.")
        return 0
    print(f"All {len(CASES)} overlay checks pass, {sum(c[2] for c in CASES)} of them "
          f"through Ghidra.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
