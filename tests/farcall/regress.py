#!/usr/bin/env python3
"""
regress.py -- Check that libsig.py and emuverify.py find a function by its
whole entry, segment and offset, not by the offset alone.

The fixture is tests/farcall/fixtures/farcall.asm: a startup and a near routine
in the first segment, and `farfunc`, a far routine at offset 0 of a segment of
its own, reached by a relocated far call. Read by its offset alone, farfunc is
the startup. Every expected value is worked out from the fixture: its labels,
read from NASM's listing, and what its instructions do.

Without Ghidra
--------------
An export shaped like the pipeline's -- functions.json and the verified
loadimage.json beside it -- built from the labels:

* emuverify.py profiles farfunc as the far routine it is: entered with a far
  return address, it reads its argument past CS and IP, returns the argument
  plus 0x1111 in AX and 0x00FA in DX, and writes the sum to far_result.
* The near routine still runs exactly as before: an offset into the image.
* libsig.py reads farfunc's own bytes, so a signature of them matches at
  farfunc's entry and nowhere else.
* Without a verified loadimage.json, both fall back to segment * 16 + offset,
  and say so.

With Ghidra (skipped, and saying so, without it)
------------------------------------------------
* The same, on the export the pipeline writes for the fixture.

Usage:
    python tests/farcall/regress.py
"""

import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TOOLS = ROOT / "tools"
FIXTURE = HERE / "fixtures" / "farcall.asm"
sys.path.insert(0, str(TOOLS))
import emuverify  # noqa: E402
import evidence  # noqa: E402
import libsig  # noqa: E402

LOAD = 0x1000
HEADER = 0x40

CASES = []


def case(name, ghidra=False):
    def wrap(fn):
        CASES.append((name, fn, ghidra))
        return fn
    return wrap


WORK = None
EXE = None
LABELS = {}
GHIDRA = None


def labels_from_listing(path):
    """Image offset of every label, from NASM's listing."""
    pending, out = [], {}
    for line in Path(path).read_text(encoding="latin-1").splitlines():
        addr = re.match(r"\s*\d+\s+([0-9A-F]{8})\s", line)
        label = re.search(r"^\s*\d+\s+(?:[0-9A-F]{8}\s+\S+\s+)?([.\w]+):", line)
        if label and not addr:
            pending.append(label.group(1))
            continue
        if addr:
            for p in pending:
                out[p] = int(addr.group(1), 16) - HEADER
            pending = []
    return out


def L(name):
    return LABELS[name]


def far_segment():
    return L("far_start") // 16


def dgroup():
    return L("data_start") // 16


def entries():
    """name -> (segment as Ghidra writes it, offset, mnemonics)"""
    return {"start": (LOAD, L("start"), ["ADD", "CALL", "CALLF", "INT", "MOV", "PUSH"]),
            "nearfunc": (LOAD, L("nearfunc"), ["MOV", "POP", "PUSH", "RET"]),
            "farfunc": (LOAD + far_segment(), L("farfunc") - L("far_start"),
                        ["ADD", "MOV", "POP", "PUSH", "RETF"])}


def addr(seg, off):
    return f"{seg:04x}:{off:04x}"


def far_entry():
    seg, off, _ = entries()["farfunc"]
    return addr(seg, off)


def export(folder, with_loadimage=True):
    """functions.json, and the verified loadimage.json beside it, for the
    assembled fixture -- the shape the pipeline writes, from the labels."""
    folder.mkdir(parents=True, exist_ok=True)
    target = evidence.target_identity(EXE)
    records = [{"name": n, "entry": addr(s, o), "size": 1, "thunk": False,
                "mnemonics": m} for n, (s, o, m) in entries().items()]
    (folder / "functions.json").write_text(json.dumps({
        "program": EXE.name, "functions": records,
        "target": {"path": target["path"], "size": target["size"], "sha256": target["sha256"]},
        "observed_profile": {"load_segment": f"0x{LOAD:04x}"}}), encoding="utf-8")
    if with_loadimage:
        image = EXE.read_bytes()[HEADER:]
        bounds = [0, L("far_start"), L("data_start"), len(image)]
        mappings = [{"block": f"CODE_{i}", "segment": f"{LOAD + lo // 16:04x}",
                     "linear_start": LOAD * 16 + lo, "linear_end_inclusive": LOAD * 16 + hi - 1,
                     "length": hi - lo, "file_start": HEADER + lo,
                     "file_end_inclusive": HEADER + hi - 1}
                    for i, (lo, hi) in enumerate(zip(bounds, bounds[1:]))]
        (folder / "loadimage.json").write_text(json.dumps({
            "status": "verified",
            "result": {"load_segment": f"0x{LOAD:04x}", "file_size": len(EXE.read_bytes()),
                       "header": {"size": HEADER},
                       "module": {"file_start": HEADER, "file_end_inclusive": HEADER + len(image) - 1},
                       "mappings": mappings, "uninitialized": [], "relocations": []}}),
            encoding="utf-8")
    return folder / "functions.json"


def linker_map(folder):
    """A Microsoft LINK /MAP for the fixture, from the labels: the segment
    table, DGROUP's origin, and the publics by name and by value."""
    folder.mkdir(parents=True, exist_ok=True)
    segments = [(0, L("far_start") - 1, "_TEXT", "CODE"),
                (L("far_start"), L("far_end") - 1, "FAR_TEXT", "CODE"),
                (L("data_start"), len(EXE.read_bytes()) - HEADER - 1, "_DATA", "DATA")]
    publics = [(0, L("nearfunc"), "_nearfunc"), (far_segment(), 0, "_farfunc"),
               (dgroup(), L("near_result") - L("data_start"), "_near_result"),
               (dgroup(), L("far_result") - L("data_start"), "_far_result")]
    lines = ["", " Start  Stop   Length Name                   Class"]
    lines += [f" {lo:05X}H {hi:05X}H {hi - lo + 1:05X}H {name:<22} {cls}"
              for lo, hi, name, cls in segments]
    lines += ["", " Origin   Group", f" {dgroup():04X}:0   DGROUP", "",
              "  Address         Publics by Name", ""]
    lines += [f" {s:04X}:{o:04X}       {n}" for s, o, n in sorted(publics, key=lambda p: p[2])]
    lines += ["", "  Address         Publics by Value", ""]
    lines += [f" {s:04X}:{o:04X}       {n}" for s, o, n in sorted(publics)]
    lines += ["", "Program entry point at 0000:0000", ""]
    path = folder / "FARCALL.MAP"
    path.write_text("\r\n".join(lines), encoding="latin-1")
    return path


def far_profile_expected():
    """farfunc, from its source: AX = argument + 0x1111, DX = 0x00FA, the sum
    written to far_result, no calls, no globals read."""
    out = []
    for vector in emuverify.VECTORS:
        ax = (vector[0] + 0x1111) & 0xFFFF
        out.append({"partial": False, "ax": ax, "dx": 0x00FA, "calls": 0,
                    "writes": ((L("far_result") - L("data_start"), 2, ax),), "reads": ()})
    return out


def signature_db():
    """A signature of farfunc's own bytes, every byte fixed."""
    data = EXE.read_bytes()
    code = data[HEADER + L("farfunc"):HEADER + L("far_end")]
    return {"source": EXE.name, "count": 1, "signatures": [
        {"name": "farfunc", "module": None, "length": len(code), "bytes": code.hex(),
         "mask": "1" * len(code)}]}


def check_emulation(functions_json):
    emu = emuverify.Emulator(EXE, functions_json, dgroup=dgroup())
    near = emu.symbols.get(addr(LOAD, L("nearfunc")))
    if near != L("nearfunc"):
        raise AssertionError(f"the near routine is no longer an image offset: {near!r}")
    got = emu.profile(emu.symbols[far_entry()])
    want = far_profile_expected()
    if got != want:
        raise AssertionError(f"farfunc profiled as {got}, not {want}")
    return f"{far_entry()}: AX 0x{want[0]['ax']:04x}..0x{want[-1]['ax']:04x}, DX 0x00fa, far_result written"


def check_signature(functions_json):
    hits = libsig.apply(EXE, functions_json, signature_db())
    found = [(h["entry"], h["name"]) for h in hits]
    if found != [(far_entry(), "farfunc")]:
        raise AssertionError(f"libsig found {found}, not farfunc at {far_entry()}")
    return f"farfunc's {hits[0]['fixed_bytes']} bytes matched at {far_entry()}"


@case("emuverify runs the far function at its own segment, with a far return")
def _():
    return check_emulation(export(WORK / "export"))


@case("libsig reads the far function's own bytes")
def _():
    return check_signature(export(WORK / "export"))


@case("without a verified loadimage.json both place it by segment * 16 + offset, and say so")
def _():
    path = export(WORK / "no-loadimage", with_loadimage=False)
    r = subprocess.run([sys.executable, "-c",
                        "import sys; sys.path.insert(0, sys.argv[1]); import libsig, json; "
                        "print(len(libsig.apply(sys.argv[2], sys.argv[3], json.loads(sys.argv[4]))))",
                        str(TOOLS), str(EXE), str(path), json.dumps(signature_db())],
                       capture_output=True, text=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    if r.stdout.strip() != "1" or "segment * 16 + offset" not in r.stderr:
        raise AssertionError(f"libsig: {r.stdout!r} {r.stderr!r}")
    said = io.StringIO()
    with contextlib.redirect_stderr(said):
        result = check_emulation(path)
    if "segment * 16 + offset" not in said.getvalue():
        raise AssertionError(f"emuverify did not say how it placed the entry: {said.getvalue()!r}")
    return result + "; both said so on stderr"


@case("emuverify takes DGROUP from what the startup loads into DS, not the lowest relocated segment")
def _():
    # The relocated words are DGROUP twice and the far segment once, and the
    # far segment is lower: the old guess. The startup's `mov ds, ax` at
    # image offset 3 loads DGROUP.
    lowest = min(far_segment(), dgroup())
    said = io.StringIO()
    with contextlib.redirect_stderr(said):
        emu = emuverify.Emulator(EXE, export(WORK / "export"))
    if emu.dgroup != dgroup():
        raise AssertionError(f"DGROUP 0x{emu.dgroup:04x}, not 0x{dgroup():04x}; the lowest "
                             f"relocated segment is 0x{lowest:04x}")
    want = (f"DGROUP 0x{dgroup():04x}, the segment the startup loads into DS "
            f"(at {addr(LOAD, L('start') + 3)})")
    if want not in said.getvalue():
        raise AssertionError(f"stderr does not say {want!r}: {said.getvalue()!r}")
    got = emu.profile(emu.symbols[far_entry()])
    if got != far_profile_expected():
        raise AssertionError(f"farfunc profiled as {got} with that DGROUP")
    return (f"0x{dgroup():04x} from the startup at {addr(LOAD, L('start') + 3)}, where the "
            f"lowest relocated segment is 0x{lowest:04x}; farfunc's write lands in far_result")


@case("a linker map's far routine is read from its own code segment, and carried to functions.json")
def _():
    # The map puts _farfunc at 0003:0000, in FAR_TEXT, class CODE. Reading
    # segment 0000 alone dropped it.
    said = io.StringIO()
    with contextlib.redirect_stderr(said):
        mapped = emuverify.Emulator(EXE, linker_map(WORK / "map"))
        exported = emuverify.Emulator(EXE, export(WORK / "export"))
    far = mapped.symbols.get("_farfunc")
    if not isinstance(far, emuverify.Entry) or (far.segment, far.offset, far.far) != \
            (LOAD + far_segment(), 0, True):
        raise AssertionError(f"_farfunc read from the map as {far!r}, not "
                             f"Entry({LOAD + far_segment():04x}:0000, far)")
    if mapped.symbols.get("_nearfunc") != L("nearfunc") or mapped.dgroup != dgroup():
        raise AssertionError(f"_nearfunc {mapped.symbols.get('_nearfunc')!r}, DGROUP "
                             f"0x{mapped.dgroup:04x}")
    if f"DGROUP 0x{dgroup():04x}, the linker map's DGROUP" not in said.getvalue():
        raise AssertionError(f"stderr: {said.getvalue()!r}")
    got = mapped.profile(far)
    if got != far_profile_expected():
        raise AssertionError(f"_farfunc profiled as {got}")
    res = emuverify.compare(mapped, exported, mapped.symbols, exported.symbols)
    if ("_farfunc", far_entry()) not in res["matches"]:
        raise AssertionError(f"_farfunc not carried to {far_entry()}: {res['matches']}")
    return (f"_farfunc at {LOAD + far_segment():04x}:0000, far, DGROUP 0x{dgroup():04x} from "
            f"the map; matched to {far_entry()} in functions.json")


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


@case("the same, on the export the pipeline writes", ghidra=True)
def _():
    global EXE
    ghidra, java, pwsh = GHIDRA
    folder = WORK / "pipeline"
    folder.mkdir()
    exe = folder / "FARCALL.EXE"
    shutil.copy(EXE, exe)
    env = dict(os.environ, PYTHON=sys.executable)
    env.pop("DOS_DECOMPILER_FORCE_DRIFT", None)
    r = subprocess.run([pwsh, "-NoProfile", "-File", str(TOOLS / "pipeline.ps1"), "-Exe", str(exe),
                        "-OutDir", str(folder / "out"), "-Ghidra", ghidra, "-JavaHome", java],
                       capture_output=True, text=True, env=env)
    if r.returncode != 0:
        raise AssertionError(f"pipeline exit {r.returncode}\n{(r.stdout + r.stderr)[-1500:]}")
    data = json.loads((folder / "out" / "functions.json").read_text(encoding="utf-8"))
    far = [f for f in data["functions"] if f["entry"] == far_entry()]
    if not far or "RETF" not in far[0]["mnemonics"]:
        raise AssertionError(f"no far function at {far_entry()}: "
                             f"{[f['entry'] for f in data['functions']]}")
    keep, EXE = EXE, exe
    try:
        return check_emulation(folder / "out" / "functions.json") + "; " + \
            check_signature(folder / "out" / "functions.json")
    finally:
        EXE = keep


def main():
    global WORK, EXE, LABELS, GHIDRA
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    if not nasm:
        print("farcall regress: nasm not found (set NASM); the fixture cannot be assembled")
        return 77
    GHIDRA, why = ghidra_ready()
    WORK = Path(tempfile.mkdtemp(prefix="farcall-regress-"))
    failures = skipped = 0
    try:
        EXE = WORK / "FARCALL.EXE"
        listing = WORK / "farcall.lst"
        r = subprocess.run([nasm, "-f", "bin", "-o", str(EXE), "-l", str(listing),
                            str(FIXTURE)], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FAIL  nasm could not build the fixture:\n{r.stderr}")
            return 1
        LABELS = labels_from_listing(listing)
        for name, fn, needs_ghidra in CASES:
            if needs_ghidra and GHIDRA is None:
                print(f"  SKIP  {name:<74} skipped: {why}")
                skipped += 1
                continue
            try:
                print(f"  PASS  {name:<74} {fn()}")
            except AssertionError as e:
                print(f"  FAIL  {name:<74} {e}")
                failures += 1
    finally:
        shutil.rmtree(WORK, ignore_errors=True)

    print()
    if failures:
        print(f"{failures} of {len(CASES)} far-call checks failed.")
        return 1
    if skipped:
        print(f"{len(CASES) - skipped} far-call checks pass; {skipped} skipped.")
        return 0
    print(f"All {len(CASES)} far-call checks pass, {sum(c[2] for c in CASES)} "
          f"of them through Ghidra.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
