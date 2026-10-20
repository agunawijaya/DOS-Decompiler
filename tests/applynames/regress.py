#!/usr/bin/env python3
"""
regress.py -- Check that names are validated before anything is written, read
back after, and rolled back whole when anything goes wrong.

Everything here goes through Ghidra, so without it the suite skips, saying so.
The program is tests/bodies/fixtures/bodies.asm, run through pipeline.ps1 once;
each case works on a copy of that output, writes with tools/applynames.py (which
runs ApplyNames.java), and is checked by *re-exporting*: what the database
holds afterwards, not what the script says it did. Addresses come from the
fixture's labels, read from NASM's listing.

* A valid mapping is applied, every name and comment read back, and the
  re-export shows each name; one below the floor is skipped, one below the
  certain level gets `__maybe`.
* One clash among valid entries, a name another function already has, an
  address inside a body, or an illegal name: nothing at all is written.
* A comment is set by a string, cleared by "", and left alone when omitted.
* A fault injected into the readback, or into a setter, rolls the whole
  batch back.
* A dry run reports what would be applied and writes nothing.
* anchors.py's --names output and match.py's --json shape are both read.

Usage:
    python tests/applynames/regress.py
    python tests/applynames/regress.py --only "roll"
"""

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
FIXTURE = ROOT / "tests" / "bodies" / "fixtures" / "bodies.asm"
FAULT = "DOS_DECOMPILER_APPLYNAMES_FAULT"
LOAD = 0x1000

CASES = []


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


WORK = None
LABELS = {}
GHIDRA = None


def labels_from_listing(path):
    pending, out = [], {}
    for line in Path(path).read_text(encoding="latin-1").splitlines():
        addr = re.match(r"\s*\d+\s+([0-9A-F]{8})\s", line)
        label = re.search(r"^\s*\d+\s+(?:[0-9A-F]{8}\s+\S+\s+)?([.\w]+):", line)
        if label and not addr:
            pending.append(label.group(1))
            continue
        if addr:
            for p in pending:
                out[p] = int(addr.group(1), 16) - 0x40
            pending = []
    return out


def at(label, delta=0):
    return f"{LOAD:04x}:{LABELS[label] + delta:04x}"


def default(label):
    return f"FUN_{LOAD:04x}_{LABELS[label]:04x}"


def copy_of_base(name):
    """A fresh copy of the pipeline's output, project included."""
    dest = WORK / name
    shutil.copytree(WORK / "base" / "out", dest / "out")
    return dest / "out"


def apply(out, mapping, *flags, fault=None):
    """applynames.py on one output folder: (exit code, prose, envelope)."""
    path = out.parent / f"mapping-{len(list(out.parent.glob('mapping-*')))}.json"
    path.write_text(mapping if isinstance(mapping, str) else json.dumps(mapping),
                    encoding="utf-8")
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    env.pop(FAULT, None)
    if fault:
        env[FAULT] = fault
    r = subprocess.run([sys.executable, str(TOOLS / "applynames.py"), str(path), str(out)]
                       + list(flags), capture_output=True, text=True, env=env)
    result = json.loads((out / "applynames-result.json").read_text(encoding="utf-8"))
    return r.returncode, r.stdout + r.stderr, result


def reexport(out):
    """What the database holds now: names by entry, and decompiled.c."""
    ghidra, java = GHIDRA
    dest = out.parent / f"reexport-{len(list(out.parent.glob('reexport-*')))}"
    script = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    r = subprocess.run([str(Path(ghidra) / "support" / script), str(out / "ghidra-project"),
                        "target", "-process", "BODIES.EXE", "-noanalysis", "-readOnly",
                        "-scriptPath", str(TOOLS / "ghidra_scripts"),
                        "-postScript", "ExportDecompiledC.java", str(dest)],
                       capture_output=True, text=True, env=dict(os.environ, JAVA_HOME=java))
    fj = dest / "functions.json"
    if not fj.exists():
        raise AssertionError(f"re-export failed:\n{(r.stdout + r.stderr)[-1500:]}")
    data = json.loads(fj.read_text(encoding="utf-8"))
    return ({f["entry"]: f["name"] for f in data["functions"]},
            (dest / "decompiled.c").read_text(encoding="utf-8"))


def outcomes(result):
    return [(e["address"], e["outcome"]) for e in result["result"]["entries"]]


BASE_NAMES = {}


def untouched(names):
    """Every function still has the name the pipeline's export gave it."""
    renamed = {e: n for e, n in names.items() if BASE_NAMES.get(e) != n}
    if renamed or set(names) != set(BASE_NAMES):
        raise AssertionError(f"names written although nothing should have been: {renamed}")


VALID = lambda: {"mapping": [  # noqa: E731 -- built after the labels are read
    {"source": "left_func", "binary": at("left"), "score": 0.9,
     "comment": "first plate", "inline_comment": "first eol"},
    {"source": "right_func", "binary": at("right"), "score": 0.6},
    {"source": "middle_func", "binary": at("middle"), "score": 0.3}]}


@case("a valid mapping is applied; every name and comment reads back; a re-export shows them")
def _():
    out = copy_of_base("valid")
    code, log, res = apply(out, VALID())
    if code != 0 or res["status"] != "ok" or res["result"]["phase"] != "applied":
        raise AssertionError(f"exit {code}, {res['status']}\n{log}")
    want = [(at("left"), "applied"), (at("right"), "applied"),
            (at("middle"), "skipped-below-floor")]
    if outcomes(res) != want:
        raise AssertionError(f"outcomes {outcomes(res)}")
    left, right = res["result"]["entries"][:2]
    if (left["stored_name"], right["stored_name"]) != ("left_func", "right_func__maybe") \
            or left["stored_comment"] != "first plate" \
            or left["stored_inline_comment"] != "first eol" \
            or left["stored_note"] != "identified as left_func (confidence 0.900)" \
            or not right["stored_note"].endswith("LOW CONFIDENCE -- verify before relying on this name."):
        raise AssertionError(f"readback {left}\n{right}")
    names, c = reexport(out)
    if (names[at("left")], names[at("right")], names[at("middle")]) != \
            ("left_func", "right_func__maybe", default("middle")):
        raise AssertionError(f"re-export {names}")
    for text in ("/* first plate */", "identified as left_func (confidence 0.900)"):
        if text not in c:
            raise AssertionError(f"decompiled.c lacks {text!r}")
    return "left_func, right_func__maybe applied and re-exported; middle_func below the floor"


@case("one clash among valid entries writes nothing")
def _():
    out = copy_of_base("clash")
    code, log, res = apply(out, {"mapping": [
        {"source": "alpha", "binary": at("left"), "score": 0.9},
        {"source": "alpha", "binary": at("right"), "score": 0.9},
        {"source": "beta", "binary": at("chunky"), "score": 0.9}]})
    entries = res["result"]["entries"]
    if code != 3 or res["status"] != "blocked" or res["result"]["phase"] != "refused" \
            or [e["outcome"] for e in entries] != ["refused"] * 3:
        raise AssertionError(f"exit {code}, {res['status']}, {outcomes(res)}")
    if "gives the name alpha to 2 functions" not in entries[0]["reason"] \
            or "another entry failed validation" not in entries[2]["reason"]:
        raise AssertionError(f"reasons {[e['reason'] for e in entries]}")
    untouched(reexport(out)[0])
    return f"{entries[0]['reason']}; beta not written either; re-export unchanged"


@case("a name another function already has is refused")
def _():
    out = copy_of_base("taken")
    apply(out, {"mapping": [{"source": "taken_name", "binary": at("left"), "score": 0.9}]})
    code, log, res = apply(out, {"mapping": [
        {"source": "taken_name", "binary": at("right"), "score": 0.9},
        {"source": "fresh_name", "binary": at("chunky"), "score": 0.9}]})
    reason = res["result"]["entries"][0]["reason"]
    if code != 3 or f"already belongs to the function at {at('left')}" not in reason:
        raise AssertionError(f"exit {code}: {reason}")
    names = reexport(out)[0]
    if names[at("right")] != default("right") or names[at("chunky")] != default("chunky"):
        raise AssertionError(f"re-export {names}")
    return reason


@case("an address inside a body is refused, with that reason")
def _():
    out = copy_of_base("inside")
    code, log, res = apply(out, {"mapping": [
        {"source": "good_name", "binary": at("left"), "score": 0.9},
        {"source": "inner", "binary": at("left", 3), "score": 0.9}]})
    reason = res["result"]["entries"][1]["reason"]
    want = f"inside the body of {default('left')} (entry {at('left')}), not a function entry"
    if code != 3 or reason != want:
        raise AssertionError(f"exit {code}: {reason!r}")
    untouched(reexport(out)[0])
    return reason


@case("illegal names are refused, each with its reason")
def _():
    out = copy_of_base("illegal")
    bad = ["has space", "int", f"FUN_{LOAD:04x}_9999", "a:b", "9lives"]
    code, log, res = apply(out, {"mapping": [
        {"source": n, "binary": at(lab), "score": 0.9}
        for n, lab in zip(bad, ("left", "right", "chunky", "middle", "switcher"))]})
    reasons = [e["reason"] for e in res["result"]["entries"]]
    expected = ["not a C identifier", "a C keyword", "the form of a name Ghidra makes up",
                "not a C identifier", "not a C identifier"]
    if code != 3 or any(not r.startswith(x) for r, x in zip(reasons, expected)):
        raise AssertionError(f"exit {code}: {reasons}")
    untouched(reexport(out)[0])
    return "; ".join(r.split(":")[0] for r in reasons)


@case("Turbo C's register pseudovariables and segment modifiers are refused")
def _():
    # Upper case for the registers, lower case for the segment modifiers:
    # the cases Turbo C itself reserves. Ghidra accepts every one of them.
    out = copy_of_base("turboc")
    reserved = ["_AX", "_FLAGS", "_CS", "_ds", "_AL"]
    code, log, res = apply(out, {"mapping": [
        {"source": n, "binary": at(lab), "score": 0.9}
        for n, lab in zip(reserved, ("left", "right", "chunky", "middle", "switcher"))]})
    reasons = [e["reason"] for e in res["result"]["entries"]]
    if code != 3 or any(not r.startswith("reserved by Turbo C") for r in reasons):
        raise AssertionError(f"exit {code}: {reasons}")
    untouched(reexport(out)[0])
    return f"{', '.join(reserved)}: each 'reserved by Turbo C', nothing written"


@case("a comment is set by a string, cleared by \"\", and left alone when omitted")
def _():
    out = copy_of_base("comments")
    steps = [
        ({"comment": "first plate", "inline_comment": "first eol"}, "first plate", "first eol"),
        ({}, "first plate", "first eol"),                     # omitted: untouched
        ({"comment": "", "inline_comment": ""}, None, None)]  # "": cleared
    seen = []
    for fields, plate, eol in steps:
        entry = {"source": "commented", "binary": at("left"), "score": 0.9}
        entry.update(fields)
        code, log, res = apply(out, {"mapping": [entry]})
        e = res["result"]["entries"][0]
        if code != 0 or e["stored_comment"] != plate or e["stored_inline_comment"] != eol:
            raise AssertionError(f"{fields}: exit {code}, plate {e['stored_comment']!r}, "
                                 f"eol {e['stored_inline_comment']!r}")
        c = reexport(out)[1]
        if ("/* first plate */" in c) != (plate is not None):
            raise AssertionError(f"{fields}: the plate in decompiled.c")
        seen.append(repr(e["stored_comment"]))
    return "plate " + " -> ".join(seen) + ", read back and re-exported"


@case("a fault in the readback rolls the whole batch back, and a read-only pass confirms it")
def _():
    found = []
    for fault in ("readback", "throw"):
        out = copy_of_base(f"fault-{fault}")
        code, log, res = apply(out, VALID(), fault=fault)
        entries = res["result"]["entries"]
        rollback = res["result"].get("rollback") or {}
        if code != 1 or res["status"] != "blocked" or res["result"]["phase"] != "rolled-back" \
                or [e["outcome"] for e in entries[:2]] != ["rolled-back", "rolled-back"]:
            raise AssertionError(f"{fault}: exit {code}, {res['status']}, "
                                 f"{res['result']['phase']}, {outcomes(res)}; the read-only "
                                 f"pass: {rollback.get('differences')}")
        if not rollback.get("confirmed") or rollback.get("checked") != 2:
            raise AssertionError(f"{fault}: rollback not confirmed: {rollback}")
        names, c = reexport(out)
        untouched(names)
        if "first plate" in c or "identified as" in c:
            raise AssertionError(f"{fault}: a comment survived the rollback")
        found.append(f"{fault}: {entries[1]['reason'][:50]}, confirmed in "
                     f"{rollback['seconds']} s")
    return "; ".join(found) + "; re-export shows the original names"


@case("a dry run reports what would be applied and writes nothing")
def _():
    out = copy_of_base("dryrun")
    code, log, res = apply(out, VALID(), "--dryrun")
    if code != 0 or res["result"]["phase"] != "dry-run" \
            or [o for _, o in outcomes(res)] != ["would-apply", "would-apply",
                                                  "skipped-below-floor"]:
        raise AssertionError(f"exit {code}, {outcomes(res)}")
    names, c = reexport(out)
    untouched(names)
    if "first plate" in c:
        raise AssertionError("the dry run wrote a comment")
    return "2 would-apply, 1 below the floor; re-export unchanged"


@case("anchors.py --names and match.py --json are both read, with the __maybe rule")
def _():
    out = copy_of_base("shapes")
    names_json = out.parent / "anchors-names.json"
    r = subprocess.run([sys.executable, str(TOOLS / "anchors.py"), str(out / "functions.json"),
                        "--entry", at("start"), "--names", str(names_json)],
                       capture_output=True, text=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    anchors = json.loads(names_json.read_text(encoding="utf-8"))
    if r.returncode != 0 or not anchors["mapping"]:
        raise AssertionError(f"anchors.py: exit {r.returncode}, {r.stdout}{r.stderr}")
    code, log, res = apply(out, anchors)
    if code != 0:
        raise AssertionError(f"anchors shape: exit {code}\n{log}")
    for e in res["result"]["entries"]:
        if e["outcome"] == "applied":
            want = e["requested_name"] + ("__maybe" if e["score"] < 0.70 else "")
            if e["stored_name"] != want:
                raise AssertionError(f"anchors shape: {e}")
    # match.py's record, as its result() writes it, field for field.
    match = {"rounds": [], "source_functions": 2, "binary_functions": 16, "mapped": 2,
             "unmapped_source": [], "unmapped_binary": [], "mapping": [
                 {"source": "swmove", "file": "swmove.c", "kind": "function",
                  "binary": at("chunky"), "binary_name": default("chunky"), "score": 0.83,
                  "source_lines": 20, "binary_instructions": 9},
                 {"source": "swdraw", "file": "swdraw.c", "kind": "function",
                  "binary": at("switcher"), "binary_name": default("switcher"), "score": 0.5,
                  "source_lines": 12, "binary_instructions": 15}]}
    code, log, res = apply(out, match)
    names = reexport(out)[0]
    if code != 0 or names[at("chunky")] != "swmove" or names[at("switcher")] != "swdraw__maybe":
        raise AssertionError(f"match shape: exit {code}, {names}")
    applied = [e["stored_name"] for e in res["result"]["entries"] if e["outcome"] == "applied"]
    return (f"anchors: {len(anchors['mapping'])} entries; match: {', '.join(applied)}")


@case("a mapping that is not one is blocked, and nothing is written")
def _():
    out = copy_of_base("malformed")
    code, log, res = apply(out, "this is not JSON")
    if code != 3 or res["status"] != "blocked" or not res["result"]["problems"]:
        raise AssertionError(f"exit {code}, {res['status']}, {res['result'].get('problems')}")
    untouched(reexport(out)[0])
    return res["result"]["problems"][0][:80]


def ghidra_ready():
    ghidra = os.environ.get("GHIDRA_HOME")
    java = os.environ.get("JAVA_HOME")
    if not ghidra or not any((Path(ghidra) / "support" / n).exists()
                             for n in ("analyzeHeadless.bat", "analyzeHeadless")):
        return None, "Ghidra not found (set GHIDRA_HOME)"
    if not java or not Path(java).exists():
        return None, "JDK not found (set JAVA_HOME)"
    if not shutil.which("pwsh"):
        return None, "pwsh not found; pipeline.ps1 needs PowerShell 7"
    return (ghidra, java), None


def main():
    global WORK, LABELS, GHIDRA
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    if not nasm:
        print("applynames regress: nasm not found (set NASM); the fixture cannot be assembled")
        return 77
    GHIDRA, why = ghidra_ready()
    if GHIDRA is None:
        for name, _ in CASES:
            print(f"  SKIP  {name:<74} skipped: {why}")
        print(f"\nevery applynames check needs Ghidra: {why}")
        return 77
    WORK = Path(tempfile.mkdtemp(prefix="applynames-regress-"))
    failures = 0
    try:
        base = WORK / "base"
        base.mkdir()
        exe = base / "BODIES.EXE"
        r = subprocess.run([nasm, "-f", "bin", "-o", str(exe), "-l", str(base / "bodies.lst"),
                            str(FIXTURE)], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FAIL  nasm could not build the fixture:\n{r.stderr}")
            return 1
        LABELS = labels_from_listing(base / "bodies.lst")
        ghidra, java = GHIDRA
        env = dict(os.environ, PYTHON=sys.executable)
        env.pop("DOS_DECOMPILER_FORCE_DRIFT", None)
        r = subprocess.run([shutil.which("pwsh"), "-NoProfile", "-File", str(TOOLS / "pipeline.ps1"),
                            "-Exe", str(exe), "-OutDir", str(base / "out"), "-Ghidra", ghidra,
                            "-JavaHome", java], capture_output=True, text=True, env=env)
        if r.returncode != 0:
            print(f"FAIL  the pipeline did not run on the fixture:\n{(r.stdout + r.stderr)[-1500:]}")
            return 1
        BASE_NAMES.update({f["entry"]: f["name"] for f in json.loads(
            (base / "out" / "functions.json").read_text(encoding="utf-8"))["functions"]})
        only =sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else None
        for name, fn in CASES:
            if only and only not in name:
                continue
            try:
                print(f"  PASS  {name:<74} {fn()}", flush=True)
            except AssertionError as e:
                print(f"  FAIL  {name:<74} {e}", flush=True)
                failures += 1
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
    print()
    if only:
        print(f"--only {only!r}: {failures} failed")
        return 1 if failures else 0
    if failures:
        print(f"{failures} of {len(CASES)} applynames checks failed.")
        return 1
    print(f"All {len(CASES)} applynames checks pass, through Ghidra.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
