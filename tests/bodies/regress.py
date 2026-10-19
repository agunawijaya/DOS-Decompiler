#!/usr/bin/env python3
"""
regress.py -- Check function bodies, origins and claims in functions.json, and
what tools/bodies.py says about the bytes no function claims.

The fixture is tests/bodies/fixtures/bodies.asm: a shared epilogue, a jump into
the middle of a neighbour, a chunk past another function, a jump table in the
middle of a function, routines reached only through a pointer table, a
fall-through RecoverFunctions splits, a prologue after a string, and code
nothing reaches. Every expected value is worked out from the fixture's own
labels, read from NASM's listing -- never from what the tools wrote.

Where Ghidra decides the shape, the expectation is what Ghidra 12.1.2 was
measured to do, said once in BODIES below: two functions jumping to one
epilogue make it a third function, so the bytes are claimed by the jumps
rather than by two bodies (Ghidra refuses overlapping bodies); a chunk past
another function stays in its body when a conditional jump reaches it; the
jump table is data, which splits its function's body in two.

Without Ghidra
--------------
* residue.py's rules, through bodies.py, on byte runs taken from the
  assembled fixture: the table is a pointer table, the banner text, the
  never-reached routine code, the 90 90 and 00 fill padding -- and code that
  does not end in a return or jump, or runs into zeroes, is not code.
* bodies.py on a synthetic export built from the labels: the claimed share,
  the unclaimed runs and their kinds, the non-contiguous bodies, a body
  without its entry, and its refusal of an export from before bodies.

With Ghidra (skipped, and saying so, without it)
------------------------------------------------
* The pipeline on the fixture: every record has `body` and `origin`, every
  body is the one the labels give, `size` equals `total_bytes` and differs
  from the span where the body is split, every origin is the one the shape
  gives, and the origins agree with RecoverFunctions' own counts.
* `body_overlaps` lists the shared epilogue, the jump into the neighbour and
  the fall-through the split left, with the instruction each claim leaves by.
* bodies.py on that export finds the never-reached code and classifies the
  jump table.

Usage:
    python tests/bodies/regress.py
    python tests/bodies/regress.py --only "overlap"     # cases matching
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
FIXTURE = HERE / "fixtures" / "bodies.asm"
sys.path.insert(0, str(TOOLS))
import bodies  # noqa: E402
import evidence  # noqa: E402

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
EXE = None
LABELS = {}
GHIDRA = None
PIPELINE = {}


def labels_from_listing(path):
    """Image offset of every label, from NASM's listing: a label on a line of
    its own takes the address of the next line that has one."""
    pending, out = [], {}
    for line in Path(path).read_text(encoding="latin-1").splitlines():
        addr = re.match(r"\s*\d+\s+([0-9A-F]{8})\s", line)
        label = re.search(r"^\s*\d+\s+(?:[0-9A-F]{8}\s+\S+\s+)?([.\w]+):", line)
        if label and not addr:
            pending.append(label.group(1))
            continue
        if addr:
            for p in pending:
                out[p] = int(addr.group(1), 16) - 0x40       # past the 64-byte header
            pending = []
    return out


def L(name):
    return LABELS[name]


def a(offset):
    return f"{LOAD:04x}:{offset:04x}"


# Each function's body, from the labels: the label it starts at, and the
# inclusive byte ranges it covers. The shapes, as Ghidra 12.1.2 makes them:
def expected_bodies():
    return {
        "start": [(L("start"), L("main") - 1)],
        "main": [(L("main"), L("left") - 1)],
        # Both end at their own `jmp short`; the epilogue is a function of its own.
        "left": [(L("left"), L("right") - 1)],
        "right": [(L("right"), L("shared_tail") - 1)],
        "shared_tail": [(L("shared_tail"), L("jumper") - 1)],
        # jumper ends at its jump; fall keeps the tail it falls into.
        "jumper": [(L("jumper"), L("fall") - 1)],
        "fall": [(L("fall"), L("chunky") - 1)],
        # The conditional jump keeps the chunk past `middle` in chunky's body.
        "chunky": [(L("chunky"), L("middle") - 1), (L("chunky_rest"), L("switcher") - 1)],
        "middle": [(L("middle"), L("chunky_rest") - 1)],
        # The jump table is data: the body is the code either side of it.
        "switcher": [(L("switcher"), L(".table") - 1), (L(".case0"), L("pointed_a") - 1)],
        "pointed_a": [(L("pointed_a"), L("pointed_b") - 1)],
        "pointed_b": [(L("pointed_b"), L("faller") - 1)],
        # RecoverFunctions splits the fall-through at fallen's prologue.
        "faller": [(L("faller"), L("fallen") - 1)],
        "fallen": [(L("fallen"), L("banner") - 1)],
        "lonely": [(L("lonely"), L("orphan") - 3)],          # then the 90 90
    }


ORIGINS = {"pointed_a": "recovered-code-pointer", "pointed_b": "recovered-code-pointer",
           "fallen": "recovered-split", "lonely": "recovered-prologue"}


def expected_unclaimed():
    """(lo, hi, kind) image offsets, inclusive, from the labels."""
    return [(L(".table"), L(".case0") - 1, "pointer table"),
            (L("banner"), L("lonely") - 1, "text"),
            (L("orphan") - 2, L("orphan") - 1, "padding"),
            (L("orphan"), L(".found"), "looks like code"),
            (L(".found") + 1, L("data_start") - 1, "padding")]


# ---------------------------------------------------------------- no Ghidra

def image():
    return EXE.read_bytes()[0x40:]


@case("residue's rules, through bodies.py, name the fixture's runs from their bytes")
def _():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    img = image()
    # "Into the code", as bodies.py means it: into some function's body.
    claimed = [(LOAD * 16 + lo, LOAD * 16 + hi)
               for ranges in expected_bodies().values() for lo, hi in ranges]

    def in_code(linear):
        return any(lo <= linear <= hi for lo, hi in claimed)

    got = []
    for lo, hi, want in expected_unclaimed():
        pieces = bodies.classify(LOAD * 16 + lo, LOAD * 16 + hi, img[lo:hi + 1], LOAD,
                                 in_code, md, 3)
        kinds = [k for _, _, k in pieces]
        if kinds != [want]:
            raise AssertionError(f"{a(lo)}..{a(hi)}: {kinds}, not [{want!r}]")
        got.append(want)
    # The whole tail as one run -- 90 90, the routine, the zero fill -- must
    # split into what each part is.
    lo, hi = L("orphan") - 2, L("data_start") - 1
    pieces = bodies.classify(LOAD * 16 + lo, LOAD * 16 + hi, img[lo:hi + 1], LOAD,
                             in_code, md, 3)
    if [k for _, _, k in pieces] != ["padding", "looks like code", "padding"]:
        raise AssertionError(f"the tail as one run: {pieces}")
    # Not code: the routine without its `ret`, the routine running into zeroes,
    # and a run too short.
    routine = img[L("orphan"):L(".found") + 1]
    for label, run in (("no return", routine[:-1]),
                       ("into zeroes", routine + b"\x00\x00\x00\x00"),
                       ("two instructions", bytes([0x40, 0xC3]))):
        if bodies.looks_like_code(md, run, 0, 3):
            raise AssertionError(f"{label}: looks like code")
    # One byte value throughout: a lone 90 is alignment like a run of them; a
    # run of anything else is repeated bytes; a lone anything else is nothing.
    for run, want in ((b"\x90", "padding"), (b"\xee\xee\xee", "repeated bytes"),
                      (b"\x10", "other")):
        got = bodies.kind_of(run, 0, LOAD, in_code, md, 3)
        if got != want:
            raise AssertionError(f"{run.hex()}: {got}, not {want}")
    return ("table, text, padding, code, padding; three near misses refused; "
            "90 padding, ee ee ee repeated")


def synthetic_export(folder, functions, overlaps=()):
    """functions.json and loadimage.json shaped like the pipeline's, for the
    assembled fixture, from (name, entry offset, [(lo, hi)]) triples."""
    folder.mkdir(parents=True, exist_ok=True)
    records = []
    for name, entry, ranges in functions:
        total = sum(hi - lo + 1 for lo, hi in ranges)
        span = max(hi for _, hi in ranges) - min(lo for lo, _ in ranges) + 1
        records.append({
            "name": name, "entry": a(entry), "size": total, "origin": "ghidra-analysis",
            "body": {"available": True, "provenance": "ghidra-function-body-address-set",
                     "ranges": [{"start": a(lo), "end": a(hi),
                                 "start_linear": f"0x{LOAD * 16 + lo:x}",
                                 "end_linear": f"0x{LOAD * 16 + hi:x}"} for lo, hi in ranges],
                     "total_bytes": total, "span_bytes": span,
                     "non_contiguous": total != span,
                     "contains_entry": any(lo <= entry <= hi for lo, hi in ranges)}})
    target = evidence.target_identity(EXE)
    (folder / "functions.json").write_text(json.dumps({
        "program": EXE.name, "target": {"path": target["path"], "size": target["size"],
                                        "sha256": target["sha256"]},
        "functions": records, "body_overlaps": list(overlaps)}), encoding="utf-8")
    data_start = L("data_start")
    size = len(image())
    (folder / "loadimage.json").write_text(json.dumps({
        "status": "verified", "result": {"load_segment": "0x1000", "mappings": [
            {"block": "CODE_0", "segment": "1000", "linear_start": LOAD * 16,
             "linear_end_inclusive": LOAD * 16 + data_start - 1, "length": data_start,
             "file_start": 0x40, "file_end_inclusive": 0x40 + data_start - 1},
            {"block": "CODE_1", "segment": f"{LOAD + data_start // 16:04x}",
             "linear_start": LOAD * 16 + data_start,
             "linear_end_inclusive": LOAD * 16 + size - 1, "length": size - data_start,
             "file_start": 0x40 + data_start, "file_end_inclusive": 0x40 + size - 1}]}}),
        encoding="utf-8")
    return folder / "functions.json"


@case("bodies.py on an export built from the labels: claimed share, runs, shapes")
def _():
    want = expected_bodies()
    funcs = [(n, L(n), r) for n, r in want.items()]
    # One body that does not contain its entry, as a recovered function's can
    # end up after a split goes wrong: the entry at main, the body elsewhere.
    funcs.append(("adrift", L("main"), [(L("pointed_a"), L("pointed_a"))]))
    path = synthetic_export(WORK / "synthetic", funcs)
    env = bodies.analyse(path)
    r = env["result"]
    code = L("data_start")
    unclaimed = sum(hi - lo + 1 for lo, hi, _ in expected_unclaimed())
    if r["code"]["bytes"] != code or r["claimed_bytes"] != code - unclaimed:
        raise AssertionError(f"code {r['code']['bytes']}, claimed {r['claimed_bytes']}")
    got = [(int(u["start_linear"], 16) - LOAD * 16, int(u["end_linear"], 16) - LOAD * 16,
            u["kind"]) for u in r["unclaimed"]]
    if got != expected_unclaimed():
        raise AssertionError(f"unclaimed {got}")
    split = sorted(s["entry"] for s in r["non_contiguous"])
    if split != sorted([a(L("chunky")), a(L("switcher"))]):
        raise AssertionError(f"non-contiguous {split}")
    if [o["entry"] for o in r["entry_outside_body"]] != [a(L("main"))]:
        raise AssertionError(f"entry outside body {r['entry_outside_body']}")
    if r["code"]["blocks"][0]["block"] != "CODE_0" or len(r["code"]["blocks"]) != 1:
        raise AssertionError(f"code blocks {r['code']['blocks']}")
    lines = bodies.summary(env)
    want_last = (f"1 unclaimed range looks like code: {a(L('orphan'))}..{a(L('.found'))} "
                 f"({L('.found') - L('orphan') + 1} bytes)")
    if lines[-1] != want_last:
        raise AssertionError(f"last line {lines[-1]!r}")
    if len(env["unknowns"]) != 1 or a(L("orphan")) not in env["unknowns"][0]:
        raise AssertionError(f"unknowns {env['unknowns']}")
    return (f"{r['claimed_bytes']} of {code} claimed ({r['claimed_percent']}%), "
            f"{len(got)} runs as the labels say; " + lines[-1])


@case("with nothing unclaimed that looks like code, bodies.py says so")
def _():
    want = expected_bodies()
    funcs = [(n, L(n), r) for n, r in want.items()]
    funcs.append(("orphan", L("orphan"), [(L("orphan"), L(".found"))]))
    env = bodies.analyse(synthetic_export(WORK / "claimed", funcs))
    last = bodies.summary(env)[-1]
    if last != "nothing unclaimed looks like code" or env["unknowns"]:
        raise AssertionError(f"{last!r}, unknowns {env['unknowns']}")
    return last


@case("an export from before function bodies is refused, with what to do")
def _():
    path = synthetic_export(WORK / "old", [("start", 0, [(0, 0x14)])])
    data = json.loads(path.read_text(encoding="utf-8"))
    for f in data["functions"]:
        del f["body"]
    path.write_text(json.dumps(data), encoding="utf-8")
    r = subprocess.run([sys.executable, str(TOOLS / "bodies.py"), str(path)],
                       capture_output=True, text=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    if r.returncode != 3 or "Re-run tools/pipeline.ps1" not in r.stderr or "Traceback" in r.stderr:
        raise AssertionError(f"exit {r.returncode}: {r.stderr}")
    (path.parent / "loadimage.json").unlink()
    data["functions"][0]["body"] = json.loads(synthetic_export(
        WORK / "again", [("start", 0, [(0, 0x14)])]).read_text())["functions"][0]["body"]
    path.write_text(json.dumps(data), encoding="utf-8")
    r2 = subprocess.run([sys.executable, str(TOOLS / "bodies.py"), str(path)],
                        capture_output=True, text=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    if r2.returncode != 3 or "loadimage.json" not in r2.stderr:
        raise AssertionError(f"without loadimage.json: exit {r2.returncode}: {r2.stderr}")
    return "exit 3 both times: no bodies, and no loadimage.json"


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


def pipeline():
    """Run pipeline.ps1 on the fixture once; later calls reuse the result."""
    if PIPELINE:
        return PIPELINE["code"], PIPELINE["log"], PIPELINE["out"]
    ghidra, java, pwsh = GHIDRA
    folder = WORK / "pipeline"
    folder.mkdir(parents=True, exist_ok=True)
    exe = folder / "BODIES.EXE"
    shutil.copy(EXE, exe)
    env = dict(os.environ, PYTHON=sys.executable)
    env.pop("DOS_DECOMPILER_FORCE_DRIFT", None)
    r = subprocess.run([pwsh, "-NoProfile", "-File", str(TOOLS / "pipeline.ps1"),
                        "-Exe", str(exe), "-OutDir", str(folder / "out"),
                        "-Ghidra", ghidra, "-JavaHome", java],
                       capture_output=True, text=True, env=env)
    PIPELINE.update(code=r.returncode, log=r.stdout + r.stderr, out=folder / "out")
    return pipeline()


def exported():
    code, log, out = pipeline()
    if code != 0:
        raise AssertionError(f"pipeline exit {code}\n{log[-1500:]}")
    return json.loads((out / "functions.json").read_text(encoding="utf-8"))


@case("every body is the one the labels give, and size is its address count", ghidra=True)
def _():
    data = exported()
    by_entry = {f["entry"]: f for f in data["functions"]}
    want = expected_bodies()
    if sorted(by_entry) != sorted(a(L(n)) for n in want):
        raise AssertionError(f"functions at {sorted(by_entry)}")
    for name, ranges in want.items():
        f = by_entry[a(L(name))]
        body = f["body"]
        got = [(int(r["start_linear"], 16) - LOAD * 16, int(r["end_linear"], 16) - LOAD * 16)
               for r in body["ranges"]]
        if got != ranges:
            raise AssertionError(f"{name}: body {got}, not {ranges}")
        if [(r["start"], r["end"]) for r in body["ranges"]] != [(a(lo), a(hi)) for lo, hi in ranges]:
            raise AssertionError(f"{name}: addresses {body['ranges']}")
        total = sum(hi - lo + 1 for lo, hi in ranges)
        span = ranges[-1][1] - ranges[0][0] + 1
        if (body["total_bytes"], body["span_bytes"], body["non_contiguous"],
                body["contains_entry"], body["available"], f["size"]) != \
                (total, span, total != span, True, True, total):
            raise AssertionError(f"{name}: {body}, size {f['size']}")
        if body["provenance"] != "ghidra-function-body-address-set":
            raise AssertionError(f"{name}: provenance {body['provenance']}")
    sw = by_entry[a(L("switcher"))]
    return (f"{len(want)} bodies; switcher size {sw['size']} = total_bytes, "
            f"span {sw['body']['span_bytes']}")


@case("every origin is the one its shape gives, and agrees with RecoverFunctions' count",
      ghidra=True)
def _():
    data = exported()
    _, log, _ = pipeline()
    by_entry = {f["entry"]: f for f in data["functions"]}
    for name in expected_bodies():
        want = ORIGINS.get(name, "ghidra-analysis")
        got = by_entry[a(L(name))].get("origin")
        if got != want:
            raise AssertionError(f"{name}: origin {got!r}, not {want!r}")
    m = re.search(r"RecoverFunctions: \d+ prologues seen, \+(\d+) from call targets, "
                  r"\+(\d+) from code pointers, (\d+) over-long functions split, "
                  r"\+(\d+) new from prologues", log)
    if not m:
        raise AssertionError("RecoverFunctions' summary line not in the log")
    counts = {o: sum(1 for f in data["functions"] if f["origin"] == o)
              for o in ("recovered-call-target", "recovered-code-pointer",
                        "recovered-split", "recovered-prologue")}
    if tuple(counts.values()) != tuple(int(g) for g in m.groups()):
        raise AssertionError(f"origins {counts}, RecoverFunctions said {m.groups()}")
    return ", ".join(f"{n} {o}" for o, n in counts.items()) + ", the rest ghidra-analysis"


@case("body_overlaps lists the shared epilogue, the jump into a neighbour, the split's "
      "fall-through", ghidra=True)
def _():
    data = exported()
    want = [
        # left and right jump to the epilogue Ghidra made a function of its
        # own; each claim leaves by its `jmp short`, the last two bytes.
        ((L("shared_tail"), L("jumper") - 1),
         [(a(L("left")), "jump", [a(L("right") - 2)]),
          (a(L("right")), "jump", [a(L("shared_tail") - 2)]),
          (a(L("shared_tail")), "body", None)]),
        ((L("fall_tail"), L("chunky") - 1),
         [(a(L("jumper")), "jump", [a(L("fall") - 2)]),
          (a(L("fall")), "body", None)]),
        # faller's `pop bp` falls into fallen's prologue.
        ((L("fallen"), L("banner") - 1),
         [(a(L("faller")), "fallthrough", [a(L("fallen") - 1)]),
          (a(L("fallen")), "body", None)]),
    ]
    got = [((int(o["start_linear"], 16) - LOAD * 16, int(o["end_linear"], 16) - LOAD * 16),
            [(c["entry"], c["claim"], c.get("via")) for c in o["functions"]])
           for o in data["body_overlaps"]]
    if got != want:
        raise AssertionError(f"body_overlaps {json.dumps(data['body_overlaps'])}")
    for o in data["body_overlaps"]:
        if o["bytes"] != int(o["end_linear"], 16) - int(o["start_linear"], 16) + 1:
            raise AssertionError(f"bytes {o}")
    return (f"{len(got)} ranges; the epilogue {a(L('shared_tail'))}..{a(L('jumper') - 1)} "
            f"claimed by left, right and its own body")


@case("bodies.py on the pipeline's export finds the code nothing reaches, and the table",
      ghidra=True)
def _():
    _, _, out = pipeline()
    exported()
    r = subprocess.run([sys.executable, str(TOOLS / "bodies.py"), str(out / "functions.json"),
                        "--evidence", str(out / "bodies.json")],
                       capture_output=True, text=True, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    if r.returncode != 0:
        raise AssertionError(f"exit {r.returncode}: {r.stderr}")
    env = json.loads((out / "bodies.json").read_text(encoding="utf-8"))
    got = [(int(u["start_linear"], 16) - LOAD * 16, int(u["end_linear"], 16) - LOAD * 16,
            u["kind"]) for u in env["result"]["unclaimed"]]
    if got != expected_unclaimed():
        raise AssertionError(f"unclaimed {got}")
    table = env["result"]["unclaimed"][0]
    if table["detail"] != "3 words, 3 into the code":
        raise AssertionError(f"table {table}")
    last = r.stdout.strip().splitlines()[-1]
    if not last.startswith(f"1 unclaimed range looks like code: {a(L('orphan'))}"):
        raise AssertionError(f"last line {last!r}")
    if env["result"]["overlaps"] != 3 or env["result"]["load_image"] != "verified":
        raise AssertionError(f"overlaps {env['result']['overlaps']}, "
                             f"load image {env['result']['load_image']}")
    return f"table at {table['start']}: {table['detail']}; {last}"


def main():
    global WORK, EXE, LABELS, GHIDRA
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    if not nasm:
        print("bodies regress: nasm not found (set NASM); the fixture cannot be assembled")
        return 77
    GHIDRA, why = ghidra_ready()
    WORK = Path(tempfile.mkdtemp(prefix="bodies-regress-"))
    failures = skipped = 0
    try:
        EXE = WORK / "BODIES.EXE"
        listing = WORK / "bodies.lst"
        r = subprocess.run([nasm, "-f", "bin", "-o", str(EXE), "-l", str(listing),
                            str(FIXTURE)], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FAIL  nasm could not build the fixture:\n{r.stderr}")
            return 1
        LABELS = labels_from_listing(listing)
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
        print(f"{failures} of {len(CASES)} body checks failed.")
        return 1
    if skipped:
        print(f"{len(CASES) - skipped} body checks pass; {skipped} skipped.")
        return 0
    print(f"All {len(CASES)} body checks pass, {sum(c[2] for c in CASES)} of them "
          f"through Ghidra.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
