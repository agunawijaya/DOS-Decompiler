#!/usr/bin/env python3
"""
regress.py -- Check that `emuverify.py sweep` proves what it says it proves,
and finds what it should, at the input where it is.

The fixtures, all in tests/sweep/fixtures:

  sweep.asm     the original: muldiv (IMUL, IDIV), clamp_store (two globals
                on one side of a signed comparison, an unsigned shift on the
                other), rare (a branch one input in 65,536 takes) and caller
                (calls helper, a second time only when a < b)
  rebuild.asm   the same four written differently, as a binary candidate;
                with -DWRONG, clamp_store compares with JG for JGE
  ref.py        Python candidates; port.mjs, JavaScript ones. Each has
                correct ones and ones wrong at one boundary.

Every expected value is worked out from the fixtures, not from a run: the
labels from NASM's listing, the instruction counts and the first wrong input
by hand, written beside each case. The functions.json the coverage is
measured against is built from the labels, a body per routine from its label
to the one after it.

The JavaScript cases need Node on PATH; without it they are skipped and say
so. The last case runs the pipeline and needs Ghidra; it is skipped and says
so without it.

Usage:
    python tests/sweep/regress.py [--only TEXT]
"""

import argparse
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
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(TOOLS))
import evidence  # noqa: E402

LOAD = 0x1000
HEADER = 0x40

CASES = []


def case(name, needs=()):
    def wrap(fn):
        CASES.append((name, fn, needs))
        return fn
    return wrap


WORK = None
BUILT = {}          # "sweep", "rebuild", "rebuild-wrong" -> (exe, labels, listing lines)


def listing(path):
    """{label: image offset}, a local label as `routine.local`, and
    [(image offset, source text)] for every line that holds an instruction."""
    labels, pending, code, routine = {}, [], [], None
    for line in Path(path).read_text(encoding="latin-1").splitlines():
        m = re.match(r"\s*\d+\s+([0-9A-F]{8})\s+([0-9A-F]+)\s+(.*)$", line)
        label = re.search(r"^\s*\d+\s+(?:[0-9A-F]{8}\s+\S+\s+)?([.\w]+):", line)
        if label and not m:
            name = label.group(1)
            if name.startswith("."):
                name = f"{routine}{name}"
            else:
                routine = name
            pending.append(name)
            continue
        if m:
            at = int(m.group(1), 16) - HEADER
            if label:                       # `g_limit:    dw 10`, on one line
                pending.append(label.group(1))
            for p in pending:
                labels[p] = at
            pending = []
            text = m.group(3).split(";")[0].strip()
            if text and not re.match(r"(d[bwd]|times|align)\b", text):
                code.append((at, text))
    return labels, code


def assemble(name, source, *defines):
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    exe, lst = WORK / f"{name}.exe", WORK / f"{name}.lst"
    r = subprocess.run([nasm, "-f", "bin", *[f"-D{d}" for d in defines], "-o", str(exe),
                        "-l", str(lst), str(FIXTURES / source)], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"nasm could not build {source}:\n{r.stderr}")
    labels, code = listing(lst)
    BUILT[name] = (exe, labels, code)


def L(which, label):
    return BUILT[which][1][label]


def at(which, label):
    return f"{LOAD:04x}:{L(which, label):04x}"


def data(which, label):
    """A global's DGROUP offset."""
    return L(which, label) - L(which, "data_start")


ROUTINES = ["start", "muldiv", "clamp_store", "rare", "caller", "helper", "quot7", "quot7b"]


def instructions(which, lo, hi):
    """How many instruction lines the listing has in [lo, hi)."""
    return sum(1 for a, _ in BUILT[which][2] if lo <= a < hi)


def export(which="sweep"):
    """functions.json for the original, shaped as the pipeline writes it: one
    body per routine, from its label to the next routine's."""
    folder = WORK / f"export-{which}"
    if (folder / "functions.json").exists():
        return folder / "functions.json"
    folder.mkdir()
    exe, labels, _ = BUILT[which]
    ends = {"start": "muldiv", "muldiv": "muldiv_end", "clamp_store": "clamp_store_end",
            "rare": "rare_end", "caller": "caller_end", "helper": "helper_end",
            "quot7": "quot7_end", "quot7b": "quot7b_end"}
    records = []
    for name in ROUTINES:
        if name not in labels:              # rebuild.asm has only the first four
            continue
        lo, hi = labels[name], labels[ends[name]] - 1
        records.append({
            "name": name, "entry": f"{LOAD:04x}:{lo:04x}", "size": hi - lo + 1, "thunk": False,
            "mnemonics": ["RET"] if name != "start" else ["INT"],
            "body": {"available": True, "ranges": [{
                "start": f"{LOAD:04x}:{lo:04x}", "end": f"{LOAD:04x}:{hi:04x}",
                "start_linear": f"0x{(LOAD << 4) + lo:x}", "end_linear": f"0x{(LOAD << 4) + hi:x}"}]}})
    target = evidence.target_identity(exe)
    (folder / "functions.json").write_text(json.dumps({
        "program": exe.name, "functions": records,
        "target": {"path": target["path"], "size": target["size"], "sha256": target["sha256"]},
        "observed_profile": {"load_segment": f"0x{LOAD:04x}"}}), encoding="utf-8")
    return folder / "functions.json"


def domain(name, spec):
    path = WORK / f"{name}.json"
    path.write_text(json.dumps(spec, indent=1), encoding="utf-8")
    return path


def sweep(entry, spec_path, *candidate, functions=True, extra=(), which="sweep"):
    """Run the command line; (exit code, prose, envelope)."""
    out = WORK / f"result-{len(list(WORK.glob('result-*')))}.json"
    args = [sys.executable, str(TOOLS / "emuverify.py"), "sweep", str(BUILT[which][0]), entry,
            "--domain", str(spec_path), *candidate, "--evidence", str(out), "--quiet", *extra]
    if functions:
        args += ["--functions", str(export(which))]
    r = subprocess.run(args, capture_output=True, text=True,
                       env=dict(os.environ, PYTHONIOENCODING="utf-8"))
    env = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
    return r.returncode, r.stdout + r.stderr, env


def py(fn):
    return ["--candidate", f"{FIXTURES / 'ref.py'}:{fn}"]


def js(fn):
    return ["--candidate", f"{FIXTURES / 'port.mjs'}:{fn}"]


def binary(which, routine):
    return ["--candidate-exe", str(BUILT[which][0]), "--candidate-entry", at(which, routine)]


def last_line(text):
    return [l for l in text.splitlines() if l.strip()][-1]


def expect_verified(code, text, env, cases, mode="exhaustive", percent=100.0):
    if code != 0 or env is None or env["status"] != "verified":
        raise AssertionError(f"exit {code}, status {env and env['status']}\n{text[-1500:]}")
    r = env["result"]
    if r["cases_run"] != cases or r["mode"] != mode:
        raise AssertionError(f"{r['cases_run']} cases ({r['mode']}), not {cases} ({mode})")
    cov = r["coverage"]
    if percent is not None and (not cov["available"] or cov["percent"] != percent):
        raise AssertionError(f"coverage {cov}, not {percent}%")
    line = last_line(text)
    want = f"VERIFIED over {cases} cases ({'exhaustive' if mode == 'exhaustive' else 'sampled'}"
    if not line.startswith(want):
        raise AssertionError(f"last line {line!r} does not start {want!r}")
    return r


def expect_mismatch(code, text, env, case_number, inputs, fields):
    if code != 1 or env is None or env["status"] != "mismatch":
        raise AssertionError(f"exit {code}, status {env and env['status']}\n{text[-1500:]}")
    first = env["result"]["first_divergence"]
    if first["case"] != case_number or first["inputs"] != inputs or first["fields"] != fields:
        raise AssertionError(f"first divergence at case {first['case']} {first['inputs']} "
                             f"{first['fields']}, not case {case_number} {inputs} {fields}")
    line = last_line(text)
    if not line.startswith(f"MISMATCH at case {case_number}: "):
        raise AssertionError(f"last line {line!r}")
    return first


# ---------------------------------------------------------------- the domains

def muldiv_domain():
    # 601 * 3 * 7 = 12,621 cases. By hand, the divide faults: c = 0 for every
    # a and b, 601 * 3 = 1,803; and the wrapped product -32768 with c = -1,
    # which with b in {1, 3, 128} and |a| <= 300 is a = -256 and a = 256 at
    # b = 128 (256 * 128 = 32768 wraps to -32768): 2. 1,805 on a 386. An 8088,
    # the default, also refuses that product with c = 1, whose quotient is
    # -32768: 2 more, 1,807.
    return domain("muldiv", {"args": [{"name": "a", "range": [-300, 300]},
                                      {"name": "b", "list": [1, 3, 128]},
                                      {"name": "c", "range": [-3, 3]}],
                             "compare": ["ax"], "max_cases": 20000})


def clamp_domain(which="rebuild"):
    # 101 values of x, two limits: 202 cases. -60 sends every x above the
    # limit; 10 sends x <= 10 below it, so both sides of the branch run.
    return domain("clamp-" + which, {
        "args": [{"name": "x", "range": [-50, 50]}],
        "globals": [
            {"name": "g_limit", "offset": data("sweep", "g_limit"),
             "candidate_offset": data(which, "g_limit"), "list": [-60, 10]},
            {"name": "g_over", "offset": data("sweep", "g_over"),
             "candidate_offset": data(which, "g_over")},
            {"name": "g_hits", "offset": data("sweep", "g_hits"),
             "candidate_offset": data(which, "g_hits"), "value": 5},
            {"name": "g_under", "offset": data("sweep", "g_under"),
             "candidate_offset": data(which, "g_under")}],
        "compare": ["writes", "calls"]})


def rare_domain(name, arg, max_cases=70000):
    return domain(name, {"args": [dict({"name": "x"}, **arg)], "compare": ["ax"],
                         "max_cases": max_cases})


def caller_domain():
    # a and b in -2..2: 25 cases, a < b in 10 of them. The first call answers
    # 100; the second keeps the default stub, 0x1234 + 2 * 7 = 0x1242.
    return domain("caller", {
        "args": [{"name": "a", "range": [-2, 2]}, {"name": "b", "range": [-2, 2]}],
        "callees": {"helper": {"original": at("sweep", "helper"),
                               "candidate": at("rebuild", "helper"), "args": 2}},
        "stubs": [100], "compare": ["ax", "calls"]})


# ---------------------------------------------------------------- the cases

@case("muldiv against a correct Python candidate: every case, divide faults compared")
def _():
    code, text, env = sweep(at("sweep", "muldiv"), muldiv_domain(), *py("muldiv"))
    r = expect_verified(code, text, env, 12621)
    if r["faults_on_both_sides"] != {"divide": 1807}:
        raise AssertionError(f"faults {r['faults_on_both_sides']}, not 1,807 divide faults")
    if r["coverage"]["instructions"] != 8 or instructions("sweep", L("sweep", "muldiv"),
                                                          L("sweep", "muldiv_end")) != 8:
        raise AssertionError(f"coverage {r['coverage']}; muldiv has 8 instructions")
    return "12,621 cases, exhaustive, 1,807 divide faults on both sides, 8 of 8 instructions"


@case("muldiv against a correct JavaScript port, in one Node process", needs=("node",))
def _():
    code, text, env = sweep(at("sweep", "muldiv"), muldiv_domain(), *js("muldiv"))
    r = expect_verified(code, text, env, 12621)
    if r["faults_on_both_sides"] != {"divide": 1807} or r["candidate"]["processes"] != 1:
        raise AssertionError(f"faults {r['faults_on_both_sides']}, processes "
                             f"{r['candidate']['processes']}")
    return f"12,621 cases, 1,807 divide faults, 1 Node process ({r['candidate']['runtime']})"


@case("muldiv against the rebuild, a binary candidate")
def _():
    code, text, env = sweep(at("sweep", "muldiv"), muldiv_domain(), *binary("rebuild", "muldiv"))
    r = expect_verified(code, text, env, 12621)
    if r["faults_on_both_sides"] != {"divide": 1807}:
        raise AssertionError(f"faults {r['faults_on_both_sides']}")
    return "12,621 cases, the rebuild's IDIV faults on the same 1,807"


@case("a Python candidate that forgets -32768 / -1 fails at that input, case 941")
def _():
    # Product order: a slowest, then b, then c. The first input where only the
    # overflow fault is missing: a = -256 (index 44), b = 128 (index 2),
    # c = -1 (index 2) -- (44 * 3 + 2) * 7 + 2 = 940, so case 941.
    code, text, env = sweep(at("sweep", "muldiv"), muldiv_domain(),
                            *py("muldiv_without_overflow_fault"),
                            extra=["--trace-on-divergence", "4"])
    first = expect_mismatch(code, text, env, 941, {"a": -256, "b": 128, "c": -1}, ["fault"])
    if first["original"] != {"fault": "divide"} or first["candidate"].get("ax") != 0x8000:
        raise AssertionError(f"original {first['original']}, candidate {first['candidate']}")
    trace = [t["instruction"] for t in env["result"]["trace"]]
    if len(trace) != 4 or not trace[-1].startswith("idiv"):
        raise AssertionError(f"the trace does not end at the IDIV that faulted: {trace}")
    return f"case 941, a=-256 b=128 c=-1: divide fault vs ax=0x8000; trace ends {trace[-1]!r}"


@case("a JavaScript port that does not wrap the product fails at case 15", needs=("node",))
def _():
    # a = -300 with b = 1 and b = 3 never leaves 16 bits: cases 1-14 agree.
    # b = 128 gives -38400, which wraps to 27136; at c = -3 the original
    # returns 27136 / -3 = -9045, the port -38400 / -3 = 12800.
    code, text, env = sweep(at("sweep", "muldiv"), muldiv_domain(), *js("muldivWithoutWrap"))
    first = expect_mismatch(code, text, env, 15, {"a": -300, "b": 128, "c": -3}, ["ax"])
    if (first["original"]["ax"], first["candidate"]["ax"]) != ((-9045) & 0xFFFF, 12800):
        raise AssertionError(f"{first['original']} vs {first['candidate']}")
    return "case 15, a=-300 b=128 c=-3: ax 0xdcab (-9045) vs 0x3200 (12800)"


@case("a JavaScript port that divides without Math.trunc diverges at case 15, not a contract break",
      needs=("node",))
def _():
    # Every quotient before case 15 is exact: -300 and -900 divide by 1, 2
    # and 3. 27136 / -3 is the first that is not.
    code, text, env = sweep(at("sweep", "muldiv"), muldiv_domain(), *js("muldivWithoutTrunc"))
    first = expect_mismatch(code, text, env, 15, {"a": -300, "b": 128, "c": -3}, ["ax"])
    if not str(first["candidate"]["ax"]).startswith("-9045.33"):
        raise AssertionError(f"candidate {first['candidate']}")
    return f"case 15: ax {first['candidate']['ax']!r}"


def quot7_domain():
    # n from -229,390 to -229,370: 21 cases, in order. 7 * -32768 = -229,376,
    # and IDIV truncates toward zero: n <= -229,383 (cases 1-8) gives a
    # quotient below -32768, a fault on both CPUs; -229,382..-229,376 (cases
    # 9-15) gives -32768, which only an 8088 refuses; the last 6 give -32767.
    return domain("quot7", {"args": [{"name": "n", "range": [-229390, -229370], "size": 4}],
                            "compare": ["ax"]})


def quot7b_domain():
    # n from -910 to -890: 21 cases. 7 * -128 = -896: n <= -903 (cases 1-8)
    # overflows a byte on both CPUs; -902..-896 (cases 9-15) gives -128, an
    # 8088's fault; the last 6 give -127.
    return domain("quot7b", {"args": [{"name": "n", "range": [-910, -890]}],
                             "compare": ["ax"]})


@case("8088, the default: quot7 across -32768, against a Python candidate that models it")
def _():
    code, text, env = sweep(at("sweep", "quot7"), quot7_domain(), *py("quot7"))
    r = expect_verified(code, text, env, 21)
    if r["cpu"] != "8088" or r["faults_on_both_sides"] != {"divide": 15}:
        raise AssertionError(f"cpu {r['cpu']}, faults {r['faults_on_both_sides']}, not 8 + 7")
    if r["coverage"]["instructions"] != 8 or instructions("sweep", L("sweep", "quot7"),
                                                          L("sweep", "quot7_end")) != 8:
        raise AssertionError(f"coverage {r['coverage']}; quot7 has 8 instructions")
    said = [l for l in text.splitlines() if l.startswith("cpu ")]
    if said != ["cpu        8088: IDIV faults on a quotient of -32768 or -128"]:
        raise AssertionError(f"the prose says {said}")
    if not any(l.startswith("The CPU is an 8088 in one respect only") for l in env["limitations"]):
        raise AssertionError("the limitations do not say the CPU is an 8088")
    return "21 cases, 15 divide faults on both sides: 8 that fault anywhere, 7 an 8088's"


@case("8088: a Python candidate that divides as a 386 does fails at n = -229,382, case 9")
def _():
    code, text, env = sweep(at("sweep", "quot7"), quot7_domain(), *py("quot7_as_a_386_divides"))
    first = expect_mismatch(code, text, env, 9, {"n": -229382}, ["fault"])
    if first["original"] != {"fault": "divide"} or first["candidate"].get("ax") != 0x8000:
        raise AssertionError(f"original {first['original']}, candidate {first['candidate']}")
    if first["original_at"] != at("sweep", "quot7.div"):
        raise AssertionError(f"the fault is at {first['original_at']}, not the IDIV, "
                             f"{at('sweep', 'quot7.div')}")
    why = "(an 8088 refuses the quotient -32768)"
    if not first["text"]["original"].endswith(why):
        raise AssertionError(f"the original's fault reads {first['text']['original']!r}")
    return f"case 9: {first['text']['original']} vs ax=0x8000"


@case("--cpu 386: the 386 candidate verifies, and the 8088 one fails at case 9")
def _():
    code, text, env = sweep(at("sweep", "quot7"), quot7_domain(), *py("quot7_as_a_386_divides"),
                            extra=["--cpu", "386"])
    r = expect_verified(code, text, env, 21)
    if r["cpu"] != "386" or r["faults_on_both_sides"] != {"divide": 8}:
        raise AssertionError(f"cpu {r['cpu']}, faults {r['faults_on_both_sides']}, not 8")
    if not any(l.startswith("Unicorn implements DIV and IDIV as a later x86 does")
               for l in env["limitations"]):
        raise AssertionError("the limitations do not say IDIV is a 386's")
    code, text, env = sweep(at("sweep", "quot7"), quot7_domain(), *py("quot7"),
                            extra=["--cpu", "386"])
    first = expect_mismatch(code, text, env, 9, {"n": -229382}, ["fault"])
    if first["original"].get("ax") != 0x8000 or first["candidate"] != {"fault": "divide"}:
        raise AssertionError(f"original {first['original']}, candidate {first['candidate']}")
    return "8 faults on both sides with the 386 candidate; the 8088 one: ax=0x8000 vs fault"


@case("quot7b, the byte divide: -128 is an 8088's fault, at n = -902, case 9")
def _():
    code, text, env = sweep(at("sweep", "quot7b"), quot7b_domain(), *py("quot7b"))
    r = expect_verified(code, text, env, 21)
    if r["faults_on_both_sides"] != {"divide": 15}:
        raise AssertionError(f"faults {r['faults_on_both_sides']}")
    code, text, env = sweep(at("sweep", "quot7b"), quot7b_domain(),
                            *py("quot7b_as_a_386_divides"))
    first = expect_mismatch(code, text, env, 9, {"n": -902}, ["fault"])
    if first["candidate"].get("ax") != 0xFF80 or not first["text"]["original"].endswith(
            "(an 8088 refuses the quotient -128)"):
        raise AssertionError(f"{first['text']}")
    code, text, env = sweep(at("sweep", "quot7b"), quot7b_domain(),
                            *py("quot7b_as_a_386_divides"), extra=["--cpu", "386"])
    r = expect_verified(code, text, env, 21)
    if r["faults_on_both_sides"] != {"divide": 8}:
        raise AssertionError(f"386: faults {r['faults_on_both_sides']}")
    return "8088: 15 faults, the 386 candidate wrong at case 9 (ax=0xff80); 386: 8 faults"


@case("muldiv under both CPUs: 1,805 faults on a 386, 1,807 on an 8088, case 943 between")
def _():
    # a = -256 (index 44), b = 128 (index 2), c = 1 (index 4): (44 * 3 + 2)
    # * 7 + 4 = 942, case 943 -- the first wrapped -32768 divided by 1.
    code, text, env = sweep(at("sweep", "muldiv"), muldiv_domain(),
                            *py("muldiv_as_a_386_divides"), extra=["--cpu", "386"])
    r = expect_verified(code, text, env, 12621)
    if r["faults_on_both_sides"] != {"divide": 1805}:
        raise AssertionError(f"386: faults {r['faults_on_both_sides']}, not 1,805")
    code, text, env = sweep(at("sweep", "muldiv"), muldiv_domain(),
                            *py("muldiv_as_a_386_divides"))
    first = expect_mismatch(code, text, env, 943, {"a": -256, "b": 128, "c": 1}, ["fault"])
    if first["original"] != {"fault": "divide"} or first["candidate"].get("ax") != 0x8000:
        raise AssertionError(f"original {first['original']}, candidate {first['candidate']}")
    return "386: 1,805 on both sides; 8088: case 943, a=-256 b=128 c=1, through a memory operand"


@case("the CPU is the binary candidate's too: quot7 against itself, under each")
def _():
    out = []
    for cpu, faults in (("8088", 15), ("386", 8)):
        code, text, env = sweep(at("sweep", "quot7"), quot7_domain(), *binary("sweep", "quot7"),
                                extra=["--cpu", cpu])
        r = expect_verified(code, text, env, 21)
        if r["faults_on_both_sides"] != {"divide": faults}:
            raise AssertionError(f"{cpu}: faults {r['faults_on_both_sides']}, not {faults}")
        out.append(f"{cpu}: {faults} faults on both sides")
    return "; ".join(out)


@case("a JavaScript port of quot7: with the 8088's rule it verifies, without it case 9",
      needs=("node",))
def _():
    code, text, env = sweep(at("sweep", "quot7"), quot7_domain(), *js("quot7"))
    r = expect_verified(code, text, env, 21)
    if r["faults_on_both_sides"] != {"divide": 15}:
        raise AssertionError(f"faults {r['faults_on_both_sides']}")
    code, text, env = sweep(at("sweep", "quot7"), quot7_domain(), *js("quot7AsA386Divides"))
    first = expect_mismatch(code, text, env, 9, {"n": -229382}, ["fault"])
    if first["candidate"].get("ax") != 0x8000:
        raise AssertionError(f"candidate {first['candidate']}")
    return "15 faults with the rule; case 9, ax=0x8000, without"


@case("clamp_store against Python, JavaScript and the rebuild: writes compared by name")
def _():
    out = []
    candidates = [("Python", py("clamp_store")), ("rebuild", binary("rebuild", "clamp_store"))]
    if shutil.which("node"):
        candidates.append(("JavaScript", js("clampStore")))
    for label, cand in candidates:
        code, text, env = sweep(at("sweep", "clamp_store"), clamp_domain(), *cand)
        r = expect_verified(code, text, env, 202)
        if r["coverage"]["instructions"] != 14:
            raise AssertionError(f"{label}: coverage {r['coverage']}; clamp_store has 14")
        out.append(label)
    return f"202 cases each ({', '.join(out)}), 14 of 14 instructions" + \
        ("" if shutil.which("node") else "; JavaScript skipped: node not on PATH")


@case("the rebuild with JG for JGE fails at x == g_limit, case 122")
def _():
    # x slowest, then g_limit in [-60, 10]. x never equals -60; it equals 10
    # at index 60, limit index 1: 60 * 2 + 1 = 121, so case 122.
    code, text, env = sweep(at("sweep", "clamp_store"), clamp_domain("rebuild-wrong"),
                            *binary("rebuild-wrong", "clamp_store"))
    first = expect_mismatch(code, text, env, 122, {"x": 10, "g_limit": 10}, ["writes"])
    o, c = first["original"]["writes"], first["candidate"]["writes"]
    if (o["g_under"], o["g_hits"], c["g_under"], c["g_hits"]) != (2, 5, 0, 6):
        raise AssertionError(f"original {o}, candidate {c}")
    return "case 122, x=10 g_limit=10: g_under=2 vs g_over=0, g_hits=6"


@case("a JavaScript port with SAR for SHR fails at the first negative x below the limit",
      needs=("node",))
def _():
    # Case 1 is x = -50 with limit -60: above it, no shift. Case 2 is x = -50
    # with limit 10: SHR gives 0xFFCE >> 2 = 0x3FF3, SAR gives -13 = 0xFFF3.
    code, text, env = sweep(at("sweep", "clamp_store"), clamp_domain(), *js("clampStoreSignedShift"))
    first = expect_mismatch(code, text, env, 2, {"x": -50, "g_limit": 10}, ["writes"])
    if (first["original"]["writes"]["g_under"], first["candidate"]["writes"]["g_under"]) != \
            (0x3FF3, 0xFFF3):
        raise AssertionError(f"{first['original']} vs {first['candidate']}")
    return "case 2, x=-50 g_limit=10: g_under 0x3ff3 vs 0xfff3"


@case("rare over 0..1000 verifies, and exercises 8 of 10 instructions -- and says so")
def _():
    # 0x1234 = 4660 is outside the domain, so `mov ax, 7` and the `jmp` after
    # it never run: 2 of rare's 10 instructions, one range, ending the byte
    # before .common.
    code, text, env = sweep(at("sweep", "rare"), rare_domain("rare-small", {"range": [0, 1000]}),
                            *py("rare"))
    r = expect_verified(code, text, env, 1001, percent=80.0)
    cov = r["coverage"]
    seven = next(a for a, t in BUILT["sweep"][2] if t.startswith("mov ax, 7"))
    want = [{"start": f"{LOAD:04x}:{seven:04x}",
             "end": f"{LOAD:04x}:{L('sweep', 'rare.common') - 1:04x}", "instructions": 2}]
    if (cov["instructions"], cov["exercised"], cov["unreached"]) != (10, 8, want):
        raise AssertionError(f"coverage {cov}, not 8 of 10 with {want} unreached")
    if not last_line(text).endswith("80.0% of the body exercised"):
        raise AssertionError(f"last line {last_line(text)!r}")
    return f"1,001 cases, 8 of 10 instructions (80.0%), never reached {want[0]['start']}..{want[0]['end']}"


@case("rare over every int16: 65,536 cases, exhaustive, 100% of the body")
def _():
    out = []
    candidates = [("Python", py("rare")), ("rebuild", binary("rebuild", "rare"))]
    if shutil.which("node"):
        candidates.append(("JavaScript", js("rare")))
    spec = rare_domain("rare-full", {"set": "int16"})
    for label, cand in candidates:
        code, text, env = sweep(at("sweep", "rare"), spec, *cand)
        r = expect_verified(code, text, env, 65536, percent=100.0)
        if r["coverage"]["unreached"]:
            raise AssertionError(f"{label}: {r['coverage']['unreached']}")
        out.append(label)
    return f"65,536 cases each ({', '.join(out)}), 10 of 10 instructions"


@case("a Python candidate masking with 0x7F fails at x = 128; --all finds all 489")
def _():
    spec = rare_domain("rare-small", {"range": [0, 1000]})
    code, text, env = sweep(at("sweep", "rare"), spec, *py("rare_masking_seven_bits"))
    expect_mismatch(code, text, env, 129, {"x": 128}, ["ax"])
    # x & 0x7F differs from x & 0xFF when bit 7 is set: 128 of every 256, so
    # 3 * 128 = 384 in 0..767, and 896..1000 = 105 more. 489.
    code, text, env = sweep(at("sweep", "rare"), spec, *py("rare_masking_seven_bits"),
                            extra=["--all"])
    r = env["result"]
    group = (r["divergence_groups"] or {}).get("ax", {})
    if (r["diverge"], r["cases_run"], group.get("cases")) != (489, 1001, 489) \
            or [e["case"] for e in group["examples"]] != [129, 130, 131]:
        raise AssertionError(f"diverge {r['diverge']} of {r['cases_run']}, group {group}")
    return "case 129, x=128; with --all, 489 of 1,001 diverge, all in ax"


@case("caller: calls and their arguments compared, against Python, JavaScript and the rebuild")
def _():
    out = []
    candidates = [("Python", py("caller")), ("rebuild", binary("rebuild", "caller"))]
    if shutil.which("node"):
        candidates.append(("JavaScript", js("caller")))
    for label, cand in candidates:
        code, text, env = sweep(at("sweep", "caller"), caller_domain(), *cand)
        r = expect_verified(code, text, env, 25)
        if r["coverage"]["instructions"] != 21:
            raise AssertionError(f"{label}: {r['coverage']}; caller has 21 instructions")
        out.append(label)
    return f"25 cases each ({', '.join(out)}), 21 of 21 instructions"


@case("a JavaScript port comparing unsigned fails at a=-2 b=0, case 3", needs=("node",))
def _():
    # a = -2 first: b = -2 and b = -1 compare the same either way. At b = 0,
    # -2 < 0 signed, but 0xFFFE < 0 is false unsigned: one call fewer.
    code, text, env = sweep(at("sweep", "caller"), caller_domain(), *js("callerUnsignedCompare"))
    first = expect_mismatch(code, text, env, 3, {"a": -2, "b": 0}, ["ax", "calls"])
    o, c = first["original"], first["candidate"]
    if (o["ax"], c["ax"], len(o["calls"]), len(c["calls"])) != (100 + 0x1242, 100, 2, 1):
        raise AssertionError(f"{o} vs {c}")
    return "case 3, a=-2 b=0: ax 100 + 0x1242 vs 100; helper(0, 1) missing from the calls"


@case("a domain too big for max_cases is sampled, with its seed, boundary values first")
def _():
    import sweep as engine
    spec_path = domain("muldiv-sampled", {
        "args": [{"name": "a", "set": "int16"}, {"name": "b", "set": "int16"},
                 {"name": "c", "set": "int16"}],
        "compare": ["ax"], "max_cases": 3000, "seed": 7})
    spec = engine.Spec(spec_path)
    mode, cases, info = engine.plan(spec)
    first = [next(cases) for _ in range(info["boundary_cases"])]
    for i, d in enumerate(spec.dimensions):
        missing = set(d.boundary()) - {c[i] for c in first}
        if missing:
            raise AssertionError(f"{d.name}: boundary values never run: {sorted(missing)}")
    must = {-32768, 32767, 0, 1, -1, 0x4000, 0x3FFF, -0x4001, 0x7FFE}
    if not must <= set(spec.dimensions[0].boundary()):
        raise AssertionError(f"boundary {spec.dimensions[0].boundary()} lacks {must}")
    code, text, env = sweep(at("sweep", "muldiv"), spec_path, *py("muldiv"))
    r = expect_verified(code, text, env, 3000, mode="sampled")
    if r["seed"] != 7 or "(sampled, seed 7)" not in last_line(text) or "exhaustive" in last_line(text):
        raise AssertionError(f"seed {r['seed']}, last line {last_line(text)!r}")
    return (f"{info['boundary_cases']} boundary cases ({info['boundary_rule']}), then random "
            f"to 3,000; {last_line(text)}")


@case("exhaustive exactly when the whole domain fits in max_cases")
def _():
    # 0..99 is 100 cases: exhaustive at max_cases 100, sampled at 99.
    out = []
    for limit, mode in ((100, "exhaustive"), (99, "sampled")):
        code, text, env = sweep(at("sweep", "rare"),
                                rare_domain(f"rare-{limit}", {"range": [0, 99]}, limit),
                                *py("rare"), extra=["--seed", "3"])
        r = expect_verified(code, text, env, limit, mode=mode, percent=80.0)
        out.append(f"max_cases {limit}: {r['mode']}")
    return "; ".join(out)


@case("a Python candidate that never returns for one input is a hang there, and the sweep goes on")
def _():
    # x = 16 is case 17 of 0..1000. The original returns 16 there.
    spec = rare_domain("rare-small", {"range": [0, 1000]})
    code, text, env = sweep(at("sweep", "rare"), spec, *py("rare_loops_at_sixteen"),
                            extra=["--case-timeout", "1"])
    first = expect_mismatch(code, text, env, 17, {"x": 16}, ["fault"])
    if first["candidate"] != {"fault": "hang"} or first["original"].get("fault"):
        raise AssertionError(f"{first['original']} vs {first['candidate']}")
    code, text, env = sweep(at("sweep", "rare"), spec, *py("rare_loops_at_sixteen"),
                            extra=["--case-timeout", "1", "--all"])
    r = env["result"]
    if (r["cases_run"], r["diverge"], r["candidate"]["hangs"]) != (1001, 1, 1):
        raise AssertionError(f"{r['cases_run']} run, {r['diverge']} diverge, "
                             f"{r['candidate']['hangs']} hangs")
    return "case 17, x=16: the original returns, the candidate hangs; with --all 1,001 run, 1 hang"


@case("a JavaScript port that never returns is killed, restarted once, then the sweep is blocked",
      needs=("node",))
def _():
    spec = rare_domain("rare-small", {"range": [0, 1000]})
    code, text, env = sweep(at("sweep", "rare"), spec, *js("rareLoopsAtSixteen"),
                            extra=["--case-timeout", "1", "--all"])
    r = env["result"]
    if code != 1 or "candidate" not in r:
        raise AssertionError(f"exit {code}, {env['status']}: {r.get('reason') or text[-600:]}")
    c = r["candidate"]
    if (r["cases_run"], r["diverge"], c["hangs"], c["restarts"], c["processes"]) \
            != (1001, 1, 1, 1, 2) or r["first_divergence"]["case"] != 17:
        raise AssertionError(f"exit {code}: {r['cases_run']} run, {r['diverge']} diverge, "
                             f"candidate {c}")
    code, text, env = sweep(at("sweep", "rare"), spec, *js("rareLoopsAtSixteenAndThirtyTwo"),
                            extra=["--case-timeout", "1", "--all"])
    reason = (env or {}).get("result", {}).get("reason", "")
    if code != 3 or "case 33" not in reason or "restarted once" not in reason:
        raise AssertionError(f"exit {code}: {reason or text[-600:]}")
    return ("x=16: hang, Node killed and restarted, 1,001 cases run; a second loop at "
            "x=32: blocked at case 33")


@case("a candidate that answers outside the contract stops the sweep")
def _():
    code, text, env = sweep(at("sweep", "rare"), rare_domain("rare-small", {"range": [0, 1000]}),
                            *py("rare_misspelt"))
    if code != 3 or env["status"] != "blocked" or "Ax" not in env["result"]["reason"]:
        raise AssertionError(f"exit {code}, {env and env['result']}")
    return env["result"]["reason"][:110]


@case("the sweep says which DGROUP it used, and takes one it is given")
def _():
    spec = rare_domain("rare-small", {"range": [0, 1000]})
    dgroup = L("sweep", "data_start") // 16
    code, text, env = sweep(at("sweep", "rare"), spec, *py("rare"))
    found = f"DGROUP 0x{dgroup:04x} (the segment the startup loads into DS, at {LOAD:04x}:0003)"
    if found not in text:
        raise AssertionError(f"{found!r} not in\n{text[:600]}")
    code, text, env = sweep(at("sweep", "rare"), spec, *py("rare"), extra=["--dgroup", hex(dgroup)])
    if f"DGROUP 0x{dgroup:04x} (given)" not in text or code != 0:
        raise AssertionError(text[:600])
    return found


# ---------------------------------------------------------------- Ghidra

def ghidra_ready():
    ghidra, java = os.environ.get("GHIDRA_HOME"), os.environ.get("JAVA_HOME")
    if not ghidra or not any((Path(ghidra) / "support" / n).exists()
                             for n in ("analyzeHeadless.bat", "analyzeHeadless")):
        return "Ghidra not found (set GHIDRA_HOME)"
    if not java or not Path(java).exists():
        return "JDK not found (set JAVA_HOME)"
    if not shutil.which("pwsh"):
        return "pwsh not found; pipeline.ps1 needs PowerShell 7"
    return None


@case("the 8088's rule, by hand: operands, widths, signs, segments and where it stops")
def _():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    from unicorn import x86_const as R
    import sweep

    class FakeUnicorn:
        """Registers and memory as a test sets them, read the way the hook reads."""
        def __init__(self, regs, memory=()):
            self.regs, self.memory, self.stopped = dict(regs), dict(memory), False

        def reg_read(self, reg):
            return self.regs.get(reg, 0)

        def mem_read(self, at, n):
            return bytes(self.memory.get(at + i, 0) for i in range(n))

        def emu_stop(self):
            self.stopped = True

    def word_at(at, value):
        return {at: value & 0xFF, at + 1: (value >> 8) & 0xFF}

    # The operand, as the hook reads it from the decoded instruction.
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = True
    for code, want in ((b"\xF7\xF9", (2, ("reg", "cx"))),                   # idiv cx
                       (b"\xF6\xFB", (1, ("reg", "bl"))),                   # idiv bl
                       (b"\xF7\x7E\x08", (2, ("mem", None, "bp", None, 8))),
                       (b"\xF6\x78\x04", (1, ("mem", None, "bx", "si", 4))),
                       (b"\x26\xF7\x3D", (2, ("mem", "es", "di", None, 0))),
                       (b"\x66\xF7\xF8", None),                             # idiv eax
                       (b"\x66\xF7\x3F", None)):                            # dword [bx]
        got = sweep.idiv_form(next(md.disasm(code, 0)))
        if got != want:
            raise AssertionError(f"{code.hex()}: {got}, not {want}")
    for value, bits, want in ((0xFFFF, 16, -1), (0x7FFF, 16, 32767), (0x8000, 16, -32768),
                              (0x1FF, 8, -1), (0x80, 8, -128), (0x17F, 8, 127),
                              (0x100000005, 32, 5)):
        if sweep.signed(value, bits) != want:
            raise AssertionError(f"signed({value:#x}, {bits}) is {sweep.signed(value, bits)}")

    # The quotient, from DX:AX or AX and a divisor of every kind. The large
    # divisors need all their bits, so a wrong width shows; the signs take
    # every pair; -32769 and +32768 fault on both CPUs and are Unicorn's.
    prog = object.__new__(sweep.Program)
    W, B = ("reg", "cx"), ("reg", "bl")

    def dxax(n):
        return {R.UC_X86_REG_DX: (n >> 16) & 0xFFFF, R.UC_X86_REG_AX: n & 0xFFFF}
    cases = [
        (2, W, {**dxax(-229376), R.UC_X86_REG_CX: 7}, {}, -32768),
        (2, W, {**dxax(-229382), R.UC_X86_REG_CX: 7}, {}, -32768),
        (2, W, {**dxax(-229375), R.UC_X86_REG_CX: 7}, {}, None),
        (2, W, {**dxax(-229383), R.UC_X86_REG_CX: 7}, {}, None),
        (2, W, {**dxax(229376), R.UC_X86_REG_CX: 0xFFF9}, {}, -32768),       # / -7
        (2, W, {**dxax(-229376), R.UC_X86_REG_CX: 0xFFF9}, {}, None),        # +32768
        (2, W, {**dxax(655360000), R.UC_X86_REG_CX: 0xB1E0}, {}, -32768),    # / -20000
        (2, W, {**dxax(-229376), R.UC_X86_REG_CX: 0}, {}, None),
        (1, B, {R.UC_X86_REG_AX: 0xFC80, R.UC_X86_REG_BL: 7}, {}, -128),     # -896 / 7
        (1, B, {R.UC_X86_REG_AX: 896, R.UC_X86_REG_BL: 0xF9}, {}, -128),
        (1, B, {R.UC_X86_REG_AX: 12800, R.UC_X86_REG_BL: 0x9C}, {}, -128),   # / -100
        (1, B, {R.UC_X86_REG_AX: 0xFC81, R.UC_X86_REG_BL: 7}, {}, None),     # -895
        (1, B, {R.UC_X86_REG_AX: 0xFC7F, R.UC_X86_REG_BL: 7}, {}, -128),     # -897: -128.1
        (1, B, {R.UC_X86_REG_AX: 0xFC79, R.UC_X86_REG_BL: 7}, {}, None),     # -903: -129
    ]
    # Memory: [bp + 8] is SS's, [bx + si + 4] DS's, es:[di] ES's, and an
    # offset past 0xFFFF wraps. The wrong segment, or the index left out,
    # finds a 3 there instead of the 7.
    seg = {R.UC_X86_REG_SS: 0x2000, R.UC_X86_REG_DS: 0x3000, R.UC_X86_REG_ES: 0x4000}
    decoys = {**word_at(0x30108, 3), **word_at(0x20034, 3), **word_at(0x30014, 3),
              **word_at(0x30050, 3), **word_at(0x40010, 3), **word_at(0x31010, 3)}
    cases += [
        (2, ("mem", None, "bp", None, 8), {**dxax(-229376), **seg, R.UC_X86_REG_BP: 0x100},
         {**decoys, **word_at(0x20108, 7)}, -32768),
        (2, ("mem", None, "bx", "si", 4), {**dxax(-229376), **seg, R.UC_X86_REG_BX: 0x10,
                                          R.UC_X86_REG_SI: 0x20},
         {**decoys, **word_at(0x30034, 7)}, -32768),
        (2, ("mem", "es", "di", None, 0), {**dxax(655360000), **seg, R.UC_X86_REG_DI: 0x50},
         {**decoys, **word_at(0x40050, 0xB1E0)}, -32768),                    # / -20000
        (2, ("mem", None, "bx", "si", 0), {**dxax(-229376), **seg, R.UC_X86_REG_BX: 0xFFF0,
                                          R.UC_X86_REG_SI: 0x20},
         {**decoys, **word_at(0x30010, 7)}, -32768),
        (1, ("mem", None, "bx", None, 0), {R.UC_X86_REG_AX: 896, **seg, R.UC_X86_REG_BX: 0x1000},
         {**decoys, 0x31000: 0xF9}, -128),
    ]
    for size, operand, regs, memory, want in cases:
        got = prog._refused_by_8088(FakeUnicorn(regs, memory), size, operand)
        if got != want:
            raise AssertionError(f"{size}-byte IDIV of {operand} with {regs}: {got}, not {want}")

    # Where it stops: on an 8088 only, only at an IDIV, at the IDIV itself.
    form = (2, ("reg", "cx"))
    for cpu, given, want in (("8088", form, "divide: an 8088 refuses the quotient -32768"),
                             ("386", form, None), ("8088", None, None)):
        prog.cpu, prog.state = cpu, sweep.CaseState(None, None)
        uc = FakeUnicorn({**dxax(-229376), R.UC_X86_REG_CX: 7})
        prog._on_divide(uc, 0x1000, 0x10023, sweep.Insn("div", 2, given, "idiv cx"))
        st = prog.state
        if (st.end, uc.stopped) != (want, want is not None) or \
                (want and st.where != (0x1000, 0x23)):
            raise AssertionError(f"{cpu}, form {given}: end {st.end!r} at {st.where}, "
                                 f"stopped {uc.stopped}")

    # The limitations: every one, with the CPU's own third.
    for cpu, opening in (("8088", "The CPU is an 8088 in one respect only"),
                         ("386", "Unicorn implements DIV and IDIV as a later x86 does")):
        got = sweep.limitations(cpu)
        if len(got) != len(sweep.LIMITATIONS) + 1 or not got[2].startswith(opening) \
                or [l for i, l in enumerate(got) if i != 2] != sweep.LIMITATIONS:
            raise AssertionError(f"{cpu}: limitations {got}")
    return (f"7 operands decoded, 7 widths, {len(cases)} quotients, 3 places to stop or "
            f"not, both CPUs' limitations")


@case("the comparison's pieces and coverage give the answers worked out by hand")
def _():
    from types import SimpleNamespace
    import sweep
    case_ = SimpleNamespace(number=7, view={"g": 5, "h": 0xFFFF}, inputs={"x": 1})
    spec = SimpleNamespace(globals=[sweep.Global("g", 0x10, 0x10, 2, False, None, None),
                                    sweep.Global("h", 0x12, 0x12, 2, False, None, None)],
                           compare=["writes"])

    def refused(why, fn, *args):
        try:
            fn(*args)
        except sweep.ContractError as e:
            if why not in str(e):
                raise AssertionError(f"{fn.__name__}{args[:1]} refused, but: {e}")
            return
        except Exception as e:
            raise AssertionError(f"{fn.__name__}{args[:1]} raised {e!r}, not a contract error")
        raise AssertionError(f"{fn.__name__}{args[:1]} broke the contract and was taken")
    # Not numbers, and no answer: the contract refuses them, each for its reason.
    refused("ax is True, not a number", sweep.value_of, True, 0xFFFF, "ax", case_)
    refused("ax is '12', not a number", sweep.value_of, "12", 0xFFFF, "ax", case_)
    refused("returned True; return a number", sweep.candidate_outcome, {"result": True}, spec, case_)
    refused("returned None; return a number", sweep.candidate_outcome, {"result": None}, spec, case_)
    # dx:ax as a candidate returns it is 32 bits wide; a byte write is 8, at
    # the address its hex name gives.
    for given, want in ((0x89ABCDEF, 0x89ABCDEF), (0x189ABCDEF, 0x89ABCDEF)):
        got = sweep.candidate_outcome({"result": {"dx:ax": given}}, spec, case_)["dx:ax"]
        if got != want:
            raise AssertionError(f"dx:ax {given:#x} came back as {got:#x}")
    got = sweep.candidate_outcome({"result": {"writes": {"0x0123": 0x1FF}}}, spec,
                                  case_)["writes"]
    if got != {"g": 5, "h": 0xFFFF, "0x0123": 0xFF}:
        raise AssertionError(f"writes {got}")
    # The original's dx:ax: as given, else made from DX and AX, else nothing.
    for outcome, want in (({"fault": None, "dx:ax": 0x12345678}, 0x12345678),
                          ({"fault": None, "ax": 0x1234, "dx": 0xABCD}, 0xABCD1234),
                          ({"fault": None, "ax": 0x1234}, None),
                          ({"fault": None, "dx": 0xABCD}, None)):
        got = sweep.view(outcome, ["dx:ax"])
        if got != {"fault": None, "dx:ax": want}:
            raise AssertionError(f"view({outcome}): {got}")
    # A record says what changed, judged against each global as the case
    # began; h holds 0xffff throughout.
    original = {"fault": None, "writes": {"g": 5, "h": 0xFFFF}}
    candidate = {"fault": None, "writes": {"g": 6, "h": 0xFFFF}}
    got = sweep.record(case_, original, candidate, ["writes"], spec)
    want = {"case": 7, "inputs": {"x": 1}, "fields": ["writes"],
            "original": {"fault": None, "writes": {"g": 5, "h": 0xFFFF}},
            "candidate": {"fault": None, "writes": {"g": 6, "h": 0xFFFF}}, "original_at": None,
            "text": {"original": "writes nothing changed", "candidate": "writes g=0x6"}}
    if got != want:
        raise AssertionError(f"record {got}")

    # Coverage. CS is 0x4001, so the body's offsets are taken from 0x40010,
    # and the load segment 0x2000 makes it 5001 as reported. Two ranges:
    # inc ax / mov al, 1 / nop / nop / ret / nop at 5001:0010, and mov ax,
    # 0x1234 / nop / ret at 5001:0023 -- three bytes at an address that is 3
    # mod 4, so a + size - 1 differs from a ^ size - 1, a | size - 1 and the
    # rest. Only the first inc ax and the second nop ran: nine instructions,
    # two run, 22.2%. And 25 addresses outside the body ran.
    cs = sweep.IMAGE_SEG + 0x3001
    first = bytes([0x40, 0xB0, 0x01, 0x90, 0x90, 0xC3, 0x90])
    second = bytes([0xB8, 0x34, 0x12, 0x90, 0xC3])
    lo1, lo2 = (cs << 4) + 0x10, (cs << 4) + 0x23
    image = bytearray(lo2 - sweep.IMAGE_BASE + 0x10)
    image[lo1 - sweep.IMAGE_BASE:lo1 - sweep.IMAGE_BASE + len(first)] = first
    image[lo2 - sweep.IMAGE_BASE:lo2 - sweep.IMAGE_BASE + len(second)] = second
    program = SimpleNamespace(image=bytes(image), cs=cs, load_segment=0x2000)
    executed = {lo1, lo1 + 4} | {(cs << 4) + 0x100 + i for i in range(25)}
    got = sweep.coverage(program, [(lo1, lo1 + len(first) - 1), (lo2, lo2 + len(second) - 1)],
                         executed)
    want = {"available": True, "instructions": 9, "exercised": 2, "percent": 22.2,
            "unreached": [{"start": "5001:0011", "end": "5001:0013", "instructions": 2},
                          {"start": "5001:0015", "end": "5001:0016", "instructions": 2},
                          {"start": "5001:0023", "end": "5001:0027", "instructions": 3}],
            "executed_outside_body": 25,
            "outside_body": [f"5001:{0x100 + i:04x}" for i in range(20)]}
    if got != want:
        raise AssertionError(f"coverage {got}")
    got = sweep.coverage(program, [], set())
    if got != {"available": True, "instructions": 0, "exercised": 0, "percent": 0.0,
               "unreached": [], "executed_outside_body": 0, "outside_body": []}:
        raise AssertionError(f"coverage of nothing {got}")
    return ("the contract's refusals; dx:ax and byte writes at their widths; a record's "
            "text; coverage over two ranges, by hand")


@case("the same coverage against the body Ghidra gives rare and muldiv", needs=("ghidra",))
def _():
    folder = WORK / "pipeline"
    folder.mkdir()
    exe = folder / "SWEEP.EXE"
    shutil.copy(BUILT["sweep"][0], exe)
    env_ = dict(os.environ, PYTHON=sys.executable)
    env_.pop("DOS_DECOMPILER_FORCE_DRIFT", None)
    r = subprocess.run(["pwsh", "-NoProfile", "-File", str(TOOLS / "pipeline.ps1"), "-Exe", str(exe),
                        "-OutDir", str(folder / "out"), "-Ghidra", os.environ["GHIDRA_HOME"],
                        "-JavaHome", os.environ["JAVA_HOME"]], capture_output=True, text=True,
                       env=env_)
    if r.returncode != 0:
        raise AssertionError(f"pipeline exit {r.returncode}\n{(r.stdout + r.stderr)[-1500:]}")
    functions = folder / "out" / "functions.json"
    out = []
    for routine, spec, cand, want in (
            ("rare", rare_domain("rare-small", {"range": [0, 1000]}), py("rare"), (10, 8)),
            ("muldiv", muldiv_domain(), py("muldiv"), (8, 8))):
        args = [sys.executable, str(TOOLS / "emuverify.py"), "sweep", str(exe), at("sweep", routine),
                "--domain", str(spec), *cand, "--functions", str(functions),
                "--evidence", str(folder / f"{routine}.json"), "--quiet"]
        p = subprocess.run(args, capture_output=True, text=True,
                           env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        cov = json.loads((folder / f"{routine}.json").read_text(encoding="utf-8"))["result"]["coverage"]
        if p.returncode != 0 or (cov.get("instructions"), cov.get("exercised")) != want:
            raise AssertionError(f"{routine}: exit {p.returncode}, coverage {cov}, not {want}\n"
                                 f"{(p.stdout + p.stderr)[-800:]}")
        out.append(f"{routine} {want[1]} of {want[0]}")
    return ", ".join(out) + ", from the pipeline's functions.json"


def main():
    global WORK
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", help="run only the cases whose name contains this")
    args = ap.parse_args()
    if not (os.environ.get("NASM") or shutil.which("nasm")):
        print("sweep regress: nasm not found (set NASM); the fixtures cannot be assembled")
        return 77
    have = {"node": shutil.which("node") is not None}
    ghidra_why = ghidra_ready()
    have["ghidra"] = ghidra_why is None
    why = {"node": "node not on PATH; the JavaScript candidates need Node.js",
           "ghidra": ghidra_why}
    WORK = Path(tempfile.mkdtemp(prefix="sweep-regress-"))
    failures = skipped = run = through_ghidra = 0
    try:
        assemble("sweep", "sweep.asm")
        assemble("rebuild", "rebuild.asm")
        assemble("rebuild-wrong", "rebuild.asm", "WRONG")
        for name, fn, needs in CASES:
            if args.only and args.only not in name:
                continue
            missing = [n for n in needs if not have[n]]
            if missing:
                print(f"  SKIP  {name:<78} skipped: {why[missing[0]]}")
                skipped += 1
                continue
            run += 1
            through_ghidra += "ghidra" in needs
            try:
                print(f"  PASS  {name:<78} {fn()}", flush=True)
            except AssertionError as e:
                print(f"  FAIL  {name:<78} {e}", flush=True)
                failures += 1
    finally:
        shutil.rmtree(WORK, ignore_errors=True)
    print()
    if failures:
        print(f"{failures} of {run} sweep checks failed.")
        return 1
    if skipped:
        print(f"{run} sweep checks pass; {skipped} skipped.")
        return 0
    print(f"All {run} sweep checks pass, {through_ghidra} of them through Ghidra.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
