#!/usr/bin/env python3
"""Checks for comdiff.py, the routine-by-routine comparison of two .COM files.

The fixtures are two sibling programs written for the purpose (fixtures/),
related the way Moon Bugs is to Rollo: cmpb.asm's header lists what each of
its routines is to cmpa.asm, and every line of that table is checked here --
the kind, the counterpart, and for an instruction-identical pair whether
running both confirms it. Both are assembled with NASM and reconstructed
with comrec.py, so the comparison reads exactly what a user's listings hold.

Then the refusals: a listing that does not rebuild its file, and an MZ.

Usage:
    python tests/comdiff/regress.py [--nasm PATH]
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
sys.path.insert(0, str(ROOT / "tools"))

CASES = []


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


class Built:
    """Both fixtures assembled, reconstructed, and their labels' offsets."""

    def __init__(self, nasm, work):
        self.nasm, self.work = nasm, work
        self.com, self.asm, self.at = {}, {}, {}
        for name in ("cmpa", "cmpb"):
            src = HERE / "fixtures" / f"{name}.asm"
            com, lst = work / f"{name}.com", work / f"{name}.lst"
            subprocess.run([nasm, "-f", "bin", "-o", str(com), "-l", str(lst), str(src)],
                           check=True)
            asm = work / f"{name}-comrec.asm"
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "comrec.py"), str(com),
                                "--out", str(asm), "--nasm", nasm],
                               capture_output=True, text=True)
            if "BYTE-IDENTICAL" not in r.stdout:
                raise SystemExit(f"comrec did not rebuild {name}: {r.stdout[-400:]}")
            self.com[name], self.asm[name] = com, asm
            self.at[name] = labels(lst)


def labels(lst):
    """{label: file offset} from NASM's listing: a label line carries no
    offset, so it takes the next line's."""
    out, pending = {}, []
    for raw in lst.read_text(encoding="latin-1").splitlines():
        # The bytes column carries relocations in brackets: `A1[D100]`.
        m = re.match(r"\s*\d+\s+([0-9A-F]{8})\s+[0-9A-F]\S*\s+(?:(\w+):)?", raw)
        if m:
            for name in pending + ([m.group(2)] if m.group(2) else []):
                out[name] = int(m.group(1), 16)
            pending = []
            continue
        m = re.match(r"\s*\d+\s+(\w+):", raw)
        if m:
            pending.append(m.group(1))
    return out


B = None          # set in main()
RESULT = None


def row(name):
    at = B.at["cmpb"][name]
    for r in RESULT["pairs"]:
        if r["b"] == at:
            return r
    raise AssertionError(f"no routine of B starts at {name} (0x{at:05X})")


def expect(name, status, counterpart=None):
    r = row(name)
    if r["status"] != status:
        raise AssertionError(f"{name}: {r['status']}, not {status}")
    if counterpart and B.at["cmpa"][counterpart] not in r.get("a", []):
        raise AssertionError(f"{name}: counterpart {r.get('a')}, not A's {counterpart}")
    return r


@case("the same bytes: byte-identical")
def _():
    expect("times_ten", "byte-identical", "times_ten")
    return "times_ten"


@case("the same instructions with moved globals: confirmed by running both")
def _():
    r = expect("accumulate", "instruction-identical", "accumulate")
    if r["emulation"]["result"] != "confirmed":
        raise AssertionError(f"emulation: {r['emulation']}")
    return "confirmed on 4 vectors"


@case("the numbers that differ map A's globals onto B's")
def _():
    r = row("accumulate")
    want = [("address", B.at["cmpa"][g] + 0x100, B.at["cmpb"][g] + 0x100)
            for g in ("counter", "step", "result")]
    have = [tuple(n) for n in r["numbers"]]
    missing = [w for w in want if w not in have]
    if missing:
        raise AssertionError(f"missing {missing}; have {have}")
    return f"{len(want)} globals paired, and the callee's address"


@case("the same instructions, a different count: emulation says they differ")
def _():
    r = expect("find_key", "instruction-identical", "find_key")
    e = r["emulation"]
    if e["result"] != "differs" or "return frame" not in e["why"]:
        raise AssertionError(f"emulation: {e}")
    return e["why"]


@case("one instruction inserted: similar, with its score")
def _():
    r = expect("halve_twice", "similar", "halve_twice")
    if not 0.85 <= r["score"] < 1.0:
        raise AssertionError(f"score {r['score']}")
    return f"score {r['score']}"


@case("a routine only B has: no counterpart")
def _():
    r = expect("beep", "no counterpart")
    if r["best_score"] >= 0.85:
        raise AssertionError(f"best score {r['best_score']}")
    return f"nearest scored {r['best_score']}"


@case("a three-byte routine is too small to classify")
def _():
    expect("one", "too small")
    return "one"


@case("a switch's cases are part of it, not routines")
def _():
    starts = {r["b"] for r in RESULT["pairs"]}
    cases = [B.at["cmpb"][f"case{i}"] for i in range(4)]
    if starts & set(cases):
        raise AssertionError(f"cases read as routines: {sorted(starts & set(cases))}")
    r = expect("pick", "instruction-identical", "pick")
    if r["data_same"]:
        raise AssertionError("the table moved, so its words cannot be the same")
    if RESULT["b"]["jump_table_cases"] != 4:
        raise AssertionError(f"{RESULT['b']['jump_table_cases']} cases counted")
    return "4 cases inside pick; its table differs, its instructions do not"


@case("a handler nothing branches to is a routine, and iret ends it")
def _():
    r = expect("tick", "instruction-identical", "tick")
    if RESULT["b"]["starts"]["nothing branches here"] != 1:
        raise AssertionError(f"starts: {RESULT['b']['starts']}")
    if r["emulation"]["result"] != "confirmed":
        raise AssertionError(f"emulation: {r['emulation']}")
    return "tick, confirmed"


@case("the entry: calls to other routines are numbers, the rest agrees")
def _():
    r = expect("start", "instruction-identical", "start")
    kinds = {n[0] for n in r["numbers"]}
    if "target" not in kinds:
        raise AssertionError(f"numbers {r['numbers']}")
    return "instruction-identical, call targets differ"


@case("every row is accounted for")
def _():
    c = RESULT["counts"]
    want = {"byte-identical": 1, "instruction-identical": 5, "similar": 1,
            "no counterpart": 1, "too small": 1}
    if c != want:
        raise AssertionError(f"counts {c}")
    e = RESULT["emulation"]
    if e != {"confirmed": 4, "differs": 1, "uninformative": 0, "not run": 0}:
        raise AssertionError(f"emulation {e}")
    return "1 / 5 / 1 / 1 / 1; 4 confirmed, 1 differs"


@case("a program against itself: every routine byte-identical to itself")
def _():
    import comdiff
    res = comdiff.compare(B.com["cmpa"], B.asm["cmpa"], B.com["cmpa"], B.asm["cmpa"],
                          emulate=False, nasm=B.nasm)
    wrong = [r for r in res["pairs"] if r["status"] not in ("byte-identical", "too small")
             or (r["status"] == "byte-identical" and r["b"] not in r["a"])]
    if wrong:
        raise AssertionError(f"{len(wrong)} rows: {wrong[:2]}")
    return f"{res['counts']['byte-identical']} of {res['a']['considered']}"


@case("without emulation the pairs say why they were not run")
def _():
    import comdiff
    res = comdiff.compare(B.com["cmpa"], B.asm["cmpa"], B.com["cmpb"], B.asm["cmpb"],
                          emulate=False, nasm=B.nasm)
    if res["emulation"] is not None or res["emulation_skipped"] != "not asked for" \
            or any("emulation" in r for r in res["pairs"]):
        raise AssertionError(f"{res['emulation']}, {res['emulation_skipped']}")
    return "not asked for"


@case("a listing that does not rebuild its file is refused")
def _():
    import comdiff
    bad = B.work / "cmpb-changed.com"
    data = bytearray(B.com["cmpb"].read_bytes())
    data[B.at["cmpb"]["times_ten"]] ^= 0xFF
    bad.write_bytes(bytes(data))
    try:
        comdiff.compare(B.com["cmpa"], B.asm["cmpa"], bad, B.asm["cmpb"], nasm=B.nasm)
    except comdiff.Refused as e:
        if "does not rebuild" not in str(e) or "comrec" not in str(e):
            raise AssertionError(f"message: {e}")
        return "refused, and told to regenerate it"
    raise AssertionError("compared a listing of another file")


@case("an MZ is refused, with where to take it")
def _():
    import comdiff
    mz = B.work / "x.exe"
    mz.write_bytes(b"MZ" + bytes(62))
    try:
        comdiff.compare(mz, B.asm["cmpa"], B.com["cmpb"], B.asm["cmpb"], nasm=B.nasm)
    except comdiff.Refused as e:
        if "bindiff.py or emuverify.py" not in str(e):
            raise AssertionError(f"message: {e}")
        return "refused"
    raise AssertionError("compared an MZ")


@case("the envelope: identical pairs as evidence, the one that differs unknown")
def _():
    import comdiff
    env = comdiff.envelope(RESULT)
    kinds = [e["kind"] for e in env["evidence"]]
    if env["status"] != "ok" or kinds.count("listing-rebuilds") != 2 \
            or kinds.count("instruction-identical") != 5 or kinds.count("byte-identical") != 1:
        raise AssertionError(f"status {env['status']}, kinds {kinds}")
    if len(env["unknowns"]) != 1 or "behave differently" not in env["unknowns"][0]:
        raise AssertionError(f"unknowns {env['unknowns']}")
    json.dumps(env)
    return f"{len(env['evidence'])} items, 1 unknown"


def main():
    global B, RESULT
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nasm", default=os.environ.get("NASM") or shutil.which("nasm"))
    args = ap.parse_args()
    if not args.nasm or not Path(args.nasm).exists():
        print("NASM not found (pass --nasm, set NASM, or put it on PATH)")
        return 77
    import comdiff
    with tempfile.TemporaryDirectory() as td:
        B = Built(args.nasm, Path(td))
        RESULT = comdiff.compare(B.com["cmpa"], B.asm["cmpa"], B.com["cmpb"], B.asm["cmpb"],
                                 nasm=args.nasm)
        failures = 0
        for name, fn in CASES:
            try:
                print(f"  PASS  {name:<72} {fn()}")
            except AssertionError as e:
                print(f"  FAIL  {name:<72} {e}")
                failures += 1
    print()
    if failures:
        print(f"{failures} of {len(CASES)} checks failed.")
        return 1
    print(f"All {len(CASES)} comdiff checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
