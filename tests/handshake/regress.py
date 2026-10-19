#!/usr/bin/env python3
"""
regress.py -- Run the real pipeline through Ghidra and hold it to its profile.

tests/evidence/ checks the handshake's comparison against exports written by
hand. This checks the part that hand-written exports cannot: that Ghidra,
driven by pipeline.ps1, really does what tools/analysis_profile.py says it will, that
ExportDecompiledC.java really observes it, and that a drift really stops the
run.

Two pipeline runs over tests/evidence/fixtures/smallc.asm:

1. Plain. profile.json is written and its profile_id recomputes;
   functions.json keeps every field it always had and gains `target`, whose
   SHA-256 matches the executable, and `observed_profile`, whose every field
   matches the profile -- the load segment 0x1000, the recovery hash of the
   RecoverFunctions.java in this checkout. handshake.json says verified.
2. With DOS_DECOMPILER_FORCE_DRIFT=load_segment=0x2000. The pipeline must
   exit non-zero with a message naming load_segment, the expected 0x2000 and
   the observed 0x1000.

Then, without Ghidra, the first run's export is checked against a profile that
expects no recovery: the recovery mark RecoverFunctions left in the program
has to be what makes that fail.

Needs NASM, Ghidra (GHIDRA_HOME), a JDK (JAVA_HOME) and pwsh. Without any of
them it says which and exits 77, which tests/run-all.ps1 reports as a skip.
About a minute.

Usage:
    python tests/handshake/regress.py
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TOOLS = ROOT / "tools"
FIXTURE = ROOT / "tests" / "evidence" / "fixtures" / "smallc.asm"
sys.path.insert(0, str(TOOLS))
import evidence                                          # noqa: E402

# The fields functions.json has always carried. A consumer written before
# this change reads these and nothing else, so every one must still be there.
OLD_TOP_LEVEL = ("program", "language", "image_base", "decompiled_ok",
                 "decompiled_failed", "functions")
OLD_PER_FUNCTION = ("name", "entry", "size", "thunk", "external",
                    "calling_convention", "return_type", "param_count", "params",
                    "decompiled", "instruction_count", "blocks", "edges", "loops",
                    "returns", "indirect_jumps", "cyclomatic", "calls", "scalars",
                    "interrupts", "io_ports", "strings", "data_refs", "mnemonics")
CRLF, LF = bytes([13, 10]), bytes([10])

OBSERVED = ("loader", "language", "compiler_spec", "image_base", "load_segment",
            "address_convention", "ghidra_version", "recovery")


def prerequisites():
    """(nasm, ghidra, java, pwsh), or the reason one is missing."""
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    if not nasm or not Path(nasm).exists():
        return None, "nasm not found (set NASM)"
    ghidra = os.environ.get("GHIDRA_HOME")
    if not ghidra or not any((Path(ghidra) / "support" / n).exists()
                             for n in ("analyzeHeadless.bat", "analyzeHeadless")):
        return None, "Ghidra not found (set GHIDRA_HOME)"
    java = os.environ.get("JAVA_HOME")
    if not java or not Path(java).exists():
        return None, "JDK not found (set JAVA_HOME)"
    pwsh = shutil.which("pwsh")
    if not pwsh:
        return None, "pwsh not found; pipeline.ps1 needs PowerShell 7"
    return (nasm, ghidra, java, pwsh), None


def pipeline(pwsh, exe, out, ghidra, java, drift=None):
    env = dict(os.environ)
    # pipeline.ps1 calls `python`; make it this interpreter.
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    env.pop("DOS_DECOMPILER_FORCE_DRIFT", None)
    if drift:
        env["DOS_DECOMPILER_FORCE_DRIFT"] = drift
    r = subprocess.run([pwsh, "-NoProfile", "-File", str(TOOLS / "pipeline.ps1"),
                        "-Exe", str(exe), "-OutDir", str(out),
                        "-Ghidra", ghidra, "-JavaHome", java],
                       capture_output=True, text=True, env=env)
    return r.returncode, r.stdout + r.stderr


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_plain(out, exe):
    """[(ok, what)] for the first run's outputs."""
    results = []

    def expect(ok, what):
        results.append((bool(ok), what))
        return ok

    prof = json.loads((out / "profile.json").read_text(encoding="utf-8"))
    p = prof["profile"]
    body = {k: v for k, v in p.items() if k not in ("profile_id", "toolkit_version")}
    expect(p["profile_id"] == hashlib.sha256(
        evidence.canonical(body).encode("ascii")).hexdigest(),
        "profile.json: profile_id recomputes")
    expect(prof["target"]["sha256"] == sha(exe), "profile.json: names this executable")

    fj = json.loads((out / "functions.json").read_text(encoding="utf-8"))
    missing = [k for k in OLD_TOP_LEVEL if k not in fj]
    expect(not missing, "functions.json: every old top-level field present"
           + (f" (missing {missing})" if missing else ""))
    lacking = sorted({k for f in fj["functions"] for k in OLD_PER_FUNCTION
                      if k not in f})
    expect(fj["functions"] and not lacking,
           f"functions.json: {len(fj['functions'])} functions, every old field "
           f"present" + (f" (missing {lacking})" if lacking else ""))

    t = fj.get("target") or {}
    expect(t.get("sha256") == sha(exe) and t.get("size") == exe.stat().st_size,
           f"functions.json: target is this executable ({t.get('size')} bytes, "
           f"{str(t.get('sha256'))[:12]})")
    expect(Path(t.get("path", "")).resolve() == exe.resolve(),
           "functions.json: target.path opens as written")

    o = fj.get("observed_profile") or {}
    for field in OBSERVED:
        expect(o.get(field) == p.get(field),
               f"observed {field} = {o.get(field)!r}, profile {p.get(field)!r}")
    expect(o.get("load_segment") == "0x1000", "observed load segment is 0x1000")
    # The rule, written out: the script's bytes with CRLF read as LF. On a
    # checkout with CRLF endings this is what proves the Java side folds them
    # the way Python does.
    recover = (TOOLS / "ghidra_scripts" / "RecoverFunctions.java").read_bytes()
    folded = hashlib.sha256(recover.replace(CRLF, LF)).hexdigest()
    endings = "CRLF" if CRLF in recover else "LF"
    expect((o.get("recovery") or {}).get("ran") is True and
           o["recovery"].get("script_sha256") == folded,
           f"observed recovery: ran, and the script in this checkout "
           f"({endings} here, hashed as LF)")
    off = [f["entry"] for f in fj["functions"] if not f["entry"].startswith("1000:")]
    expect(not off, "every entry is in segment 1000" + (f" (not {off})" if off else ""))

    hs = json.loads((out / "handshake.json").read_text(encoding="utf-8"))
    expect(hs["status"] == "verified" and not hs["result"]["drift"],
           f"handshake.json: {hs['status']}")
    return results


def main():
    found, why = prerequisites()
    if not found:
        print(f"handshake regress: {why}; nothing to test")
        return 77
    nasm, ghidra, java, pwsh = found

    work = Path(tempfile.mkdtemp(prefix="handshake-regress-"))
    results = []
    try:
        exe = work / "SMALLC.EXE"
        r = subprocess.run([nasm, "-f", "bin", "-o", str(exe), str(FIXTURE)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"FAIL  nasm could not build the fixture:\n{r.stderr}")
            return 1

        code, log = pipeline(pwsh, exe, work / "plain", ghidra, java)
        results.append((code == 0, f"plain run exits 0 (got {code})"))
        if code != 0:
            print(log[-3000:])
        else:
            results += check_plain(work / "plain", exe)

        code, log = pipeline(pwsh, exe, work / "drift", ghidra, java,
                             drift="load_segment=0x2000")
        want = "profile drift: load_segment: expected 0x2000, observed 0x1000"
        results.append((code != 0, f"forced drift stops the pipeline (exit {code})"))
        results.append((want in log, f"and names it: {want!r}"))
        hs_path = work / "drift" / "handshake.json"
        if hs_path.exists():
            hs = json.loads(hs_path.read_text(encoding="utf-8"))
            results.append((hs["status"] == "mismatch" and
                            hs["result"]["drift"] == ["load_segment"],
                            f"handshake.json: {hs['status']}, drift "
                            f"{hs['result']['drift']}"))
        else:
            results.append((False, "handshake.json written for the drifted run"))

        # Without Ghidra: the first export, against a profile expecting no
        # recovery. Only the mark RecoverFunctions left can make this differ.
        if (work / "plain" / "functions.json").exists():
            prof = work / "no-recovery-profile.json"
            env = dict(os.environ)
            env.pop("DOS_DECOMPILER_FORCE_DRIFT", None)
            subprocess.run([sys.executable, str(TOOLS / "analysis_profile.py"), "write",
                            "--exe", str(exe), "--ghidra", ghidra, "--out",
                            str(prof), "--skip-recovery"],
                           capture_output=True, env=env, check=True)
            r = subprocess.run([sys.executable, str(TOOLS / "analysis_profile.py"), "check",
                                "--profile", str(prof), "--functions",
                                str(work / "plain" / "functions.json")],
                               capture_output=True, text=True)
            results.append((r.returncode == 1 and
                            "profile drift: recovery.ran: expected False, observed True"
                            in r.stdout,
                            "a profile expecting no recovery refuses an export "
                            "that had it"))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    for ok, what in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {what}")
    failed = sum(1 for ok, _ in results if not ok)
    print()
    if failed:
        print(f"{failed} of {len(results)} handshake checks failed.")
        return 1
    print(f"All {len(results)} handshake checks pass, through Ghidra.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
