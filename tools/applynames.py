#!/usr/bin/env python3
"""
applynames.py -- Write names into a pipeline's Ghidra project, and say exactly
what happened to each one.

Why a wrapper
-------------
ApplyNames.java does the work inside Ghidra: it validates every entry of a
mapping before writing any, writes them all in one transaction, reads each
name and comment back, and aborts the whole transaction on any difference.
What it cannot do is report back. A headless run exits 0 whatever its script
did -- measured on Ghidra 12.1.2, even a script that throws -- so a caller
such as pipeline.ps1, or prompt 06's server, could not tell a batch that was
applied from one that was refused or rolled back. This runs the script, reads
the record it leaves, and turns it into an evidence envelope and an exit
status, the way loadimage.py turns DumpLoadImage.java's dump into one.

The mapping is tools/match.py's --json output or tools/anchors.py's --names
output; both are {"mapping": [{"source", "binary", "score", ...}]}. An entry
may also carry "comment" (the plate comment) and "inline_comment" (the
end-of-line comment at the entry): a string sets it, "" clears it, a missing
field leaves it alone.

What it does not do
-------------------
Judge a name. Readback holds what Ghidra stored to what was asked; whether
the name is *right* is the evidence's job, and the reason anchors.py and
match.py score what they propose.

Usage:
    python applynames.py names.json out/                 # out/ from pipeline.ps1
    python applynames.py names.json out/ --dryrun        # validate, write nothing
    python applynames.py names.json out/ --min-score 0.5 --certain 0.8

Writes out/applynames-result.json (or --evidence). Exit codes: 0 applied, or a
dry run with nothing refused; 1 rolled back, nothing kept, and a read-only
pass confirms it; 3 blocked -- refused before writing, or the script could
not run; 4 rolled back, but the read-only pass found the batch's changes
still there (status mismatch).

A rolled-back batch is confirmed rather than assumed. The abort takes effect
only when the writing script ends, so that script cannot see it; a second,
read-only headless run reads every entry back and holds each name and
comment to what it was before the batch. Each headless run is stopped after
--timeout seconds (default 900).
"""

import argparse
import json
import os
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402

TOOLS = Path(__file__).resolve().parent
SCRIPTS = TOOLS / "ghidra_scripts"

LIMITATIONS = [
    "Readback holds what Ghidra stored to what was asked. It says nothing about "
    "whether a name is right: that rests on the evidence that proposed it.",
    "A rolled-back run discards every change the script made in that run: it "
    "aborts the transaction the headless framework opened for the script, which "
    "Ghidra 12.1.2 was measured to roll back whole. The names the program had "
    "before the run stand.",
    "The per-entry record is the script's own account. That the database holds "
    "it afterwards is shown by re-exporting, not by this record.",
]

LEVELS = {"applied": "info", "would-apply": "info", "skipped-below-floor": "warn",
          "refused": "blocker", "rolled-back": "blocker"}


def headless():
    home = os.environ.get("GHIDRA_HOME")
    if not home:
        return None, "GHIDRA_HOME is not set; point it at a Ghidra installation (env.ps1)"
    for name in ("analyzeHeadless.bat", "analyzeHeadless"):
        p = Path(home) / "support" / name
        if p.exists():
            return p, None
    return None, f"no analyzeHeadless under {home}\\support"


def program_name(outdir, given):
    if given:
        return given
    try:
        data = json.loads((Path(outdir) / "functions.json").read_text(encoding="utf-8"))
        return Path(data["target"]["path"]).name
    except (OSError, ValueError, KeyError, TypeError):
        return None


def blocked(reason, outdir):
    return evidence.envelope("applynames", None, status="blocked",
                             result={"phase": "not run", "reason": reason,
                                     "outdir": str(outdir)},
                             limitations=LIMITATIONS)


HEADLESS_TIMEOUT = 900     # seconds for one headless run before it is stopped


def headless_run(args, timeout):
    """Run analyzeHeadless; (log, None), or (None, why) when it ran out of time."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, errors="replace",
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, (f"the headless run did not finish in {timeout} s and was stopped; "
                      f"pass a longer timeout if the project is large")
    return r.stdout + r.stderr, None


def confirm_rollback(record, readback):
    """Every rolled-back entry's name and comments, read back in a later run,
    against what they were before the batch. Returns the differences."""
    now = {e["index"]: e for e in readback["entries"]}
    differences = []
    for e in record["entries"]:
        if e["outcome"] != "rolled-back":
            continue
        r = now.get(e["index"]) or {}
        if not r.get("found"):
            differences.append(f"entry {e['index']} at {e['address']}: no function there now")
            continue
        for what, before, after in (
                ("name", "previous_name", "current_name"),
                ("PRE comment", "previous_note", "current_note"),
                ("plate comment", "previous_comment", "current_comment"),
                ("EOL comment", "previous_inline_comment", "current_inline_comment")):
            if e.get(before) != r.get(after):
                differences.append(f"entry {e['index']} at {e['address']}: {what} is "
                                   f"{r.get(after)!r}, was {e.get(before)!r} before the batch")
    return differences


def run(mapping, outdir, dryrun=False, min_score=None, certain=None, program=None,
        project=None, project_name="target", timeout=HEADLESS_TIMEOUT):
    """Run ApplyNames.java and return (envelope, exit code)."""
    outdir = Path(outdir)
    script, why = headless()
    if script is None:
        return blocked(why, outdir), 3
    program = program_name(outdir, program)
    if not program:
        return blocked(f"no program name: {outdir / 'functions.json'} is missing or "
                       f"records no target; pass --program", outdir), 3
    project = Path(project) if project else outdir / "ghidra-project"
    if not (project / f"{project_name}.gpr").exists():
        return blocked(f"no Ghidra project at {project / (project_name + '.gpr')}; run "
                       f"tools/pipeline.ps1 first, or pass --project", outdir), 3

    record_path = outdir / "applynames-record.json"
    if record_path.exists():
        record_path.unlink()
    args = [str(script), str(project), project_name, "-process", program, "-noanalysis",
            "-scriptPath", str(SCRIPTS), "-postScript", "ApplyNames.java",
            str(Path(mapping).resolve())]
    if min_score is not None or certain is not None:
        args += [str(min_score if min_score is not None else 0.45),
                 str(certain if certain is not None else 0.70)]
    if dryrun:
        args.append("dryrun")
    # out:DIR, not out=DIR: cmd.exe splits a headless argument at '='.
    args.append(f"out:{outdir.resolve()}")
    log, why = headless_run(args, timeout)
    if log is None:
        return blocked(why, outdir), 3
    try:
        record = json.loads(record_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        tail = "\n".join(log.strip().splitlines()[-12:])
        return blocked(f"ApplyNames.java left no record ({e}); the end of the headless "
                       f"log:\n{tail}", outdir), 3

    # A rollback takes effect only when the writing script ends (measured,
    # knowledge/04-pitfalls.md), so that script cannot see it. A second,
    # read-only run reads every entry back and holds it to what it was
    # before the batch.
    rollback = None
    if record["phase"] == "rolled-back":
        readback_path = outdir / "applynames-readback.json"
        if readback_path.exists():
            readback_path.unlink()
        started = time.perf_counter()
        log2, why = headless_run(
            [str(script), str(project), project_name, "-process", program, "-noanalysis",
             "-readOnly", "-scriptPath", str(SCRIPTS), "-postScript", "ApplyNames.java",
             str(Path(mapping).resolve()), "readback", f"out:{outdir.resolve()}"], timeout)
        seconds = time.perf_counter() - started
        try:
            readback = json.loads(readback_path.read_text(encoding="utf-8"))
            differences = confirm_rollback(record, readback)
            rollback = {"checked": sum(1 for e in record["entries"]
                                       if e["outcome"] == "rolled-back"),
                        "confirmed": not differences, "differences": differences,
                        "readback": str(readback_path)}
        except (OSError, ValueError, KeyError) as e:
            tail = "\n".join((log2 or why or "").strip().splitlines()[-12:])
            rollback = {"confirmed": False, "checked": 0,
                        "differences": [f"the read-only pass left no readable record ({e}): "
                                        f"{tail}"], "readback": str(readback_path)}
        rollback["seconds"] = round(seconds, 1)

    entries = record["entries"]
    counts = Counter(e["outcome"] for e in entries)
    phase = record["phase"]
    status = "ok" if phase in ("applied", "dry-run") else "blocked"
    if rollback is not None and not rollback["confirmed"]:
        status = "mismatch"   # said rolled back, and a later read disagrees
    items = []
    for e in entries:
        name = e.get("applied_name") or e.get("requested_name")
        item = {"kind": "name", "level": LEVELS.get(e["outcome"], "warn"),
                "claim": f"{name} at {e['address']}: {e['outcome']}",
                "location": {"address": e["address"]},
                "value": {"requested": e["requested_name"], "applied": e.get("applied_name"),
                          "stored": e.get("stored_name"), "outcome": e["outcome"]}}
        if e.get("reason"):
            item["detail"] = e["reason"]
        items.append(item)
    for p in record.get("problems") or []:
        items.append({"kind": "mapping", "level": "blocker", "claim": p})
    if rollback is not None:
        items.append({"kind": "rollback",
                      "level": "info" if rollback["confirmed"] else "mismatch",
                      "claim": ("rolled back, confirmed by a read-only pass"
                                if rollback["confirmed"] else
                                "rolled back, but a read-only pass found the batch's changes"),
                      "value": {"checked": rollback["checked"],
                                "differences": rollback["differences"]}})
    result = {
        "phase": phase, "transaction": record["transaction"], "dryrun": record["dryrun"],
        "mapping": record["mapping"], "program": record["program"],
        "min_score": record["min_score"], "certain_score": record["certain_score"],
        "counts": dict(sorted(counts.items())), "problems": record.get("problems") or [],
        "fault_injected": record.get("fault_injected"),
        "script_sha256": record["script_sha256"],
        "record": str(record_path),
        "entries": [{k: e.get(k) for k in (
            "index", "address", "requested_name", "score", "applied_name", "provisional",
            "previous_name", "stored_name", "note", "stored_note", "comment_given",
            "comment", "stored_comment", "inline_comment_given", "inline_comment",
            "stored_inline_comment", "long_routine", "outcome", "reason")} for e in entries],
        "rollback": rollback,
    }
    target = record.get("target") or {}
    env = evidence.envelope("applynames", {"path": target.get("path"), "size": target.get("size"),
                                           "sha256": target.get("sha256")},
                            status=status, result=result, evidence=items,
                            limitations=LIMITATIONS)
    if status == "ok":
        code = 0
    elif phase == "rolled-back":
        code = 1 if rollback["confirmed"] else 4
    else:
        code = 3
    return env, code


def summary(env):
    r = env["result"]
    if r.get("phase") == "not run":
        return [f"applynames: blocked: {r['reason']}"]
    counts = ", ".join(f"{n} {k}" for k, n in r["counts"].items()) or "no entries"
    phase = r["phase"]
    rollback = r.get("rollback")
    if rollback is not None:
        phase += (f", confirmed by a read-only pass ({rollback['checked']} entries, "
                  f"{rollback['seconds']} s)" if rollback["confirmed"] else
                  ", NOT confirmed: a read-only pass found the batch's changes")
    out = [f"applynames: {phase} ({counts}) -- {r['program']}, transaction "
           f"{r['transaction']}"]
    for d in (rollback or {}).get("differences") or []:
        out.append(f"  rollback: {d}")
    for p in r["problems"]:
        out.append(f"  mapping: {p}")
    for e in r["entries"]:
        if e["outcome"] in ("applied", "would-apply"):
            out.append(f"  {e['address']}  {e['outcome']:<12} {e['applied_name']}"
                       + (f"  (stored {e['stored_name']})" if e["stored_name"] else ""))
        else:
            out.append(f"  {e['address']}  {e['outcome']:<12} {e['requested_name']}: "
                       f"{e['reason']}")
    if r.get("fault_injected"):
        out.append(f"  (a fault was injected for a test: {r['fault_injected']})")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mapping", help="match.py --json or anchors.py --names output")
    ap.add_argument("outdir", help="a pipeline.ps1 output folder (its ghidra-project/ "
                                   "and functions.json)")
    ap.add_argument("--dryrun", action="store_true", help="validate and report; write nothing")
    ap.add_argument("--min-score", type=float, help="skip entries scoring below this (0.45)")
    ap.add_argument("--certain", type=float,
                    help="names scoring below this get __maybe (0.70)")
    ap.add_argument("--program", help="the program's name in the project; default: the "
                                      "file functions.json records")
    ap.add_argument("--project", help="the Ghidra project folder; default OUTDIR/ghidra-project")
    ap.add_argument("--project-name", default="target")
    ap.add_argument("--evidence", help="write the envelope here; default "
                                       "OUTDIR/applynames-result.json")
    ap.add_argument("--timeout", type=int, default=HEADLESS_TIMEOUT,
                    help=f"seconds for each headless run (default {HEADLESS_TIMEOUT})")
    args = ap.parse_args()
    env, code = run(args.mapping, args.outdir, args.dryrun, args.min_score, args.certain,
                    args.program, args.project, args.project_name, args.timeout)
    evidence.write(env, args.evidence or str(Path(args.outdir) / "applynames-result.json"))
    for line in summary(env):
        print(line)
    return code


if __name__ == "__main__":
    sys.exit(main())
