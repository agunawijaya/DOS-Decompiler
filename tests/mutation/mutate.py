#!/usr/bin/env python3
"""
mutate.py -- Mutation testing of the comparison code, with cosmic-ray.

A test that passes whatever the code does is counted as evidence and is not.
This changes the code in small ways -- a flipped comparison, a dropped
branch, a changed constant -- and runs the tests against each change. A
change no test notices is a survivor: a gap in the tests, a change that
makes no difference (an equivalent mutant), or code that does nothing.

What is mutated, and by which tests, is scope.toml: one [[target]] per
module or set of functions, each with the test command that should catch a
change there. known.toml lists the survivors already looked at, each
classified as equivalent or as a code problem, with the reason.

How it runs. The working tree -- tracked files and new ones, as they are on
disk now -- is copied once per worker into a temporary folder, and one
cosmic-ray HTTP worker is started in each copy. A worker applies a mutation
to its own copy, runs the test command there, and puts the file back; the
working tree is never written. Before a target's mutants are sent out, its
test command is run once on the unmutated code, and the target stops there
unless that passes: cosmic-ray's own baseline, under the HTTP distributor,
reports success without running anything when no worker answers.

Reading the result. One line per target: mutants in scope, killed (of them,
by timeout), survived, and of the survivors how many known.toml explains.
Each target's survivors are written to OUT/<target>.survivors.txt with the
function, the line and the diff, and the session to OUT/<target>.sqlite for
cr-report or cr-html. Exit 0 when every survivor is explained, 1 when one is
not, 2 when a target could not be run.

Requires cosmic-ray (pip install cosmic-ray; measured with 8.7.0), in any
environment: give its executable with --cosmic-ray or COSMIC_RAY, or have it
on PATH. The tests run with --python, $PYTHON, or this interpreter.

Usage:
    python tests/mutation/mutate.py [--only NAME ...] [--workers N]
                                    [--python PATH] [--cosmic-ray PATH] [--out DIR]
"""

import argparse
import ast
import hashlib
import json
import os
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent

try:
    import tomllib
except ImportError:                         # Python 3.10 and older
    tomllib = None


def load_toml(path):
    if tomllib is None:
        sys.exit("mutate.py needs Python 3.11 or later (tomllib) to read its scope")
    with open(path, "rb") as f:
        return tomllib.load(f)


# ---------------------------------------------------------------- what to mutate

def function_lines(module, names):
    """Line ranges, as cosmic-ray's line filter takes them, of the named
    top-level functions or classes ("Class.method" for one method)."""
    tree = ast.parse((ROOT / module).read_text(encoding="utf-8"))
    found, ranges = set(), []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            candidates = [(node.name, node)]
            if isinstance(node, ast.ClassDef):
                candidates += [(f"{node.name}.{n.name}", n) for n in node.body
                               if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            for name, n in candidates:
                if name in names:
                    first = min([n.lineno] + [d.lineno for d in n.decorator_list])
                    ranges.append(f"{first}-{n.end_lineno}")
                    found.add(name)
    missing = sorted(set(names) - found)
    if missing:
        sys.exit(f"mutate.py: {module} has no top-level {', '.join(missing)}; "
                 f"scope.toml names something that is not there")
    return ranges


def signature(module, operator, diff):
    """What identifies a mutant across runs: the module, the operator, and
    the lines it removes and adds -- not cosmic-ray's occurrence number,
    which moves whenever code above it changes."""
    changed = [line[0] + line[1:].strip() for line in diff.splitlines()
               if line[:1] in "+-" and not line.startswith(("+++", "---"))]
    text = "\n".join([module.replace("\\", "/"), operator] + changed)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------- workers

def tree_files():
    r = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-co", "--exclude-standard", "-z"],
                       capture_output=True, check=True)
    return [f for f in r.stdout.decode("utf-8").split("\0") if f and (ROOT / f).is_file()]


def copy_tree(files, dest):
    for f in files:
        target = dest / f
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / f, target)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for(port, seconds=60):
    end = time.time() + seconds
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def end_strays(work):
    """End every process still running a program from the copies, and say how
    many there were. A test cosmic-ray stops at its timeout is killed alone:
    the tools it started run on. Measured in prompt 08: twenty comrec.py
    processes, each looping on a mutant of the round trip, still running
    hours after two runs ended, a core each, and slowing every run after."""
    marker = str(work)
    if os.name == "nt":
        script = ("Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and "
                  "$_.CommandLine -and $_.CommandLine.Contains('" + marker.replace("'", "''")
                  + "') } | ForEach-Object { $_.ProcessId }")
        found = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                               capture_output=True, text=True).stdout.split()
    else:
        found = [line.split(None, 1)[0] for line in subprocess.run(
            ["ps", "-eo", "pid=,args="], capture_output=True, text=True).stdout.splitlines()
            if marker in line]
    pids = [int(p) for p in found if p.isdigit() and int(p) != os.getpid()]
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    return len(pids)


def tool(cosmic_ray, name):
    """A sibling of the cosmic-ray executable (cr-filter-lines, cr-report)."""
    p = Path(cosmic_ray)
    sibling = p.with_name(name + p.suffix)
    return str(sibling) if sibling.exists() else name


# ---------------------------------------------------------------- one target

def run_target(t, args, work, copies, urls, known, out):
    name, module = t["name"], t["module"]
    command = [args.python.replace("\\", "/")] + list(t["test"])
    test_command = shlex.join(command)    # cosmic-ray splits it the POSIX way
    first = copies[0]

    # The test command on the unmutated code, in a copy, must pass.
    started = time.time()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    base = subprocess.run(command, cwd=first, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)
    baseline = time.time() - started
    if base.returncode != 0:
        tail = (base.stdout + base.stderr).strip().splitlines()[-5:]
        print(f"  {name}: the tests fail on the unmutated code (exit {base.returncode}); "
              f"not mutated.\n    " + "\n    ".join(tail), flush=True)
        return None
    timeout = float(t.get("timeout", max(60.0, round(5 * baseline))))

    config = work / f"{name}.toml"
    lines = ""
    if t.get("functions"):
        ranges = function_lines(module, t["functions"])
        lines = (f"\n[cosmic-ray.filters.line-filter.lines]\n"
                 f"{json.dumps(module)} = {json.dumps(ranges)}\n")
    config.write_text(
        f"[cosmic-ray]\nmodule-path = {json.dumps(module)}\ntimeout = {timeout}\n"
        f"excluded-modules = []\ntest-command = {json.dumps(test_command)}\n\n"
        f"[cosmic-ray.distributor]\nname = \"http\"\n\n"
        f"[cosmic-ray.distributor.http]\nworker-urls = {json.dumps(urls)}\n" + lines,
        encoding="utf-8")
    session = out / f"{name}.sqlite"
    if session.exists():
        session.unlink()

    def cr(*argv):
        r = subprocess.run([str(a) for a in argv], cwd=first, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        if r.returncode != 0:
            raise RuntimeError(f"{' '.join(str(a) for a in argv[:2])} exited {r.returncode}: "
                               f"{(r.stdout + r.stderr).strip()[-500:]}")
        return r

    cr(args.cosmic_ray, "init", config, session)
    if lines:
        cr(tool(args.cosmic_ray, "cr-filter-lines"), "--config", config, session)
    module_sha256 = hashlib.sha256((ROOT / module).read_bytes()).hexdigest()
    if args.retest:
        retest_only_survivors(name, module, module_sha256, Path(args.retest), session)
    started = time.time()
    cr(args.cosmic_ray, "exec", config, session)
    seconds = time.time() - started

    # Every copy must hold the module as it was: a worker puts it back.
    original = (ROOT / module).read_bytes()
    changed = [c.name for c in copies if (c / module).read_bytes() != original]
    if changed:
        raise RuntimeError(f"{module} was left mutated in {', '.join(changed)}")

    db = sqlite3.connect(session)
    rows = db.execute(
        "select r.worker_outcome, r.test_outcome, r.output, r.diff, m.operator_name, "
        "m.start_pos_row, m.definition_name from work_results r join mutation_specs m "
        "on r.job_id = m.job_id").fetchall()
    pending = db.execute("select count(*) from work_items where job_id not in "
                         "(select job_id from work_results)").fetchone()[0]
    db.close()
    tally = dict(scope=0, killed=0, timeout=0, survived=0, equivalent=0, problem=0,
                 incompetent=0, pending=pending)
    survivors = []
    for worker, test, output, diff, operator, line, definition in rows:
        if worker == "SKIPPED":
            continue
        tally["scope"] += 1
        if worker != "NORMAL" or test == "INCOMPETENT":
            tally["incompetent"] += 1
            continue
        if test == "KILLED":
            tally["killed"] += 1
            tally["timeout"] += output == "timeout"
            continue
        tally["survived"] += 1
        sig = signature(module, operator, diff or "")
        entry = known.get(sig)
        if entry:
            tally["equivalent" if entry["kind"] == "equivalent" else "problem"] += 1
        survivors.append((line, definition, operator, diff or "", sig, entry))
    tally["unexplained"] = tally["survived"] - tally["equivalent"] - tally["problem"]
    tally["seconds"] = round(seconds, 1)
    tally["baseline"] = round(baseline, 1)
    tally["module_sha256"] = module_sha256
    tally["retest_of"] = str(args.retest) if args.retest else None

    with open(out / f"{name}.survivors.txt", "w", encoding="utf-8") as f:
        f.write(f"{name}: {module}, {tally['scope']} mutants in scope, {tally['survived']} "
                f"survived, {tally['unexplained']} not in known.toml\n"
                f"test command: {test_command}\n\n")
        for line, definition, operator, diff, sig, entry in sorted(survivors, key=lambda s: s[0]):
            status = (f"{entry['kind']}: {entry['why']}" if entry else "NOT EXPLAINED")
            f.write(f"--- line {line}, in {definition}, {operator}, signature {sig}\n"
                    f"    {status}\n")
            for d in diff.splitlines():
                if d[:1] in "+-@" and not d.startswith(("+++", "---")):
                    f.write(f"    {d}\n")
            f.write("\n")
    return tally


def retest_only_survivors(name, module, module_sha256, earlier, session):
    """Leave only the mutants that survived an earlier run of this target
    to be run, the rest marked skipped.

    For checking new tests: a test added since cannot revive a mutant an
    earlier test killed, so only the survivors need running again. A mutant
    is matched by its operator and occurrence, which name the same change
    only while the module is byte for byte what it was, so a changed module
    is refused rather than matched."""
    summary = earlier / "summary.json"
    old = earlier / f"{name}.sqlite"
    try:
        then = json.loads(summary.read_text(encoding="utf-8"))[name]["module_sha256"]
    except (OSError, ValueError, KeyError) as e:
        raise RuntimeError(f"no record of {module} as {earlier} mutated it ({e}); "
                           f"retest needs that run's summary.json")
    if then != module_sha256:
        raise RuntimeError(f"{module} has changed since {earlier} mutated it, so its "
                           f"mutants are not the same ones; run the target in full")
    with sqlite3.connect(old) as db:
        survived = set(db.execute(
            "select m.operator_name, m.occurrence from work_results r join mutation_specs m "
            "on r.job_id = m.job_id where r.test_outcome = 'SURVIVED'"))
    with sqlite3.connect(session) as db:
        pending = db.execute(
            "select job_id, operator_name, occurrence from mutation_specs where job_id "
            "not in (select job_id from work_results)").fetchall()
        db.executemany(
            "insert into work_results (worker_outcome, output, test_outcome, diff, job_id) "
            "values ('SKIPPED', 'killed in the run retested', NULL, NULL, ?)",
            [(job,) for job, op, occ in pending if (op, occ) not in survived])


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", action="append", help="run only this target; may be repeated")
    ap.add_argument("--workers", type=int,
                    default=max(1, min(16, (os.cpu_count() or 2) // 2)))
    ap.add_argument("--python", default=os.environ.get("PYTHON") or sys.executable,
                    help="the interpreter that runs the tests (default $PYTHON, else this one)")
    ap.add_argument("--cosmic-ray", default=os.environ.get("COSMIC_RAY")
                    or shutil.which("cosmic-ray"))
    ap.add_argument("--out", help="where the survivor lists and sessions go "
                                  "(default: a new folder under the system temp folder)")
    ap.add_argument("--scope", default=str(HERE / "scope.toml"))
    ap.add_argument("--retest", metavar="OUT",
                    help="run only the mutants that survived the run whose output "
                         "folder this is, to check tests added since")
    args = ap.parse_args()
    if not args.cosmic_ray or not Path(args.cosmic_ray).exists():
        print("mutate.py: cosmic-ray not found; pip install cosmic-ray, then pass "
              "--cosmic-ray or set COSMIC_RAY to its executable")
        return 2
    scope = load_toml(args.scope)["target"]
    if args.only:
        unknown = sorted(set(args.only) - {t["name"] for t in scope})
        if unknown:
            print(f"mutate.py: no target {', '.join(unknown)} in {args.scope}")
            return 2
        scope = [t for t in scope if t["name"] in args.only]
    known = {}
    known_path = HERE / "known.toml"
    if known_path.exists():
        for entry in load_toml(known_path).get("survivor", []):
            known[entry["signature"]] = entry
    out = Path(args.out) if args.out else Path(tempfile.mkdtemp(prefix="dosdec-mutation-"))
    out.mkdir(parents=True, exist_ok=True)
    # The Ghidra halves of the suites would run once per mutant. They skip
    # without GHIDRA_HOME, and are shown able to fail by hand instead.
    os.environ.pop("GHIDRA_HOME", None)

    work = Path(tempfile.mkdtemp(prefix="dosdec-mutants-"))
    workers, results, failed = [], {}, False
    try:
        files = tree_files()
        copies = []
        for i in range(args.workers):
            copy = work / f"w{i}"
            copy_tree(files, copy)
            copies.append(copy)
        ports = [free_port() for _ in copies]
        for copy, port in zip(copies, ports):
            with open(work / f"{copy.name}.log", "w") as log:
                workers.append(subprocess.Popen(
                    [args.cosmic_ray, "http-worker", "--port", str(port)], cwd=copy,
                    stdout=subprocess.DEVNULL, stderr=log))
        if not all(wait_for(p) for p in ports):
            tail = (work / "w0.log").read_text(errors="replace").strip()[-800:]
            print(f"mutate.py: a cosmic-ray worker did not start. The first one said:\n{tail}")
            return 2
        urls = [f"http://127.0.0.1:{p}" for p in ports]
        print(f"{len(scope)} target(s), {args.workers} workers, tests run with {args.python}",
              flush=True)
        for t in scope:
            try:
                tally = run_target(t, args, work, copies, urls, known, out)
            except RuntimeError as e:
                print(f"  {t['name']}: {e}", flush=True)
                tally = None
            strays = end_strays(work)
            if strays:
                print(f"  {t['name']}: ended {strays} process(es) a timed-out test left "
                      f"running", flush=True)
            if tally is None:
                failed = True
                continue
            tally["strays_ended"] = strays
            results[t["name"]] = tally
            print(f"  {t['name']:<14} {tally['scope']:4} mutants  {tally['killed']:4} killed "
                  f"({tally['timeout']} by timeout)  {tally['survived']:3} survived  "
                  f"{tally['equivalent']:3} equivalent  {tally['problem']:2} code problem  "
                  f"{tally['unexplained']:3} not explained  {tally['seconds']:7.1f} s",
                  flush=True)
    finally:
        for w in workers:
            w.kill()
        for w in workers:
            w.wait()
        end_strays(work)
        shutil.rmtree(work, ignore_errors=True)

    (out / "summary.json").write_text(json.dumps(results, indent=1), encoding="utf-8")
    print(f"survivors and sessions in {out}")
    if failed:
        return 2
    return 1 if any(r["unexplained"] or r["pending"] or r["incompetent"]
                    for r in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
