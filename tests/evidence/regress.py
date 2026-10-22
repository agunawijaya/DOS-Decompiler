#!/usr/bin/env python3
"""
regress.py -- Check the evidence envelope, the profile handshake's logic, and
the refusal of a functions.json made from a different file.

Three claims are made in knowledge/17-evidence.md, and each is checked here
rather than trusted:

* **An envelope is deterministic.** Two runs over the same file give the same
  bytes, and an evidence id depends on the bytes examined and what was claimed
  about them -- not on the file's name, its folder, or the order of a list.
* **An envelope says everything the report says.** Every line triage.py,
  survey.py and mzinfo.py print is matched to the envelope field that carries
  it. A line with no counterpart is a failure, so a report that grows a new
  kind of line fails here until the envelope carries it too.
* **A stale result is refused.** Each tool that reads functions.json beside an
  executable refuses one recorded against a different file, names the file to
  regenerate, and still opens an old functions.json with exactly one warning.

The handshake's comparison is tested here without Ghidra, against exports
written by hand, one field at a time: drifting each compared field must stop
the check and name that field. The same handshake run through Ghidra itself is
tests/handshake/, which skips on its own when Ghidra is not installed.

Fixtures are NASM source, assembled at test time: tests/evidence/fixtures/ for
the MZ shapes triage distinguishes, and tests/com/fixtures/ reused for the
.COM ones. The refusal checks for libsig.py and emuverify.py need capstone and
unicorn; without them those two checks are reported as skipped.

Usage:
    python tests/evidence/regress.py [--nasm PATH] [--only TEXT ...]
"""

import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from contextlib import contextmanager, redirect_stderr
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
import evidence                                          # noqa: E402
import analysis_profile                                  # noqa: E402

CASES = []
ID_SHAPE = re.compile(r"^ev-[0-9a-f]{8}-[0-9a-f]{8}(-\d+)?$")


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


class Skip(Exception):
    pass


def unpack_cases():
    """tests/unpack/regress.py, imported for the EXEPACK layout it tests
    unpack.py's reader against."""
    spec = importlib.util.spec_from_file_location(
        "unpack_regress", ROOT / "tests" / "unpack" / "regress.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ------------------------------------------------------------------ fixtures

class Fixtures:
    """Everything assembled once, in one temporary folder."""

    def __init__(self, nasm, work):
        self.work = work
        self.mz, self.com = {}, {}
        for asm in sorted((HERE / "fixtures").glob("*.asm")):
            self.mz[asm.stem] = self._build(nasm, asm, work / "mz" / f"{asm.stem}.exe")
        for asm in sorted((ROOT / "tests" / "com" / "fixtures").glob("*.asm")):
            self.com[asm.stem] = self._build(nasm, asm, work / "com" / f"{asm.stem}.com")
        self.text = work / "other" / "notes.txt"
        self.text.parent.mkdir(parents=True, exist_ok=True)
        self.text.write_bytes(b"not an executable\r\n")
        self.folders = self._folders()
        self.shapes = self._shapes()

    @staticmethod
    def _build(nasm, src, out):
        out.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run([nasm, "-f", "bin", "-o", str(out), str(src)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(f"nasm could not build {src.name}:\n{r.stderr}")
        return out

    def _folders(self):
        """Three game folders: one with every kind of thing survey reports,
        one with only the game, one whose game is packed."""
        full = self.work / "survey" / "full"
        (full / "ART").mkdir(parents=True)
        shutil.copy(self.mz["smallc"], full / "GAME.EXE")
        shutil.copy(self.mz["packed"], full / "INSTALL.EXE")
        shutil.copy(self.com["plain"], full / "SETUP.COM")
        shutil.copy(self.mz["overlay"], full / "GAME.OVL")
        (full / "PLAY.BAT").write_bytes(b"@echo off\r\ncls\r\nGAME.EXE %1\r\n")
        (full / "README.TXT").write_bytes(b"A game.\r\n")
        # Two data files far larger than the game: the interpreter pattern.
        (full / "SOUND.DAT").write_bytes(bytes(i & 0xFF for i in range(20000)))
        (full / "LEVELS.DAT").write_bytes(bytes((i * 7) & 0xFF for i in range(40000)))
        (full / "ART" / "TITLE.GIF").write_bytes(b"GIF89a" + bytes(100))
        # An index of ascending offsets into a same-named heap.
        (full / "ART" / "TILES.IND").write_bytes(
            b"".join(v.to_bytes(2, "little") for v in (0, 100, 250, 400)))
        (full / "ART" / "TILES.DAT").write_bytes(bytes(500))

        plain = self.work / "survey" / "plain"
        plain.mkdir(parents=True)
        shutil.copy(self.mz["smallc"], plain / "GAME.EXE")

        blocked = self.work / "survey" / "blocked"
        blocked.mkdir(parents=True)
        shutil.copy(self.mz["packed"], blocked / "GAME.EXE")
        return {"full": full, "plain": plain, "blocked": blocked}

    def _shapes(self):
        """The files triage's verdict cases need beyond the fixtures: the
        fixtures with bytes appended, tests/unpack's EXEPACK layout behind a
        header, and a file that is neither MZ nor .COM under another suffix.
        Each folder holds one, so no file is another's opaque sibling."""
        def place(name, data):
            path = self.work / "shapes" / name.split(".")[0] / name
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            return path

        smallc = self.mz["smallc"].read_bytes()
        blob, at = unpack_cases().exepack_blob()
        total = 32 + len(blob)
        header = bytearray(32)
        header[0:2] = b"MZ"
        struct.pack_into("<HHHHHHHHHHHH", header, 2, total % 512, (total + 511) // 512,
                         0, 2, 0, 0xFFFF, 0, 0, 0, at & 0xF, at >> 4, 0x1C)
        return {
            "exepack": place("exepack.exe", bytes(header) + blob),
            # Triage warns past 1,024 bytes and not at them.
            "appended-1024": place("appended-1024.exe", smallc + bytes(1024)),
            "appended-1025": place("appended-1025.exe", smallc + bytes(1025)),
            # Borland's overlay manager marks its overlays with FBOV.
            "fbov": place("fbov.exe", smallc + b"FBOV" + bytes(2044)),
            "notes.bin": place("notes.bin", b"not an executable either\r\n"),
        }

    def files(self):
        return (list(self.mz.values()) + list(self.com.values()) + [self.text]
                + list(self.shapes.values()))


FIX = None


def run(*args, env=None):
    # survey.py prints an em dash; pinning the encoding lets the report be
    # decoded the same way on every platform. Envelopes are ASCII regardless.
    env = dict(env if env is not None else os.environ, PYTHONIOENCODING="utf-8")
    r = subprocess.run([sys.executable] + [str(a) for a in args],
                       capture_output=True, env=env)
    return r.returncode, r.stdout, r.stderr.decode("utf-8", "replace")


def triage_envelope(path):
    code, out, err = run(TOOLS / "triage.py", path, "--evidence", "-")
    return code, out, err


def mzinfo_envelope(path):
    return run(TOOLS / "mzinfo.py", path, "--evidence", "-")


def survey_envelope(folder):
    return run(TOOLS / "survey.py", folder, "--evidence", "-")


def norm(text):
    return " ".join(str(text).split())


def has_module(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False


# ------------------------------------------------- names in tools/

@case("cProfile, imported with tools/ first on the path, gets the standard module")
def _():
    # The analysis profile lived in tools/profile.py for one prompt, which
    # every script run from tools/ then imported in place of the standard
    # library's `profile` -- and cProfile imports `profile`.
    probe = ("import sys, sysconfig; sys.path.insert(0, sys.argv[1]); "
             "import cProfile, profile; "
             "cProfile.Profile().runcall(sum, [1, 2]); "
             "print(profile.__file__); print(sysconfig.get_paths()['stdlib'])")
    r = subprocess.run([sys.executable, "-c", probe, str(TOOLS)],
                       capture_output=True, text=True, cwd=TOOLS)
    if r.returncode != 0:
        raise AssertionError(f"cProfile failed: {r.stderr.strip()[-300:]}")
    found, stdlib = r.stdout.split("\n")[:2]
    if Path(found).resolve().parent == TOOLS.resolve():
        raise AssertionError(f"`profile` came from {found}")
    if not Path(found).resolve().is_relative_to(Path(stdlib).resolve()):
        raise AssertionError(f"`profile` came from {found}, not {stdlib}")
    return f"profile from {Path(found).parent.name}/{Path(found).name}"


@case("no module in tools/ takes a standard library name")
def _():
    names = getattr(sys, "stdlib_module_names", None)
    if names is None:
        raise Skip("sys.stdlib_module_names needs Python 3.10 -- skipped")
    clashes = sorted(p.name for p in TOOLS.glob("*.py") if p.stem in names)
    if clashes:
        raise AssertionError(f"these shadow the standard library: {clashes}")
    return f"{len(list(TOOLS.glob('*.py')))} modules, no clash"


@case("run-all.ps1 uses $env:PYTHON over PATH, and -Python over both")
def _():
    pwsh = shutil.which("pwsh")
    if not pwsh:
        raise Skip("pwsh not on PATH -- skipped")
    decoy = FIX.work / "decoy"
    decoy.mkdir(exist_ok=True)
    (decoy / "python.cmd").write_text("@echo decoy\r\n@exit /b 9\r\n", encoding="ascii")
    posix = decoy / "python"
    posix.write_text("#!/bin/sh\necho decoy\nexit 9\n", encoding="ascii")
    posix.chmod(0o755)
    path = str(decoy) + os.pathsep + os.environ.get("PATH", "")
    runner = ROOT / "tests" / "run-all.ps1"

    def run_all(python_env, *extra):
        env = dict(os.environ, PATH=path)
        env.pop("PYTHON", None)
        if python_env:
            env["PYTHON"] = python_env
        r = subprocess.run([pwsh, "-NoProfile", "-File", str(runner), "-Only",
                            "pcxlib"] + list(extra),
                           capture_output=True, text=True, env=env)
        return r.returncode, r.stdout + r.stderr

    real = str(Path(sys.executable).resolve())
    for label, python_env, extra in (
            ("$env:PYTHON", real, []),
            ("-Python over a wrong $env:PYTHON", str(FIX.work / "nowhere.exe"),
             ["-Python", real])):
        code, out = run_all(python_env, *extra)
        header = next((l for l in out.splitlines() if l.startswith("python :")), "")
        passed = re.search(r"(?m)^pcxlib\s+PASS\b", out)
        if code != 0 or real.lower() not in header.lower() or not passed:
            raise AssertionError(f"{label}: exit {code}, {header!r}")
    # With neither, bare `python` is the decoy, and run-all must say it has no
    # Python rather than run the suites under something that prints and fails.
    code, out = run_all(None)
    if code != 1 or "no Python at 'python'" not in out:
        raise AssertionError(f"with no PYTHON: exit {code}, {out.strip()[-160:]!r}")
    return "PYTHON honoured, -Python wins, a decoy python is refused"


# ------------------------------------------------------------ identity

def independent_sha256(path):
    """The hash from a program that is not Python's hashlib.

    The Unix tools read the file on stdin. Given a Windows path, GNU
    sha256sum escapes the backslashes and marks the line with a leading
    backslash -- `\\3499b82b...` -- which reads as a different hash; measured
    under Git for Windows, where it is the first of these on PATH.
    """
    attempts = [
        (["sha256sum"], True, lambda o: o.split()[0]),
        (["shasum", "-a", "256"], True, lambda o: o.split()[0]),
        (["certutil", "-hashfile", str(path), "SHA256"], False,
         lambda o: o.splitlines()[1].replace(" ", "")),
        (["openssl", "dgst", "-sha256"], True, lambda o: o.split()[-1]),
    ]
    for cmd, on_stdin, parse in attempts:
        if not shutil.which(cmd[0]):
            continue
        with open(path, "rb") as f:
            r = subprocess.run(cmd, stdin=f if on_stdin else subprocess.DEVNULL,
                               capture_output=True, text=True)
        if r.returncode == 0:
            return parse(r.stdout).lower(), cmd[0]
    raise Skip("no sha256sum, shasum, certutil or openssl on PATH -- skipped")


@case("target identity agrees with a hash taken outside Python")
def _():
    used = None
    for path in FIX.files():
        ident = evidence.target_identity(path)
        want, used = independent_sha256(path)
        if ident["sha256"] != want:
            raise AssertionError(f"{path.name}: {ident['sha256']} but {used} "
                                 f"says {want}")
        if ident["size"] != len(path.read_bytes()):
            raise AssertionError(f"{path.name}: size {ident['size']}")
        if not Path(ident["path"]).is_absolute() or \
                Path(ident["path"]).resolve() != path.resolve():
            raise AssertionError(f"{path.name}: path {ident['path']}")
    return f"{len(FIX.files())} files, against {used}"


@case("a folder's identity moves with its contents and only with them")
def _():
    folder = FIX.folders["plain"]
    first = evidence.directory_identity(folder)
    if evidence.directory_identity(folder) != first:
        raise AssertionError("two readings of an untouched folder differ")
    game = folder / "GAME.EXE"
    original = game.read_bytes()
    try:
        game.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
        if evidence.directory_identity(folder)["sha256"] == first["sha256"]:
            raise AssertionError("one changed byte did not change the hash")
    finally:
        game.write_bytes(original)
    if evidence.directory_identity(folder) != first:
        raise AssertionError("restoring the byte did not restore the hash")
    if first["size"] != sum(f.stat().st_size for f in folder.rglob("*") if f.is_file()):
        raise AssertionError(f"size {first['size']} is not the files' bytes")
    # A file in a subfolder counts, and so does one sorted after a subfolder.
    nested = FIX.work / "nested-folder"
    (nested / "a").mkdir(parents=True, exist_ok=True)
    (nested / "a" / "inner.bin").write_bytes(b"inner")
    (nested / "b.bin").write_bytes(b"after the folder")
    ident = evidence.directory_identity(nested)
    if (ident["files"], ident["size"]) != (2, 21):
        raise AssertionError(f"nested: {ident['files']} files, {ident['size']} bytes")
    (nested / "b.bin").write_bytes(b"after the folder.")
    if evidence.directory_identity(nested)["sha256"] == ident["sha256"]:
        raise AssertionError("a file after a subfolder does not move the hash")
    return f"{first['files']} file, hash {first['sha256'][:12]}; a nested folder too"


# ---------------------------------------------------------- determinism

@case("two runs of triage --evidence give identical bytes")
def _():
    for path in FIX.files():
        a = triage_envelope(path)[1]
        b = triage_envelope(path)[1]
        if a != b or not a:
            raise AssertionError(f"{path.name}: the two runs differ")
    # The file form and the stdout form are the same bytes.
    dest = FIX.work / "triage-envelope.json"
    run(TOOLS / "triage.py", FIX.mz["smallc"], "--evidence", dest)
    if dest.read_bytes() != triage_envelope(FIX.mz["smallc"])[1]:
        raise AssertionError("--evidence FILE and --evidence - differ")
    return f"{len(FIX.files())} fixtures, each run twice"


@case("two runs of mzinfo --evidence give identical bytes")
def _():
    for path in FIX.mz.values():
        a, b = mzinfo_envelope(path)[1], mzinfo_envelope(path)[1]
        if a != b or not a:
            raise AssertionError(f"{path.name}: the two runs differ")
    return f"{len(FIX.mz)} fixtures, each run twice"


@case("two runs of survey --evidence give identical bytes")
def _():
    for name, folder in FIX.folders.items():
        if survey_envelope(folder)[1] != survey_envelope(folder)[1]:
            raise AssertionError(f"{name}: the two runs differ")
    return f"{len(FIX.folders)} folders, each run twice"


def written_out_id(target_sha256, item):
    """The id rule of knowledge/17, written out rather than imported, so a
    change to it has to change this test as well as evidence.py."""
    content = {k: item[k] for k in ("kind", "claim", "location", "value") if k in item}
    body = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return (f"ev-{(target_sha256 or '0' * 8)[:8]}-"
            f"{hashlib.sha256(body.encode('ascii')).hexdigest()[:8]}")


@case("envelopes are canonical and their ids recompute")
def _():
    envelopes = [triage_envelope(p)[1] for p in FIX.files()]
    envelopes += [mzinfo_envelope(p)[1] for p in FIX.mz.values()]
    envelopes += [survey_envelope(f)[1] for f in FIX.folders.values()]
    items = 0
    for raw in envelopes:
        text = raw.decode("ascii")                     # ASCII only, or it raises
        env = json.loads(text)
        # The form written out, not evidence.dumps compared with itself.
        if json.dumps(env, sort_keys=True, indent=2, ensure_ascii=True) + "\n" != text:
            raise AssertionError(f"{env['tool']}: not in canonical form")
        seen = {}
        for item in env["evidence"]:
            base = written_out_id(env["target"]["sha256"], item)
            seen[base] = seen.get(base, 0) + 1
            want = base if seen[base] == 1 else f"{base}-{seen[base]}"
            if item["id"] != want:
                raise AssertionError(f"{env['tool']}: id {item['id']}, by the rule {want}")
        for key in ("schema", "tool", "tool_version", "target", "profile",
                    "status", "result", "evidence", "limitations", "unknowns"):
            if key not in env:
                raise AssertionError(f"{env['tool']}: no {key!r}")
        if env["schema"] != evidence.SCHEMA or env["status"] not in evidence.STATUSES:
            raise AssertionError(f"{env['tool']}: schema or status wrong")
        ids = [i["id"] for i in env["evidence"]]
        if len(set(ids)) != len(ids):
            raise AssertionError(f"{env['tool']}: duplicate ids")
        for item in env["evidence"]:
            items += 1
            if not ID_SHAPE.match(item["id"]):
                raise AssertionError(f"badly formed id {item['id']}")
            if not item["id"].startswith(evidence.evidence_id(
                    env["target"]["sha256"], item)):
                raise AssertionError(f"{item['id']} does not recompute")
            if item["id"][3:11] != env["target"]["sha256"][:8]:
                raise AssertionError(f"{item['id']} is not tied to the target")
    return f"{len(envelopes)} envelopes, {items} ids"


@case("ids without a target, and items one id apart, follow the rule")
def _():
    item = {"kind": "k", "claim": "c", "location": {"file_offset": "0x10"}, "value": 1}
    want = written_out_id(None, item)
    if not want.startswith("ev-00000000-") or evidence.evidence_id(None, item) != want:
        raise AssertionError(f"no target: {evidence.evidence_id(None, item)}, not {want}")
    other = {"kind": "other", "claim": "c"}
    # Same id content, different detail or level: one id apart. The very same
    # item twice: one item.
    env = evidence.envelope("probe", None, evidence=[
        dict(item, detail="first"), dict(item, detail="second"),
        dict(item, level="warn", detail="third"), other, dict(item, detail="first")])
    ids = [i["id"] for i in env["evidence"]]
    if ids != [want, f"{want}-2", f"{want}-3", written_out_id(None, other)]:
        raise AssertionError(f"ids {ids}")
    return f"{want}, then -2 and -3; the repeat kept once"


@case("NaN and infinity are refused anywhere, and JSON is written in one form")
def _():
    for bad in ({"x": float("nan")}, {"x": {"y": [1, float("inf")]}},
                [{"z": (float("-inf"),)}]):
        for fn in (evidence.canonical, evidence.dumps):
            try:
                fn(bad)
            except ValueError as e:
                if "evidence: NaN and infinity" not in str(e):
                    raise AssertionError(f"{fn.__name__}({bad}): {e}")
            else:
                raise AssertionError(f"{fn.__name__} took {bad}")
    sample = {"b": "caf\u00e9", "a": [1, {"d": 2, "c": 3}]}
    if evidence.canonical(sample) != '{"a":[1,{"c":3,"d":2}],"b":"caf\\u00e9"}':
        raise AssertionError(f"canonical: {evidence.canonical(sample)!r}")
    indented = ('{\n  "a": [\n    1,\n    {\n      "c": 3,\n      "d": 2\n    }\n  ],\n'
                '  "b": "caf\\u00e9"\n}\n')
    if evidence.dumps(sample) != indented:
        raise AssertionError(f"dumps: {evidence.dumps(sample)!r}")
    # write() takes a Path as well as a string, and writes those bytes.
    env = evidence.envelope("probe", None, result=sample)
    dest = FIX.work / "written-by-path.json"
    evidence.write(env, dest)
    if dest.read_bytes() != evidence.dumps(env).encode("ascii"):
        raise AssertionError("write(Path) wrote other bytes")
    return "nested NaN and infinity refused; sorted keys, two-space indent, ASCII"


@case("without git on PATH the toolkit version is unknown, not a traceback")
def _():
    probe = ("import sys; sys.path.insert(0, sys.argv[1]); import evidence; "
             "print(evidence.toolkit_version())")
    r = subprocess.run([sys.executable, "-c", probe, str(TOOLS)], capture_output=True,
                       text=True, env=dict(os.environ, PATH=""))
    if r.returncode != 0 or r.stdout.strip() != "unknown":
        raise AssertionError(f"exit {r.returncode}: {r.stdout.strip()!r} {r.stderr[-300:]!r}")
    return "unknown"


@case("an id follows the bytes, not the file's name or folder")
def _():
    elsewhere = FIX.work / "moved" / "RENAMED.BIN"
    elsewhere.parent.mkdir(exist_ok=True)
    shutil.copy(FIX.mz["smallc"], elsewhere)
    here = json.loads(triage_envelope(FIX.mz["smallc"])[1])
    there = json.loads(triage_envelope(elsewhere)[1])
    a = [i["id"] for i in here["evidence"]]
    b = [i["id"] for i in there["evidence"]]
    if a != b:
        raise AssertionError(f"ids moved with the file: {a} vs {b}")
    if here["target"]["path"] == there["target"]["path"]:
        raise AssertionError("the two paths should differ")
    return f"{len(a)} ids unchanged"


# --------------------------------------------------- nothing left behind

TRIAGE_LEVEL = {"BLOCKER": "blocker", "ROUTE": "route", "WARN": "warn",
                "INFO": "info", "NEXT": "note"}


def triage_unmapped(prose, env):
    """Lines of the triage report that nothing in the envelope carries."""
    result, items = env["result"], env["evidence"]
    kinds = {i["kind"]: i for i in items}
    lines = prose.splitlines()
    unmapped, i = [], 0

    def block_matches(level, title, detail):
        if level == "note":
            return norm(result.get("next_step")) == detail
        for item in items:
            if item.get("level") == level and item["claim"] == title \
                    and norm(item.get("detail", "")) == detail:
                return True
        return any(norm(l) == norm(f"{title}: {detail}")
                   for l in env["limitations"])

    while i < len(lines):
        line = lines[i]
        m = re.match(r"^\[(\w+)\s*\] (.+)$", line)
        if not line.strip():
            i += 1
            continue
        if line.startswith("File   : "):
            ok = (line[9:] == result["file"] and
                  Path(env["target"]["path"]) == Path(line[9:]).resolve())
        elif line.startswith("Format : "):
            ok = line[9:] == result["format"] and "format" in kinds
        elif line.startswith("Image  : "):
            mm = re.match(r"^Image  : ([\d,]+) bytes, (\d+) relocations$", line)
            n, r = int(mm.group(1).replace(",", "")), int(mm.group(2))
            ok = (result["image_bytes"] == n == kinds["load-image"]["value"]
                  and result["relocations"] == r
                  == kinds["relocation-count"]["value"])
        elif line.startswith("Entry  : "):
            ok = line[9:] == result["entry"] == kinds["entry-point"]["value"]
        elif line.startswith("VERDICT: "):
            ok = line == result["verdict_text"]
        elif m:
            detail = []
            while i + 1 < len(lines) and lines[i + 1].startswith("           "):
                i += 1
                detail.append(lines[i])
            ok = block_matches(TRIAGE_LEVEL[m.group(1)], m.group(2),
                               norm(" ".join(detail)))
        else:
            ok = False
        if not ok:
            unmapped.append(line)
        i += 1
    return unmapped


@case("every line of triage's report has a counterpart in its envelope")
def _():
    lines = 0
    for path in FIX.files():
        code, prose, _ = run(TOOLS / "triage.py", path)
        env = json.loads(triage_envelope(path)[1])
        prose = prose.decode("utf-8")
        missing = triage_unmapped(prose, env)
        if missing:
            raise AssertionError(f"{path.name}: no counterpart for "
                                 + "; ".join(repr(m) for m in missing))
        lines += sum(1 for l in prose.splitlines() if l.strip())
    return f"{lines} lines over {len(FIX.files())} fixtures"


def mzinfo_unmapped(prose, env):
    """Lines of the mzinfo report that nothing in the envelope carries."""
    result = env["result"]
    kinds = {i["kind"]: i for i in env["evidence"]}
    h, lay, relocs = result["header"], result["layout"], result["relocations"]
    lines, unmapped, i = prose.splitlines(), [], 0
    field = lambda kind: kinds.get(kind, {}).get("value")  # noqa: E731
    while i < len(lines):
        line, s = lines[i], lines[i].strip()
        ok = False
        if not s or re.match(r"^-- .+ -+$", line):
            ok = True
        elif line.startswith("File            : "):
            ok = line[18:] == result["file"]
        elif m := re.match(r"^Size            : (\d+) bytes$", line):
            ok = int(m.group(1)) == result["file_size"] == env["target"]["size"]
        elif m := re.match(r"^  magic\s+(\S+)$", line):
            ok = field("magic") == m.group(1)
        elif m := re.match(r"^  header size\s+(\d+) bytes \((\d+) paragraphs\)$", line):
            ok = field("header-size") == int(m.group(1)) and \
                h["header_paragraphs"] == int(m.group(2))
        elif m := re.match(r"^  pages / last page\s+(\d+) / (\d+)$", line):
            v = field("load-image")
            ok = (v["pages_512"], v["bytes_on_last_page"]) == \
                (int(m.group(1)), int(m.group(2)))
        elif m := re.match(r"^  relocations\s+(\d+) \(table at 0x([0-9A-F]+)\)$", line):
            ok = field("relocation-count") == int(m.group(1)) and \
                kinds["relocation-count"]["location"]["file_offset"] == \
                f"0x{int(m.group(2), 16):x}"
        elif m := re.match(r"^  entry CS:IP\s+(\S+)  -> file offset 0x([0-9A-F]+)$", line):
            ok = field("entry-point") == m.group(1) and \
                kinds["entry-point"]["location"]["file_offset"] == \
                f"0x{int(m.group(2), 16):x}"
        elif m := re.match(r"^  stack SS:SP\s+(\S+)$", line):
            ok = field("stack") == m.group(1)
        elif m := re.match(r"^  extra memory\s+min ([\d,]+) / max ([\d,]+) bytes$", line):
            ok = field("memory-request") == {"min": int(m.group(1).replace(",", "")),
                                             "max": int(m.group(2).replace(",", ""))}
        elif m := re.match(r"^  overlay number\s+(\d+)$", line):
            ok = field("overlay-field") == int(m.group(1))
        elif m := re.match(r"^  load image\s+0x([0-9A-F]+) \.\. 0x([0-9A-F]+)  \((\d+) bytes\)$", line):
            ok = (lay["image_start"], lay["image_end"], field("load-image")["image_size"]) \
                == (int(m.group(1), 16), int(m.group(2), 16), int(m.group(3)))
        elif m := re.match(r"^  trailing data\s+(-?\d+) bytes$", line):
            ok = field("load-image")["trailing_bytes"] == int(m.group(1))
        elif m := re.match(r"^  ([0-9A-F]{4})h   \((\d+) relocation\(s\)\)$", line):
            ok = any(i["kind"] == "referenced-segment" and
                     i["value"] == {"segment": int(m.group(1), 16),
                                    "count": int(m.group(2))}
                     for i in env["evidence"])
        elif m := re.match(r"^  \[\s*(\d+)\] ([0-9A-F]{4}):([0-9A-F]{4})  file "
                           r"0x([0-9A-F]+)  patches segment value (\S+)h$", line):
            r = relocs[int(m.group(1))]
            value = "----" if r["value"] is None else f"{r['value']:04X}"
            ok = (r["seg"], r["off"], r["linear"], value) == \
                (int(m.group(2), 16), int(m.group(3), 16), int(m.group(4), 16),
                 m.group(5))
        elif m := re.match(r"^  \.\.\. (\d+) more$", line):
            ok = len(relocs) - 32 == int(m.group(1))
        elif s == "(nothing unusual)":
            ok = not result["findings"]
        elif m := re.match(r"^  \[(INFO |WARN |ERROR)\] (\S+)$", line):
            detail = []
            while i + 1 < len(lines) and lines[i + 1].startswith("          "):
                i += 1
                detail.append(lines[i])
            ok = any(it["kind"] == m.group(2) and
                     it.get("level") == m.group(1).strip().lower() and
                     norm(it.get("detail", "")) == norm(" ".join(detail))
                     for it in env["evidence"])
        if not ok:
            unmapped.append(line)
        i += 1
    return unmapped


@case("every line of mzinfo's report has a counterpart in its envelope")
def _():
    lines = 0
    for path in list(FIX.mz.values()) + [FIX.com["mzsingle"], FIX.com["mzdispatchcs"]]:
        prose = run(TOOLS / "mzinfo.py", path)[1].decode("utf-8")
        env = json.loads(mzinfo_envelope(path)[1])
        missing = mzinfo_unmapped(prose, env)
        if missing:
            raise AssertionError(f"{path.name}: no counterpart for "
                                 + "; ".join(repr(m) for m in missing[:4]))
        lines += sum(1 for l in prose.splitlines() if l.strip())
    code, out, _ = mzinfo_envelope(FIX.text)
    if code != 2 or json.loads(out)["status"] != "unsupported":
        raise AssertionError(f"a text file: exit {code}, not unsupported")
    return f"{lines} lines over {len(FIX.mz) + 2} MZ fixtures; a text file is unsupported"


def survey_unmapped(prose, env):
    result, items = env["result"], env["evidence"]
    by_kind = {}
    for item in items:
        by_kind.setdefault(item["kind"], []).append(item)
    prose_text = norm(" ".join(env["limitations"] + env["unknowns"]))

    def find(kind, **where):
        for item in by_kind.get(kind, []):
            if all(_dig(item, k) == v for k, v in where.items()):
                return item
        return None

    unmapped, section, current, lines = [], None, None, prose.splitlines()
    for n, line in enumerate(lines):
        if not line.strip():
            continue
        s = line.strip()
        ok = False
        if m := re.match(r"^-- (.+?) -+$", line):
            section, ok = m.group(1), True
        elif line.startswith("Directory : "):
            ok = line[12:] == result["root"]
        elif m := re.match(r"^Files     : (\d+) in (\d+) director(?:y|ies)$", line):
            c = find("file-count")
            ok = c and c["value"]["files"] == int(m.group(1)) \
                and c["value"]["directories"] == int(m.group(2))
        elif line.startswith("Subfolders: "):
            shown = line[12:].removesuffix("...")
            ok = shown == ", ".join(result["subdirectories"][:10])
        elif section == "Executables":
            if s == "none found":
                ok = not by_kind.get("executable") and not by_kind.get("com")
            elif m := re.match(r"^  (\S+)\s+([\d,]+)  (.+?)( <== likely the game)?$", line):
                rel = Path(m.group(1)).as_posix()
                current = find("executable", **{"location.path": rel}) \
                    or find("com", **{"location.path": rel})
                ok = bool(current) and current["value"]["size"] == \
                    int(m.group(2).replace(",", "")) and \
                    current["value"]["verdict"] == m.group(3)
                if m.group(4):
                    ok = ok and bool(find("main-executable", **{"location.path": rel}))
            elif m := re.match(r"^      blocker: (.+)$", line):
                ok = bool(current) and bool(find(
                    "blocker", claim=m.group(1),
                    **{"location.path": current["location"]["path"]}))
            elif m := re.match(r"^      (.+) model, (\S+) prologues/KB$", line):
                ok = bool(current) and current["value"]["model"] == m.group(1) \
                    and str(current["value"]["prologue_density"]) == m.group(2)
            elif m := re.match(r"^  Chosen: (\S+) — (.+)$", line):
                c = find("main-executable",
                         **{"location.path": Path(m.group(1)).as_posix()})
                ok = bool(c) and c["value"]["reason"] == m.group(2)
        elif section == "Overlay modules":
            if m := re.match(r"^  (\S+)\s+([\d,]+)  overlay #(\d+)$", line):
                c = find("overlay-module",
                         **{"location.path": Path(m.group(1)).as_posix()})
                ok = bool(c) and c["value"]["overlay_number"] == int(m.group(3))
            else:
                ok = norm(s) in prose_text
        elif section == "Batch files":
            if m := re.match(r"^  They invoke: (.+)$", line):
                c = find("batch-targets")
                ok = bool(c) and ", ".join(c["value"][:12]) == m.group(1)
            elif m := re.match(r"^  (\S+)$", line):
                ok = bool(find("batch-file",
                               **{"location.path": Path(m.group(1)).as_posix()}))
        elif section == "Data files worth knowing about":
            if m := re.match(r"^  (\S+)\s+([\d,]+)$", line):
                c = find("notable-data",
                         **{"location.path": Path(m.group(1)).as_posix()})
                ok = bool(c) and c["value"] == int(m.group(2).replace(",", ""))
        elif section == "The data beside the executable":
            if m := re.match(r"^  (\S+)\s+(\d+) files\s+([\d,]+) bytes$", line):
                c = find("data-group", **{"value.extension": m.group(1)})
                ok = bool(c) and c["value"]["files"] == int(m.group(2)) and \
                    c["value"]["bytes"] == int(m.group(3).replace(",", ""))
        elif section == "Formats recognised on sight":
            if m := re.match(r"^  (\S+)\s+([\d,]+)  (.+)$", line):
                c = find("container-format",
                         **{"location.path": Path(m.group(1)).as_posix()})
                ok = bool(c) and c["value"]["format"] == m.group(3)
        elif section == "Index and heap pairs":
            if m := re.match(r"^  (\S+)\s+indexes (\S+)\s+(\d+) entries, "
                             r"(\d+)-byte stride$", line):
                current = find("index-pair", **{"location.index": m.group(1),
                                                "location.data": m.group(2)})
                ok = bool(current) and current["value"]["entries"] == \
                    int(m.group(3)) and current["value"]["stride"] == int(m.group(4))
            elif m := re.match(r"^  \.\.\. (\d+) more pairs", line):
                ok = len(by_kind.get("index-pair", [])) - 14 == int(m.group(1))
            elif current and current["kind"] == "index-pair" and \
                    s == current["value"]["note"]:
                ok = True
            else:
                ok = norm(s) in prose_text
        elif section == "Read this before starting":
            if m := re.match(r'^  Start with: (.+)$', line):
                ok = norm(m.group(1)) in norm(result.get("next_step", ""))
            elif s in ("then tools/pipeline.ps1 on the same file.",
                       "The main executable is out of scope. See its blockers above."):
                ok = s in result.get("next_step", "")
            else:
                ok = norm(s) in prose_text
        if not ok:
            unmapped.append(line)
    return unmapped


def _dig(item, dotted):
    for part in dotted.split("."):
        if not isinstance(item, dict) or part not in item:
            return None
        item = item[part]
    return item


@case("every line of survey's report has a counterpart in its envelope")
def _():
    lines = 0
    folders = dict(FIX.folders, com=FIX.work / "com", mz=FIX.work / "mz")
    for name, folder in folders.items():
        prose = run(TOOLS / "survey.py", folder)[1].decode("utf-8")
        env = json.loads(survey_envelope(folder)[1])
        missing = survey_unmapped(prose, env)
        if missing:
            raise AssertionError(f"{name}: no counterpart for "
                                 + "; ".join(repr(m) for m in missing[:4]))
        lines += sum(1 for l in prose.splitlines() if l.strip())
    return f"{lines} lines over {len(folders)} folders"


@case("a warning's open question lands in unknowns, not in evidence alone")
def _():
    env = json.loads(triage_envelope(FIX.mz["spread"])[1])
    want = ["PKLITE signature at 0xc00", "2048 bytes past the load image",
            "far-pointer model", "hand-written assembly or C"]
    missing = [w for w in want if not any(w in u for u in env["unknowns"])]
    if missing:
        raise AssertionError(f"unknowns lack {missing}: {env['unknowns']}")
    if not any(l.startswith("emuverify.py assumes small model")
               for l in env["limitations"]):
        raise AssertionError("the emuverify assumption is not a limitation")
    clean = json.loads(triage_envelope(FIX.mz["smallc"])[1])
    if clean["unknowns"]:
        raise AssertionError(f"a clean file raised questions: {clean['unknowns']}")
    return f"{len(env['unknowns'])} questions from 5 warnings; none from a clean file"


@case("two checks finding one packer stay two items, though printed once")
def _():
    prose = run(TOOLS / "triage.py", FIX.mz["packed"])[1].decode("utf-8")
    env = json.loads(triage_envelope(FIX.mz["packed"])[1])
    titled = [i for i in env["evidence"]
              if i["claim"] == "packed with Microsoft EXEPACK"]
    kinds = sorted(i["kind"] for i in titled)
    if prose.count("packed with Microsoft EXEPACK") != 1:
        raise AssertionError("the report should print the title once")
    if kinds != ["packer-marker", "packer-signature"]:
        raise AssertionError(f"expected both checks, got {kinds}")
    return f"report 1, envelope {len(titled)} ({', '.join(kinds)})"


@case("a file that is not there gives an error envelope, not a traceback")
def _():
    code, out, err = triage_envelope(FIX.work / "absent.exe")
    env = json.loads(out)
    if code != 2 or env["status"] != "error" or env["target"]["sha256"] is not None:
        raise AssertionError(f"exit {code}, status {env['status']}")
    code, out, _ = survey_envelope(FIX.work / "no-such-folder")
    if code != 2 or json.loads(out)["status"] != "error":
        raise AssertionError(f"survey: exit {code}")
    return "status error, exit 2, from both"


# ------------------------------------------------------- triage's verdict

# The four lines triage ends its report with, written out here rather than
# read from triage.py: a test that took them from the code would pass whatever
# the code said. Prompt 07's mutation run found that flipping the verdict for
# a packed, non-MZ or .COM file survived every suite; the cases below each
# pin one shape's verdict line, in_scope, confidence and exit code.
IN_SCOPE = "VERDICT: in scope. Run tools/pipeline.ps1."
COM_ROUTE = ("VERDICT: in scope, by the .COM route. Run comrec.py as shown above; it "
             "either produces a byte-identical rebuild or says why not.")
WORKABLE = ("VERDICT: probably workable, with caveats above. Expect the measured "
            "accuracy figures not to hold.")
OUT_OF_SCOPE = "VERDICT: out of scope. See the blockers above and knowledge/00-scope.md."

# shape, the file, verdict line, verdict, a blocker or warning title the
# verdict rests on, and a title that must not appear.
VERDICT_SHAPES = [
    ("in scope, a small-model C program", lambda: FIX.mz["smallc"], IN_SCOPE,
     {"in_scope": True, "confidence": "high"}, None, "bytes past the load image"),
    ("packed, tests/unpack's EXEPACK layout", lambda: FIX.shapes["exepack"], OUT_OF_SCOPE,
     {"in_scope": False, "confidence": "low"}, ("blocker", "packed with Microsoft EXEPACK"),
     None),
    ("packed, an EXEPACK stub with its error message", lambda: FIX.mz["packed"],
     OUT_OF_SCOPE, {"in_scope": False, "confidence": "low"},
     ("blocker", "packed with Microsoft EXEPACK"), None),
    ("overlaid, the header names overlay 1", lambda: FIX.mz["overlay"], OUT_OF_SCOPE,
     {"in_scope": False, "confidence": "high"}, ("blocker", "overlaid program"), None),
    ("overlaid, FBOV in the bytes past the image", lambda: FIX.shapes["fbov"],
     OUT_OF_SCOPE, {"in_scope": False, "confidence": "high"},
     ("blocker", "overlaid program"), "bytes past the load image"),
    ("1,025 bytes past the image and no marker: a warning", lambda: FIX.shapes["appended-1025"],
     IN_SCOPE, {"in_scope": True, "confidence": "high"},
     ("warn", "1025 bytes past the load image"), "overlaid program"),
    ("1,024 bytes past the image: not even a warning", lambda: FIX.shapes["appended-1024"],
     IN_SCOPE, {"in_scope": True, "confidence": "high"}, None, "bytes past the load image"),
    ("not MZ, a text file", lambda: FIX.text, OUT_OF_SCOPE,
     {"in_scope": False, "confidence": "high"}, ("blocker", "not an MZ executable"), None),
    ("not MZ, a suffix that sorts before .com", lambda: FIX.shapes["notes.bin"], OUT_OF_SCOPE,
     {"in_scope": False, "confidence": "high"}, ("blocker", "not an MZ executable"), None),
    (".COM, the comrec route", lambda: FIX.com["plain"], COM_ROUTE,
     {"in_scope": True, "confidence": "high", "route": "comrec"},
     ("route", "raw .COM image"), None),
    ("interpreted engine, Sierra SCI's resource names", lambda: FIX.mz["engine"],
     OUT_OF_SCOPE, {"in_scope": False, "confidence": "high"},
     ("blocker", "interpreted engine: Sierra SCI"), None),
    ("warnings only, far pointers and few frames", lambda: FIX.mz["spread"], WORKABLE,
     {"in_scope": True, "confidence": "low"}, ("warn", "memory model looks"), None),
    ("beside data files far larger than itself", lambda: FIX.folders["full"] / "GAME.EXE",
     IN_SCOPE, {"in_scope": True, "confidence": "high"},
     ("warn", "large opaque data files alongside"), None),
]


def verdict_case(shape, path_of, line, verdict, rests_on, absent):
    @case(f"triage verdict, {shape}")
    def _():
        path = path_of()
        code, prose, _ = run(TOOLS / "triage.py", path)
        ecode, out, _ = triage_envelope(path)
        env = json.loads(out)
        last = [l for l in prose.decode("utf-8").splitlines() if l.strip()][-1]
        if last != line:
            raise AssertionError(f"the report ends {last!r}, not {line!r}")
        result = env["result"]
        if result["verdict"] != verdict or result["verdict_text"] != line:
            raise AssertionError(f"envelope verdict {result['verdict']} "
                                 f"{result['verdict_text']!r}, not {verdict}")
        want = 0 if verdict["in_scope"] else 1
        if (code, ecode) != (want, want):
            raise AssertionError(f"exit {code} (report), {ecode} (envelope), not {want}")
        titles = [(i.get("level"), i["claim"]) for i in env["evidence"]]
        if rests_on and not any(lv == rests_on[0] and c.startswith(rests_on[1])
                                for lv, c in titles):
            raise AssertionError(f"no {rests_on[0]} {rests_on[1]!r} among {titles}")
        if absent and any(absent in c for _, c in titles):
            raise AssertionError(f"{absent!r} should not be found: {titles}")
        scope = "in scope" if verdict["in_scope"] else "out of scope"
        why = f", on {rests_on[0]} {rests_on[1]!r}" if rests_on else ""
        return f"{scope}, confidence {verdict['confidence']}, exit {want}{why}"


for _shape in VERDICT_SHAPES:
    verdict_case(*_shape)


@case("triage verdict, the file triage calls EXEPACK is one unpack.py's reader accepts")
def _():
    sys.path.insert(0, str(TOOLS))
    import unpack
    path = FIX.shapes["exepack"]
    data = path.read_bytes()
    entry = 32 + (struct.unpack_from("<H", data, 0x16)[0] << 4) + struct.unpack_from(
        "<H", data, 0x14)[0]
    got = unpack.exepack_header(data, entry)
    if got is None or (got["cs"] << 4) + got["ip"] != 0x6B2:
        raise AssertionError(f"unpack.exepack_header read {got}")
    return f"entry at file 0x{entry:x}; EXEPACK's own header says 0x6B2"


EXPECTED_TRIAGE = HERE / "expected-triage.json"
UPDATE_EXPECTED = False


def triage_files():
    """Every file the triage cases look at, by a name that does not depend
    on where the fixtures were built."""
    named = {f"mz/{p.name}": p for p in FIX.mz.values()}
    named.update({f"com/{p.name}": p for p in FIX.com.values()})
    named.update({f"shapes/{p.name}": p for p in FIX.shapes.values()})
    named["other/notes.txt"] = FIX.text
    named["survey/full/GAME.EXE"] = FIX.folders["full"] / "GAME.EXE"
    return dict(sorted(named.items()))


def without_paths(value, path):
    """`value` with this run's path to the file written as <FILE>."""
    if isinstance(value, str):
        for p in (str(Path(path).resolve()), str(path)):
            value = value.replace(p, "<FILE>")
        return value
    if isinstance(value, list):
        return [without_paths(v, path) for v in value]
    if isinstance(value, dict):
        return {k: without_paths(v, path) for k, v in value.items()}
    return value


def unwrapped(prose):
    """The report's lines with each finding's detail joined back into one.
    The report wraps at 68 columns, and a detail that holds the file's path
    wraps differently in every folder."""
    lines, in_detail = [], False
    for line in prose.splitlines():
        detail = line.startswith(" " * 11)
        if detail and in_detail:
            lines[-1] += " " + line.strip()
        else:
            lines.append(" " * 11 + line.strip() if detail else line)
        in_detail = detail
    return lines


def triage_answer(path):
    """Everything triage says about one file, in both forms, as data."""
    code, prose, _ = run(TOOLS / "triage.py", path)
    ecode, out, _ = triage_envelope(path)
    env = json.loads(out)
    env = {k: v for k, v in env.items() if k not in ("tool_version", "target")}
    return without_paths({"exit": [code, ecode],
                          "report": unwrapped(prose.decode("utf-8")),
                          "envelope": env}, path)


@case("triage's whole answer for every file, against the one written down")
def _():
    # The verdict cases above pin the verdict; this pins everything that
    # leads to it -- every finding's title, detail and value, the evidence and
    # the questions -- so a changed threshold or a changed message cannot pass
    # as long as the verdict happens to survive. The answer is written down in
    # tests/evidence/expected-triage.json; after a deliberate change, rerun
    # with --update-expected and read the diff before committing it.
    got = {name: triage_answer(path) for name, path in triage_files().items()}
    if UPDATE_EXPECTED:
        EXPECTED_TRIAGE.write_text(json.dumps(got, indent=1, sort_keys=True) + "\n",
                                   encoding="utf-8", newline="\n")
        return f"wrote {len(got)} answers to {EXPECTED_TRIAGE.name}"
    if not EXPECTED_TRIAGE.exists():
        raise AssertionError(f"{EXPECTED_TRIAGE.name} is missing; run with --update-expected")
    want = json.loads(EXPECTED_TRIAGE.read_text(encoding="utf-8"))
    if sorted(got) != sorted(want):
        raise AssertionError(f"files {sorted(set(got) ^ set(want))} added or missing")
    for name in want:
        for part in ("exit", "report", "envelope"):
            if got[name][part] != want[name][part]:
                a = json.dumps(want[name][part], indent=1, sort_keys=True).splitlines()
                b = json.dumps(got[name][part], indent=1, sort_keys=True).splitlines()
                at = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y),
                          min(len(a), len(b)))
                raise AssertionError(f"{name}, {part}, line {at + 1}: written down "
                                     f"{a[at] if at < len(a) else '(end)'!r}, now "
                                     f"{b[at] if at < len(b) else '(end)'!r}")
    lines = sum(len(v["report"]) for v in got.values())
    return f"{len(got)} files, {lines} report lines and their envelopes, as written down"


# ------------------------------------------------------- stale results

def fake_functions(exe, with_target=True):
    """A functions.json for `exe`, shaped as ExportDecompiledC writes one.

    The entries are the fixture's own prologues plus its entry point, found
    in the bytes rather than written down, so the records point at code."""
    data = exe.read_bytes()
    hdr = int.from_bytes(data[8:10], "little") * 16
    image = data[hdr:]
    entries = [0] + [m.start() for m in re.finditer(rb"\x55\x8b\xec", image)]
    records = []
    for off in entries:
        records.append({
            "name": f"FUN_1000_{off:04x}", "entry": f"1000:{off:04x}",
            "size": 8, "thunk": False, "external": False,
            "calling_convention": "unknown", "return_type": "undefined",
            "param_count": 0, "params": [], "decompiled": True,
            "instruction_count": 4, "blocks": 1, "edges": 0, "loops": 0,
            "returns": 1, "indirect_jumps": 0, "cyclomatic": 1, "calls": [],
            "scalars": [], "interrupts": [], "io_ports": [], "strings": [],
            "data_refs": [], "mnemonics": ["MOV", "RET"]})
    out = {"program": exe.name, "language": "x86:LE:16:Real Mode",
           "image_base": "0000:0000", "decompiled_ok": len(records),
           "decompiled_failed": 0, "functions": records}
    if with_target:
        out["target"] = evidence.target_identity(exe)
    return out


def consumers(functions, exe, src):
    """Every tool that reads functions.json beside an executable, as the
    command line that makes it do so. (name, args, modules it needs)"""
    db = ROOT / "signatures" / "msc50-16bit-small.json"
    return [
        ("anchors.py", [TOOLS / "anchors.py", functions, "--exe", exe], []),
        ("libsig.py", [TOOLS / "libsig.py", "apply", exe, functions, "--db", db],
         ["capstone"]),
        ("match.py", [TOOLS / "match.py", src, functions, "--exe", exe], []),
        ("modcluster.py", [TOOLS / "modcluster.py", functions, "--exe", exe], []),
        ("emuverify.py", [TOOLS / "emuverify.py", exe, functions, exe, functions,
                          "--quiet"], ["capstone", "unicorn"]),
    ]


def _stale_setup():
    work = FIX.work / "stale"
    work.mkdir(exist_ok=True)
    src = work / "src.json"
    src.write_text('{"functions": []}', encoding="utf-8")
    current = work / "functions.json"
    current.write_text(json.dumps(fake_functions(FIX.mz["smallc"])), encoding="utf-8")
    old = work / "old-functions.json"
    old.write_text(json.dumps(fake_functions(FIX.mz["smallc"], with_target=False)),
                   encoding="utf-8")
    return work, src, current, old


@case("a functions.json from another executable is refused by every reader")
def _():
    work, src, current, _ = _stale_setup()
    other = FIX.mz["spread"]           # a different MZ, so nothing else fails
    refused, skipped = [], []
    for name, args, needs in consumers(current, other, src):
        if not all(has_module(m) for m in needs):
            skipped.append(name)
            continue
        code, _, err = run(*args)
        if code == 0:
            raise AssertionError(f"{name} accepted it")
        if "was produced from a different file" not in err or str(current) not in err:
            raise AssertionError(f"{name} refused without naming the file: {err!r}")
        refused.append(name)
    # The same readers accept the export of the executable they are given.
    for name, args, needs in consumers(current, FIX.mz["smallc"], src):
        if name in skipped:
            continue
        code, _, err = run(*args)
        if code != 0 or err.strip():
            raise AssertionError(f"{name} did not accept its own export: {err!r}")
    detail = f"{len(refused)} refused, and accepted the right one"
    if skipped:
        detail += f"; {', '.join(skipped)} skipped (capstone/unicorn not installed)"
    return detail


@case("an old functions.json still opens, with exactly one warning")
def _():
    work, src, _, old = _stale_setup()
    checked, skipped = [], []
    for name, args, needs in consumers(old, FIX.mz["smallc"], src):
        if not all(has_module(m) for m in needs):
            skipped.append(name)
            continue
        code, _, err = run(*args)
        warnings = [l for l in err.splitlines() if "has no target record" in l]
        if code != 0 or len(warnings) != 1:
            raise AssertionError(f"{name}: exit {code}, {len(warnings)} warnings")
        checked.append(name)
    detail = f"{len(checked)} readers, one warning each"
    if skipped:
        detail += f"; {', '.join(skipped)} skipped (capstone/unicorn not installed)"
    return detail


def stderr_of(fn, *args, **kwargs):
    """What fn wrote to stderr, with the once-per-file memory cleared first."""
    evidence._warned.clear()
    err = io.StringIO()
    with redirect_stderr(err):
        fn(*args, **kwargs)
    return err.getvalue()


def refusal(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except SystemExit as e:
        return str(e)
    raise AssertionError(f"{fn.__name__} did not refuse")


@case("a refusal names both hashes, whichever way they sort; a target since moved is not checked")
def _():
    work = FIX.work / "refusal"
    work.mkdir(exist_ok=True)
    a, b = FIX.mz["smallc"], FIX.mz["spread"]
    for made_from, given in ((a, b), (b, a)):
        path = work / f"functions-{made_from.stem}.json"
        text = refusal(evidence.check_functions_target, fake_functions(made_from), path,
                       given, "probe")
        rec, act = evidence.sha256_file(made_from), evidence.sha256_file(given)
        for want in (f"sha256 {rec[:16]}...", f"sha256 {act[:16]}...", str(path), str(given)):
            if want not in text:
                raise AssertionError(f"{made_from.name} given {given.name}: no {want!r} in {text!r}")
    # Without --exe: the file target.path names, rebuilt so that its hash
    # sorts after the recorded one, and before it.
    game = work / "GAME.EXE"
    original = a.read_bytes()
    game.write_bytes(original)
    data = fake_functions(game)
    rec = data["target"]["sha256"]
    orders = {}
    for n in range(256):
        rebuilt = original + bytes([n])
        sha = hashlib.sha256(rebuilt).hexdigest()
        orders.setdefault(sha > rec, rebuilt)
        if len(orders) == 2:
            break
    for later, rebuilt in orders.items():
        game.write_bytes(rebuilt)
        act = hashlib.sha256(rebuilt).hexdigest()
        text = stderr_of(evidence.check_functions_target, data, work / "f.json", None, "probe")
        if f"sha256 was {rec[:16]}...; that file is now {act[:16]}..." not in text:
            raise AssertionError(f"rebuilt, sorting {'after' if later else 'before'}: {text!r}")
    game.unlink()
    text = stderr_of(evidence.check_functions_target, data, work / "f.json", None, "probe")
    if text:
        raise AssertionError(f"a target that is gone was checked: {text!r}")
    return "both orders refused with both hashes; rebuilt warned both ways; gone, silent"


@contextmanager
def unreadable(path):
    """Hold `path` so that reading it raises OSError, or yield False."""
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                    ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                    wintypes.HANDLE)
        # GENERIC_READ, no sharing, OPEN_EXISTING: every other open fails.
        handle = k32.CreateFileW(str(path), 0x80000000, 0, None, 3, 0, None)
        if handle in (None, wintypes.HANDLE(-1).value):
            yield False
            return
        try:
            yield True
        finally:
            k32.CloseHandle(handle)
        return
    mode = path.stat().st_mode
    path.chmod(0)
    try:
        try:
            path.read_bytes()
            yield False                                # root reads anything
        except OSError:
            yield True
    finally:
        path.chmod(mode)


@case("a handshake record that cannot be read warns, and one about another export is refused")
def _():
    folder, exe, src = drifted_folder("records-malformed")
    record, fj = folder / "handshake.json", folder / "functions.json"
    good = record.read_text(encoding="utf-8")
    for name, content in (("not JSON", "{not json"), ("no status", "{}"),
                          ("not an object", "[]")):
        record.write_text(content, encoding="utf-8")
        text = stderr_of(evidence.check_handshake, fj, "probe", False)
        if "could not read" not in text:
            raise AssertionError(f"{name}: {text!r}")
    record.write_text(good, encoding="utf-8")
    with unreadable(record) as held:
        if held:
            text = stderr_of(evidence.check_handshake, fj, "probe", False)
            if "could not read" not in text:
                raise AssertionError(f"locked: {text!r}")
    # A record of another export, its hash sorting before or after this
    # one's, is refused with the fix for a rewritten export.
    env = json.loads(good)
    env["status"] = "verified"
    for fake in ("0" * 64, "f" * 64):
        env["result"]["functions_sha256"] = fake
        record.write_text(json.dumps(env), encoding="utf-8")
        text = refusal(evidence.check_handshake, fj, "probe", False)
        if "checked an earlier export" not in text or "analysis_profile.py check" not in text:
            raise AssertionError(f"record of {fake[:4]}...: {text!r}")
    # The drift: refused by default, naming only the field that drifted,
    # with the fix for a drift.
    record.write_text(good, encoding="utf-8")
    for fn, args in ((evidence.check_handshake, (fj,)), (evidence.load_functions, (fj, exe))):
        text = refusal(fn, *args)
        if "the handshake found load_segment: expected 0x2000, observed 0x1000.\n" not in text \
                or "Find out why Ghidra" not in text:
            raise AssertionError(f"{fn.__name__} by default: {text!r}")
    return (f"three malformed records{'' if held else ' (a locked one could not be made)'} "
            f"warned; both hash orders refused; drift refused by default")


@case("an export from a load image that did not verify is read with one warning")
def _():
    work = FIX.work / "unverified-load"
    work.mkdir(exist_ok=True)
    exe = FIX.mz["smallc"]
    fj, li = work / "functions.json", work / "loadimage.json"
    data = fake_functions(exe)
    data["load_image"] = {"status": "mismatch", "corrections": None,
                          "mismatch_allowed": True, "record": "loadimage.json"}
    fj.write_text(json.dumps(data), encoding="utf-8")
    li.write_text(json.dumps({"result": {"first_failure": {"name": "module.coverage"}}}),
                  encoding="utf-8")

    def twice():
        return stderr_of(lambda: [evidence.load_functions(fj, exe, "probe") for _ in "ab"])
    want = (f"probe: warning: {fj} was exported from a load image that did not verify "
            f"(mismatch); the pipeline went on only because it was told -AllowLoadMismatch. "
            f"The first failing check was module.coverage. Addresses and bytes in it may not "
            f"be the file's; see {li}.\n")
    if twice() != want:
        raise AssertionError(f"mismatch: {twice()!r}")
    # The record beside it missing or unreadable: the same warning, without
    # the first failing check.
    for name, content in (("bad JSON", "{not json"), ("no result", "{}"),
                          ("not an object", "[]"), ("missing", None)):
        if content is None:
            li.unlink()
        else:
            li.write_text(content, encoding="utf-8")
        text = twice()
        if text.count("warning") != 1 or "did not verify (mismatch)" not in text \
                or "first failing check" in text:
            raise AssertionError(f"loadimage.json {name}: {text!r}")
    data["load_image"]["status"] = "verified"
    fj.write_text(json.dumps(data), encoding="utf-8")
    if twice():
        raise AssertionError(f"verified: {twice()!r}")
    return "warned once with the first failing check; once without it when unreadable; verified silent"


@case("with no --exe, a target rebuilt since the export is warned about")
def _():
    work = FIX.work / "rebuilt"
    work.mkdir(exist_ok=True)
    game = work / "GAME.EXE"
    shutil.copy(FIX.mz["smallc"], game)
    functions = work / "functions.json"
    functions.write_text(json.dumps(fake_functions(game)), encoding="utf-8")
    code, _, err = run(TOOLS / "anchors.py", functions)
    if code != 0 or err.strip():
        raise AssertionError(f"unchanged target: exit {code}, {err!r}")
    game.write_bytes(game.read_bytes() + b"\0")
    code, _, err = run(TOOLS / "anchors.py", functions)
    if code != 0 or "that file is now" not in err:
        raise AssertionError(f"rebuilt target: exit {code}, {err!r}")
    return "silent while current, one warning once rebuilt"


# --------------------------------------------------- the handshake, by hand

def fake_ghidra(work):
    home = work / "ghidra"
    (home / "Ghidra").mkdir(parents=True, exist_ok=True)
    (home / "Ghidra" / "application.properties").write_text(
        "application.name=Ghidra\napplication.version=12.1.2\n", encoding="utf-8")
    return home


def handshake_setup():
    work = FIX.work / "handshake"
    work.mkdir(exist_ok=True)
    ghidra = fake_ghidra(work)
    exe = FIX.mz["smallc"]
    prof = work / "profile.json"
    env = dict(os.environ)
    env.pop(analysis_profile.DRIFT_VARIABLE, None)
    code, _, err = run(TOOLS / "analysis_profile.py", "write", "--exe", exe,
                       "--ghidra", ghidra, "--out", prof, env=env)
    if code != 0:
        raise AssertionError(f"analysis_profile.py write failed: {err}")
    expected = json.loads(prof.read_text(encoding="utf-8"))
    observed = {k: v for k, v in expected["profile"].items()
                if k not in ("profile_id", "toolkit_version")}
    functions = fake_functions(exe)
    functions["observed_profile"] = json.loads(json.dumps(observed))
    return work, ghidra, exe, prof, expected, functions, env


def check(work, prof, functions, name="functions.json"):
    path = work / name
    path.write_text(json.dumps(functions), encoding="utf-8")
    record = work / "handshake.json"
    code, out, err = run(TOOLS / "analysis_profile.py", "check", "--profile", prof,
                         "--functions", path, "--evidence", record)
    env = json.loads(record.read_text(encoding="utf-8"))
    return code, out.decode("utf-8") + err, env


@case("profile.json is an envelope whose profile_id recomputes")
def _():
    work, ghidra, exe, prof, expected, _, env = handshake_setup()
    p = expected["profile"]
    # The rule from knowledge/17, written out rather than imported, so a
    # change to what the id covers has to change this test too.
    body = {k: v for k, v in p.items() if k not in ("profile_id", "toolkit_version")}
    want = hashlib.sha256(evidence.canonical(body).encode("ascii")).hexdigest()
    if p["profile_id"] != want or expected["result"]["profile_id"] != want:
        raise AssertionError("profile_id does not recompute")
    if expected["status"] != "ok" or expected["tool"] != "analysis_profile":
        raise AssertionError(f"status {expected['status']}")
    if expected["target"]["sha256"] != evidence.sha256_file(exe):
        raise AssertionError("profile.json names the wrong target")
    # The id names the settings, not the file: another executable, same id.
    other = work / "other-profile.json"
    code, out, err = run(TOOLS / "analysis_profile.py", "write", "--exe", FIX.mz["spread"],
                         "--ghidra", ghidra, "--out", other, env=env)
    if json.loads(other.read_text())["profile"]["profile_id"] != want:
        raise AssertionError("profile_id changed with the target")
    # What write prints is the profile it wrote, not a summary of something else.
    line = (f"profile {want[:16]}  ({p['loader']}, {p['language']}:{p['compiler_spec']}, "
            f"load segment {p['load_segment']}, Ghidra 12.1.2, recovery on, load "
            f"correction on) -> {other}")
    if code != 0 or out.decode("utf-8").strip() != line:
        raise AssertionError(f"write printed {out.decode('utf-8').strip()!r}, not {line!r}")
    return f"profile {want[:12]}, the same for two executables"


def drifted_folder(name, drift="load_segment=0x2000"):
    """A work folder as a failed pipeline leaves it: functions.json, and a
    handshake.json beside it that says mismatch."""
    work, ghidra, exe, _, _, functions, env = handshake_setup()
    folder = FIX.work / name
    folder.mkdir(exist_ok=True)
    forced = folder / "profile.json"
    run(TOOLS / "analysis_profile.py", "write", "--exe", exe, "--ghidra", ghidra,
        "--out", forced, env=dict(env, **{analysis_profile.DRIFT_VARIABLE: drift}))
    (folder / "functions.json").write_text(json.dumps(functions), encoding="utf-8")
    code, _, _ = run(TOOLS / "analysis_profile.py", "check", "--profile", forced,
                     "--functions", folder / "functions.json",
                     "--evidence", folder / "handshake.json")
    if code != 1:
        raise AssertionError(f"the forced handshake did not fail (exit {code})")
    src = folder / "src.json"
    src.write_text('{"functions": []}', encoding="utf-8")
    return folder, exe, src


def readers_on(folder, exe, src, extra=()):
    """Run every reader on folder/functions.json: [(name, code, stderr)]."""
    out = []
    for name, args, needs in consumers(folder / "functions.json", exe, src):
        if not all(has_module(m) for m in needs):
            continue
        code, _, err = run(*(list(args) + list(extra)))
        out.append((name, code, err))
    return out


@case("a drifted handshake stops every reader; the override reads, and says so")
def _():
    folder, exe, src = drifted_folder("drifted")
    want = "load_segment: expected 0x2000, observed 0x1000"
    refused = readers_on(folder, exe, src)
    for name, code, err in refused:
        if code == 0 or "did not pass its profile handshake" not in err \
                or want not in err or "--accept-profile-drift" not in err:
            raise AssertionError(f"{name}: exit {code}, {err.strip()[-200:]!r}")
    accepted = readers_on(folder, exe, src, ["--accept-profile-drift"])
    for name, code, err in accepted:
        if code != 0 or "--accept-profile-drift: reading" not in err or want not in err:
            raise AssertionError(f"{name} with the override: exit {code}, {err!r}")
    (folder / "handshake.json").unlink()
    for name, code, err in readers_on(folder, exe, src):
        if code != 0 or err.strip():
            raise AssertionError(f"{name} with no handshake.json: exit {code}, {err!r}")
    skipped = 5 - len(refused)
    return (f"{len(refused)} refused, {len(accepted)} read with the override, "
            f"{len(refused)} unchanged without the record"
            + (f"; {skipped} skipped (capstone/unicorn)" if skipped else ""))


@case("a verified, blocked or out-of-date handshake is read for what it says")
def _():
    folder, exe, src = drifted_folder("records")
    record = folder / "handshake.json"
    env = json.loads(record.read_text(encoding="utf-8"))
    name, args, _ = consumers(folder / "functions.json", exe, src)[0]   # anchors

    env["status"] = "verified"
    record.write_text(json.dumps(env), encoding="utf-8")
    code, _, err = run(*args)
    if code != 0 or err.strip():
        raise AssertionError(f"verified: exit {code}, {err!r}")

    env["status"] = "blocked"
    record.write_text(json.dumps(env), encoding="utf-8")
    code, _, err = run(*args)
    if code == 0 or "could not run" not in err:
        raise AssertionError(f"blocked: exit {code}, {err!r}")

    # functions.json rewritten after a check that passed: the record is about
    # an earlier export, so this one never went through a handshake. Refused
    # like a mismatch, and read only with the override, which says why.
    env["status"] = "verified"
    record.write_text(json.dumps(env), encoding="utf-8")
    fj = folder / "functions.json"
    fj.write_text(fj.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    code, _, err = run(*args)
    if code == 0 or "checked an earlier export" not in err:
        raise AssertionError(f"out of date: exit {code}, {err!r}")
    code, _, err = run(*(list(args) + ["--accept-profile-drift"]))
    if code != 0 or "--accept-profile-drift: reading" not in err \
            or "checked an earlier export" not in err:
        raise AssertionError(f"out of date, overridden: exit {code}, {err!r}")
    return "verified silent, blocked refused, out-of-date refused and overridable"


@case("CRLF and LF copies of a source file hash the same; a target does not")
def _():
    work = FIX.work / "endings"
    work.mkdir(exist_ok=True)
    lf, crlf, bare = work / "lf.java", work / "crlf.java", work / "cr.java"
    lf.write_bytes(b"class A {\n    int b;\n}\n")
    crlf.write_bytes(b"class A {\r\n    int b;\r\n}\r\n")
    bare.write_bytes(b"class A {\r    int b;\r}\r")
    if evidence.source_sha256(lf) != evidence.source_sha256(crlf):
        raise AssertionError("CRLF and LF copies hash differently")
    if evidence.source_sha256(bare) == evidence.source_sha256(lf):
        raise AssertionError("a lone CR was folded; only CRLF should be")
    if evidence.sha256_file(lf) == evidence.sha256_file(crlf):
        raise AssertionError("the raw files should differ")
    if evidence.target_identity(lf)["sha256"] == evidence.target_identity(crlf)["sha256"]:
        raise AssertionError("a target was hashed with its line endings folded")
    return "source hashes agree, raw and target hashes differ, a lone CR is kept"


class ToolkitCopy:
    """tools/ and knowledge/ copied into a git repository of their own, with
    a git configuration of their own too, so nothing in the user's (hooks,
    signing, autocrlf) reaches it, and nothing done here reaches the real
    checkout."""

    def __init__(self, work):
        self.root = work / "toolkit"
        shutil.copytree(ROOT / "tools", self.root / "tools",
                        ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(ROOT / "knowledge", self.root / "knowledge")
        # Without it the __pycache__ that importing evidence.py leaves behind
        # is an untracked file, and every reading says -dirty.
        shutil.copy(ROOT / ".gitignore", self.root / ".gitignore")
        self.ghidra = fake_ghidra(work)
        config = work / "gitconfig"
        config.write_text("[user]\n\tname = evidence regress\n"
                          "\temail = regress@example.invalid\n", encoding="utf-8")
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=str(config),
                        GIT_CONFIG_NOSYSTEM="1")
        self.env.pop(analysis_profile.DRIFT_VARIABLE, None)
        self.git_ok = shutil.which("git") is not None
        if self.git_ok:
            self.git("init", "-q")
            self.commit("the toolkit, copied")

    def git(self, *args):
        r = subprocess.run(["git", "-C", str(self.root)] + list(args),
                           capture_output=True, text=True, env=self.env)
        if r.returncode != 0:
            raise AssertionError(f"git {' '.join(args)}: {r.stderr.strip()}")
        return r.stdout.strip()

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)

    def profile(self):
        code, out, err = run(self.root / "tools" / "analysis_profile.py", "show",
                             "--ghidra", self.ghidra, env=self.env)
        if code != 0:
            raise AssertionError(f"analysis_profile.py show: {err}")
        return json.loads(out)


def _touched(path, edit):
    original = path.read_bytes()
    path.write_bytes(edit(original))
    return original


@case("a documentation commit leaves profile_id alone; analysis code moves it")
def _():
    copy = ToolkitCopy(FIX.work / "profile-id")
    base = copy.profile()
    notes = []

    doc = copy.root / "knowledge" / "17-evidence.md"
    doc.write_bytes(doc.read_bytes() + b"\nA line a later commit added.\n")
    if copy.git_ok:
        copy.commit("knowledge: a documentation-only change")
    after_doc = copy.profile()
    if after_doc["profile_id"] != base["profile_id"]:
        raise AssertionError("a knowledge edit moved profile_id")
    if copy.git_ok:
        if after_doc["toolkit_version"] == base["toolkit_version"]:
            raise AssertionError("the commit did not move toolkit_version")
        notes.append(f"doc commit: toolkit_version {base['toolkit_version']} -> "
                     f"{after_doc['toolkit_version']}, profile_id kept")
    else:
        notes.append("doc edit kept profile_id (git not on PATH: not committed)")

    # A tool the export does not depend on: the record says dirty, the id
    # does not move.
    other = copy.root / "tools" / "evidence.py"
    original = _touched(other, lambda b: b + b"\n# an edit\n")
    edited = copy.profile()
    other.write_bytes(original)
    if edited["profile_id"] != base["profile_id"]:
        raise AssertionError("an edit to evidence.py moved profile_id")
    if copy.git_ok and not edited["toolkit_version"].endswith("-dirty"):
        raise AssertionError(f"toolkit_version {edited['toolkit_version']} not dirty")

    # Every hashed file, the load corrector included, moves the id on its own.
    moved = []
    hashed = sorted(base["analysis_code"]["files"])
    for rel in ("tools/ghidra_scripts/CorrectMzLoad.java",
                "tools/ghidra_scripts/ExportDecompiledC.java",
                "tools/pipeline.ps1"):
        if rel not in hashed:
            raise AssertionError(f"{rel} is not hashed in analysis_code")
    for rel in hashed:
        path = copy.root / rel
        original = _touched(path, lambda b: b + b"\n// an edit\n")
        edited = copy.profile()
        path.write_bytes(original)
        if edited["profile_id"] == base["profile_id"]:
            raise AssertionError(f"an edit to {rel} left profile_id alone")
        changed = [f for f, h in edited["analysis_code"]["files"].items()
                   if base["analysis_code"]["files"].get(f) != h]
        if changed != [rel]:
            raise AssertionError(f"editing {rel} changed {changed}")
        moved.append(Path(rel).name)
    if copy.git_ok and base["toolkit_version"].endswith("-dirty"):
        raise AssertionError(f"a fresh commit reads as {base['toolkit_version']}")
    if copy.profile()["profile_id"] != base["profile_id"]:
        raise AssertionError("restoring the files did not restore profile_id")
    notes.append("moved by " + ", ".join(moved))
    return "; ".join(notes)


@case("a CRLF checkout and an LF checkout of the same code share a profile_id")
def _():
    copy = ToolkitCopy(FIX.work / "profile-endings")
    base = copy.profile()
    flipped = 0
    for rel in analysis_profile.ANALYSIS_CODE:
        path = copy.root / rel
        for p in (sorted(path.rglob("*")) if path.is_dir() else [path]):
            if not p.is_file():
                continue
            raw = p.read_bytes()
            lf = raw.replace(b"\r\n", b"\n")
            p.write_bytes(lf if lf != raw else lf.replace(b"\n", b"\r\n"))
            flipped += 1
    other = copy.profile()
    if other["profile_id"] != base["profile_id"]:
        raise AssertionError("the same code with other line endings has another "
                             "profile_id")
    if other["recovery"]["script_sha256"] != base["recovery"]["script_sha256"]:
        raise AssertionError("the recovery script's hash moved with its line endings")
    return f"{flipped} files flipped, profile {base['profile_id'][:12]} both ways"


@case("the handshake verifies an export that matches")
def _():
    work, _, _, prof, expected, functions, _ = handshake_setup()
    code, out, env = check(work, prof, functions)
    pid = expected["profile"]["profile_id"]
    line = f"profile handshake: verified, 15 fields agree (profile {pid[:16]})"
    if code != 0 or env["status"] != "verified" or out.strip() != line:
        raise AssertionError(f"exit {code}, {env['status']}: {out!r}, not {line!r}")
    levels = {i["location"]["field"]: i["level"] for i in env["evidence"]}
    if len(levels) != 15 or set(levels.values()) != {"info"}:
        raise AssertionError(f"a verified handshake recorded {levels}")
    return out.strip()


# Written out here rather than read from profile.COMPARED: a field quietly
# dropped from the comparison has to fail this test, and a list taken from the
# code under test would drop with it. These are the fields
# ExportDecompiledC.java writes.
OBSERVED_FIELDS = ("loader", "language", "compiler_spec", "image_base",
                   "load_segment", "address_convention", "ghidra_version",
                   "recovery.ran", "recovery.script_sha256",
                   "export.script_sha256", "export.helper_sha256",
                   "load_correction.ran", "load_correction.script_sha256",
                   "target.sha256", "target.size")


@case("drifting any one compared field stops the handshake and names it")
def _():
    work, _, _, prof, expected, functions, _ = handshake_setup()
    pid = expected["profile"]["profile_id"]
    named = []
    for field in OBSERVED_FIELDS:
        drifted = json.loads(json.dumps(functions))
        holder = drifted["observed_profile"] if not field.startswith("target.") \
            else drifted
        parts = field.split(".")
        node = holder
        for part in parts[:-1]:
            node = node[part]
        old = node[parts[-1]]
        node[parts[-1]] = (not old) if isinstance(old, bool) else \
            (old + 1 if isinstance(old, int) else f"{old}-drifted")
        code, out, env = check(work, prof, drifted)
        if code != 1 or env["status"] != "mismatch":
            raise AssertionError(f"{field}: exit {code}, {env['status']}")
        if f"profile drift: {field}: expected" not in out:
            raise AssertionError(f"{field}: not named in {out!r}")
        # Exit 1 is also what an uncaught exception gives: the message has to
        # be there whole, and nothing after it.
        tail = (f"was not produced under profile {pid[:16]}. Do not use it until the "
                f"difference is understood; the record is in {work / 'handshake.json'}.")
        if tail not in out or "Traceback" in out:
            raise AssertionError(f"{field}: {out!r}")
        levels = {i["location"]["field"]: i["level"] for i in env["evidence"]}
        wrong = {f: lv for f, lv in levels.items() if lv != ("mismatch" if f == field else "info")}
        if len(levels) != 15 or wrong:
            raise AssertionError(f"{field}: levels {wrong or levels}")
        named.append(field)
    return f"{len(named)} fields, each refused by name, alone in the record"


@case("a forced drift is expected, and refused, like any other")
def _():
    work, ghidra, exe, _, _, functions, env = handshake_setup()
    forced = work / "forced-profile.json"
    env = dict(env, **{analysis_profile.DRIFT_VARIABLE: "load_segment=0x2000"})
    code, _, err = run(TOOLS / "analysis_profile.py", "write", "--exe", exe,
                       "--ghidra", ghidra, "--out", forced, env=env)
    if code != 0 or analysis_profile.DRIFT_VARIABLE not in err:
        raise AssertionError(f"the forced write did not announce itself: {err!r}")
    code, out, record = check(work, forced, functions)
    if code != 1 or "profile drift: load_segment: expected 0x2000, observed 0x1000" not in out:
        raise AssertionError(f"exit {code}: {out!r}")
    if record["result"]["drift"] != ["load_segment"]:
        raise AssertionError(f"drift recorded as {record['result']['drift']}")
    return "load_segment: expected 0x2000, observed 0x1000"


@case("a forced drift reaches dotted fields, reads true and false, and refuses a typo")
def _():
    work, ghidra, exe, _, _, functions, env = handshake_setup()

    def write(spec, name):
        out = work / name
        code, _, err = run(TOOLS / "analysis_profile.py", "write", "--exe", exe,
                           "--ghidra", ghidra, "--out", out,
                           env=dict(env, **{analysis_profile.DRIFT_VARIABLE: spec}))
        return code, err, (json.loads(out.read_text(encoding="utf-8"))["profile"]
                           if code == 0 else None)

    # A value is everything after the first '=', and true, false and null are read.
    code, err, p = write("recovery.ran=false,load_correction.ran=true,"
                         "export.helper_sha256=null,ghidra_version=12=x", "dotted.json")
    if code != 0:
        raise AssertionError(f"the forced write failed: {err.strip()[-300:]}")
    got = (p["recovery"]["ran"], p["load_correction"]["ran"], p["export"]["helper_sha256"],
           p["ghidra_version"], "ran" in p)
    if got != (False, True, None, "12=x", False):
        raise AssertionError(f"forced to {got}")
    code, out, record = check(work, work / "dotted.json", functions)
    if code != 1 or record["result"]["drift"] != ["ghidra_version", "recovery.ran",
                                                   "export.helper_sha256"]:
        raise AssertionError(f"exit {code}, drift {record['result']['drift']}")
    # A field the profile does not have is a typo, refused; one it has but the
    # export does not report is taken, and moves only the id.
    code, err, _ = write("load_segmnet=0x2000", "typo.json")
    if code == 0 or "load_segmnet" not in err or "not a profile field" not in err:
        raise AssertionError(f"a typo was taken: exit {code}, {err.strip()[-200:]!r}")
    code, err, p = write("load_image_dump.script_sha256=x", "uncompared.json")
    if code != 0 or p["load_image_dump"]["script_sha256"] != "x":
        raise AssertionError(f"an uncompared field was refused: {err.strip()[-200:]!r}")
    code, out, record = check(work, work / "uncompared.json", functions)
    if code != 0 or record["status"] != "verified":
        raise AssertionError(f"forcing an uncompared field broke the handshake: {out!r}")
    return "dotted fields, true/false/null and '=' in a value; a typo refused"


@case("a field missing from the export is a drift named (absent), not a crash")
def _():
    work, _, _, prof, _, functions, _ = handshake_setup()
    for drop, field in (("recovery", "recovery.ran"), ("loader", "loader")):
        bare = json.loads(json.dumps(functions))
        del bare["observed_profile"][drop]
        code, out, env = check(work, prof, bare)
        if code != 1 or env["status"] != "mismatch" or "Traceback" in out \
                or f"profile drift: {field}: expected" not in out \
                or "observed (absent)" not in out:
            raise AssertionError(f"without {drop}: exit {code}, {out.strip()[-300:]!r}")
    return "recovery and loader removed: each named, observed (absent)"


@case("an export with no observed_profile, or none at all, is not verified")
def _():
    work, _, _, prof, _, functions, _ = handshake_setup()
    bare = dict(functions)
    del bare["observed_profile"]
    code, out, env = check(work, prof, bare)
    if code != 1 or env["status"] != "mismatch":
        raise AssertionError(f"no observed_profile: exit {code}")
    record = work / "absent-handshake.json"
    code, _, err = run(TOOLS / "analysis_profile.py", "check", "--profile", prof,
                       "--functions", work / "absent.json", "--evidence", record)
    if code != 2 or json.loads(record.read_text())["status"] != "blocked":
        raise AssertionError(f"absent export: exit {code}")
    return "mismatch, and blocked"


def main():
    global FIX, UPDATE_EXPECTED
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nasm")
    ap.add_argument("--only", action="append",
                    help="run only the cases whose name contains this; may be repeated")
    ap.add_argument("--update-expected", action="store_true",
                    help="write triage's answers to expected-triage.json instead of "
                         "comparing them; read the diff before committing it")
    args = ap.parse_args()
    UPDATE_EXPECTED = args.update_expected
    nasm = args.nasm or os.environ.get("NASM") or shutil.which("nasm")
    if not nasm or not Path(nasm).exists():
        print("evidence regress: nasm not found (set NASM or pass --nasm); "
              "the fixtures cannot be assembled")
        return 77

    cases = [(name, fn) for name, fn in CASES
             if not args.only or any(o in name for o in args.only)]
    work = Path(tempfile.mkdtemp(prefix="evidence-regress-"))
    failures = skipped = 0
    try:
        FIX = Fixtures(nasm, work)
        for name, fn in cases:
            try:
                print(f"  PASS  {name:<66} {fn()}")
            except Skip as e:
                print(f"  SKIP  {name:<66} {e}")
                skipped += 1
            except AssertionError as e:
                print(f"  FAIL  {name:<66} {e}")
                failures += 1
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print()
    if not cases:
        print(f"no evidence check matches --only {args.only}")
        return 1
    if failures:
        print(f"{failures} of {len(cases)} evidence checks failed.")
        return 1
    if skipped:
        print(f"{len(cases) - skipped} evidence checks pass; {skipped} skipped.")
        return 0
    print(f"All {len(cases)} evidence checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
