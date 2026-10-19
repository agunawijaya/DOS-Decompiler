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
    python tests/evidence/regress.py [--nasm PATH]
"""

import argparse
import hashlib
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
sys.path.insert(0, str(TOOLS))
import evidence                                          # noqa: E402
import profile as profile_tool                           # noqa: E402

CASES = []
ID_SHAPE = re.compile(r"^ev-[0-9a-f]{8}-[0-9a-f]{8}(-\d+)?$")


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


class Skip(Exception):
    pass


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

    def files(self):
        return list(self.mz.values()) + list(self.com.values()) + [self.text]


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


# ------------------------------------------------------------ identity

def independent_sha256(path):
    """The hash from a program that is not Python's hashlib."""
    attempts = [
        (["sha256sum", str(path)], lambda o: o.split()[0]),
        (["shasum", "-a", "256", str(path)], lambda o: o.split()[0]),
        (["certutil", "-hashfile", str(path), "SHA256"],
         lambda o: o.splitlines()[1].replace(" ", "")),
        (["openssl", "dgst", "-sha256", str(path)], lambda o: o.split()[-1]),
    ]
    for cmd, parse in attempts:
        if not shutil.which(cmd[0]):
            continue
        r = subprocess.run(cmd, capture_output=True, text=True)
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
    return f"{first['files']} file, hash {first['sha256'][:12]}"


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


@case("envelopes are canonical and their ids recompute")
def _():
    envelopes = [triage_envelope(p)[1] for p in FIX.files()]
    envelopes += [mzinfo_envelope(p)[1] for p in FIX.mz.values()]
    envelopes += [survey_envelope(f)[1] for f in FIX.folders.values()]
    items = 0
    for raw in envelopes:
        text = raw.decode("ascii")                     # ASCII only, or it raises
        env = json.loads(text)
        if evidence.dumps(env) != text:
            raise AssertionError(f"{env['tool']}: not in canonical form")
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
    env.pop(profile_tool.DRIFT_VARIABLE, None)
    code, _, err = run(TOOLS / "profile.py", "write", "--exe", exe,
                       "--ghidra", ghidra, "--out", prof, env=env)
    if code != 0:
        raise AssertionError(f"profile.py write failed: {err}")
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
    code, out, err = run(TOOLS / "profile.py", "check", "--profile", prof,
                         "--functions", path, "--evidence", record)
    env = json.loads(record.read_text(encoding="utf-8"))
    return code, out.decode("utf-8") + err, env


@case("profile.json is an envelope whose profile_id recomputes")
def _():
    work, ghidra, exe, prof, expected, _, env = handshake_setup()
    p = expected["profile"]
    body = {k: v for k, v in p.items() if k != "profile_id"}
    want = hashlib.sha256(evidence.canonical(body).encode("ascii")).hexdigest()
    if p["profile_id"] != want or expected["result"]["profile_id"] != want:
        raise AssertionError("profile_id does not recompute")
    if expected["status"] != "ok" or expected["tool"] != "profile":
        raise AssertionError(f"status {expected['status']}")
    if expected["target"]["sha256"] != evidence.sha256_file(exe):
        raise AssertionError("profile.json names the wrong target")
    # The id names the settings, not the file: another executable, same id.
    other = work / "other-profile.json"
    run(TOOLS / "profile.py", "write", "--exe", FIX.mz["spread"], "--ghidra",
        ghidra, "--out", other, env=env)
    if json.loads(other.read_text())["profile"]["profile_id"] != want:
        raise AssertionError("profile_id changed with the target")
    return f"profile {want[:12]}, the same for two executables"


@case("the handshake verifies an export that matches")
def _():
    work, _, _, prof, _, functions, _ = handshake_setup()
    code, out, env = check(work, prof, functions)
    if code != 0 or env["status"] != "verified" or "verified" not in out:
        raise AssertionError(f"exit {code}, {env['status']}: {out}")
    return out.strip()


# Written out here rather than read from profile.COMPARED: a field quietly
# dropped from the comparison has to fail this test, and a list taken from the
# code under test would drop with it. These are the fields
# ExportDecompiledC.java writes.
OBSERVED_FIELDS = ("loader", "language", "compiler_spec", "image_base",
                   "load_segment", "address_convention", "ghidra_version",
                   "recovery.ran", "recovery.script_sha256",
                   "target.sha256", "target.size")


@case("drifting any one compared field stops the handshake and names it")
def _():
    work, _, _, prof, _, functions, _ = handshake_setup()
    named = []
    for field in OBSERVED_FIELDS:
        drifted = json.loads(json.dumps(functions))
        holder = drifted["observed_profile"] if not field.startswith("target.") \
            else drifted
        parts = field.split(".") if field.startswith(("recovery.", "target.")) \
            else [field]
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
        named.append(field)
    return f"{len(named)} fields, each refused by name"


@case("a forced drift is expected, and refused, like any other")
def _():
    work, ghidra, exe, _, _, functions, env = handshake_setup()
    forced = work / "forced-profile.json"
    env = dict(env, **{profile_tool.DRIFT_VARIABLE: "load_segment=0x2000"})
    code, _, err = run(TOOLS / "profile.py", "write", "--exe", exe,
                       "--ghidra", ghidra, "--out", forced, env=env)
    if code != 0 or profile_tool.DRIFT_VARIABLE not in err:
        raise AssertionError(f"the forced write did not announce itself: {err!r}")
    code, out, record = check(work, forced, functions)
    if code != 1 or "profile drift: load_segment: expected 0x2000, observed 0x1000" not in out:
        raise AssertionError(f"exit {code}: {out!r}")
    if record["result"]["drift"] != ["load_segment"]:
        raise AssertionError(f"drift recorded as {record['result']['drift']}")
    return "load_segment: expected 0x2000, observed 0x1000"


@case("an export with no observed_profile, or none at all, is not verified")
def _():
    work, _, _, prof, _, functions, _ = handshake_setup()
    bare = dict(functions)
    del bare["observed_profile"]
    code, out, env = check(work, prof, bare)
    if code != 1 or env["status"] != "mismatch":
        raise AssertionError(f"no observed_profile: exit {code}")
    record = work / "absent-handshake.json"
    code, _, err = run(TOOLS / "profile.py", "check", "--profile", prof,
                       "--functions", work / "absent.json", "--evidence", record)
    if code != 2 or json.loads(record.read_text())["status"] != "blocked":
        raise AssertionError(f"absent export: exit {code}")
    return "mismatch, and blocked"


def main():
    global FIX
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--nasm")
    args = ap.parse_args()
    nasm = args.nasm or os.environ.get("NASM") or shutil.which("nasm")
    if not nasm or not Path(nasm).exists():
        print("evidence regress: nasm not found (set NASM or pass --nasm); "
              "the fixtures cannot be assembled")
        return 77

    work = Path(tempfile.mkdtemp(prefix="evidence-regress-"))
    failures = skipped = 0
    try:
        FIX = Fixtures(nasm, work)
        for name, fn in CASES:
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
    if failures:
        print(f"{failures} of {len(CASES)} evidence checks failed.")
        return 1
    if skipped:
        print(f"{len(CASES) - skipped} evidence checks pass; {skipped} skipped.")
        return 0
    print(f"All {len(CASES)} evidence checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
