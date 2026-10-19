#!/usr/bin/env python3
"""
evidence.py -- The shape every tool's result takes when a program, not a
person, is going to read it.

Every tool here prints prose for a person. An agent reading that prose has to
guess at its structure, and the guess is where findings get lost: a warning
wrapped over three lines, a blocker printed once although two checks found
it. The result also used to carry no record of which file produced it, so a
`functions.json` from last week's import could be read against this week's
executable and nothing would notice.

So a tool that supports it can also emit an *evidence envelope*: the result,
each observation behind it with where it was seen, what the method cannot
see, and what it raised but could not settle -- all tied to the target's size
and SHA-256. The schema is written down in knowledge/17-evidence.md.

What it provides
----------------
  target_identity(path)      absolute path, size and SHA-256 of a file
  directory_identity(path)   the same for a folder, hashed over a manifest
  source_sha256(path)        a hash of the toolkit's own source that does not
                             change with the checkout's line endings
  envelope(...)              build one, with deterministic evidence ids
  write(env, dest)           canonical JSON to a file, or '-' for stdout
  canonical(obj)             the compact form that ids and profile ids hash
  check_functions_target()   refuse a functions.json made from another file
  check_handshake()          refuse one whose handshake.json says it drifted
  check_load_image()         warn about one exported from an unverified load
  load_functions()           all three, then the parsed functions.json

Statuses
--------
  ok           The tool ran to completion and its result describes the
               target. Nothing was compared against an oracle, so nothing
               is proved: triage, survey, a profile written down.
  verified     The result was compared with an independent oracle and they
               agree: the profile handshake, a byte-identical rebuild.
  mismatch     It was compared and they disagree; the evidence says where.
               The profile handshake on drift, a stale functions.json.
  unsupported  The target is a kind of input this tool does not handle,
               and the tool says so rather than producing something.
  blocked      Something outside the target is missing -- a prerequisite
               tool, an input file -- or a precondition refused the run.
  error        The tool failed. Nothing in the result is to be trusted.

A tool may use only the statuses it can honestly reach: a tool that compares
nothing never says `verified`, and `ok` never means "checked".

Evidence ids
------------
`ev-<8 hex of the target's SHA-256>-<8 hex of the item>`. The second half
hashes the item's kind, claim, location and value -- not its explanatory
detail, and not its position in the list -- so rewording an explanation or
reordering a report leaves every id alone, and the same claim about the same
bytes gets the same id in every run. Two different items that would collide
take `-2`, `-3` in the order given, which is still deterministic.

Output is canonical: keys sorted, ASCII only, integers as integers, floats in
Python's shortest round-trip form, NaN and infinity refused. Two runs over
the same input can be compared with a plain diff.

What it does not do: decide anything. It records what a tool established; it
cannot make an observation truer than the tool that made it.

No third-party dependencies.

Usage, from a tool:
    import evidence
    env = evidence.envelope("triage", evidence.target_identity(path),
                            status="ok", result={...}, evidence=[...])
    evidence.write(env, "-")
"""

import hashlib
import json
import math
import os
import subprocess
import sys
from pathlib import Path

SCHEMA = "dos-decompiler/evidence/1"
STATUSES = ("ok", "verified", "mismatch", "unsupported", "blocked", "error")

TOOLKIT_ROOT = Path(__file__).resolve().parent.parent

# What part of an item its id is computed from. `detail` and `level` are left
# out on purpose: they explain or rank an observation, they are not it.
ID_FIELDS = ("kind", "claim", "location", "value")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def source_sha256(path):
    """SHA-256 of a source file with CRLF line endings read as LF.

    For the toolkit's own code, not for targets. git checks a file out with
    CRLF or LF depending on the machine (core.autocrlf), so the raw bytes of
    one commit differ between a Windows and a Linux checkout; hashing them raw
    gave the two different analysis profiles for the same code. Only the
    two-byte CRLF pair is folded, exactly as git folds it. A target
    executable is always hashed raw (target_identity): there a 0D 0A is data.
    """
    return hashlib.sha256(Path(path).read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def target_identity(path):
    """Absolute path, size and SHA-256 of one file."""
    p = Path(path)
    return {"path": str(p.resolve()), "size": p.stat().st_size,
            "sha256": sha256_file(p)}


def directory_identity(path):
    """An identity for a folder: one hash over every file in it.

    The manifest is each file's path relative to the folder (with forward
    slashes, so the same folder hashes the same on Windows and Linux), size
    and SHA-256, sorted by path. Change, add, remove or rename any file and
    the hash changes; touch nothing and it does not.
    """
    root = Path(path).resolve()
    manifest, total = [], 0
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        size = p.stat().st_size
        total += size
        manifest.append([p.relative_to(root).as_posix(), size, sha256_file(p)])
    manifest.sort()
    digest = hashlib.sha256(canonical(manifest).encode("ascii")).hexdigest()
    return {"path": str(root), "kind": "directory", "files": len(manifest),
            "size": total, "sha256": digest}


def toolkit_version():
    """The toolkit's git short hash, `-dirty` if tools/ has uncommitted
    changes, or 'unknown' outside a git checkout.

    Only tools/ counts towards dirty, untracked files included -- a new tool
    module not yet committed is still code the result came from. Editing a
    document does not change what any tool computes; editing a tool does, and
    a result produced by edited code should not claim the version of the code
    it was edited from.
    """
    def git(*args):
        r = subprocess.run(["git", "-C", str(TOOLKIT_ROOT)] + list(args),
                           capture_output=True, text=True, timeout=20)
        return r.returncode, r.stdout.strip()

    try:
        code, head = git("rev-parse", "--short", "HEAD")
        if code != 0 or not head:
            return "unknown"
        code, changes = git("status", "--porcelain", "--", "tools")
        return head + ("-dirty" if code == 0 and changes else "")
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _check_numbers(obj):
    if isinstance(obj, float) and (math.isnan(obj) or math.isinf(obj)):
        raise ValueError("evidence: NaN and infinity have no canonical JSON form")
    if isinstance(obj, dict):
        for v in obj.values():
            _check_numbers(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _check_numbers(v)


def canonical(obj):
    """Compact canonical JSON: what ids and profile ids are hashed over."""
    _check_numbers(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def dumps(obj):
    """Indented canonical JSON with a final newline: what files hold."""
    _check_numbers(obj)
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=True,
                      allow_nan=False) + "\n"


def evidence_id(target_sha256, item):
    head = (target_sha256 or "0" * 8)[:8]
    content = {k: item[k] for k in ID_FIELDS if k in item}
    body = hashlib.sha256(canonical(content).encode("ascii")).hexdigest()[:8]
    return f"ev-{head}-{body}"


def envelope(tool, target, status="ok", result=None, evidence=(),
             limitations=(), unknowns=(), profile=None):
    """Assemble an envelope and give every evidence item its id.

    An item listed twice with identical content is kept once: it is one
    observation, and repeating it would read as corroboration it is not.
    Limitations and unknowns are deduplicated the same way, keeping order.
    """
    if status not in STATUSES:
        raise ValueError(f"evidence: status {status!r} is not one of {STATUSES}")
    sha = (target or {}).get("sha256")

    items, seen_content, used_ids = [], set(), {}
    for raw in evidence:
        item = {k: v for k, v in raw.items() if k != "id"}
        content = canonical(item)
        if content in seen_content:
            continue
        seen_content.add(content)
        base = evidence_id(sha, item)
        n = used_ids.get(base, 0) + 1
        used_ids[base] = n
        item["id"] = base if n == 1 else f"{base}-{n}"
        items.append(item)

    def unique(texts):
        out = []
        for t in texts:
            if t not in out:
                out.append(t)
        return out

    return {
        "schema": SCHEMA,
        "tool": tool,
        "tool_version": toolkit_version(),
        "target": target,
        "profile": profile,
        "status": status,
        "result": result if result is not None else {},
        "evidence": items,
        "limitations": unique(limitations),
        "unknowns": unique(unknowns),
    }


def write(env, dest):
    """Write an envelope to `dest`, or to stdout when `dest` is '-'.

    Written as bytes, so the newline is '\\n' on every platform and two runs
    compare equal byte for byte rather than only after line-ending
    translation.
    """
    data = dumps(env).encode("ascii")
    if dest == "-":
        sys.stdout.flush()
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
    else:
        Path(dest).write_bytes(data)


# ---------------------------------------------------------------- stale results

_warned = set()


def _warn_once(key, message):
    if key in _warned:
        return
    _warned.add(key)
    print(message, file=sys.stderr)


def check_functions_target(data, functions_path, exe=None, tool="this tool"):
    """Refuse a functions.json that was produced from a different file.

    `data` is the parsed functions.json; `exe` the executable the caller was
    given alongside it. Three outcomes:

      * the hashes agree: silence.
      * they differ: SystemExit, naming the file to regenerate.
      * functions.json predates the `target` record: one warning per file per
        run, then carry on, so old work folders still open.

    With no `exe`, the file recorded in `target.path` is checked instead if it
    is still there. A tool given no executable is not reading one, so a
    difference there is a warning rather than a refusal -- but it is the
    common way a result goes stale (the game rebuilt in place, the pipeline
    not re-run), and it should not pass silently.
    """
    target = data.get("target") if isinstance(data, dict) else None
    key = str(Path(functions_path).resolve())
    if not target or not target.get("sha256"):
        _warn_once(key, (
            f"{tool}: warning: {functions_path} has no target record (it was "
            f"written before the pipeline recorded one), so nothing can confirm "
            f"which executable it describes. Re-run tools/pipeline.ps1 to add it."))
        return
    recorded = target["sha256"].lower()

    if exe is not None:
        actual = sha256_file(exe)
        if actual != recorded:
            raise SystemExit(
                f"{tool}: {functions_path} was produced from a different file "
                f"than {exe}.\n"
                f"  functions.json target : {target.get('path', '?')}  "
                f"{target.get('size', '?')} bytes  sha256 {recorded[:16]}...\n"
                f"  given                 : {exe}  {os.path.getsize(exe)} bytes  "
                f"sha256 {actual[:16]}...\n"
                f"Regenerate {functions_path} from {exe} with tools/pipeline.ps1, "
                f"or pass the executable it was made from.")
        return

    path = target.get("path")
    if not path or not Path(path).is_file():
        return
    actual = sha256_file(path)
    if actual != recorded:
        _warn_once(key, (
            f"{tool}: warning: {functions_path} was made from {path} when its "
            f"sha256 was {recorded[:16]}...; that file is now {actual[:16]}... "
            f"If the executable was rebuilt, regenerate {functions_path} with "
            f"tools/pipeline.ps1. Pass --exe to make this an error."))


# A handshake in one of these states means the export beside it was not
# produced under the profile the pipeline expected, or was never checked.
HANDSHAKE_REFUSED = ("mismatch", "blocked")
ACCEPT_DRIFT_FLAG = "--accept-profile-drift"


def check_handshake(functions_path, tool="this tool", accept_drift=False):
    """Refuse a functions.json whose handshake.json says it drifted.

    pipeline.ps1 stops when the handshake fails, but it leaves functions.json
    on disk, and before this every reader would open it. Now:

      * handshake.json beside it says mismatch or blocked: SystemExit, with
        the fields that drifted and what to do -- unless accept_drift, which
        says on stderr that it is reading a drifted export, every time.
      * it is about a different export -- functions.json was rewritten after
        the check, so the export beside it never went through a handshake:
        refused the same way, and overridden the same way.
      * it says verified, or there is none (a work folder from before the
        handshake): silence, as before.
      * it cannot be read: one warning, and carry on.
    """
    record = Path(functions_path).parent / "handshake.json"
    if not record.is_file():
        return
    key = "handshake:" + str(record.resolve())
    try:
        env = json.loads(record.read_text(encoding="utf-8"))
        status = env["status"]
        result = env.get("result") or {}
    except (OSError, ValueError, KeyError, TypeError) as e:
        _warn_once(key, f"{tool}: warning: could not read {record} ({e}); "
                        f"nothing confirms {functions_path} passed its handshake.")
        return

    # A record of a different export says nothing about this one, and an
    # export that was never checked is refused like one that failed: the
    # architect's decision after 01a, which had this warn and carry on.
    checked = result.get("functions_sha256")
    rewritten = bool(checked) and checked != sha256_file(functions_path)
    if not rewritten and status not in HANDSHAKE_REFUSED:
        return

    if rewritten:
        what = ("the handshake beside it checked an earlier export, so this one "
                "never went through a handshake")
    elif status == "blocked":
        what = ("the handshake could not run when this folder was made -- there "
                "was no export to check")
    else:
        drifted = [i["claim"] for i in env.get("evidence", [])
                   if i.get("level") == "mismatch"]
        what = ("the handshake found " + "; ".join(drifted)) if drifted else \
            "the handshake failed"
    if accept_drift:
        print(f"{tool}: {ACCEPT_DRIFT_FLAG}: reading {functions_path} although "
              f"{what}. Everything below rests on settings the rest of the "
              f"toolkit does not assume.", file=sys.stderr)
        return
    if rewritten:
        fix = (f"Re-run tools/pipeline.ps1, or tools/analysis_profile.py check "
               f"--evidence {record}, to check the export as it is now")
    else:
        fix = ("Find out why Ghidra did not do what the profile expected, fix "
               "it and re-run tools/pipeline.ps1")
    raise SystemExit(
        f"{tool}: {functions_path} did not pass its profile handshake: {what}.\n"
        f"The record is {record}. {fix}. If you have understood why and want "
        f"these results anyway, pass {ACCEPT_DRIFT_FLAG}.")


def check_load_image(data, functions_path, tool="this tool"):
    """Warn about an export whose load image did not verify.

    The pipeline stops on a load image that does not verify unless it was
    given -AllowLoadMismatch, and then ExportDecompiledC.java records the
    verdict in functions.json. Reading such an export was a decision someone
    made, so this does not refuse; it says, once, what the export rests on,
    with the first failing check from the loadimage.json beside it.
    """
    record = data.get("load_image") if isinstance(data, dict) else None
    if not record or record.get("status") == "verified":
        return
    detail = ""
    beside = Path(functions_path).parent / record.get("record", "loadimage.json")
    try:
        first = json.loads(beside.read_text(encoding="utf-8"))["result"].get("first_failure")
        if first:
            detail = f" The first failing check was {first.get('name')}."
    except (OSError, ValueError, KeyError, TypeError):
        pass
    _warn_once("load:" + str(Path(functions_path).resolve()), (
        f"{tool}: warning: {functions_path} was exported from a load image that "
        f"did not verify ({record.get('status')}); the pipeline went on only "
        f"because it was told -AllowLoadMismatch.{detail} Addresses and bytes in "
        f"it may not be the file's; see {beside}."))


def load_functions(functions_path, exe=None, tool="this tool", accept_drift=False):
    """Read a functions.json, and check it against `exe`, against the
    handshake.json beside it and against its load-image verdict, before
    returning it."""
    data = json.loads(Path(functions_path).read_text(encoding="utf-8"))
    check_functions_target(data, functions_path, exe, tool)
    check_handshake(functions_path, tool, accept_drift)
    check_load_image(data, functions_path, tool)
    return data
