"""
operations.py -- What each tool of the MCP server does, with no MCP in it.

Every function here takes plain arguments and returns an evidence envelope
(knowledge/17-evidence.md). It calls the same functions the command-line
tools call -- triage.envelope, bodies.analyse, applynames.run, sweep.run_sweep
and the rest -- and does no analysis of its own: where a tool already writes
an envelope, that envelope is returned; where it returns data, the data is
put in one, unchanged. server.py registers these as MCP tools; keeping them
here, free of the SDK, means nothing else in the toolkit imports it, and the
tests can call them directly.

A refusal is an envelope too: status `blocked`, `result.reason` saying why
and `result.next_step` what to do. Nothing reaches the agent as a bare
exception.
"""

import fnmatch
import io
import json
import os
import shutil
import sys
import time
from contextlib import redirect_stderr
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(HERE))

import evidence  # noqa: E402
import paging  # noqa: E402
import safety  # noqa: E402
import sessions  # noqa: E402
from safety import Refused  # noqa: E402

PIPELINE_TIMEOUT = 1800        # seconds for one analysis
MAX_READ = 4096                # bytes one read_bytes may return
MAX_TARGET = 16 * 1024 * 1024  # a DOS program is far smaller; larger is not one
MAX_COM = 0xFF00               # what fits in a segment after the PSP


def blocked(tool, reason, next_step, target=None):
    return evidence.envelope(tool, target, status="blocked",
                             result={"reason": reason, "next_step": next_step})


def failed(tool, error, target=None):
    return evidence.envelope(tool, target, status="error", result={
        "reason": f"{type(error).__name__}: {error}",
        "next_step": "this is a fault in the toolkit, not in the target; run the "
                     "command-line tool on the same input to see it in full, and "
                     "report it"})


def guarded(tool):
    """Turn a refusal into a blocked envelope and anything else into an
    error envelope, so the agent always gets an envelope back."""
    def wrap(fn):
        def run(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except Refused as r:
                return blocked(tool, r.reason, r.next_step)
            except SystemExit as e:        # the toolkit's own refusals
                return blocked(tool, str(e), "read the reason: it names what to do")
            except Exception as e:  # noqa: BLE001 -- reported, not swallowed
                return failed(tool, e)
        run.__name__, run.__doc__ = fn.__name__, fn.__doc__
        return run
    return wrap


def paged(env, limit, cursor, *lists, whole=()):
    """Page the evidence and every list at the top of the result but those
    named in `whole`, plus any deeper ones named."""
    paths = [("evidence",), ("unknowns",)]
    paths += [("result", k) for k, v in (env.get("result") or {}).items()
              if isinstance(v, list) and k not in whole]
    paths += [tuple(p) for p in lists]
    return paging.page(env, paths, limit, cursor)


def target_of(session):
    return evidence.target_identity(session.copy)


def need_analysis(session):
    if session.format != "mz":
        raise Refused(f"session {session.id} holds a .COM, which the Ghidra pipeline does "
                      f"not take", "use comrec for a .COM")
    if not session.analysed():
        raise Refused(f"session {session.id} has not been analysed",
                      "run analyze on it first")


def quietly(fn, *args, **kwargs):
    """Call a toolkit function whose notes go to stderr; (value, notes)."""
    err = io.StringIO()
    with redirect_stderr(err):
        value = fn(*args, **kwargs)
    return value, [line for line in err.getvalue().splitlines() if line.strip()]


# ---------------------------------------------------------------- admission

@guarded("survey")
def survey(folder, limit=None, cursor=None):
    import survey as tool
    p = safety.absolute(folder, "folder", kind="dir")
    return paged(tool.envelope(str(p)), limit, cursor)


@guarded("triage")
def triage(session_id=None, path=None, limit=None, cursor=None):
    import triage as tool
    if session_id:
        p = sessions.get(session_id).copy
    else:
        p = safety.absolute(path, "path", kind="file")
    return paged(tool.envelope(str(p)), limit, cursor)


@guarded("open_binary")
def open_binary(path, format="auto"):
    p = safety.absolute(path, "path", kind="file")
    size = p.stat().st_size
    if size > MAX_TARGET:
        raise Refused(f"{p} is {size:,} bytes, far larger than any DOS program",
                      "check that this is the program you meant")
    with open(p, "rb") as fh:
        magic = fh.read(2)
    is_mz = magic in (b"MZ", b"ZM")
    if format not in ("auto", "mz", "com"):
        raise Refused(f"format {format!r} is not auto, mz or com", "pass one of those")
    if format == "auto":
        if not is_mz:
            raise Refused(
                f"{p.name} does not start with MZ, so it is not an MZ executable; and a "
                f".COM has no header to recognise it by, so neither its name nor a guess "
                f"is enough to read it as one",
                'if it is a .COM, open it again with format="com"')
        fmt = "mz"
    elif format == "mz":
        if not is_mz:
            raise Refused(f"{p.name} does not start with MZ", 'if it is a .COM, pass format="com"')
        fmt = "mz"
    else:
        if is_mz:
            raise Refused(f"{p.name} starts with MZ, and DOS loads such a file as an MZ "
                          f"executable whatever its name says", 'open it with format="mz"')
        if size > MAX_COM:
            raise Refused(f"{p.name} is {size:,} bytes; a .COM is at most {MAX_COM:,}",
                          "check the file: DOS would refuse to run it as a .COM")
        fmt = "com"
    s = sessions.admit(p, fmt)
    return evidence.envelope("open_binary", s.record["original"], status="ok", result={
        "session_id": s.id, "format": fmt, "folder": str(s.folder), "copy": str(s.copy),
        "original": str(p),
        "next_step": "triage it" if fmt == "mz" else "comrec it: a .COM takes the .COM route"})


@guarded("close_binary")
def close_binary(session_id):
    s = sessions.get(session_id)
    gone = sessions.close(s)
    if not gone:
        raise Refused(f"could not delete {s.folder} entirely (a file in it is in use)",
                      "close whatever holds it, then close_binary again")
    return evidence.envelope("close_binary", s.record["original"], status="ok", result={
        "session_id": s.id, "deleted": str(s.folder), "exists_after": False})


@guarded("list_sessions")
def list_sessions(limit=None, cursor=None):
    found = [{"session_id": s.id, "format": s.format, "original": str(s.original),
              "sha256": s.sha256, "analysed": s.analysed()} for s in sessions.all_sessions()]
    env = evidence.envelope("list_sessions", None, status="ok",
                            result={"work": str(sessions.work_root()), "sessions": found})
    return paged(env, limit, cursor)


# ---------------------------------------------------------------- unpacking, .COM

def keep(paths, keep_to, original):
    if not keep_to:
        return []
    folder = safety.keep_folder(keep_to, original)
    folder.mkdir(parents=True, exist_ok=True)
    out = []
    for p in paths:
        dest = folder / Path(p).name
        shutil.copy2(p, dest)
        out.append(str(dest))
    return out


@guarded("unpack")
def unpack(session_id, out=None, keep_to=None):
    import unpack as tool
    s = sessions.get(session_id)
    if s.format != "mz":
        raise Refused("a .COM is not unpacked by this tool", "use comrec for a .COM")
    out = safety.output_inside(out, "out", s.folder) if out else \
        s.folder / "unpacked" / f"{s.copy.stem}-unpacked.exe"
    (data, info), notes = quietly(tool.unpack, str(s.copy))
    info = {k: v for k, v in info.items() if isinstance(v, (int, str, bool, float, type(None)))}
    if data is None:
        return evidence.envelope("unpack", target_of(s), status="blocked", result={
            "reason": "no unpacked entry point was reached: either the file is not packed, "
                      "or its decompressor needs more of DOS than unpack.py stubs out",
            "next_step": "triage says whether it is packed; nothing was written",
            "info": info, "notes": notes})
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    return evidence.envelope("unpack", target_of(s), status="ok", result={
        "written": str(out), "kept": keep([out], keep_to, s.original), "info": info,
        "notes": notes,
        "next_step": f"open_binary {out} to work on the unpacked image; it is for "
                     f"analysis, and relocations are not reconstructed, so it will not run"})


@guarded("comrec")
def comrec(session_id, out=None, keep_to=None, limit=None, cursor=None):
    import comrec as tool
    s = sessions.get(session_id)
    if s.format != "com":
        raise Refused("comrec takes a .COM session; a single-segment MZ can take the .COM "
                      "route too, but that is the command line's --max-relocations decision",
                      "run tools/comrec.py on it directly if that is what you mean")
    out = safety.output_inside(out, "out", s.folder) if out else \
        s.folder / "comrec" / f"{s.copy.stem}.asm"
    report, code = tool.reconstruct(str(s.copy), str(out), mapfile=str(out.with_suffix(".map")))
    report["kept"] = keep(report["written"], keep_to, s.original)
    return paged(evidence.envelope("comrec", target_of(s),
                                   status="verified" if report["byte_identical"] else "mismatch",
                                   result=report), limit, cursor)


# ---------------------------------------------------------------- analysis

def ghidra_env():
    ghidra, java = os.environ.get("GHIDRA_HOME"), os.environ.get("JAVA_HOME")
    if not ghidra or not Path(ghidra).is_dir():
        raise Refused("GHIDRA_HOME is not set to a Ghidra installation",
                      "set GHIDRA_HOME (env.ps1 does) in the environment the server starts in")
    if not java or not Path(java).is_dir():
        raise Refused("JAVA_HOME is not set to a JDK", "set JAVA_HOME (env.ps1 does)")
    if not shutil.which("pwsh"):
        raise Refused("pwsh is not on PATH; the pipeline is a PowerShell 7 script",
                      "install PowerShell 7 and put pwsh on PATH")
    return ghidra, java


def profile_for(ghidra, skip_recovery):
    import analysis_profile
    return analysis_profile.with_id(analysis_profile.expected_profile(ghidra, skip_recovery))


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


@guarded("analyze")
def analyze(session_id, skip_recovery=False, timeout=PIPELINE_TIMEOUT, progress=None):
    """pipeline.ps1 on the session's copy, or the cached analysis of the same
    bytes under the same profile."""
    s = sessions.get(session_id)
    if s.format != "mz":
        raise Refused("a .COM does not go through the Ghidra pipeline", "use comrec")
    ghidra, java = ghidra_env()
    profile = profile_for(ghidra, skip_recovery)
    pid = profile["profile_id"]
    started = time.perf_counter()
    if sessions.cache_fetch(s, pid):
        cache = "hit"
        log_tail = []
    else:
        cache = "miss"
        shutil.rmtree(s.analysis, ignore_errors=True)
        args = ["pwsh", "-NoProfile", "-File", str(TOOLS / "pipeline.ps1"), "-Exe", str(s.copy),
                "-OutDir", str(s.analysis), "-Ghidra", ghidra, "-JavaHome", java]
        if skip_recovery:
            args.append("-SkipRecovery")
        env = dict(os.environ, PYTHON=sys.executable)

        def on_line(line):
            # "[3/6] Correct the load": the stage, for the client's progress.
            if progress and line.startswith("[") and "/6]" in line[:6]:
                progress(int(line[1]), 6, line[6:].strip())
        code, log = safety.run(args, timeout, "pipeline.ps1", env=env, on_line=on_line)
        log_tail = log.strip().splitlines()[-12:]
        if code != 0 or not s.analysed():
            raise Refused(f"pipeline.ps1 stopped (exit {code}) before writing functions.json",
                          "read the end of its log: " + " | ".join(log_tail))
    handshake = read_json(s.analysis / "handshake.json") or {}
    load = read_json(s.analysis / "loadimage.json") or {}
    functions = read_json(s.analysis / "functions.json") or {}
    verified = handshake.get("status") == "verified" and load.get("status") == "verified"
    if cache == "miss" and verified:
        sessions.cache_store(s, pid)
    count = len(functions.get("functions") or [])
    items = [{"kind": "handshake", "claim": f"profile handshake: {handshake.get('status')}",
              "value": handshake.get("status")},
             {"kind": "load-image", "claim": f"load image: {load.get('status')}, "
                                             f"{(load.get('result') or {}).get('corrections_made', 0)} "
                                             f"corrections",
              "value": load.get("status")},
             {"kind": "functions", "claim": f"{count} functions exported", "value": count}]
    return evidence.envelope("analyze", target_of(s), status="ok" if verified else "mismatch",
                             result={"session_id": s.id, "cache": cache, "profile_id": pid,
                                     "cache_key": sessions.cache_dir(s.sha256, pid).name,
                                     "seconds": round(time.perf_counter() - started, 1),
                                     "functions": count, "handshake": handshake.get("status"),
                                     "load_image": load.get("status"),
                                     "outputs": sorted(p.name for p in s.analysis.iterdir()),
                                     "log_tail": log_tail},
                             evidence=items, profile=profile)


@guarded("verify_load_image")
def verify_load_image(session_id, limit=None, cursor=None):
    import loadimage
    s = sessions.get(session_id)
    need_analysis(s)
    profile = (read_json(s.analysis / "profile.json") or {}).get("profile")
    corrections = s.analysis / "load-corrections.json"
    env = loadimage.verify(str(s.copy), str(s.analysis / "loadimage-observed"), profile,
                           str(corrections) if corrections.exists() else None)
    return paged(env, limit, cursor)


def layout(s):
    """The record map_address reads: the verified load once analysed, the
    load DOS would make from the header before that."""
    import loadimage
    if s.analysed():
        env = read_json(s.analysis / "loadimage.json") or {}
        if env.get("status") == "verified":
            return env["result"], "the verified load (loadimage.json)"
    return loadimage.dos_map(str(s.copy)), ("the load DOS makes from the header; nothing "
                                            "has analysed it yet")


def com_map(s, file_offset=None, address=None):
    """A .COM: the file is the image, loaded at offset 0x100 of its segment."""
    size = s.copy.stat().st_size
    if address is not None:
        seg, _, off = address.partition(":")
        file_offset = int(off, 16) - 0x100
    if file_offset is None or not 0 <= file_offset < size:
        raise Refused(f"offset {file_offset} is outside the {size}-byte file",
                      "a .COM's bytes are at offsets 0x100.. of its segment")
    return {"file_offset": file_offset, "address": f"{0x1000:04x}:{0x100 + file_offset:04x}",
            "notes": ["a .COM is loaded whole at offset 0x100, after its PSP; segment 1000 "
                      "stands for wherever DOS put it"]}


def parse_number(value, what):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 0)
    except ValueError:
        raise Refused(f"{what} {value!r} is not a number", f"pass {what} as 0x1234 or 4660")


@guarded("address_map")
def address_map(session_id, file_offset=None, address=None, linear=None):
    import loadimage
    s = sessions.get(session_id)
    file_offset, linear = parse_number(file_offset, "file_offset"), parse_number(linear, "linear")
    if s.format == "com":
        out, source = com_map(s, file_offset, address), "the .COM rule"
    else:
        record, source = layout(s)
        try:
            out = loadimage.map_address(record, file_offset, linear, address)
        except loadimage.MapError as e:
            raise Refused(str(e), "pass a file offset inside the load image, or an address "
                                  "it maps")
    return evidence.envelope("address_map", target_of(s), status="ok",
                             result=dict(out, source=source))


@guarded("read_bytes")
def read_bytes(session_id, address=None, file_offset=None, length=64):
    """Bytes as the program holds them once loaded. Stops at the first byte
    that is not initialised from the file, and says so."""
    import loadimage
    s = sessions.get(session_id)
    length = parse_number(length, "length")
    if not 1 <= length <= MAX_READ:
        raise Refused(f"length {length} is not between 1 and {MAX_READ}",
                      f"read at most {MAX_READ} bytes at a time")
    file_offset = parse_number(file_offset, "file_offset")
    data = s.copy.read_bytes()
    if s.format == "com":
        start = com_map(s, file_offset, address)["file_offset"]
        got = data[start:start + length]
        stop = None if len(got) == length else \
            f"0x{0x100 + start + len(got):x} is past the end of the file: not initialised"
        out = {"address": f"1000:{0x100 + start:04x}", "file_offset": start}
    else:
        record, source = layout(s)
        try:
            first = loadimage.map_address(record, file_offset, None, address)
        except loadimage.MapError as e:
            raise Refused(str(e), "start at an address the load image maps")
        memory = {}
        for r in record["relocations"]:
            for i, b in enumerate(r["relocated_word"].to_bytes(2, "little")):
                memory[r["linear"] + i] = b
        got, stop = bytearray(), None
        for i in range(length):
            linear = first["linear"] + i
            try:
                where = loadimage.map_address(record, None, linear, None)
            except loadimage.MapError as e:
                stop = str(e)
                break
            got.append(memory.get(linear, data[where["file_offset"]]))
        out = {"address": first["address"], "file_offset": first["file_offset"],
               "source": source, "relocated_words": [r["address"] for r in record["relocations"]
                                                     if first["linear"] <= r["linear"]
                                                     < first["linear"] + len(got)]}
    out.update(length_asked=length, length_read=len(got), complete=stop is None,
               stopped_because=stop, hex=bytes(got).hex(" "))
    return evidence.envelope("read_bytes", target_of(s), status="ok", result=out)


# ---------------------------------------------------------------- functions

def functions_of(s):
    need_analysis(s)
    data, notes = quietly(evidence.load_functions, s.analysis / "functions.json", str(s.copy),
                          "the MCP server")
    return data


@guarded("list_functions")
def list_functions(session_id, origin=None, name=None, min_size=None, max_size=None,
                   limit=None, cursor=None):
    s = sessions.get(session_id)
    data = functions_of(s)
    rows = []
    for f in data.get("functions") or []:
        if origin and f.get("origin") != origin:
            continue
        if name and not fnmatch.fnmatch(f.get("name", ""), name):
            continue
        size = f.get("size") or 0
        if (min_size is not None and size < min_size) or (max_size is not None and size > max_size):
            continue
        rows.append({"entry": f["entry"], "name": f.get("name"), "size": size,
                     "origin": f.get("origin"), "instructions": f.get("instruction_count"),
                     "calls": len(f.get("calls") or []),
                     "interrupts": f.get("interrupts") or [],
                     "ranges": len((f.get("body") or {}).get("ranges") or [])})
    env = evidence.envelope("list_functions", target_of(s), status="ok", result={
        "filters": {"origin": origin, "name": name, "min_size": min_size,
                    "max_size": max_size},
        "functions": rows})
    return paged(env, limit, cursor)


def c_of(s, entry):
    """The decompiled C of one function, from decompiled.c's marker lines."""
    text = (s.analysis / "decompiled.c").read_text(encoding="utf-8", errors="replace")
    out, inside = [], False
    for line in text.splitlines():
        if line.startswith("/* ---- "):
            if inside:
                break
            inside = f" @ {entry} " in line
        if inside:
            out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return out


FUNCTION_PARTS = ("c", "asm", "record")


@guarded("function")
def function(session_id, entry=None, name=None, parts=None, limit=None, cursor=None):
    """One function: body, origin, its decompiled C alone, its body
    disassembled, and the calls out and in the export records.

    `parts` picks which of those to return -- "c" the decompiled C, "asm" the
    disassembly, "record" everything else the export says about it -- default
    all three. entry and name come back whatever is asked, so a part is never
    read without knowing whose it is."""
    if parts is None:
        parts = list(FUNCTION_PARTS)
    if (not isinstance(parts, list) or not parts
            or any(p not in FUNCTION_PARTS for p in parts)):
        raise Refused(f"parts {parts!r} is not a list drawn from {list(FUNCTION_PARTS)}",
                      'pass any of "c", "asm" and "record", or leave parts out for all three')
    s = sessions.get(session_id)
    data = functions_of(s)
    found = [f for f in data.get("functions") or []
             if (entry and f["entry"].lower() == entry.lower()) or (name and f.get("name") == name)]
    if not found:
        raise Refused(f"no function {entry or name}", "list_functions shows the entries")
    f = found[0]
    result = {"entry": f["entry"], "name": f.get("name"),
              "parts": [p for p in FUNCTION_PARTS if p in parts]}
    if "record" in parts:
        keep = ("size", "origin", "body", "instruction_count", "blocks", "loops",
                "returns", "calls", "interrupts", "io_ports", "strings", "data_refs",
                "calling_convention", "return_type", "param_count")
        result.update({k: f.get(k) for k in keep})
        result["callers"] = sorted(g["entry"] for g in data["functions"]
                                   if f["entry"] in (g.get("calls") or []))
    if "c" in parts:
        result["c"] = c_of(s, f["entry"])
    if "asm" in parts:
        result["disassembly"] = disassembly_of(s, data, f)
    env = evidence.envelope("function", target_of(s), status="ok", result=result)
    return paged(env, limit, cursor, ("result", "c"), ("result", "disassembly"),
                 whole=("parts",))


def disassembly_of(s, data, f):
    """The function's body ranges, disassembled from the loaded image."""
    import bodies
    from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    load = int(((data.get("observed_profile") or {}).get("load_segment") or "0x1000"), 16)
    image = bodies.Bytes(str(s.copy), load)
    md = Cs(CS_ARCH_X86, CS_MODE_16)
    lines = []
    for lo, hi in bodies.body_ranges(f):
        seg = int(f["entry"][:4], 16)
        for insn in md.disasm(image.get(lo, hi), lo - (seg << 4)):
            lines.append(f"{seg:04x}:{insn.address & 0xFFFF:04x}  "
                         f"{insn.bytes.hex():<14} {insn.mnemonic} {insn.op_str}".rstrip())
    return lines


@guarded("coverage")
def coverage(session_id, limit=None, cursor=None):
    import bodies
    s = sessions.get(session_id)
    need_analysis(s)
    env, notes = quietly(bodies.analyse, s.analysis / "functions.json", str(s.copy))
    return paged(env, limit, cursor)


@guarded("anchors")
def anchors(session_id, entry=None, write_names=False, limit=None, cursor=None):
    import anchors as tool
    s = sessions.get(session_id)
    need_analysis(s)
    (functions, _), notes = quietly(tool.load, s.analysis / "functions.json", str(s.copy))
    findings = tool.analyze(functions, entry)
    names = tool.propose_names(findings)
    written = None
    if write_names:
        written = s.analysis / "names.json"
        written.write_text(json.dumps(names, indent=2), encoding="utf-8")
    result = {"entry": entry, "findings": findings if isinstance(findings, list) else None,
              "mapping": names.get("mapping"), "mapped": names.get("mapped"),
              "corroborated": names.get("corroborated"),
              "names_written": str(written) if written else None}
    if not isinstance(findings, list):
        result["findings_summary"] = {k: (v if not isinstance(v, (list, dict)) else len(v))
                                      for k, v in findings.items()}
    return paged(evidence.envelope("anchors", target_of(s), status="ok", result=result),
                 limit, cursor)


@guarded("libsig")
def libsig(session_id, database="auto", limit=None, cursor=None):
    """Library functions, against one database from signatures/ or, with
    "auto", each of them: the one that matches names the compiler."""
    import libsig as tool
    s = sessions.get(session_id)
    need_analysis(s)
    dbs = sorted((ROOT / "signatures").glob("*.json"))
    if database != "auto":
        dbs = [d for d in dbs if d.stem == database]
        if not dbs:
            raise Refused(f"no signature database {database!r}",
                          "pass one of: auto, " + ", ".join(d.stem for d in
                                                           sorted((ROOT / "signatures").glob("*.json"))))
    tried = []
    for d in dbs:
        db = json.loads(d.read_text(encoding="utf-8"))
        hits, notes = quietly(tool.apply, str(s.copy), str(s.analysis / "functions.json"), db)
        tried.append({"database": d.stem, "signatures": db["count"], "found": len(hits),
                      "hits": hits})
    best = max(tried, key=lambda t: t["found"])
    result = {"databases": [{k: v for k, v in t.items() if k != "hits"} for t in tried],
              "best": best["database"] if best["found"] else None, "hits": best["hits"]}
    return paged(evidence.envelope("libsig", target_of(s), status="ok", result=result),
                 limit, cursor)


@guarded("apply_names")
def apply_names(session_id, mapping, dryrun=True, confirm=False, min_score=None,
                certain=None, timeout=900, limit=None, cursor=None):
    """applynames.py on this session's own Ghidra project. A dry run unless
    dryrun is false *and* confirm is true."""
    import applynames
    s = sessions.get(session_id)
    need_analysis(s)
    if isinstance(mapping, (dict, list)):
        body = mapping if isinstance(mapping, dict) else {"mapping": mapping}
        path = s.folder / "mapping.json"
        path.write_text(json.dumps(body, indent=1), encoding="utf-8")
    else:
        path = safety.absolute(mapping, "mapping", kind="file")
    writing = not dryrun and confirm
    env, code = applynames.run(str(path), s.analysis, dryrun=not writing, min_score=min_score,
                               certain=certain, timeout=timeout)
    env["result"]["write_requested"] = not dryrun
    env["result"]["confirmed"] = bool(confirm)
    if not dryrun and not confirm:
        env["result"]["note"] = ("run as a dry run: writing names needs dryrun false and "
                                 "confirm true")
    return paged(env, limit, cursor)


# ---------------------------------------------------------------- emulation

def side(session_id, map_path):
    s = sessions.get(session_id)
    if map_path:
        return s, safety.absolute(map_path, "map", kind="file")
    need_analysis(s)
    return s, s.analysis / "functions.json"


@guarded("emuverify")
def emuverify(session_a, session_b, map_a=None, map_b=None, dgroup_a=None, dgroup_b=None,
              limit_functions=None, limit=None, cursor=None):
    import emuverify as tool
    a, ma = side(session_a, map_a)
    b, mb = side(session_b, map_b)
    (res, checked), notes = quietly(tool.pair, str(a.copy), str(ma), str(b.copy), str(mb),
                                    parse_number(dgroup_a, "dgroup_a"),
                                    parse_number(dgroup_b, "dgroup_b"),
                                    limit_functions, False, False, None)
    result = {"profiled_a": res["profiled_a"], "profiled_b": res["profiled_b"],
              "matches": [{"a": x, "b": y} for x, y in res["matches"]],
              "partial_matches": res["partial_matches"],
              "ambiguous": [{"a": x, "b": ys} for x, ys in res["ambiguous"]],
              "uninformative": res["uninformative"], "checked": checked, "notes": notes}
    return paged(evidence.envelope("emuverify", target_of(a), status="ok", result=result),
                 limit, cursor)


@guarded("emuverify sweep")
def sweep(session_id, entry, domain, candidate=None, candidate_session=None,
          candidate_entry=None, functions=True, all_divergences=False, trace=0,
          max_cases=None, seed=None, case_timeout=None, dgroup=None, limit=None, cursor=None):
    """emuverify.py sweep, with the session's copy as the original."""
    import sweep as tool
    s = sessions.get(session_id)
    if isinstance(domain, dict):
        path = s.folder / "domain.json"
        path.write_text(json.dumps(domain, indent=1), encoding="utf-8")
    else:
        path = safety.absolute(domain, "domain", kind="file")
    argv = [str(s.copy), entry, "--domain", str(path), "--quiet"]
    if candidate_session:
        c = sessions.get(candidate_session)
        argv += ["--candidate-exe", str(c.copy), "--candidate-entry", candidate_entry or ""]
    elif candidate:
        file, _, fn = candidate.rpartition(":")
        safety.absolute(file, "candidate", kind="file")
        argv += ["--candidate", candidate]
    else:
        raise Refused("no candidate", "pass candidate (an absolute path:function) or "
                                      "candidate_session and candidate_entry")
    if functions and s.analysed():
        argv += ["--functions", str(s.analysis / "functions.json")]
    for flag, value in (("--max-cases", max_cases), ("--seed", seed),
                        ("--case-timeout", case_timeout), ("--dgroup", dgroup)):
        if value is not None:
            argv += [flag, str(value)]
    if all_divergences:
        argv.append("--all")
    if trace:
        argv += ["--trace-on-divergence", str(trace)]
    args = tool.parser().parse_args(argv)
    try:
        (env, seconds), notes = quietly(tool.run_sweep, args)
    except tool.Blocked as e:
        raise Refused(str(e), "read the reason: it names what to change")
    env["result"]["seconds"] = round(seconds, 2)
    return paged(env, limit, cursor)
