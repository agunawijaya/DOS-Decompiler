#!/usr/bin/env python3
"""
regress.py -- Check the MCP server the way a client sees it.

The server is started as a subprocess and talked to over stdio with the MCP
Python SDK's own client: every call below goes through the protocol, not
through operations.py. Sessions are kept in a temporary DOSDEC_WORK.

Fixtures are the repository's own NASM sources: tests/sweep/fixtures/sweep.asm
(a small-model MZ with a minalloc, so its load ends in uninitialised memory),
tests/com/fixtures/plain.asm (a .COM), and the sweep fixture's Python
candidate.

Without the SDK the suite cannot run and exits 77, saying so. The checks that
need Ghidra are skipped, each saying so, without GHIDRA_HOME.

Usage:
    python tests/mcp/regress.py [--only TEXT]
"""

import argparse
import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SERVER = ROOT / "mcp_server" / "server.py"
SWEEP_FIX = ROOT / "tests" / "sweep" / "fixtures"
COM_FIX = ROOT / "tests" / "com" / "fixtures"
COMDIFF_FIX = ROOT / "tests" / "comdiff" / "fixtures"
COMRUN_FIX = ROOT / "tests" / "comrun" / "fixtures"
OVERLAY_FIX = ROOT / "tests" / "overlays" / "fixtures"

TOOLS = ["survey", "triage", "open_binary", "close_binary", "list_sessions", "unpack",
         "analyze", "verify_load_image", "address_map", "read_bytes", "list_functions",
         "function", "coverage", "anchors", "libsig", "apply_names", "emuverify", "sweep",
         "comrec", "comdiff", "comrun", "overlays"]

CASES = []


def case(name, needs=()):
    def wrap(fn):
        CASES.append((name, fn, needs))
        return fn
    return wrap


class Fix:
    work = None          # temporary folder for fixtures and DOSDEC_WORK
    sweep_exe = None
    com = None
    siblings = ()        # the two programs tests/comdiff compares
    extra = {}           # prompt 15's: swint, a .COM named .PTL, overlaid, EXEPACK
    labels = {}
    session = None       # the MCP client session


def labels(listing):
    out, pending = {}, []
    for line in Path(listing).read_text(encoding="latin-1").splitlines():
        a = re.match(r"\s*\d+\s+([0-9A-F]{8})\s", line)
        lab = re.search(r"^\s*\d+\s+(?:[0-9A-F]{8}\s+\S+\s+)?([\w]+):", line)
        if lab and not a:
            pending.append(lab.group(1))
            continue
        if a:
            for p in pending + ([lab.group(1)] if lab else []):
                out[p] = int(a.group(1), 16) - 0x40
            pending = []
    return out


async def call(name, **args):
    """Call a tool; (envelope, is_error)."""
    r = await Fix.session.call_tool(name, {k: v for k, v in args.items() if v is not None})
    env = r.structured_content
    if env is None:
        env = json.loads(r.content[0].text)
    return env, bool(r.is_error)


def check(cond, why):
    if not cond:
        raise AssertionError(why)


def envelope_ok(env):
    check(env.get("schema") == "dos-decompiler/evidence/1" and "status" in env
          and "result" in env and "evidence" in env, f"not an evidence envelope: {env}")


async def open_mz():
    env, err = await call("open_binary", path=str(Fix.sweep_exe))
    check(not err and env["status"] == "ok", f"open_binary: {env}")
    return env["result"]["session_id"], Path(env["result"]["folder"])


# ---------------------------------------------------------------- without Ghidra

@case("without the MCP SDK the server stops at once, saying how to install it")
async def _():
    # -S: no site-packages, so the SDK cannot be imported.
    r = subprocess.run([sys.executable, "-S", str(SERVER)], capture_output=True, text=True,
                       timeout=60, stdin=subprocess.DEVNULL)
    check(r.returncode == 2 and "pip install mcp" in r.stderr and not r.stdout,
          f"exit {r.returncode}, stderr {r.stderr[:300]!r}")
    return r.stderr.strip().splitlines()[0][:100]


@case("the cache key covers the Python the pipeline runs, and not the line endings")
async def _():
    # Read here, not through the protocol: the key is the server's own business.
    sys.path.insert(0, str(SERVER.parent))
    import sessions
    tools = ROOT / "tools"
    # Every tool pipeline.ps1 runs, and every toolkit module those import.
    ran = set(re.findall(r"Join-Path \$toolDir '(\w+\.py)'",
                         (tools / "pipeline.ps1").read_text(encoding="utf-8")))
    needed, todo = set(), list(ran)
    while todo:
        name = todo.pop()
        if name in needed:
            continue
        needed.add(name)
        for mod in re.findall(r"^\s*import (\w+)", (tools / name).read_text(encoding="utf-8"),
                              re.M):
            if (tools / f"{mod}.py").exists():
                todo.append(f"{mod}.py")
    check(needed == set(sessions.PIPELINE_PYTHON),
          f"pipeline.ps1 runs {sorted(needed)}; the key covers {sorted(sessions.PIPELINE_PYTHON)}")
    copy = Fix.work / "keytools"
    copy.mkdir()
    for name in sessions.PIPELINE_PYTHON:
        shutil.copy(tools / name, copy / name)
    base = sessions.pipeline_python_sha256(tools)
    check(sessions.pipeline_python_sha256(copy) == base, "a copy hashed differently")
    data = (copy / "loadimage.py").read_bytes()
    (copy / "loadimage.py").write_bytes(data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    check(sessions.pipeline_python_sha256(copy) == base, "CRLF moved the key")
    (copy / "loadimage.py").write_bytes(data + b"\n# one more line\n")
    moved = sessions.pipeline_python_sha256(copy)
    check(moved != base, "an edit to loadimage.py did not move the key")
    a = sessions.cache_dir("ab" * 32, "cd" * 32, base).name
    b = sessions.cache_dir("ab" * 32, "cd" * 32, moved).name
    check(a != b and a.endswith(base[:12]), f"cache folders {a}, {b}")
    return (f"covers {', '.join(sorted(needed))}; CRLF keeps it, an edit to loadimage.py "
            f"moves it: {base[:12]} -> {moved[:12]}")


@case("every tool in the table is listed, with an input schema")
async def _():
    tools = {t.name: t for t in (await Fix.session.list_tools()).tools}
    missing = [t for t in TOOLS if t not in tools]
    check(not missing, f"missing tools: {missing}")
    bad = [t for t in TOOLS if (tools[t].input_schema or {}).get("type") != "object"]
    check(not bad, f"no object schema: {bad}")
    prompts = {p.name for p in (await Fix.session.list_prompts()).prompts}
    check({"standard_workflow", "extended_workflow"} <= prompts, f"prompts: {prompts}")
    resources = {str(r.uri) for r in (await Fix.session.list_resources()).resources}
    check("toolkit://AGENTS.md" in resources and
          "knowledge://18-oracle-sweeps.md" in resources, f"resources: {sorted(resources)[:5]}")
    text = await Fix.session.read_resource("knowledge://04-pitfalls.md")
    check("Pitfalls" in text.contents[0].text or "pitfall" in text.contents[0].text.lower(),
          "knowledge://04-pitfalls.md did not read back")
    prompt = await Fix.session.get_prompt("standard_workflow", {})
    words = prompt.messages[0].content.text
    check("AGENTS.md" in words and "triage" in words, f"standard_workflow: {words}")
    return (f"{len(TOOLS)} tools with schemas, 2 prompts naming AGENTS.md and triage, "
            f"{len(resources)} resources")


@case("open an MZ, triage it, read across the uninitialised edge, map an address, close it")
async def _():
    sid, folder = await open_mz()
    check(folder.is_dir() and str(folder).startswith(os.environ["DOSDEC_WORK"]),
          f"session folder {folder}")
    env, err = await call("triage", session_id=sid)
    envelope_ok(env)
    check(not err and env["tool"] == "triage"
          and (env["result"].get("verdict") or {}).get("in_scope") is True,
          f"triage: {env['status']} {env['result'].get('verdict')}")
    # The module is the file less its 64-byte header, and minalloc follows
    # it: 32 bytes asked for from 8 before its end, 8 come back. Worked out
    # from the file, which grows when a routine is added to the fixture.
    module = len(Fix.sweep_exe.read_bytes()) - 0x40
    env, err = await call("read_bytes", session_id=sid, address=f"1000:{module - 8:04x}",
                          length=32)
    r = env["result"]
    data = Fix.sweep_exe.read_bytes()[0x40 + module - 8:0x40 + module]
    check(not err and r["complete"] is False and r["length_read"] == 8
          and r["hex"] == data.hex(" ") and "uninitialised" in r["stopped_because"],
          f"read_bytes: {r}")
    env, err = await call("address_map", session_id=sid, file_offset="0x49")
    check(not err and env["result"]["address"] == "1000:0009", f"address_map: {env['result']}")
    env, err = await call("list_sessions")
    check(sid in [s["session_id"] for s in env["result"]["sessions"]], "not listed")
    env, err = await call("close_binary", session_id=sid)
    check(not err and not folder.exists(), f"close_binary left {folder}")
    env, err = await call("triage", session_id=sid)
    check(err and env["status"] == "blocked", "a closed session still answered")
    return f"8 of 32 bytes, stopped at minalloc; file 0x49 = 1000:0009; {folder.name} deleted"


# ---------------------------------------------------------------- its environment

# An agent starts the server with an environment of its own choosing: Codex
# passes a few variables, Gemini redacts some, and none of them dot-sources
# env.ps1. These start it the way an agent might, from almost nothing.
BARE = ("SYSTEMROOT", "PATH", "PATHEXT", "COMSPEC", "TEMP", "TMP", "LOCALAPPDATA",
        "USERPROFILE", "HOME")


def bare_env(**extra):
    env = {k: os.environ[k] for k in BARE if k in os.environ}
    env["DOSDEC_WORK"] = str(Fix.work / "sessions")
    env.update({k: str(v) for k, v in extra.items()})
    return env


def bare_python():
    """A Python without the SDK, capstone or unicorn: a fresh venv's."""
    venv = Fix.work / "bare-venv"
    if not venv.exists():
        subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True,
                       capture_output=True)
    for p in (venv / "Scripts" / "python.exe", venv / "bin" / "python"):
        if p.exists():
            return p
    raise AssertionError(f"no python in {venv}")


def env_file(**values):
    """An env.ps1 of our own, in the forms env.example.ps1 writes."""
    path = Fix.work / "env-test.ps1"
    lines = ["# env.ps1 written by tests/mcp", ""]
    for name, value in values.items():
        lines.append(f"$env:{name} = '{value}'   # where {name.lower()} is")
    lines.append('$env:UNUSED_BY_THE_SERVER = "double-quoted"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


async def started(command, env):
    """(initialize result, tool names, stderr) of a server started so."""
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    log = Fix.work / f"start-{len(list(Fix.work.glob('start-*')))}.log"
    params = StdioServerParameters(command=str(command), args=[str(SERVER)], env=env,
                                   cwd=str(Fix.work))
    with open(log, "w", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as streams:
            async with ClientSession(streams[0], streams[1]) as other:
                init = await other.initialize()
                names = [t.name for t in (await other.list_tools()).tools]
    return init, names, log.read_text(encoding="utf-8")


@case("a Python without the packages reads env.ps1 and hands over to its PYTHON")
async def _():
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    path = env_file(PYTHON=sys.executable, GHIDRA_HOME=Fix.work, JAVA_HOME=Fix.work, NASM=nasm)
    init, names, err = await started(bare_python(), bare_env(DOSDEC_ENV_FILE=path))
    check(sorted(names) == sorted(TOOLS), f"tools {names}")
    want = (f"handed over to PYTHON; GHIDRA_HOME, JAVA_HOME, NASM, PYTHON, "
            f"UNUSED_BY_THE_SERVER from {path}")
    check(want in err, f"stderr: {err[-600:]}")
    check("is not set" not in (init.instructions or ""), f"instructions: {init.instructions}")
    return f"{len(names)} tools from a venv's Python, through {Path(sys.executable).name}"


@case("the agent's own environment wins over env.ps1")
async def _():
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    path = env_file(PYTHON=sys.executable, GHIDRA_HOME=Fix.work / "from-env-file",
                    JAVA_HOME=Fix.work, NASM=nasm)
    init, names, err = await started(sys.executable, bare_env(DOSDEC_ENV_FILE=path,
                                                              GHIDRA_HOME=Fix.work))
    line = next((l for l in err.splitlines() if l.endswith(f"from {path}")), "")
    check(line and "GHIDRA_HOME" not in line and "JAVA_HOME" in line, f"stderr: {err[-600:]}")
    check("GHIDRA_HOME is not set" not in (init.instructions or ""), "GHIDRA_HOME reported missing")
    return line.split(": ", 1)[1][:90]


@case("with no env.ps1 and no PYTHON, a Python without the packages stops, naming them")
async def _():
    r = subprocess.run([str(bare_python()), str(SERVER)], env=bare_env(DOSDEC_ENV_FILE=""),
                       capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=120)
    check(r.returncode == 2, f"exit {r.returncode}")
    for want in ("cannot start", "cannot import mcp, capstone, unicorn", "PYTHON is not set",
                 "python -m pip install mcp capstone unicorn"):
        check(want in r.stderr, f"stderr lacks {want!r}: {r.stderr[-400:]}")
    check("Traceback" not in r.stderr, "a traceback")
    return r.stderr.strip()[:110]


@case("without GHIDRA_HOME and JAVA_HOME it starts, says so, and analyze refuses by name")
async def _():
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    env = bare_env(DOSDEC_ENV_FILE="", NASM=os.environ.get("NASM") or "")
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)], env=env,
                                   cwd=str(Fix.work))
    log = Fix.work / "no-ghidra.log"
    with open(log, "w", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as streams:
            async with ClientSession(streams[0], streams[1]) as other:
                init = await other.initialize()
                opened = (await other.call_tool("open_binary",
                                                {"path": str(Fix.sweep_exe)})).structured_content
                sid = opened["result"]["session_id"]
                refused = (await other.call_tool("analyze", {"session_id": sid})).structured_content
                await other.call_tool("close_binary", {"session_id": sid})
    err = log.read_text(encoding="utf-8")
    for name in ("GHIDRA_HOME", "JAVA_HOME"):
        check(f"{name} is not set" in (init.instructions or "") and f"{name} is not set" in err,
              f"{name} not reported at start: {err[-500:]}")
    reason = refused["result"].get("reason", "")
    check(refused["status"] == "blocked" and "GHIDRA_HOME" in reason, f"analyze: {refused['result']}")
    return reason[:90]


@case("a server starting up deletes the sessions of servers no longer running")
async def _():
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    sys.path.insert(0, str(SERVER.parent))
    import sessions
    # A session records the server that opened it.
    sid, folder = await open_mz()
    env, _ = await call("list_sessions")
    me = env["result"]["server"]
    record = json.loads((folder / "session.json").read_text(encoding="utf-8"))
    check(record.get("server") == me and me["pid"] != os.getpid() and me["started"],
          f"the session records {record.get('server')}; the server is {me}")
    await call("close_binary", session_id=sid)
    # A work folder as servers that came and went leave it. This process
    # stands in for a server still running.
    work = Fix.work / "stale"
    gone = int(subprocess.run([sys.executable, "-c", "import os; print(os.getpid())"],
                              capture_output=True, text=True, check=True).stdout)
    alive = {"pid": os.getpid(), "started": sessions.process_started(os.getpid())}
    planted = {"exited": {"pid": gone, "started": 1},
               "reusedpid": {"pid": alive["pid"], "started": alive["started"] + 1},
               "running": alive,
               "noserver": None}
    for name, server in planted.items():
        (work / name).mkdir(parents=True)
        record = {"id": name, "folder": str(work / name), "format": "mz", "original": {},
                  "copy": ""}
        if server:
            record["server"] = server
        (work / name / "session.json").write_text(json.dumps(record), encoding="utf-8")
    (work / "notasession").mkdir()     # its record's id is not its folder's name
    (work / "notasession" / "session.json").write_text(
        json.dumps({"id": "other", "server": {"pid": gone, "started": 1}}), encoding="utf-8")
    (work / "_cache").mkdir()
    log = Fix.work / "stale-stderr.log"
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)], cwd=str(Fix.work),
                                   env=dict(os.environ, DOSDEC_WORK=str(work),
                                            PYTHON=sys.executable))
    with open(log, "w", encoding="utf-8") as errlog:
        async with stdio_client(params, errlog=errlog) as streams:
            async with ClientSession(streams[0], streams[1]) as other:
                await other.initialize()
                said = (await other.call_tool("list_sessions", {})).structured_content
    said = said["result"]["removed_at_start"]
    left = sorted(p.name for p in work.iterdir())
    line = (log.read_text(encoding="utf-8").strip().splitlines() or [""])[0]
    check(said["count"] == 2 and sorted(said["sessions"]) == ["exited", "reusedpid"]
          and said["kept_without_server"] == ["noserver"], f"removed_at_start: {said}")
    check(left == ["_cache", "noserver", "notasession", "running"], f"left: {left}")
    check("removed 2 session folder" in line and "noserver" in line, f"stderr: {line}")
    return ("an exited server's session and a reused pid's removed; a running server's, "
            "one recording no server, a mismatched record and the cache kept")


@case("survey a folder: an envelope that names both fixtures in it")
async def _():
    env, err = await call("survey", folder=str(Fix.sweep_exe.parent))
    envelope_ok(env)
    text = json.dumps(env["result"])
    check(not err and env["tool"] == "survey" and "SWEEP.EXE" in text and "PLAIN.COM" in text,
          f"survey: {env['status']} {text[:300]}")
    return f"{env['status']}, {len(env['evidence'])} evidence items on this page"


@case("a .COM is admitted only when format=\"com\" is given")
async def _():
    env, err = await call("open_binary", path=str(Fix.com))
    check(err and env["status"] == "blocked" and "format=\"com\"" in env["result"]["next_step"],
          f"auto admitted a .COM: {env['result']}")
    env, err = await call("open_binary", path=str(Fix.com), format="mz")
    check(err, "format=mz admitted a .COM")
    env, err = await call("open_binary", path=str(Fix.com), format="com")
    check(not err and env["result"]["format"] == "com", f"format=com: {env['result']}")
    sid = env["result"]["session_id"]
    env, err = await call("comrec", session_id=sid)
    check(env["status"] == "verified" and env["result"]["byte_identical"], f"comrec: {env['status']}")
    env, err = await call("open_binary", path=str(Fix.sweep_exe), format="com")
    check(err and "starts with MZ" in env["result"]["reason"], "an MZ was admitted as a .COM")
    await call("close_binary", session_id=sid)
    return "auto and mz refused, com admitted and rebuilt byte-identical; an MZ refused as com"


@case("comdiff: refused before comrec, then two .COM programs routine by routine")
async def _():
    sids = []
    for path in Fix.siblings:
        env, err = await call("open_binary", path=str(path), format="com")
        check(not err, f"open_binary: {env['result']}")
        sids.append(env["result"]["session_id"])
    env, err = await call("comdiff", session_a=sids[0], session_b=sids[1])
    check(err and env["status"] == "blocked" and "run comrec on session" in
          env["result"]["next_step"], f"comdiff without a listing: {env['result']}")
    for sid in sids:
        env, err = await call("comrec", session_id=sid)
        check(env["status"] == "verified", f"comrec: {env['status']}")
    env, err = await call("comdiff", session_a=sids[0], session_b=sids[1])
    envelope_ok(env)
    r = env["result"]
    check(not err and env["status"] == "ok" and r["counts"]["byte-identical"] == 1
          and r["counts"]["instruction-identical"] == 5
          and r["emulation"] == {"confirmed": 4, "differs": 1, "uninformative": 0,
                                 "not run": 0}, f"comdiff: {r['counts']} {r['emulation']}")
    check(env["target"]["path"].endswith("CMPB.COM") and len(env["unknowns"]) == 1,
          f"target {env['target']}, unknowns {env['unknowns']}")
    for sid in sids:
        await call("close_binary", session_id=sid)
    return "blocked without comrec; then 1 byte-, 5 instruction-identical, 4 confirmed"


@case("function refuses parts it does not know, before reading anything")
async def _():
    for parts in (["c", "source"], []):
        env, err = await call("function", session_id="nosuchsession", entry="1000:0000",
                              parts=parts)
        check(err and env["status"] == "blocked" and "parts" in env["result"]["reason"],
              f"parts={parts!r}: {env['status']} {env['result']}")
    # A bare string never reaches the tool: the SDK checks it against the schema.
    r = await Fix.session.call_tool("function", {"session_id": "nosuchsession",
                                                 "entry": "1000:0000", "parts": "c"})
    check(r.is_error and "parts" in r.content[0].text, f"parts='c': {r.content[0].text[:200]}")
    return ("an unknown part and an empty list refused by the tool, naming parts; a bare "
            "string by the SDK's schema")


@case("relative paths, '..' paths and paths outside the session are refused")
async def _():
    # games\SWEEP.EXE exists relative to the server's working folder: the
    # dangerous case, a relative path that means something there. Each must
    # be refused for its own reason, not because it happens not to exist.
    for path, why in (("games\\SWEEP.EXE", "relative path"),
                      (str(Fix.work) + "\\games\\..\\games\\SWEEP.EXE", "contains '..'")):
        env, err = await call("open_binary", path=path)
        check(err and env["status"] == "blocked" and why in env["result"]["reason"],
              f"{path}: {env['status']} {env['result'].get('reason') or env['result'].get('session_id')}")
    sid, folder = await open_mz()
    outside = str(Fix.work / "elsewhere.exe")
    env, err = await call("unpack", session_id=sid, out=outside)
    check(err and "outside this session" in env["result"]["reason"], f"unpack out: {env['result']}")
    env, err = await call("unpack", session_id=sid, keep_to=str(Fix.sweep_exe.parent))
    check(env["status"] == "blocked", "unpack wrote with keep_to beside the original")
    env, err = await call("survey", folder="relative\\folder")
    check(err, "survey took a relative folder")
    await call("close_binary", session_id=sid)
    return "relative, '..', out outside the session, survey relative: all blocked"


@case("a long result pages: a cursor, and a second page that continues it")
async def _():
    sid, _ = await open_mz()
    env, _ = await call("triage", session_id=sid, limit=1)
    page = env["page"]
    total = page["lists"]["evidence"]["total"]
    check(total >= 2 and len(env["evidence"]) == 1 and page["next_cursor"], f"page: {page}")
    first = env["evidence"][0]["id"]
    env2, _ = await call("triage", session_id=sid, limit=1, cursor=page["next_cursor"])
    check(env2["page"]["lists"]["evidence"]["offset"] == 1
          and env2["evidence"][0]["id"] != first, f"second page: {env2['page']}")
    env3, err = await call("triage", session_id=sid, limit=1, cursor="not-a-cursor")
    check(err, "a made-up cursor was accepted")
    await call("close_binary", session_id=sid)
    return f"1 of {total} evidence items, then the next; a made-up cursor refused"


@case("unpack on a file that is not packed says so, and writes nothing")
async def _():
    sid, folder = await open_mz()
    env, err = await call("unpack", session_id=sid)
    envelope_ok(env)
    check(env["status"] == "blocked" and "not packed" in env["result"]["reason"]
          and not (folder / "unpacked").exists(), f"unpack: {env['result']}")
    await call("close_binary", session_id=sid)
    return env["result"]["reason"][:90]


@case("unpack an EXEPACK file: the layout read from its stub, the agreement, an MZ that loads")
async def _():
    env, err = await call("open_binary", path=str(Fix.extra["packed"]))
    check(not err, f"open_binary: {env['result']}")
    sid, folder = env["result"]["session_id"], Path(env["result"]["folder"])
    env, err = await call("unpack", session_id=sid)
    info, exepack = env["result"]["info"], env["result"]["exepack"]
    check(not err and env["status"] == "ok"
          and info["layout"] == "the 18-byte layout, with skip_len"
          and info["agreeing_bytes"] == info["compared_bytes"] and info["relocations"] == 8
          and any(w.startswith("skip_len at [0x0E]") for w in exepack["layout_why"])
          and "an MZ that loads" in env["result"]["next_step"], f"unpack: {env['result']}")
    check(Path(env["result"]["written"]).parent.parent == folder, "written outside the session")
    await call("close_binary", session_id=sid)
    return f"{info['agreement']} bytes agree, {info['relocations']} relocations rebuilt"


@case("comrun: a .COM's own INT 80h, 60h and 21h reached, the run as data, the screen kept")
async def _():
    env, err = await call("open_binary", path=str(Fix.extra["swint"]), format="com")
    sid, folder = env["result"]["session_id"], Path(env["result"]["folder"])
    env, err = await call("comrec", session_id=sid, seeds_from="session")
    check(err and "no exec map" in env["result"]["reason"], f"seeds before a run: {env['result']}")
    env, err = await call("comrun", session_id=sid, budget=100_000, exec_map=True,
                          bios_text=True, no_joystick=True)
    envelope_ok(env)
    r = env["result"]
    check(not err and env["status"] == "ok" and len(r["printed"]) == 3
          and r["dispatched"]["80h"]["count"] == 1 and r["dispatched"]["21h"]["count"] == 4
          and r["replaced_vectors"] == ["21h", "60h", "80h"] and "vectors" in r["summary_lines"],
          f"comrun: {env['status']} {r}")
    check(all(Path(p).is_file() and Path(p).parent.parent == folder for p in r["written"])
          and len(r["written"]) == 3, f"written: {r['written']}")
    env, err = await call("comrec", session_id=sid, seeds_from="session")
    check(not err and env["status"] == "verified"
          and any("executed addresses" in line for line in env["result"]["lines"]),
          f"comrec with the session's seeds: {env['status']} {env['result'].get('lines')}")
    env, err = await call("comrun", session_id=sid, keyboard="sideways")
    check(err and "bios, hw or auto" in env["result"]["reason"], "a bad keyboard was taken")
    await call("close_binary", session_id=sid)
    return "3 lines, INT 21h 4 times through its own; comrec seeded from the run, verified"


@case("format: open_binary and triage say a .PTL looks like a .COM; triage and survey take com")
async def _():
    ptl = Fix.extra["ptl"]
    env, err = await call("open_binary", path=str(ptl))
    check(err and "looks like a .COM image" in env["result"]["reason"], f"auto: {env['result']}")
    env, err = await call("triage", path=str(ptl))
    check(env["result"]["format"] == "not-MZ" and "looks_like_com" in env["result"],
          f"triage auto: {env['result']}")
    env, err = await call("triage", path=str(ptl), format="com")
    check(not err and env["result"]["format"] == "COM", f"triage com: {env['result']}")
    env, err = await call("triage", path=str(ptl), format="mz")
    check(err and env["status"] == "blocked" and "no MZ header" in env["result"]["reason"],
          f"triage mz: {env['result']}")
    env, err = await call("survey", folder=str(ptl.parent), format="com")
    coms = [f["path"] for f in env["result"]["com_files"]]
    check(not err and "GAME.PTL" in coms, f"survey com: {coms}")
    env, err = await call("survey", folder=str(ptl.parent), format="mz")
    check(err, "survey took format mz")
    return "refused with the hint; COM with format com; mz blocked; survey triages it"


@case("overlays: listed, views written in the session, a view opened with its record")
async def _():
    env, err = await call("open_binary", path=str(Fix.extra["overlaid"]))
    sid, folder = env["result"]["session_id"], Path(env["result"]["folder"])
    env, err = await call("overlays", session_id=sid)
    listing = env["result"]["listing"]
    check(not err and [m["overlay"] for m in listing["modules"]] == [1, 2]
          and listing["int3f_calls"] == 3 and not env["result"]["views"], f"list: {listing}")
    env, err = await call("overlays", session_id=sid, views=True)
    views = env["result"]["views"]
    check(not err and len(views) == 2 and all(Path(v["view"]).parent.parent == folder
                                               for v in views), f"views: {env['result']}")
    env, err = await call("open_binary", path=views[1]["view"])
    vid = env["result"]["session_id"]
    record = env["result"].get("overlay_view_record")
    check(not err and record and json.loads(Path(record).read_text())["result"]["overlay"] == 2,
          f"open the view: {env['result']}")
    for s in (vid, sid):
        await call("close_binary", session_id=s)
    return "2 modules, 3 int 3Fh; 2 views in the session; view 2 opened with its record"


@case("sweep on prompt 05's fixture with its Python candidate")
async def _():
    sid, _ = await open_mz()
    domain = {"args": [{"name": "x", "range": [0, 1000]}], "compare": ["ax"]}
    env, err = await call("sweep", session_id=sid, entry=f"1000:{Fix.labels['rare']:04x}",
                          domain=domain, candidate=f"{SWEEP_FIX / 'ref.py'}:rare")
    r = env["result"]
    check(not err and env["status"] == "verified" and r["cases_run"] == 1001
          and r["mode"] == "exhaustive", f"sweep: {env['status']} {r.get('reason') or r.get('cases_run')}")
    env, err = await call("sweep", session_id=sid, entry=f"1000:{Fix.labels['rare']:04x}",
                          domain=domain, candidate=f"{SWEEP_FIX / 'ref.py'}:rare_masking_seven_bits")
    check(env["status"] == "mismatch" and env["result"]["first_divergence"]["case"] == 129,
          f"wrong candidate: {env['status']}")
    # The CPU, as the command line takes it: an 8088 unless told otherwise.
    # quot7 divides a long by 7; n = -229,382 gives the quotient -32768.
    quot7 = {"args": [{"name": "n", "list": [-229382], "size": 4}], "compare": ["ax"]}
    seen = []
    for cpu, status in ((None, "mismatch"), ("8088", "mismatch"), ("386", "verified")):
        env, err = await call("sweep", session_id=sid, entry=f"1000:{Fix.labels['quot7']:04x}",
                              domain=quot7, cpu=cpu,
                              candidate=f"{SWEEP_FIX / 'ref.py'}:quot7_as_a_386_divides")
        check(not err and env["status"] == status
              and env["result"]["cpu"] == (cpu or "8088"), f"cpu {cpu}: {env['status']}")
        seen.append(f"{cpu or 'default'} {status}")
    await call("close_binary", session_id=sid)
    return ("1,001 cases verified; the 0x7F candidate fails at case 129, as in prompt 05; "
            "quot7 at -32768: " + ", ".join(seen))


@case("emuverify on two sessions with linker maps")
async def _():
    a, _ = await open_mz()
    b, _ = await open_mz()
    env, err = await call("emuverify", session_a=a, session_b=b, map_a=str(Fix.map),
                          map_b=str(Fix.map))
    r = env["result"]
    check(not err and r["checked"] and r["checked"]["incorrect"] == 0 and r["checked"]["correct"] >= 3,
          f"emuverify: {r}")
    for s in (a, b):
        await call("close_binary", session_id=s)
    return (f"{r['checked']['correct']} matches, {r['checked']['incorrect']} wrong, "
            f"precision {r['checked']['precision']}")


# ---------------------------------------------------------------- with Ghidra

@case("analyze, list_functions, function, coverage, anchors, libsig, verify_load_image, "
      "apply_names dry run, and a cache hit", needs=("ghidra",))
async def _():
    sid, folder = await open_mz()
    seen = []

    async def progress(p, total, message):
        seen.append(p)
    t = time.perf_counter()
    r = await Fix.session.call_tool("analyze", {"session_id": sid}, progress_callback=progress)
    first = time.perf_counter() - t
    env = r.structured_content
    check(not r.is_error and env["status"] == "ok" and env["result"]["cache"] == "miss",
          f"analyze: {env['status']} {env['result']}")
    check(len(set(seen)) >= 4, f"progress stages: {seen}")
    env, _ = await call("list_functions", session_id=sid, limit=2)
    check(len(env["result"]["functions"]) == 2 and env["page"]["next_cursor"], "list_functions")
    env, _ = await call("list_functions", session_id=sid, limit=50)
    entries = {f["entry"] for f in env["result"]["functions"]}
    rare = f"1000:{Fix.labels['rare']:04x}"
    check(rare in entries, f"{rare} not among {sorted(entries)}")
    env, _ = await call("function", session_id=sid, entry=rare)
    fr = env["result"]
    check(fr["c"] and fr["c"][0].startswith("/* ----") and len(fr["disassembly"]) == 10
          and fr["origin"], f"function: {len(fr['disassembly'])} instructions, c {fr['c'][:1]}")
    # parts: exactly the parts asked for, each the same as in the whole answer.
    env, err = await call("function", session_id=sid, entry=rare, parts=["c"])
    got = env["result"]
    check(not err and set(got) == {"entry", "name", "parts", "c"} and got["c"] == fr["c"],
          f"function parts=['c'] returned {sorted(got)}")
    paged = {name for name in env["page"]["lists"] if name.startswith("result.")}
    check(paged == {"result.c"}, f"function parts=['c'] paged {sorted(paged)}")
    env, err = await call("function", session_id=sid, entry=rare, parts=["asm", "record"])
    got = env["result"]
    check(not err and "c" not in got and got["disassembly"] == fr["disassembly"]
          and got["calls"] == fr["calls"] and got["callers"] == fr["callers"]
          and got["parts"] == ["asm", "record"],
          f"function parts=['asm', 'record'] returned {sorted(got)}")
    env, err = await call("coverage", session_id=sid)
    check(not err and env["tool"] == "bodies", f"coverage: {env['status']}")
    env, err = await call("anchors", session_id=sid)
    check(not err and env["status"] == "ok", f"anchors: {env['result']}")
    env, err = await call("libsig", session_id=sid)
    check(not err and len(env["result"]["databases"]) == 3, f"libsig: {env['result']}")
    env, err = await call("verify_load_image", session_id=sid)
    check(env["status"] == "verified", f"verify_load_image: {env['status']}")
    mapping = [{"source": "rare_func", "binary": rare, "score": 0.9}]
    env, err = await call("apply_names", session_id=sid, mapping=mapping)
    check(env["result"]["phase"] == "dry-run" and env["result"]["dryrun"],
          f"apply_names: {env['result'].get('phase')}")
    env, err = await call("apply_names", session_id=sid, mapping=mapping, dryrun=False)
    check(env["result"]["phase"] == "dry-run", "dryrun false without confirm wrote names")
    t = time.perf_counter()
    sid2, folder2 = await open_mz()
    env, err = await call("analyze", session_id=sid2)
    second = time.perf_counter() - t
    check(not err and env["result"]["cache"] == "hit", f"second open: {env['result']['cache']}")
    for s in (sid, sid2):
        await call("close_binary", session_id=s)
    check(not folder.exists() and not folder2.exists(), "a session folder survived close")
    return (f"analyzed in {first:.1f} s with progress {sorted(set(seen))}; rare has 10 "
            f"instructions and its C; apply_names stayed a dry run twice; cache hit in "
            f"{second:.1f} s")


@case("analyze an overlay view: verified, and analyze and verify_load_image say which overlay",
      needs=("ghidra",))
async def _():
    env, err = await call("open_binary", path=str(Fix.extra["overlaid"]))
    sid = env["result"]["session_id"]
    env, err = await call("overlays", session_id=sid, views=True)
    view = env["result"]["views"][1]
    env, err = await call("open_binary", path=view["view"])
    vid = env["result"]["session_id"]
    env, err = await call("analyze", session_id=vid)
    r = env["result"]
    check(not err and env["status"] == "ok" and r["load_image"] == "verified"
          and r.get("overlay_view", {}).get("overlay") == 2, f"analyze: {env['status']} {r}")
    env, err = await call("verify_load_image", session_id=vid)
    check(env["status"] == "verified" and env["result"]["overlay_view"]["overlay"] == 2,
          f"verify_load_image: {env['status']} {env['result'].get('overlay_view')}")
    for s in (vid, sid):
        await call("close_binary", session_id=s)
    return (f"view 2 verified at segment {r['overlay_view']['load_segment']}, its record "
            f"carried through analyze and verify_load_image")


# ---------------------------------------------------------------- the run

def ghidra_why():
    g, j = os.environ.get("GHIDRA_HOME"), os.environ.get("JAVA_HOME")
    if not g or not Path(g).is_dir():
        return "Ghidra not found (set GHIDRA_HOME)"
    if not j or not Path(j).is_dir():
        return "JDK not found (set JAVA_HOME)"
    if not shutil.which("pwsh"):
        return "pwsh not found"
    return None


def build():
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    if not nasm:
        return "nasm not found (set NASM)"
    Fix.sweep_exe = Fix.work / "games" / "SWEEP.EXE"
    Fix.sweep_exe.parent.mkdir(parents=True)
    lst = Fix.work / "sweep.lst"
    subprocess.run([nasm, "-f", "bin", "-o", str(Fix.sweep_exe), "-l", str(lst),
                    str(SWEEP_FIX / "sweep.asm")], check=True)
    Fix.labels = labels(lst)
    Fix.com = Fix.work / "games" / "PLAIN.COM"
    subprocess.run([nasm, "-f", "bin", "-o", str(Fix.com), str(COM_FIX / "plain.asm")], check=True)
    Fix.siblings = tuple(Fix.work / "games" / f"{n.upper()}.COM" for n in ("cmpa", "cmpb"))
    for out, n in zip(Fix.siblings, ("cmpa", "cmpb")):
        subprocess.run([nasm, "-f", "bin", "-o", str(out), str(COMDIFF_FIX / f"{n}.asm")],
                       check=True)
    # Prompt 15's, in a folder of their own: a .COM with its own INT 80h, 60h
    # and 21h; a .COM image named .PTL; an MZ with two LINK overlays; and an
    # EXEPACK file of the 18-byte layout, packed by tests/unpack's packer.
    extra = Fix.work / "more"
    extra.mkdir()
    Fix.extra = {"swint": extra / "SWINT.COM", "ptl": extra / "GAME.PTL",
                 "overlaid": extra / "OVERLAID.EXE", "packed": extra / "PACKED.EXE"}
    subprocess.run([nasm, "-f", "bin", "-o", str(Fix.extra["swint"]),
                    str(COMRUN_FIX / "swint.asm")], check=True)
    subprocess.run([nasm, "-f", "bin", "-o", str(Fix.extra["ptl"]),
                    str(COM_FIX / "jmpstub.asm")], check=True)
    subprocess.run([nasm, "-f", "bin", "-o", str(Fix.extra["overlaid"]),
                    str(OVERLAY_FIX / "overlaid.asm")], check=True)
    import importlib.util
    spec = importlib.util.spec_from_file_location("unpack_regress",
                                                  ROOT / "tests" / "unpack" / "regress.py")
    packer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(packer)
    program = Fix.work / "program.exe"
    stub = Fix.work / "stub18.bin"
    subprocess.run([nasm, "-f", "bin", "-o", str(program),
                    str(ROOT / "tests" / "unpack" / "fixtures" / "program.asm")], check=True)
    subprocess.run([nasm, "-f", "bin", "-DHEADER=18", "-o", str(stub),
                    str(ROOT / "tests" / "unpack" / "fixtures" / "stub.asm")], check=True)
    Fix.extra["packed"].write_bytes(packer.pack(program.read_bytes(), stub.read_bytes(), 18))
    # A Microsoft LINK map of the sweep fixture, from its labels.
    L = Fix.labels
    dg = L["data_start"] // 16
    size = len(Fix.sweep_exe.read_bytes()) - 0x40
    publics = [(0, L[n], "_" + n) for n in ("muldiv", "clamp_store", "rare", "caller", "helper")]
    publics += [(dg, L[n] - L["data_start"], "_" + n) for n in ("g_limit", "g_over", "g_hits",
                                                                "g_under")]
    lines = ["", " Start  Stop   Length Name                   Class",
             f" 00000H {L['data_start'] - 1:05X}H {L['data_start']:05X}H _TEXT                  CODE",
             f" {L['data_start']:05X}H {size - 1:05X}H {size - L['data_start']:05X}H _DATA                  DATA",
             "", " Origin   Group", f" {dg:04X}:0   DGROUP", "", "  Address         Publics by Value", ""]
    lines += [f" {s:04X}:{o:04X}       {n}" for s, o, n in sorted(publics)]
    Fix.map = Fix.work / "SWEEP.MAP"
    Fix.map.write_text("\r\n".join(lines + [""]), encoding="latin-1")
    return None


async def run_all(only):
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    env = dict(os.environ, DOSDEC_WORK=str(Fix.work / "sessions"), PYTHON=sys.executable)
    params = StdioServerParameters(command=sys.executable, args=[str(SERVER)], env=env,
                                   cwd=str(Fix.work))
    have = {"ghidra": ghidra_why() is None}
    failures = skipped = run = 0
    errlog = open(Fix.work / "server-stderr.log", "w", encoding="utf-8")
    async with stdio_client(params, errlog=errlog) as streams:
        async with ClientSession(streams[0], streams[1]) as session:
            await session.initialize()
            Fix.session = session
            for name, fn, needs in CASES:
                if only and only not in name:
                    continue
                if any(not have[n] for n in needs):
                    print(f"  SKIP  {name:<78} skipped: {ghidra_why()}")
                    skipped += 1
                    continue
                run += 1
                try:
                    print(f"  PASS  {name:<78} {await fn()}", flush=True)
                except AssertionError as e:
                    print(f"  FAIL  {name:<78} {e}", flush=True)
                    failures += 1
    errlog.close()
    return failures, skipped, run


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only")
    args = ap.parse_args()
    try:
        import mcp  # noqa: F401
    except ImportError:
        print("mcp regress: the MCP Python SDK is not installed (python -m pip install mcp); "
              "the server cannot be started")
        return 77
    Fix.work = Path(tempfile.mkdtemp(prefix="mcp-regress-"))
    os.environ["DOSDEC_WORK"] = str(Fix.work / "sessions")
    try:
        why = build()
        if why:
            print(f"mcp regress: {why}")
            return 77
        originals = {p: (p.stat().st_mtime_ns, p.read_bytes())
                     for p in (Fix.sweep_exe, Fix.com, *Fix.siblings, *Fix.extra.values())}
        failures, skipped, run = asyncio.run(run_all(args.only))
        left = [p for p in (Fix.work / "sessions").glob("*") if p.name != "_cache"] \
            if (Fix.work / "sessions").exists() else []
        if left:
            print(f"  FAIL  {'every session folder is gone at the end':<78} left: {left}")
            failures += 1
        run += 1
        touched = [p.name for p, (mtime, data) in originals.items()
                   if p.stat().st_mtime_ns != mtime or p.read_bytes() != data]
        beside = sorted(p.name for folder in (Fix.sweep_exe.parent,
                                              Fix.extra["swint"].parent)
                        for p in folder.iterdir() if p not in originals)
        if touched or beside:
            print(f"  FAIL  {'the originals are untouched and nothing was written beside them':<78} "
                  f"changed {touched}, new beside them {beside}")
            failures += 1
        else:
            print(f"  PASS  {'the originals are untouched and nothing was written beside them':<78} "
                  f"{', '.join(p.name for p in originals)}: same bytes, same time")
    finally:
        shutil.rmtree(Fix.work, ignore_errors=True)
    print()
    if failures:
        print(f"{failures} of {run} MCP checks failed.")
        return 1
    if skipped:
        print(f"{run} MCP checks pass; {skipped} skipped.")
        return 0
    print(f"All {run} MCP checks pass, over stdio through the SDK's client.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
