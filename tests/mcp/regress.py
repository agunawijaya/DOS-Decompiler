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

TOOLS = ["survey", "triage", "open_binary", "close_binary", "list_sessions", "unpack",
         "analyze", "verify_load_image", "address_map", "read_bytes", "list_functions",
         "function", "coverage", "anchors", "libsig", "apply_names", "emuverify", "sweep",
         "comrec"]

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
        originals = {p: (p.stat().st_mtime_ns, p.read_bytes()) for p in (Fix.sweep_exe, Fix.com)}
        failures, skipped, run = asyncio.run(run_all(args.only))
        left = [p for p in (Fix.work / "sessions").glob("*") if p.name != "_cache"] \
            if (Fix.work / "sessions").exists() else []
        if left:
            print(f"  FAIL  {'every session folder is gone at the end':<78} left: {left}")
            failures += 1
        run += 1
        touched = [p.name for p, (mtime, data) in originals.items()
                   if p.stat().st_mtime_ns != mtime or p.read_bytes() != data]
        beside = sorted(p.name for p in Fix.sweep_exe.parent.iterdir()
                        if p not in originals)
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
