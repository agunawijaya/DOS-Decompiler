#!/usr/bin/env python3
"""
server.py -- One MCP server in front of the DOS-Decompiler toolkit.

An agent working with the command-line tools runs a command, reads console
text and infers its structure. That costs context, and it fails quietly when
the text changes. This server gives Claude Code, Codex, Cursor or any other
MCP client the same tools as calls with structured results: every tool
returns the evidence envelope of knowledge/17-evidence.md -- the result, the
observations behind it with where each was seen, what the method cannot see,
and what it could not settle.

It is a thin layer. operations.py calls the same Python functions the
command-line tools call, and this file only registers those as MCP tools; it
does no analysis of its own. The command line stays the primary interface,
and AGENTS.md stays the method: the prompts this server offers tell the agent
to read it and to run triage first.

What it keeps
-------------
open_binary copies a target into a session folder under DOSDEC_WORK (default
%LOCALAPPDATA%\\dos-decompiler\\sessions) and every tool reads the copy; the
original is never opened for writing. close_binary deletes the folder, and a
server starting up deletes the folders whose server is no longer running.
Analysis is cached by the target's SHA-256, the analysis profile's id and a
hash of the Python the pipeline runs, so a second session on the same bytes
does not run Ghidra again. See sessions.py.

What it refuses
---------------
Relative paths, paths with `..`, paths that resolve somewhere else, and any
write outside the session folder or a keep_to folder the user names -- never
beside the original. Every external program has a timeout. Every result is
one page: lists are cut to `limit` with a cursor, and the page is held under
64,000 bytes. A .COM is admitted only with format="com". See safety.py and
paging.py.

Requires the MCP Python SDK (pip install mcp; 2.x, Python 3.11 or later).
Nothing else in the toolkit imports it. GHIDRA_HOME, JAVA_HOME, NASM and
PYTHON come from the environment the server starts in, and what that lacks
from env.ps1, which the server reads itself (environment.py): it must not
matter which agent started it, or what that agent's shell had loaded. A
Python without the SDK, capstone or unicorn hands over to PYTHON.

Usage:
    python mcp_server/server.py          # stdio; started by the MCP client
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import environment  # noqa: E402  (standard library only; runs under any Python)

START_NOTES, MISSING_TOOLS = environment.prepare([str(Path(__file__).resolve()), *sys.argv[1:]])

try:
    import anyio
    from anyio import from_thread, to_thread
    from mcp.server.mcpserver import Context, MCPServer
    from mcp.types import CallToolResult, TextContent
except ImportError:
    sys.stderr.write(
        "mcp_server: the MCP Python SDK is not installed in this Python "
        f"({sys.executable}).\n"
        "Install it with:  python -m pip install mcp\n"
        "(the official SDK, 2.x, which needs Python 3.11 or later). The "
        "command-line tools in tools/ do not need it.\n")
    sys.exit(2)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import operations as op  # noqa: E402

INSTRUCTIONS = (
    "Tools for decompiling DOS programs, each returning an evidence envelope: "
    "result, evidence (each observation with where it was seen), limitations "
    "and unknowns. Read the prompt standard_workflow or extended_workflow "
    "first; the method is AGENTS.md (resource toolkit://AGENTS.md). Always "
    "triage before promising anything. Paths are absolute. Long results come "
    "in pages: pass page.next_cursor back as cursor.")
if MISSING_TOOLS:
    # Said where the model reads it, not only on stderr: a tool that will
    # refuse should not be a surprise.
    INSTRUCTIONS += " On this machine " + "; ".join(
        f"{name} is not set: {why}" for name, why in MISSING_TOOLS) + "."

server = MCPServer("dos-decompiler", instructions=INSTRUCTIONS)


def answer(env):
    """The envelope as both structured content and its JSON text; an error
    when it says the tool could not do what was asked."""
    return CallToolResult(content=[TextContent(type="text", text=json.dumps(env))],
                          structured_content=env,
                          is_error=env.get("status") in ("blocked", "error"))


async def call(fn, *args, **kwargs):
    """Run an operation in a worker thread, so a long one does not stall the
    server's other requests."""
    return answer(await to_thread.run_sync(lambda: fn(*args, **kwargs)))


# ---------------------------------------------------------------- admission

@server.tool()
async def survey(folder: str, limit: int | None = None, cursor: str | None = None,
                 format: str = "auto") -> CallToolResult:
    """Survey a game folder: every executable triaged, batch files read, and
    which executable looks like the game and why. folder is absolute. Files
    whose content looks like a .COM image under another name are listed;
    format "com" triages them as .COM images."""
    return await call(op.survey, folder, limit, cursor, format)


@server.tool()
async def triage(session_id: str | None = None, path: str | None = None,
                 limit: int | None = None, cursor: str | None = None,
                 format: str = "auto") -> CallToolResult:
    """Is this program in scope? Packers, overlays, interpreted engines,
    memory model, with the file offset of each finding. Run this first.
    Pass a session_id (triaged as it was opened), or an absolute path with
    format auto, com (a .COM image whatever its name) or mz."""
    return await call(op.triage, session_id, path, limit, cursor, format)


@server.tool()
async def open_binary(path: str, format: str = "auto") -> CallToolResult:
    """Admit a target: copy it into a new session and return its session_id.
    format is auto, mz or com. A .COM is admitted only with format="com": it
    has no header, so neither its name nor a guess is enough."""
    return await call(op.open_binary, path, format)


@server.tool()
async def close_binary(session_id: str) -> CallToolResult:
    """Delete a session: the copy, its Ghidra project, everything written there."""
    return await call(op.close_binary, session_id)


@server.tool()
async def list_sessions(limit: int | None = None, cursor: str | None = None) -> CallToolResult:
    """The open sessions, with their targets and whether each was analysed."""
    return await call(op.list_sessions, limit, cursor)


# ---------------------------------------------------------------- unpacking, .COM

@server.tool()
async def unpack(session_id: str, out: str | None = None,
                 keep_to: str | None = None) -> CallToolResult:
    """Run a packed MZ's own decompressor under emulation and dump the image
    inside the session (out, if given, must be inside it); keep_to, an
    absolute folder of yours, keeps a copy."""
    return await call(op.unpack, session_id, out, keep_to)


@server.tool()
async def comrec(session_id: str, out: str | None = None, keep_to: str | None = None,
                 limit: int | None = None, cursor: str | None = None,
                 seeds_from: str | None = None) -> CallToolResult:
    """Rebuild a .COM as NASM source and prove it byte-identical (status
    verified) or say why not. The .asm is written inside the session (out,
    if given, must be inside it); keep_to keeps a copy elsewhere. seeds_from
    is an exec map comrun wrote -- an absolute path, or "session" for the one
    this session's comrun wrote with exec_map -- whose executed addresses the
    walk starts from too, each checked against the origin it ran at."""
    return await call(op.comrec, session_id, out, keep_to, limit, cursor, seeds_from)


@server.tool()
async def comrun(session_id: str, keys: str | None = None, keyboard: str = "bios",
                 timer: str = "bios", no_joystick: bool = False, bios_text: bool = False,
                 budget: int = 2_000_000, key_every: int | None = None,
                 timer_every: int | None = None, png: bool = True, exec_map: bool = False,
                 files: str | None = None, stop_at: str | None = None, timeout: int = 900,
                 keep_to: str | None = None, limit: int | None = None,
                 cursor: str | None = None) -> CallToolResult:
    """Run the session's program under emulation (comrun.py) and capture what
    it draws and does: where it stopped, interrupts, the vectors it replaced
    and the `int`s sent to its own handlers, files, what it printed, and the
    screen as comrun/screen.png in the session. keys as on the command line
    ("1,a,0x4800"); keyboard and timer bios, hw or auto -- auto moves keys and
    ticks to the program's own INT 09h and 08h when it installs them;
    no_joystick for a program that probes port 0x201; bios_text to draw text
    printed through INT 10h. exec_map writes comrun/exec-map.json for comrec's
    seeds_from="session". files is the data folder, read only; by default the
    original's. Stopped after timeout seconds."""
    return await call(op.comrun, session_id, keys, keyboard, timer, no_joystick, bios_text,
                      budget, key_every, timer_every, png, exec_map, files, stop_at,
                      timeout, keep_to, limit, cursor)


@server.tool()
async def overlays(session_id: str, views: bool = False, root_session: str | None = None,
                   load_segment: str | None = None, keep_to: str | None = None,
                   limit: int | None = None, cursor: str | None = None) -> CallToolResult:
    """The Microsoft LINK overlays appended to an MZ session, found as LINK's
    overlay manager finds them, with the overlay area's segment and the
    root's int 3Fh calls. views writes one view per module inside the
    session -- the root with that module in place, both relocation tables --
    each with a record; open_binary a view and analyze it, and its
    loadimage.json says which overlay it is. A packed root: unpack first, or
    pass the unpacked root as root_session."""
    return await call(op.overlays, session_id, views, root_session, load_segment, keep_to,
                      limit, cursor)


@server.tool()
async def comdiff(session_a: str, session_b: str, min_bytes: int | None = None,
                  similar: float | None = None, emulate: bool = True,
                  limit: int | None = None, cursor: str | None = None) -> CallToolResult:
    """Compare two .COM programs routine by routine: byte-identical,
    instruction-identical (only numbers differ; run under emulation to
    confirm), similar with a score, or no counterpart. session_a is the
    program you know, session_b the one you are reading; run comrec on both
    first. min_bytes (12) and similar (0.85) as on the command line."""
    return await call(op.comdiff, session_a, session_b, min_bytes, similar, emulate,
                      limit, cursor)


# ---------------------------------------------------------------- analysis

@server.tool()
async def analyze(session_id: str, skip_recovery: bool = False, timeout: int = 1800,
                  ctx: Context = None) -> CallToolResult:
    """The Ghidra pipeline on an MZ session: import, load correction and
    verification, analysis, function recovery, export, profile handshake.
    Reports progress by stage. A second session on the same bytes reuses the
    cached result. Stopped after timeout seconds."""
    def progress(stage, total, message):
        if ctx is not None:
            from_thread.run(ctx.report_progress, stage, total, message)
    return await call(op.analyze, session_id, skip_recovery, timeout, progress)


@server.tool()
async def verify_load_image(session_id: str, limit: int | None = None,
                            cursor: str | None = None) -> CallToolResult:
    """Check that Ghidra's program is the file: the same bytes at the
    addresses the header implies, each relocation applied once."""
    return await call(op.verify_load_image, session_id, limit, cursor)


@server.tool()
async def address_map(session_id: str, file_offset: str | None = None,
                      address: str | None = None, linear: str | None = None) -> CallToolResult:
    """Convert a file offset, a segment:offset address or a linear address
    into the other two. Give exactly one."""
    return await call(op.address_map, session_id, file_offset, address, linear)


@server.tool()
async def read_bytes(session_id: str, address: str | None = None,
                     file_offset: str | None = None, length: int = 64) -> CallToolResult:
    """Bytes as the program holds them once loaded (relocations applied), at
    most 4096. Stops at the first byte not initialised from the file and says
    so: complete false, length_read the bytes actually read."""
    return await call(op.read_bytes, session_id, address, file_offset, length)


@server.tool()
async def list_functions(session_id: str, origin: str | None = None, name: str | None = None,
                         min_size: int | None = None, max_size: int | None = None,
                         limit: int | None = None, cursor: str | None = None) -> CallToolResult:
    """The analysed functions, filterable by origin (ghidra-analysis,
    recovered-...), a name pattern (e.g. FUN_1000_*) and size."""
    return await call(op.list_functions, session_id, origin, name, min_size, max_size,
                      limit, cursor)


@server.tool()
async def function(session_id: str, entry: str | None = None, name: str | None = None,
                   parts: list[str] | None = None, limit: int | None = None,
                   cursor: str | None = None) -> CallToolResult:
    """One function: its body ranges, origin, decompiled C alone, the
    disassembly of its body, and its calls out and in. parts picks any of
    "c" (the C), "asm" (the disassembly) and "record" (the rest); default all."""
    return await call(op.function, session_id, entry, name, parts, limit, cursor)


@server.tool()
async def coverage(session_id: str, limit: int | None = None,
                   cursor: str | None = None) -> CallToolResult:
    """Which code no function's body claims, and what each unclaimed run looks like."""
    return await call(op.coverage, session_id, limit, cursor)


@server.tool()
async def anchors(session_id: str, entry: str | None = None, write_names: bool = False,
                  limit: int | None = None, cursor: str | None = None) -> CallToolResult:
    """Functions identified from evidence alone -- interrupts, ports, strings,
    constants -- and names that claim only that. write_names keeps them as
    names.json in the session, for apply_names."""
    return await call(op.anchors, session_id, entry, write_names, limit, cursor)


@server.tool()
async def libsig(session_id: str, database: str = "auto", limit: int | None = None,
                 cursor: str | None = None) -> CallToolResult:
    """C runtime functions, from the signature databases in signatures/;
    "auto" tries each, and the one that matches names the compiler."""
    return await call(op.libsig, session_id, database, limit, cursor)


@server.tool()
async def apply_names(session_id: str, mapping: str | dict | list, dryrun: bool = True,
                      confirm: bool = False, min_score: float | None = None,
                      certain: float | None = None, timeout: int = 900,
                      limit: int | None = None, cursor: str | None = None) -> CallToolResult:
    """Write names into this session's Ghidra project: validated whole first,
    read back after, rolled back whole on any failure. A dry run unless
    dryrun is false and confirm is true. mapping is an absolute path or the
    mapping itself."""
    return await call(op.apply_names, session_id, mapping, dryrun, confirm, min_score,
                      certain, timeout, limit, cursor)


# ---------------------------------------------------------------- emulation

@server.tool()
async def emuverify(session_a: str, session_b: str, map_a: str | None = None,
                    map_b: str | None = None, dgroup_a: str | None = None,
                    dgroup_b: str | None = None, limit_functions: int | None = None,
                    limit: int | None = None, cursor: str | None = None) -> CallToolResult:
    """Carry names between two builds of one program by running both under
    emulation. Each side is a session, with a linker map (absolute path) or
    its analysis's functions.json."""
    return await call(op.emuverify, session_a, session_b, map_a, map_b, dgroup_a, dgroup_b,
                      limit_functions, limit, cursor)


@server.tool()
async def sweep(session_id: str, entry: str, domain: str | dict,
                candidate: str | None = None, candidate_session: str | None = None,
                candidate_entry: str | None = None, all_divergences: bool = False,
                trace: int = 0, max_cases: int | None = None, seed: int | None = None,
                case_timeout: float | None = None, dgroup: str | None = None,
                limit: int | None = None, cursor: str | None = None,
                cpu: str | None = None) -> CallToolResult:
    """Run one routine of the original on every input of a domain against a
    candidate -- path/to/ref.py:fn, path/to/port.mjs:fn, or another session
    -- and stop at the first input where they disagree. `cpu` is 8088 (the
    default: IDIV also faults on a quotient of -32768 or -128) or 386. See the
    resource knowledge://18-oracle-sweeps.md for the domain and the contract."""
    return await call(op.sweep, session_id, entry, domain, candidate, candidate_session,
                      candidate_entry, True, all_divergences, trace, max_cases, seed,
                      case_timeout, dgroup, limit, cursor, cpu)


# ---------------------------------------------------------------- prompts

@server.prompt()
def standard_workflow() -> str:
    """The standard workflow: readable C and architecture notes."""
    return ("Use the DOS-Decompiler tools for the standard workflow: annotated "
            "pseudocode and architecture notes, verified by reading. First read "
            "AGENTS.md (resource toolkit://AGENTS.md) -- it is the method, and "
            "these tools only carry it out. Then open_binary the target and run "
            "triage before promising anything: report its verdict, the findings "
            "that set it (result.verdict_evidence) and its unknowns. Say plainly that the decompiled C will not resemble the "
            "original source. Never commit a name on one source of evidence, and "
            "say which of your conclusions are verified and which are inference.")


@server.prompt()
def extended_workflow() -> str:
    """The extended workflow: source that provably rebuilds the binary."""
    return ("Use the DOS-Decompiler tools for the extended workflow: source that "
            "rebuilds the binary, verified mechanically. First read AGENTS.md "
            "(resource toolkit://AGENTS.md) and knowledge/07-extended-"
            "reconstruction.md (resource knowledge://07-extended-reconstruction.md). "
            "Then open_binary the target and run triage before anything else, and "
            "report its verdict. This needs the period compiler; ask for it. Say "
            "which rung of the verification ladder each result stands on, and "
            "never report a per-function match as a byte-identical image.")


# ---------------------------------------------------------------- resources

def text_resource(uri, path, description):
    @server.resource(uri, mime_type="text/markdown", description=description)
    def read() -> str:
        return path.read_text(encoding="utf-8")


text_resource("toolkit://AGENTS.md", ROOT / "AGENTS.md", "The method: AGENTS.md")
for page in sorted((ROOT / "knowledge").glob("*.md")):
    text_resource(f"knowledge://{page.name}", page, f"knowledge/{page.name}")


if __name__ == "__main__":
    sys.stderr.write(op.start() + "\n")
    for note in START_NOTES:
        sys.stderr.write(note + "\n")
    server.run("stdio")
