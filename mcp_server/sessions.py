"""
sessions.py -- Where the MCP server keeps a target while it works on it.

Admitting a target copies it into a session folder and records its identity:
path, size, SHA-256. Every later tool reads the copy; the original is opened
once, to read it, and never for writing. Session folders live under
DOSDEC_WORK, default %LOCALAPPDATA%\\dos-decompiler\\sessions, one folder per
session id, and close_binary deletes the folder -- the copy, the session's
Ghidra project, everything a tool wrote there. A session records the server
process that opened it, and a server starting up deletes the folders of
servers no longer running: a client that stopped without closing them.

Analysis is cached across sessions by the target's SHA-256, the analysis
profile's id (tools/analysis_profile.py) and a hash of the Python the pipeline
runs: the same bytes analysed under the same settings by the same scripts and
the same Python give the same export and the same records, so a second
session on the same file does not start Ghidra again. Only an analysis whose
load image verified and whose handshake verified is cached. A hit copies the
cached results, Ghidra project included, into the session, so that writing
names into one session's project never touches the cache or another session.
"""

import json
import os
import secrets
import shutil
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
import evidence  # noqa: E402

from safety import Refused  # noqa: E402

CACHE = "_cache"


def work_root():
    given = os.environ.get("DOSDEC_WORK")
    if given:
        root = Path(given)
    else:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
        root = Path(base) / "dos-decompiler" / "sessions"
    root.mkdir(parents=True, exist_ok=True)
    return root


class Session:
    def __init__(self, record):
        self.record = record
        self.id = record["id"]
        self.folder = Path(record["folder"])
        self.original = Path(record["original"]["path"])
        self.copy = Path(record["copy"])
        self.format = record["format"]
        self.sha256 = record["original"]["sha256"]

    @property
    def analysis(self):
        """Where the pipeline's output for this session goes."""
        return self.folder / "analysis"

    def analysed(self):
        return (self.analysis / "functions.json").is_file()


def admit(path, fmt):
    """Copy the target into a new session folder; the Session."""
    data = path.read_bytes()                   # the one read of the original
    session_id = secrets.token_hex(6)
    folder = work_root() / session_id
    (folder / "target").mkdir(parents=True)
    copy = folder / "target" / path.name
    copy.write_bytes(data)
    identity = evidence.target_identity(path)
    copied = evidence.target_identity(copy)
    if copied["sha256"] != identity["sha256"]:
        shutil.rmtree(folder, ignore_errors=True)
        raise Refused(f"the copy of {path} does not hash as the original did; the file "
                      f"changed while it was read", "open it again when nothing is writing it")
    record = {"id": session_id, "folder": str(folder), "format": fmt,
              "original": identity, "copy": str(copy), "server": this_server()}
    (folder / "session.json").write_text(json.dumps(record, indent=1), encoding="utf-8")
    return Session(record)


def get(session_id):
    if not isinstance(session_id, str) or not session_id.isalnum():
        raise Refused(f"{session_id!r} is not a session id", "pass the session_id "
                      "open_binary returned; list_sessions shows the open ones")
    record = work_root() / session_id / "session.json"
    if not record.is_file():
        raise Refused(f"no open session {session_id}", "open_binary the target first; "
                      "list_sessions shows the open ones")
    return Session(json.loads(record.read_text(encoding="utf-8")))


def all_sessions():
    out = []
    for record in sorted(work_root().glob("*/session.json")):
        try:
            out.append(Session(json.loads(record.read_text(encoding="utf-8"))))
        except (OSError, ValueError, KeyError):
            continue
    return out


def close(session):
    shutil.rmtree(session.folder, ignore_errors=True)
    return not session.folder.exists()


# ---------------------------------------------------------------- stale sessions

# A session is closed by close_binary. A client that stops without closing
# leaves its folder -- a copy of the target, and after analyze a Ghidra
# project -- for nobody. Each session records the server that opened it, by
# process id and that process's start time (a process id is reused once its
# process ends; the pair is not), and a server starting up deletes the
# folders whose server is no longer running.

def process_started(pid):
    """Whether process `pid` is running: None if it is not, else its start
    time as the system counts it, or 0 when the system will not say."""
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.OpenProcess.restype = wintypes.HANDLE
        k32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        k32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        k32.GetProcessTimes.argtypes = (wintypes.HANDLE,) + (ctypes.POINTER(wintypes.FILETIME),) * 4
        k32.CloseHandle.argtypes = (wintypes.HANDLE,)
        handle = k32.OpenProcess(0x1000, False, pid)   # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            # ERROR_INVALID_PARAMETER: no such process. Anything else (access
            # denied) means one exists that this user may not look at.
            return None if ctypes.get_last_error() == 87 else 0
        try:
            code = wintypes.DWORD()
            if k32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value != 259:
                return None                            # exited; not STILL_ACTIVE
            times = [wintypes.FILETIME() for _ in range(4)]
            if not k32.GetProcessTimes(handle, *(ctypes.byref(t) for t in times)):
                return 0
            return (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        finally:
            k32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        return 0
    try:                                               # Linux: field 22 of stat
        stat = Path(f"/proc/{pid}/stat").read_text()
        return int(stat[stat.rindex(")") + 2:].split()[19])
    except (OSError, ValueError, IndexError):
        return 0


def this_server():
    return {"pid": os.getpid(), "started": process_started(os.getpid())}


def server_running(server):
    """Whether the server a session records is still running. A start time
    the system would not give, now or then, counts as the same process."""
    now = process_started(server["pid"])
    if now is None:
        return False
    then = server.get("started")
    return not (now and then and now != then)


def remove_stale():
    """Delete every session folder whose server is no longer running.

    Returns (removed, unknown): the session ids deleted, and those kept
    because their record names no server (opened before servers recorded
    themselves) and so cannot be judged. Only a folder holding a session.json
    whose id is the folder's own name is ever touched."""
    removed, unknown = [], []
    for record_path in sorted(work_root().glob("*/session.json")):
        folder = record_path.parent
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not folder.name.isalnum() or record.get("id") != folder.name:
            continue
        server = record.get("server")
        if not isinstance(server, dict) or not isinstance(server.get("pid"), int):
            unknown.append(folder.name)
            continue
        if server_running(server):
            continue
        shutil.rmtree(folder, ignore_errors=True)
        if not folder.exists():
            removed.append(folder.name)
    return removed, unknown


# ---------------------------------------------------------------- the cache

# The Python the pipeline runs: the tools pipeline.ps1 calls by name (as
# Join-Path $toolDir 'x.py') and the toolkit modules those import. profile_id
# covers the Ghidra scripts and pipeline.ps1 only, by design: it names the
# settings Ghidra ran under. These write the records around that run --
# mzinfo.json, profile.json, loadimage.json, handshake.json -- so an analysis
# cached under an older copy of them is an older answer, and the key has to
# say so. tests/mcp checks this list against pipeline.ps1.
PIPELINE_PYTHON = ("mzinfo.py", "analysis_profile.py", "loadimage.py", "evidence.py")


def pipeline_python_sha256(tools=TOOLS):
    """One hash over the pipeline's Python files, read with CRLF as LF (the
    rule of 01a), so a checkout's line endings do not move it."""
    import hashlib
    files = {name: evidence.source_sha256(Path(tools) / name) for name in PIPELINE_PYTHON}
    return hashlib.sha256(evidence.canonical(files).encode("ascii")).hexdigest()


def cache_dir(sha256, profile_id, python_sha256=None):
    """The cache folder for these bytes, analysed under this profile by this
    copy of the pipeline's Python."""
    python_sha256 = python_sha256 or pipeline_python_sha256()
    return work_root() / CACHE / f"{sha256[:24]}-{profile_id[:16]}-{python_sha256[:12]}"


def cache_store(session, profile_id):
    """Keep a verified analysis for the next session on the same bytes."""
    target = cache_dir(session.sha256, profile_id)
    if target.exists():
        return target
    tmp = target.with_name(target.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree(session.analysis, tmp)
    tmp.rename(target)
    return target


def cache_fetch(session, profile_id):
    """Copy a cached analysis into the session; whether there was one."""
    source = cache_dir(session.sha256, profile_id)
    if not (source / "functions.json").is_file():
        return False
    shutil.rmtree(session.analysis, ignore_errors=True)
    shutil.copytree(source, session.analysis)
    return True
