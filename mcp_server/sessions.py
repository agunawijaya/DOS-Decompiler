"""
sessions.py -- Where the MCP server keeps a target while it works on it.

Admitting a target copies it into a session folder and records its identity:
path, size, SHA-256. Every later tool reads the copy; the original is opened
once, to read it, and never for writing. Session folders live under
DOSDEC_WORK, default %LOCALAPPDATA%\\dos-decompiler\\sessions, one folder per
session id, and close_binary deletes the folder -- the copy, the session's
Ghidra project, everything a tool wrote there.

Analysis is cached across sessions by the target's SHA-256 and the analysis
profile's id (tools/analysis_profile.py): the same bytes analysed under the
same settings by the same scripts give the same export, so a second session on
the same file does not start Ghidra six times again. Only an analysis whose
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
              "original": identity, "copy": str(copy)}
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


# ---------------------------------------------------------------- the cache

def cache_dir(sha256, profile_id):
    return work_root() / CACHE / f"{sha256[:24]}-{profile_id[:16]}"


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
