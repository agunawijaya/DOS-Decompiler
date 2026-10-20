"""
safety.py -- What the MCP server refuses, and how it runs other programs.

An agent passes paths, and an agent can be wrong about a path in ways a
person at a terminal rarely is: a relative path that means something else in
the server's working folder, a `..` that climbs out of where it meant to be, a
link that points somewhere else entirely. So every path a tool is given must
be absolute, must not contain `..`, and must resolve to itself -- no link
taking it elsewhere. A path the server writes to must lie inside the
session's folder, or be a folder the user named to keep results in, and never
the folder the original target sits in: no tool writes beside the original.

Every external program runs with a timeout, and the error names it. On
Windows a timed-out pwsh or analyzeHeadless leaves Java running under it, so
the whole process tree is stopped, not only the process started.
"""

import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path


class Refused(Exception):
    """The tool cannot do what was asked. `reason` says why and `next_step`
    what to do instead; both reach the agent in the envelope."""

    def __init__(self, reason, next_step):
        super().__init__(reason)
        self.reason, self.next_step = reason, next_step


def absolute(text, what, kind="any", must_exist=True):
    """`text` as a Path, if it is absolute, has no `..`, and resolves to
    itself; `kind` is "file", "dir" or "any". Refused otherwise."""
    if not isinstance(text, str) or not text.strip():
        raise Refused(f"{what}: no path given", f"pass {what} as an absolute path")
    p = Path(text)
    if not p.is_absolute():
        raise Refused(f"{what}: {text!r} is a relative path; the server's working folder "
                      f"is not yours, so it would mean something else here",
                      f"pass {what} as an absolute path, e.g. C:\\games\\GAME.EXE")
    if ".." in p.parts:
        raise Refused(f"{what}: {text!r} contains '..'",
                      f"pass the path {what} means, written out without '..'")
    if must_exist and not p.exists():
        raise Refused(f"{what}: {text} does not exist", f"check the path; {what} must exist")
    if must_exist:
        resolved = p.resolve(strict=True)
        if os.path.normcase(str(resolved)) != os.path.normcase(os.path.abspath(str(p))):
            raise Refused(f"{what}: {text} resolves to {resolved}, somewhere else (a link "
                          f"or a junction)", f"pass {resolved} itself, if that is what you mean")
        if kind == "file" and not p.is_file():
            raise Refused(f"{what}: {text} is not a file", f"pass a file for {what}")
        if kind == "dir" and not p.is_dir():
            raise Refused(f"{what}: {text} is not a folder", f"pass a folder for {what}")
    return p


def inside(path, folder):
    """Whether `path` lies inside `folder` (or is it)."""
    a = os.path.normcase(os.path.abspath(str(path)))
    b = os.path.normcase(os.path.abspath(str(folder)))
    return a == b or a.startswith(b.rstrip("\\/") + os.sep)


def output_inside(text, what, session_folder):
    """A path the server will write to, which must lie in the session folder."""
    p = absolute(text, what, must_exist=False)
    if not inside(p, session_folder):
        raise Refused(f"{what}: {p} is outside this session's folder {session_folder}; "
                      f"the server writes only there",
                      f"leave {what} out to write inside the session, or pass keep_to: a "
                      f"folder of yours to copy the result to")
    return p


def keep_folder(text, original):
    """A folder the user named to keep results in. It may be anywhere they
    choose except beside the original target."""
    p = absolute(text, "keep_to", kind="dir", must_exist=False)
    if os.path.normcase(os.path.abspath(str(p))) == \
            os.path.normcase(os.path.abspath(str(Path(original).parent))):
        raise Refused(f"keep_to: {p} is the folder the original target is in, and no tool "
                      f"writes beside the original", "name another folder")
    return p


NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")


def plain_name(text, what):
    """A file name with no folder in it."""
    if not isinstance(text, str) or not NAME.match(text) or ".." in text:
        raise Refused(f"{what}: {text!r} is not a plain file name",
                      f"pass a name of letters, digits, '.', '_' and '-' only")
    return text


def kill_tree(proc):
    """Stop a process and everything it started."""
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                       capture_output=True)
    else:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (OSError, ProcessLookupError):
            proc.kill()
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        pass


def run(args, timeout, what, cwd=None, env=None, on_line=None):
    """Run a program to completion within `timeout` seconds; (exit code,
    output). Each line of output goes to `on_line` as it arrives. Past the
    timeout the whole tree is stopped and Refused says so."""
    kwargs = {"start_new_session": True} if sys.platform != "win32" else {}
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL, text=True, errors="replace",
                            cwd=cwd, env=env, **kwargs)
    deadline = time.monotonic() + timeout
    lines = []
    import threading
    expired = threading.Event()

    def watch():
        while proc.poll() is None:
            if time.monotonic() > deadline:
                expired.set()
                kill_tree(proc)
                return
            time.sleep(0.2)
    threading.Thread(target=watch, daemon=True).start()
    for line in proc.stdout:
        lines.append(line)
        if on_line:
            on_line(line.rstrip("\n"))
    proc.wait()
    if expired.is_set():
        raise Refused(f"{what} did not finish in {timeout} s and was stopped, with "
                      f"everything it had started",
                      f"pass a longer timeout if the target is large; the last output "
                      f"was: {''.join(lines[-5:]).strip()[-400:]}")
    return proc.returncode, "".join(lines)
