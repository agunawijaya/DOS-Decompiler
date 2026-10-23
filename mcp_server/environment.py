"""
environment.py -- The environment the MCP server runs the tools in, whichever
agent started it.

The command line gets its tool locations from env.ps1, dot-sourced into the
shell. An MCP server is started by the agent, not by that shell: Claude Code
passes on the environment it was started in, Codex passes only a few
variables of its own unless told more, and Gemini CLI redacts some. So a
server that relied on the shell would work under one agent because that
agent's shell happened to have env.ps1 loaded, and fail under the next for no
visible reason.

So the server reads env.ps1 itself, before anything else:

  * Every `$env:NAME = '...'` line in it sets NAME, unless the environment the
    server started in already has NAME: what the agent's configuration passes
    wins. DOSDEC_ENV_FILE names another file; set to an empty string, no file
    is read.
  * If the Python running the server lacks the MCP SDK, capstone or unicorn,
    and PYTHON names another interpreter, the server runs itself under that
    one, with the same standard input and output. An agent's configuration can
    then say `python`, whatever `python` is first on PATH (on the machine this
    was written on, Inkscape's, which has none of the three).
  * If no Python with all three can be found, the server stops at once and
    says which packages are missing from which interpreter, and what to set.
  * GHIDRA_HOME, JAVA_HOME and NASM are checked. The server starts without
    them, because triage, survey, unpack and the sweep do not need them, but
    it says at start which are missing and which tools will refuse, and those
    tools refuse with the same words.

Nothing here imports anything outside the standard library: it has to run
under whatever Python an agent happened to start.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ENV_FILE = ROOT / "env.ps1"
PACKAGES = ("mcp", "capstone", "unicorn")
RELAUNCHED = "DOSDEC_RELAUNCHED"

# What each external tool is for, in the words a refusal uses.
NEEDED = {
    "GHIDRA_HOME": "a Ghidra 12 installation; without it `analyze` refuses, and so "
                   "everything that reads an analysis",
    "JAVA_HOME": "a JDK 21 or newer for Ghidra; without it `analyze` refuses",
    "NASM": "nasm.exe; without it, and with no nasm on PATH, `comrec` refuses",
}

ASSIGNMENT = re.compile(r"""^\s*\$env:(\w+)\s*=\s*(['"])(.*?)\2\s*(?:#.*)?$""")


def env_file():
    """The env.ps1 to read, or None when DOSDEC_ENV_FILE is set empty."""
    given = os.environ.get("DOSDEC_ENV_FILE")
    if given is None:
        return DEFAULT_ENV_FILE
    return Path(given) if given else None


def read_env_file(path):
    """{NAME: value} for every `$env:NAME = '...'` line of a PowerShell file."""
    values = {}
    for line in Path(path).read_text(encoding="utf-8-sig", errors="replace").splitlines():
        m = ASSIGNMENT.match(line)
        if m:
            values[m.group(1)] = m.group(3)
    return values


def load():
    """Fill the environment from env.ps1. Returns (the file read or None,
    the names it set)."""
    path = env_file()
    if path is None or not path.is_file():
        return None, []
    taken = []
    for name, value in read_env_file(path).items():
        if not os.environ.get(name):
            os.environ[name] = value
            taken.append(name)
    return path, taken


def missing_packages():
    """The packages of PACKAGES this Python cannot import."""
    import importlib.util
    return [p for p in PACKAGES if importlib.util.find_spec(p) is None]


def missing_tools():
    """[(name, what it is for)] for each external tool the environment does not
    point at."""
    out = []
    for name, why in NEEDED.items():
        value = os.environ.get(name)
        if name == "NASM" and not value and shutil.which("nasm"):
            continue
        if not value or not Path(value).exists():
            out.append((name, why))
    return out


def prepare(argv):
    """Make the environment the server needs, or say why it cannot be had.

    Returns (notes for stderr, missing tools) when this Python can run the
    server. Runs the server under PYTHON and exits with its code when PYTHON
    has what this one lacks. Exits 2, saying what is missing, when no Python
    with all of PACKAGES can be found."""
    path, taken = load()
    notes = []
    handed = os.environ.get(RELAUNCHED)
    if handed and handed != "1":
        # The Python that handed over read env.ps1; say what it took.
        notes.append(f"dos-decompiler MCP server: started by {os.environ.get('DOSDEC_HANDED_BY')}, "
                     f"which lacked the packages and handed over to PYTHON; {handed}")
    if path is not None and taken:
        notes.append(f"dos-decompiler MCP server: {', '.join(sorted(taken))} from {path}")
    elif path is None:
        where = os.environ.get("DOSDEC_ENV_FILE")
        notes.append("dos-decompiler MCP server: no env.ps1 read "
                     + ("(DOSDEC_ENV_FILE is empty)" if where == "" else
                        f"(none at {where or DEFAULT_ENV_FILE})"))
    lacking = missing_packages()
    if lacking:
        other = os.environ.get("PYTHON")
        here = Path(sys.executable).resolve()
        if other and Path(other).is_file() and Path(other).resolve() != here \
                and not os.environ.get(RELAUNCHED):
            said = (f"{', '.join(sorted(taken))} from {path}" if taken else
                    "nothing taken from env.ps1")
            env = dict(os.environ, **{RELAUNCHED: said, "DOSDEC_HANDED_BY": sys.executable})
            sys.exit(subprocess.call([other, *argv], env=env))
        if not other:
            about = "PYTHON is not set"
        elif not Path(other).is_file():
            about = f"PYTHON names {other}, which does not exist"
        else:
            about = f"PYTHON names {other}, this same interpreter"
        sys.stderr.write(
            f"dos-decompiler MCP server: cannot start. This Python ({sys.executable}) "
            f"cannot import {', '.join(lacking)}, and {about}, in the environment or in "
            f"{path or 'any env.ps1'}. Set PYTHON (in env.ps1, or in the agent's MCP "
            f"configuration) to a Python 3.11 or later that has them: "
            f"python -m pip install mcp capstone unicorn\n")
        sys.exit(2)
    tools = missing_tools()
    for name, why in tools:
        notes.append(f"dos-decompiler MCP server: {name} is not set, in the environment or "
                     f"in {path or 'any env.ps1'}: {why}")
    return notes, tools
