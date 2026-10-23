#!/usr/bin/env python3
"""
regress.py -- Check that every agent-specific file is a pointer, not a copy.

AGENTS.md is the method and mcp_server/server.py the server, and each agent
is given one of them by a file of its own (knowledge/19-agents.md). Those
files are where drift would start: a skill whose description is edited in one
place, a server entry that points somewhere else for one agent, a CLAUDE.md
that would stop Claude Code reading AGENTS.md at all. This checks, without
running any agent:

* **The skills are pointers.** The two pointer skills carry SKILL.md's
  frontmatter exactly, say nothing but where the skill is, and that place is
  SKILL.md, which itself says nothing but "read AGENTS.md".
* **Every agent starts the same server.** The five MCP configurations name
  one command and one script, and the script exists.
* **Every agent reads the one method.** Gemini CLI's context file is set to
  AGENTS.md; no CLAUDE.md, GEMINI.md or override file exists beside it; and
  Codex's instruction limit is at least AGENTS.md's size.

Each check is also run against a broken copy, one fault per check, and must
fail there: a check that cannot fail would pass whatever happened to the files.

Usage:
    python tests/agents/regress.py [--only TEXT ...]
"""

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

try:
    import tomllib
except ImportError:                         # Python 3.10 and older
    tomllib = None

ROOT = Path(__file__).resolve().parent.parent.parent

POINTER_SKILLS = [".claude/skills/dos-decompile/SKILL.md",
                  ".agents/skills/dos-decompile/SKILL.md"]
JSON_SERVERS = [".mcp.json", ".gemini/settings.json", ".kimi-code/mcp.json",
                ".agents/mcp_config.json"]
CODEX = ".codex/config.toml"
SERVER = ("python", ["mcp_server/server.py"])
# Files that would be a second copy of the method, or would hide AGENTS.md:
# Claude Code reads AGENTS.md only while none of its own three exists.
SECOND_COPIES = ["CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md", "GEMINI.md",
                 "AGENTS.override.md", ".kimi-code/AGENTS.md", ".antigravity.md"]
# What the server needs from Codex, which passes only what it is told to:
# Python on Windows needs SYSTEMROOT, the sessions live under LOCALAPPDATA.
CODEX_ENV = {"PATH", "SYSTEMROOT", "LOCALAPPDATA", "TEMP", "TMP"}
# More than this many lines of body is the method being copied in.
POINTER_LINES = 8


def split_skill(text):
    """(frontmatter, body) of a SKILL.md."""
    text = text.replace("\r\n", "\n")
    assert text.startswith("---\n"), "no frontmatter"
    end = text.index("\n---\n", 4)
    return text[4:end], text[end + 5:]


def body_lines(body):
    return [line for line in body.splitlines() if line.strip()]


def check_pointer_skills(root):
    front, body = split_skill((root / "SKILL.md").read_text(encoding="utf-8"))
    assert "AGENTS.md" in body, "SKILL.md does not point at AGENTS.md"
    assert len(body_lines(body)) <= POINTER_LINES, (
        f"SKILL.md's body is {len(body_lines(body))} lines; a pointer is at most "
        f"{POINTER_LINES}")
    for rel in POINTER_SKILLS:
        path = root / rel
        assert path.exists(), f"{rel} is missing"
        f, b = split_skill(path.read_text(encoding="utf-8"))
        assert f == front, f"{rel}'s frontmatter is not SKILL.md's"
        assert len(body_lines(b)) <= POINTER_LINES, (
            f"{rel}'s body is {len(body_lines(b))} lines; a pointer is at most "
            f"{POINTER_LINES}")
        target = "../../../SKILL.md"
        assert target in b, f"{rel} does not name {target}"
        assert (path.parent / target).resolve() == (root / "SKILL.md").resolve(), (
            f"{rel}'s {target} is not the root SKILL.md")
    return f"{len(POINTER_SKILLS)} pointers, each with SKILL.md's frontmatter"


def check_servers(root):
    entries = {}
    for rel in JSON_SERVERS:
        data = json.loads((root / rel).read_text(encoding="utf-8"))
        entries[rel] = data["mcpServers"]["dos-decompiler"]
    entries[CODEX] = tomllib.loads((root / CODEX).read_text(encoding="utf-8"))[
        "mcp_servers"]["dos-decompiler"]
    for rel, e in entries.items():
        got = (e.get("command"), e.get("args"))
        assert got == SERVER, f"{rel} starts {got}, not {SERVER}"
        assert "env" not in e, (f"{rel} sets env; the server reads env.ps1 itself, "
                                f"and a value here would differ from it")
    assert (root / SERVER[1][0]).exists(), f"{SERVER[1][0]} does not exist"
    missing = CODEX_ENV - set(entries[CODEX].get("env_vars", []))
    assert not missing, f"{CODEX} does not pass the server {sorted(missing)}"
    return f"{len(entries)} configurations, one server"


def check_one_method(root):
    gemini = json.loads((root / ".gemini/settings.json").read_text(encoding="utf-8"))
    names = gemini.get("context", {}).get("fileName")
    names = [names] if isinstance(names, str) else (names or [])
    assert names == ["AGENTS.md"], f"Gemini CLI's context file is {names}, not AGENTS.md"
    present = [rel for rel in SECOND_COPIES if (root / rel).exists()]
    assert not present, f"a second instruction file exists: {present}"
    size = len((root / "AGENTS.md").read_bytes())
    limit = tomllib.loads((root / CODEX).read_text(encoding="utf-8")).get(
        "project_doc_max_bytes", 32 * 1024)
    assert limit >= size, (f"AGENTS.md is {size:,} bytes and Codex reads "
                           f"{limit:,}; raise project_doc_max_bytes")
    return f"AGENTS.md, {size:,} bytes, read whole by Codex's limit of {limit:,}"


CHECKS = [("the skills are pointers", check_pointer_skills),
          ("every agent starts the same server", check_servers),
          ("every agent reads the one method", check_one_method)]


def edit(path, old, new):
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{path.name} no longer contains {old!r}; update this fault"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


# One fault per way a check can fail: (check, description, how to break a copy).
FAULTS = [
    (check_pointer_skills, "a pointer skill's description edited",
     lambda r: edit(r / POINTER_SKILLS[1], "description: ", "description: Now ")),
    (check_pointer_skills, "the method copied into SKILL.md",
     lambda r: (r / "SKILL.md").write_text(
         (r / "SKILL.md").read_text(encoding="utf-8")
         + (r / "AGENTS.md").read_text(encoding="utf-8"), encoding="utf-8")),
    (check_pointer_skills, "a pointer skill naming another file",
     lambda r: edit(r / POINTER_SKILLS[0], "../../../SKILL.md", "../SKILL.md")),
    (check_servers, "one agent started with another script",
     lambda r: edit(r / ".kimi-code/mcp.json", "mcp_server/server.py", "mcp_server/old.py")),
    (check_servers, "one agent given its own environment",
     lambda r: edit(r / ".mcp.json", '"args"', '"env": {"PYTHON": "x"}, "args"')),
    (check_servers, "Codex not passing SYSTEMROOT",
     lambda r: edit(r / CODEX, '"SYSTEMROOT", ', "")),
    (check_one_method, "a CLAUDE.md beside AGENTS.md",
     lambda r: (r / "CLAUDE.md").write_text("@AGENTS.md\n", encoding="utf-8")),
    (check_one_method, "Gemini CLI reading GEMINI.md",
     lambda r: edit(r / ".gemini/settings.json", '"fileName": "AGENTS.md"',
                    '"fileName": "GEMINI.md"')),
    (check_one_method, "AGENTS.md grown past Codex's limit",
     lambda r: (r / "AGENTS.md").write_bytes(
         (r / "AGENTS.md").read_bytes() + b"x" * 70000)),
]


def copy_of_root(work):
    """The files the checks read, copied to a folder of their own."""
    dest = Path(tempfile.mkdtemp(dir=work))
    for rel in ["SKILL.md", "AGENTS.md", CODEX, SERVER[1][0], *POINTER_SKILLS,
                *JSON_SERVERS]:
        (dest / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / rel, dest / rel)
    return dest


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", action="append",
                    help="run only the checks whose name contains this; may be repeated")
    args = ap.parse_args()
    if tomllib is None:
        print("agents regress: needs Python 3.11 or later (tomllib) to read "
              ".codex/config.toml")
        return 77

    def wanted(name):
        return not args.only or any(o in name for o in args.only)

    cases = [(name, lambda fn=fn: fn(ROOT)) for name, fn in CHECKS if wanted(name)]
    work = Path(tempfile.mkdtemp(prefix="agents-regress-"))
    names = {fn: name for name, fn in CHECKS}
    for fn, what, breaks in FAULTS:
        name = f"{names[fn]}: fails on {what}"
        if not wanted(name):
            continue

        def broken(fn=fn, breaks=breaks):
            copy = copy_of_root(work)
            fn(copy)                       # the copy passes before it is broken
            breaks(copy)
            try:
                fn(copy)
            except AssertionError as e:
                return f"refused: {e}"
            raise AssertionError("the check passed the broken copy")
        cases.append((name, broken))

    failures = 0
    try:
        for name, fn in cases:
            try:
                print(f"  PASS  {name:<70} {fn()}")
            except (AssertionError, KeyError, FileNotFoundError, ValueError) as e:
                print(f"  FAIL  {name:<70} {type(e).__name__}: {e}")
                failures += 1
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print()
    if not cases:
        print(f"no agents check matches --only {args.only}")
        return 1
    if failures:
        print(f"{failures} of {len(cases)} agents checks failed.")
        return 1
    print(f"All {len(cases)} agents checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
