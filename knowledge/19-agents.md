# 19 — Driving the toolkit from Claude Code, Gemini CLI, Codex and Kimi Code

The toolkit has one method, `AGENTS.md`, and one MCP server,
`mcp_server/server.py`. Every agent-specific file in the repository is a
pointer to one of the two or a setting naming it, never a copy, so there is
nothing to keep in step. This file says which agent reads which, what each
needs that the repository cannot give it, and what happened when each was
run headless on the same task.

Everything marked *measured* was run on 2026-10-23 on Windows 11, from the
repository root, in a shell with no `env.ps1` loaded: Claude Code 2.1.281,
Gemini CLI 0.58.0, Codex CLI 0.154.0, Kimi Code CLI 2.1.1 and Antigravity CLI
1.4.2 (1.4.5 for the run after prompt 09a; it updates itself). Everything else
is from the agent's documentation, with the URL and the page's date (or the
date it was read, where the page has none) under
[Sources](#sources). All five change quickly; check the version before
trusting a row.

## What the repository gives each agent

| File | Read by | What it holds |
|---|---|---|
| `AGENTS.md` | Claude Code (while no `CLAUDE.md` exists), Codex, Kimi Code and Antigravity, natively; Gemini CLI through the setting below | the method |
| `SKILL.md` | whichever agent follows a pointer below | frontmatter for discovery, and "read `AGENTS.md`" |
| `.claude/skills/dos-decompile/SKILL.md` | Claude Code | the same frontmatter, and "read `../../../SKILL.md`" |
| `.agents/skills/dos-decompile/SKILL.md` | Codex, Kimi Code, Antigravity, Gemini CLI (skills on) | the same |
| `.mcp.json` | Claude Code | the server |
| `.gemini/settings.json` | Gemini CLI | `context.fileName: "AGENTS.md"`, and the server |
| `.codex/config.toml` | Codex, in a trusted project only | the server, and `project_doc_max_bytes` |
| `.kimi-code/mcp.json` | Kimi Code, in a trusted folder only | the server |
| `.agents/mcp_config.json` | Antigravity CLI | the server |

Every server entry is `python mcp_server/server.py`, relative to the
repository root. There is deliberately no `CLAUDE.md` and no `GEMINI.md`:
either would be a second copy of the method, and a `CLAUDE.md` would also stop
Claude Code reading `AGENTS.md` at all. `tests/agents/regress.py` fails if one
appears, if a pointer skill's frontmatter differs from `SKILL.md`'s, or if the
server entries stop agreeing.

The skills are pointer files rather than symbolic links. A link checked into
git is a plain text file on a Windows clone unless symlinks are enabled for
it, and a skills mechanism that finds a text file where it expected a link
finds nothing. The frontmatter repeats `SKILL.md`'s because discovery reads
it; the test above keeps the three equal.

## The server does not depend on the agent's shell

No agent passes the server the variables `env.ps1` sets, and Codex passes it
only the ones its configuration names. So the server works them out itself
when it starts (`mcp_server/environment.py`):

- It reads `env.ps1` next to the repository for every variable the agent's
  environment does not already set. The agent's environment wins.
- If the `python` that started it cannot import `mcp`, capstone and unicorn,
  and `PYTHON` names another interpreter, it hands over to that one. On this
  machine `python` on `PATH` is Inkscape's bundled 3.12, which has none of
  them, so every agent's start went this way.
- If no interpreter will do, it exits 2 with a message naming the missing
  packages and where it looked for `PYTHON`.
- A missing `GHIDRA_HOME`, `JAVA_HOME` or `NASM` does not stop it: triage,
  survey, unpack and the rest still work. It says so on stderr and in its
  instructions, and `analyze` is refused naming the variable.

*Measured*, the line Claude Code and Gemini CLI both logged. Antigravity
started the server too, but its log does not show the server's stderr:

```
dos-decompiler MCP server: started by E:/Applications/Inkscape/bin/python.exe, which lacked the
packages and handed over to PYTHON; GHIDRA_HOME, NASM, PYTHON from E:/Projects/DOS-Decompiler/env.ps1
```

(`JAVA_HOME` was already set in this machine's environment, so it was not
taken from the file.) `tests/mcp/regress.py` covers all four cases: handed
over, the agent's environment winning, no interpreter at all, and no Ghidra.

## The smoke test

Each agent was given the same task, from the repository root, headless:

> Using the dos-decompiler tools, triage `tests/com/fixtures/mzsingle.exe` and
> tell me the verdict and the evidence id behind it. Do not modify any file.

The answer, from `python tools/triage.py tests/com/fixtures/mzsingle.exe
--evidence -`: in scope, confidence low ("probably workable, with caveats
above"). The finding that lowers the confidence is `prologue-density`,
`ev-88bbb9bf-1a9ce1e6`. The memory-model and data-siblings warnings do not
change the verdict. When these runs were made the envelope did not say which
finding set the verdict, so an agent had to read `triage.py` to know, and only
Claude Code did. Since prompt 09a it does: `result.verdict_evidence`
(`17-evidence.md`).

| Agent | Found `AGENTS.md` | Called the MCP tool | Verdict | Evidence id given | Wall time |
|---|---|---|---|---|---|
| Claude Code 2.1.281 | yes, whole | yes, `triage` | right | `1a9ce1e6`, and why | 54.2 s |
| Gemini CLI 0.58.0 | yes, whole | no: refused at login | none | none | 10.6 s, 4.4 s |
| Antigravity CLI 1.4.2 | first 24,000 bytes | yes, `triage`, on the second run | right | all seven, unranked | 25.7 s, 31.1 s |
| Codex CLI 0.154.0 | first 32 KiB; whole when raised | no: the CLI through the shell | right | `896e9737`, `6ee41bc1`, `6ee41bc1` | 42.2, 23.0, 27.8 s |
| Kimi Code CLI 2.1.1 | yes, whole | no: the CLI through the shell | right | three warnings; all seven | 26.4 s, 11.8 s |

No run changed a tracked or untracked file: after each run, `git status` was
the same as before it.

**After 09a**, with `AGENTS.md` at 22,322 bytes and `verdict_evidence` in the
envelope, two rows were run again the same way:

| Agent | Command | Found `AGENTS.md` | Called the MCP tool | Evidence id given | Wall time |
|---|---|---|---|---|---|
| Antigravity CLI 1.4.5 | `agy --output-format stream-json --dangerously-skip-permissions -p "<task>"`, the grant of the first table's second run | whole: no truncation | yes, `triage` | `1a9ce1e6`, read from `verdict_evidence.confidence`, with `in_scope` `[]` | 35.9 s |
| Codex CLI 0.154.0 | `codex exec --json -s read-only "<task>"`, no `-c` | whole, at the default 32 KiB | no: the project is untrusted, so the CLI through the shell | `1a9ce1e6` | 24.4 s |

The verdict was right in both. Each gave the id that set the confidence, where
in the first runs Antigravity listed all seven and Codex a wrong one three
times.

## Claude Code

**Instructions.** Reads `AGENTS.md` when the project has no `CLAUDE.md`,
`.claude/CLAUDE.md` or `CLAUDE.local.md`. *Measured*, from `--debug-file`:
`[agents-md] no CLAUDE.md found; AGENTS.md loaded`. The whole file.

**MCP.** `.mcp.json` at the project root. *Measured*: under `-p` the project
server loaded without asking (`"status": "connected", "source": "project"`),
all 19 tools as `mcp__dos-decompiler__<tool>`. The tools are deferred: it
loaded `triage` with its own `ToolSearch` before calling it. Claude Code logs
everything the server writes to stderr at `[ERROR]` level in its debug log,
informational lines included. Its default maximum for one result is 25,000
tokens (`MAX_MCP_OUTPUT_TOKENS`). The server's pages stop at 64,000 bytes,
which is under it.

**Skills.** `.claude/skills/<name>/SKILL.md`. *Measured*: `dos-decompile` in
the session's skill list.

**Run:**

```
claude -p "<task>" --output-format stream-json --verbose --allowedTools "mcp__dos-decompiler"
```

`--allowedTools` lets the server's tools run without a prompt nobody is there
to answer. Nothing else was granted; it read `tools/triage.py` with its own
read-only tools.

## Gemini CLI

**Instructions.** Reads `GEMINI.md` by default. The project setting
`context.fileName` names the file instead, so `.gemini/settings.json` sets it
to `AGENTS.md` and no second file exists. *Measured*: `[MemoryDiscovery]
Successfully read and processed imports: E:/Projects/DOS-Decompiler/AGENTS.md
(Length: 40514)`. The whole file.

**MCP.** `mcpServers` in `.gemini/settings.json`, which applies in a trusted
folder. This machine trusts `E:\Projects`, and the project settings applied
here. The timeout is set to 30 minutes, the server's own limit for one
`analyze` (`PIPELINE_TIMEOUT`); Gemini's default is 10. Tools are named
`mcp_dos-decompiler_<tool>`. Gemini cuts names at 63 characters. From
schemas it removes `$schema`, `additionalProperties`, and the `default` of an
`anyOf`. *Measured*: the server started, handed over, and connected.

**Skills.** `.gemini/skills/` or `.agents/skills/`, off until enabled.

**Run:**

```
gemini -p "<task>" --output-format stream-json --allowed-mcp-server-names dos-decompiler --allowed-tools mcp_dos-decompiler_triage
```

**Result: refused at sign-in, twice.**

```
Error authenticating: IneligibleTierError: This client is no longer supported for Gemini Code
Assist for individuals. To continue using Gemini, please migrate to the Antigravity suite of
products: https://antigravity.google
```

This is the account, not the toolkit. Google ended Gemini CLI for personal
Google sign-ins in 2026, and this error has appeared since September. The
same sources say a paid Gemini API key, or a Code Assist Standard or
Enterprise licence, still works. That was not tested here: the machine signs
in with `oauth-personal` and has no key. Everything up to the model call
worked: the instructions loaded, and the server started and connected.
`--allowed-tools` is deprecated in favour of the policy engine, but still
accepted.

## Antigravity CLI

Google's replacement for Gemini CLI (`agy`), which the error above names. It
is not one of the four, but it is the way left to run Gemini models here.

**Instructions.** Reads `AGENTS.md` (and `GEMINI.md`) natively, up to 24,000
bytes. *Measured* on 1.4.2: `Rule file E:\Projects\DOS-Decompiler\AGENTS.md
truncated by 16726 bytes (original 40684 bytes, limit 24000 bytes)`, which cut
the method inside Step 3. *Measured* on 1.4.5, after `AGENTS.md` went under
the limit (22,322 bytes): no truncation line, and the first model call's input
fell from 14,178 tokens to 13,828, about what the 1,678 bytes fewer would
account for. The log has no line for a rule file loaded whole; the missing
warning and the token count are the evidence.

**MCP.** `.agents/mcp_config.json` in the workspace, `~/.gemini/config/mcp_config.json`
globally; the workspace file wins. *Measured*: loaded with no trust prompt.
`agy mcp list` shows only the global file ("No MCP servers configured")
even while the workspace one is in use. The agent calls every MCP tool through
one tool of its own, `call_mcp_tool(ServerName, ToolName, Arguments)`. It
caches each tool's schema under `~/.gemini/antigravity-cli/mcp/dos-decompiler/`
and reads it before calling. A long result is saved to a file under its
`brain` folder and read back from there.

**Skills.** `.agents/skills/`.

**Permissions.** Headless, an MCP call is soft-denied. *Measured*: `a tool
required the "mcp" permission that headless mode cannot prompt for, so it was
auto-denied`. The agent then stopped and answered nothing, as the denial told
it to. The scoped grant is an allow rule, `mcp(dos-decompiler/*)`, under
`permissions.allow` in its user-level `settings.json`; it was not set here.
The other way is `--dangerously-skip-permissions`, which grants everything,
writes included.

**Run** (the second; the first was the same without the flag):

```
agy --output-format stream-json --dangerously-skip-permissions -p "<task>"
```

The model was this machine's setting, Gemini 3.8 Flash (Medium).

## Codex CLI

**Instructions.** Reads `AGENTS.md` natively, but only the first
`project_doc_max_bytes` of it, 32 KiB by default. *Measured*, in the session
log: the 40,684-byte file stopped inside Step 5. Run with
`-c project_doc_max_bytes=65536`, it ended with the references. The same key
is in `.codex/config.toml`, and takes effect once that file is read. Since
prompt 09a `AGENTS.md` fits the default: *measured* with no `-c`, the whole
file was in the session log's instructions.

**MCP.** `[mcp_servers.<name>]` in `.codex/config.toml`, read only in a
project the user has trusted. Trust is kept in the user's
`~/.codex/config.toml`, and this repository is not in it. Codex passes a
server only the variables listed in `env_vars`. The file lists `PATH`,
`PATHEXT`, `SYSTEMROOT`, `LOCALAPPDATA`, `USERPROFILE`, `TEMP` and `TMP`; the
server finds the rest in `env.ps1`. Its start timeout is 60 s, against a
default of 10; its tool timeout is 30 minutes, against 60 s.

*Measured*: `codex mcp list` in this repository shows no `dos-decompiler`.
Trusting the project for one run with
`-c "projects.'e:\projects\dos-decompiler'.trust_level=\"trusted\""` did not
change that. Defining the server with `-c mcp_servers.dos-decompiler.…` did:
it was then listed as enabled. Started as Codex starts it, with only those
seven variables, the server listed 19 tools and answered `triage` correctly.

**Skills.** `.agents/skills/`. *Measured*: every run opened the pointer
skill, then `SKILL.md`.

**Runs:**

```
codex exec --json -s read-only "<task>"
codex exec --json -s read-only -c "projects.'e:\projects\dos-decompiler'.trust_level=\"trusted\"" "<task>"
codex exec --json -s read-only -c project_doc_max_bytes=65536 -c 'mcp_servers.dos-decompiler.command="python"' \
    -c 'mcp_servers.dos-decompiler.args=["mcp_server/server.py"]' -c 'mcp_servers.dos-decompiler.env_vars=[...]' \
    -c mcp_servers.dos-decompiler.startup_timeout_sec=60 -c mcp_servers.dos-decompiler.tool_timeout_sec=1800 "<task>"
```

**Result.** All three ran `python tools/triage.py tests/com/fixtures/mzsingle.exe
--evidence -` through PowerShell, in the read-only sandbox, and reported the
right verdict. None called the MCP tool, the third included, where the server
was configured and enabled. Codex's session log does not record the tools the
model was offered, so whether it saw them is unknown. None of the evidence
ids it gave is the one that lowers the confidence. The model was
`gpt-5.6-luna`.

## Kimi Code CLI

**Instructions.** Reads `AGENTS.md` natively. *Measured*: the session log
holds the method's last section, so the whole file.

**MCP.** `.kimi-code/mcp.json`, used only in a trusted folder. Trust is
recorded per folder under `~/.kimi-code/workspace-trust/`. A trusted
`E:\Projects` does not cover `E:\Projects\DOS-Decompiler`, which has no
record. *Measured*:

```
Warning: this folder is not trusted; skipped 1 project-level MCP server: dos-decompiler
(stdio: python mcp_server/server.py).
  Run `kimi` here and choose "Trust this folder" to enable them.
```

The documentation gives `KIMI_CODE_TRUST_WORKSPACE=1` as the way to trust a
folder for one headless run, without recording it. On 2.1.1 it did nothing:
the same warning, and no trust record written. A third-party report says the
variable arrived in 2.2.0. Tools are named `mcp__dos-decompiler__<tool>`.

**Skills.** `.kimi-code/skills/` or `.agents/skills/`; the frontmatter needs
both `name` and `description`.

**Runs:**

```
kimi -p "<task>" --output-format stream-json
KIMI_CODE_TRUST_WORKSPACE=1 kimi -p "<task>" --output-format stream-json
```

**Result.** Both ran the CLI through its shell tool and reported the right
verdict. The first gave the three warnings, the right one among them; the
second gave all seven. The model was `kimi-for-coding-highspeed`. In `-p`
mode Kimi copies a shell tool's output to stderr.

## How much of `AGENTS.md` each agent reads

| Agent | Reads |
|---|---|
| Claude Code | all of it |
| Gemini CLI | all of it |
| Kimi Code | all of it |
| Codex | 32 KiB by default; `project_doc_max_bytes` raises it |
| Antigravity CLI | 24,000 bytes |

When the agents were first run, `AGENTS.md` was 40,684 bytes, and Codex cut
it inside Step 5 and Antigravity inside Step 3. Since prompt 09a it is kept
under the smallest limit: 22,322 bytes as checked out on Windows, 21,887 with
Unix line endings. The rules stay in it; the measurements and cases behind
them moved to the `knowledge/` file each step names. `tests/agents` fails if
it grows past 24,000 bytes in either form.

*Measured* again on 2026-10-23, with the same task and wrapper as the first
runs ("After 09a" under the smoke test): Antigravity CLI 1.4.5 logged no truncation, and
Codex at its default limit, with no `-c` and the project untrusted (so
`.codex/config.toml` unread), had all of `AGENTS.md` in its instructions.
`project_doc_max_bytes = 65536` stays in `.codex/config.toml`: it costs
nothing and covers growth.

The sentence near the top of `AGENTS.md` still tells an agent that loaded only
part to read the rest with its own file tool, for an agent with a smaller
limit than any measured here.

## Tool names and schemas against each agent's limits

Checked against the 19 tools the server lists (no tool changed in this pass):

| | Value | Limit found |
|---|---|---|
| Longest tool name | `verify_load_image`, 17 characters | — |
| Longest qualified name | `mcp__dos-decompiler__verify_load_image`, 38 | Gemini 63; the others document none on the pages read |
| Characters | `[a-z_]` in tool names, `dos-decompiler` for the server | Gemini `[A-Za-z0-9_.:-]`; Claude Code replaces anything outside `[A-Za-z0-9_-]` |
| Schema keywords | `type`, `properties`, `required`, `title`, `default`, `anyOf` (optional values), `items`, `additionalProperties` (the dict arguments of `apply_names` and `sweep`) | Gemini removes `$schema`, `additionalProperties` and an `anyOf`'s `default`, and keeps the rest |
| Longest description | `sweep`, 376 characters | none documented |
| Largest result | one page, at most 64,000 bytes | Claude Code 25,000 tokens by default |

Nothing is over a documented limit, so nothing was renamed. `apply_names`
takes `items` as an array of any JSON values (`"items": {}`). Gemini drops
`additionalProperties`, so its model sees the dict arguments of `apply_names`
and `sweep` as untyped objects. It also drops the `null` default of every
optional argument, which changes nothing, since leaving an argument out means
the same. Measured: Claude Code and Antigravity called
`triage`, and Gemini CLI registered the server without a schema warning. No
run exercised `apply_names` or `sweep`.

## What the repository cannot do for you

These are user-level, so nothing here ran them. Each is the user's step:

- **Codex: trust the project**, so `.codex/config.toml` (the server and the
  larger instruction limit) is read. Either start `codex` in the repository
  once and accept its prompt, or add to `~/.codex/config.toml`:

  ```toml
  [projects.'e:\projects\dos-decompiler']
  trust_level = "trusted"
  ```

- **Kimi Code: trust the folder**, so `.kimi-code/mcp.json` is read: run `kimi`
  in the repository and choose "Trust this folder". That writes a record under
  `~/.kimi-code/workspace-trust/`. On 2.2.0 or later,
  `KIMI_CODE_TRUST_WORKSPACE=1` should do it for one run, according to the
  documentation.
- **Gemini CLI: sign in with something it still accepts**, a paid Gemini API
  key (`$env:GEMINI_API_KEY`) or a Code Assist Standard or Enterprise
  licence. Or use Antigravity CLI instead.
- **Antigravity CLI: grant the server, not everything**, with
  `"permissions": {"allow": ["mcp(dos-decompiler/*)"]}` in
  `~/.gemini/antigravity-cli/settings.json` (from a third-party guide; not
  tried here). Or answer the prompt interactively.
- **Claude Code** needs nothing.

## Working from a separate folder

The project files apply only where the agent starts. Started in a game's own
work folder (the arrangement in the README), an agent finds the method through
that folder's `AGENTS.md`, but not the server. Either start the agent in this
repository instead (the server takes absolute paths, so the game can live
anywhere), or register the server for that folder or for the user. For
example, for Claude Code: `claude mcp add dos-decompiler --scope user --
python C:\Projects\DOS-Decompiler\mcp_server\server.py`. Nothing else is
needed: the server finds `env.ps1` beside itself whatever folder it is started
from.

## Sources

Read on 2026-10-23 unless a page date is given.

- Claude Code, `AGENTS.md` and memory: <https://code.claude.com/docs/en/memory>.
  MCP and `.mcp.json`: <https://code.claude.com/docs/en/mcp>. Skills:
  <https://code.claude.com/docs/en/skills>.
- Gemini CLI, `context.fileName`: <https://geminicli.com/docs/cli/gemini-md/>
  (2026-06-18). MCP servers, naming and schema sanitisation:
  <https://geminicli.com/docs/tools/mcp-server/> (2026-10-06). Skills:
  <https://geminicli.com/docs/cli/skills/> (2026-04-30).
- Gemini CLI, the sign-in error: <https://github.com/google-gemini/gemini-cli/issues/28229>;
  <https://www.aibuilderclub.com/blog/google-kills-gemini-cli-june-18-2026>.
- Antigravity CLI, MCP: <https://antigravity.google/docs/mcp>;
  <https://atamel.dev/posts/2026/07-10_where_agy_mcp_servers/> (2026-07-10).
  Instructions, skills and print-mode permissions:
  <https://www.aibuilderclub.com/blog/antigravity-cli-guide> (2026-06-21,
  updated 2026-08-24); <https://computingforgeeks.com/antigravity-cli-cheat-sheet/>
  (updated 2026-10-08).
- Codex, `AGENTS.md` and `project_doc_max_bytes`:
  <https://learn.chatgpt.com/docs/agent-configuration/agents-md>. MCP,
  project configuration and trust, `env_vars`:
  <https://learn.chatgpt.com/docs/extend/mcp?surface=cli>.
- Kimi Code, MCP, trust and `KIMI_CODE_TRUST_WORKSPACE`:
  <https://moonshotai.github.io/kimi-code/en/customization/mcp.html>. The
  version that added the variable: <https://github.com/briandconnelly/amicus/issues/354>.
