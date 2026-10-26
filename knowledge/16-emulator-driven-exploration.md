# 16 — Emulator-driven exploration: bugs and patterns

Session 10 of Transylvania (in the sibling `retro-ports-2` repo,
2026-08-21) established that a scripted 8086 emulator plays the
game and captures its text output for essentially free once the
right memory-write hook is in place — see
[15-adventure-engine-shape.md](15-adventure-engine-shape.md)
§"Extracting a room map without decompiling the byte-code". This
document is the follow-on: what session 11 (2026-08-22) learned
when the exploration was **extended from simple BFS to
puzzle-aware BFS**, and the bugs that pattern produced.

## The pattern that hangs

A BFS explorer that only walks the map is well-behaved: it sends
one direction, records the response, moves on. But a
*puzzle-aware* explorer needs more: pick up items in each room,
retry deadly edges with defensive items, replay paths from a
fresh start when the current state diverges. Each of those adds
a restart, and each restart re-instantiates the emulator from
scratch.

Session 11's v1 puzzle explorer hung for over an hour with 0
bytes of output. The root cause was three bugs stacked on top of
each other, each individually survivable, together fatal.

### Bug 1: restart-heavy design multiplies cost linearly

Every restart in the v1 explorer did:

- Allocate a fresh 1 MB Unicorn memory map.
- Load the MZ image (~100 KB).
- Apply relocations.
- Run 30 M instructions of engine startup.
- Send name-entry keys and run another 60 M.
- Send `LOOK` and run another 30 M.

That is roughly 120 M emulated instructions per restart, plus the
memory-allocation overhead. Unicorn on modern hardware executes
about **1 M instructions per second when hooks are installed**
(the per-instruction hook adds a Python callback), so one restart
takes **~2 minutes**.

The v1 loop did *"for each of the 3 deadly edges, restart and try
each of 6 defence actions with a restart between each retry"* —
approximately 3 × 6 × restart-count nested restarts. Two hours of
restarts before hitting any progress.

**The fix**: cap total restarts (`MAX_RESTARTS = 12`), raise an
exception when exceeded, catch it at the outermost driver and
report a partial result. A partial result terminates; a hang
does not. The bound is more valuable than the exhaustiveness.

### Bug 2: silent progress hides the linear cost

The v1 code used `print(...)` without `flush=True`. On Windows,
Python's stdout is line-buffered when a terminal is attached but
fully-buffered when redirected — and the `Bash tool` redirects.
So the log file stayed empty until the process either finished or
crashed. From the user's perspective, silent stdout for an hour
is indistinguishable from a hang.

**The fix**: `print(..., flush=True)` on every branch. Explicit
flush on every message. This is worth doing even when the process
is fast, because *"how do I know the exploration is progressing"*
is a question the user will eventually ask.

### Bug 3: the "give up" set was the same as the "known bad" set

The v1 retry loop marked an edge as *"tried all defences, still
deadly"* by adding it to the same `deadly_edges` set that the
outer loop scanned for candidates. Adding a member to a set that
already contains it is a no-op. The next iteration of the outer
loop scanned the same set, picked the same edge, and retried
forever.

**The fix**: two sets. `deadly_edges` records *observations* —
directions that killed the player. `retried_deadly` records
*decisions* — edges we have exhausted our defence options on.
Candidate selection is `deadly_edges - retried_deadly - overcome_edges`.

Generalising: **any exploration algorithm that has both an
observation set and a decision-history needs them to be
different collections**. Reusing one for both is the same class
of bug as reusing a variable to mean two things.

## The exact fix, as a diff of concepts

|  | v1 (hangs) | v2 (terminates) |
|---|---|---|
| Restart budget | unbounded | `MAX_RESTARTS = 12`, raises on excess |
| Retry-tracking | `deadly_edges` (double-use) | `retried_deadly` (separate set) |
| Defence per edge | 6 (one restart between each) | try each in sequence, one restart total |
| Progress visibility | `print(...)` | `print(..., flush=True)` |
| Death recovery | nested restart inside `try_direction` | flag-and-continue; retry logic at loop level |
| Top-level driver | `explore()` returns normally | `try: explore() except RuntimeError` |

Session 11's v2 explorer took **50 minutes wall-clock** to
complete (13 restarts × ~2 minutes plus 100 emulator command
sends). v1 was still hanging at 60 minutes with no meaningful
progress.

## What auto-pickup teaches

The v2 explorer detected items in room descriptions correctly
(regex against *"A garlic clove lies"* etc.) but failed to
register that any pickup had **succeeded** — final inventory was
empty. Root cause: the success-detection strings (`taken`, `ok`,
`you have`) do not match Transylvania's actual response
phrasing.

**The lesson**: response-string classification is engine-specific
and fragile. Different Comprehend games in the same family may
phrase success and failure differently, and there is no
convention across period adventure engines. Sierra AGI, Infocom
Z-machine, Magnetic Scrolls, Legend, and Polarware all use
different response templates.

**The reliable test**: after every `TAKE`, send `INVENTORY` and
diff the returned list. This is engine-independent — every
adventure game supports some form of inventory query. Cost: one
extra emulator command send per pickup attempt, negligible.

## Directional exhaustiveness

The v2 explorer tested all six directions (N, S, E, W, U, D)
from every room and discovered two additional deadly edges (R5 →
D and R9 → U) that a four-direction BFS would have missed. Both
came out to be terrain-appropriate deaths (falling into an open
grave in the cemetery; falling from the top of the castle) that
matched player expectation.

**The lesson**: an adventure game's rooms may accept vertical
movement even when the description doesn't mention it, and the
game's designer will absolutely have put death traps at the
"try up in the castle" and "try down in the cemetery" positions
because those are the natural mistakes to make. **Always try all
six**; you learn something either way (a new room, a new
deadly-edge, or a *"you can't go that direction"* to confirm the
graph shape).

## The mini-port method

Once the BFS map, item catalogue, and puzzle catalogue are in
hand, one puzzle can be extracted into a **standalone teaching
mini-port** at very low cost. Session 11 built one at
`transylvania/web/index.html` in about 300 lines of
self-contained JavaScript — no build step, works offline.

The technique:

1. **Pick the shortest puzzle** — one room with an item, one
   room with an obstacle, one verb that combines them. For
   Transylvania this was the werewolf/garlic puzzle (rooms R9 and
   R14, item "garlic clove", verb "SHOW GARLIC TO WEREWOLF").
2. **Rebuild it structurally**, not textually. Use your own
   prose, your own room count, your own verb list. The point is
   the technique, not the reproduction. This is also what keeps
   the mini-port on the right side of copyright.
3. **Implement the four-step pattern** — tokenise, rule-table
   match, guarded transition, state mutation — as four numbered
   blocks in the code, so a reader can see the technique.
4. **Add a `selfTest()` on `window`** that scripts the happy
   path and prints PASS/FAIL for each expected state.

**What this deliverable teaches** (which the decompilation
documents alone do not): the reader can *play* the puzzle, then
*read the source*, and see how the running code implements what
they just experienced. The gap between "puzzle catalogue" and
"understanding how a puzzle is programmed" closes in a few
minutes rather than a few sessions.

**What this does not deliver**: any actual understanding of the
target game's byte-code. The mini-port is JavaScript from
scratch; it shares nothing with Comprehend's compiled interpreter
except the design pattern. That is intentional. The port is a
teaching artefact, not a decompilation output.

## The overall shape

Between session 10 and session 11, the two documents that emerged
were:

- **Session 10 →** a working emulator + BFS + a room map. That is
  what unlocks the engine's actual world without touching the
  byte-code.
- **Session 11 →** a puzzle catalogue + a mini-port. That is what
  turns the world into teaching material.

Both are cheap given the toolkit that produces them. Neither
required naming individual opcodes. **The path from "no code
runs" to "everything is playable and documented and teachable"
does not go through the interpreter's implementation** — it goes
around it, using emulation as a stand-in for understanding.

This is the important claim of this document. For a 1980s
adventure engine, you do not need to fully decompile the
interpreter to produce a useful port and a useful set of teaching
material. You need to run it, hook its output, script its input,
and *record what happens* faithfully. The playing-the-game step
gets you 80% of what the full opcode-naming pass would, at 5% of
the cost.

## Concrete additions worth building into the toolkit

- **A BFS-explorer template.** The v2 explorer at
  `retro-ports-2/transylvania/reference/puzzle_explorer_v2.py`
  is 300 lines and about 200 of them are engine-agnostic
  (`Emu` class, `send`, direction loop, restart cap, deadly-edge
  tracking, path replay). Extracting those 200 lines as a
  template with per-game hook points would drop the emulator
  time on the next game from 6 hours to 2.
- **An inventory-diff pickup helper.** Wrap `TAKE X` with a
  before/after `INVENTORY` diff and return the delta. Universal
  across adventure engines.
- **A restart-budget monitor.** Not just the cap itself, but a
  print of restart count every N iterations so hung-looking
  progress is clearly visible.
- **A stopped-reason chain.** In Unicorn-based explorers,
  distinguishing "game exited cleanly", "keyboard queue empty
  and blocked read", "instruction budget hit", and "invalid
  address" is worth doing at the driver level. v2 tracks
  `stopped_reason` but doesn't use it uniformly.

Each is a small piece of scaffolding that would make the *next*
Comprehend game — or any other 1980s adventure — cheaper to
open up.

## When a run stops, it may be the machine the program asked about

Four games stopped short in comrun before prompt 16, and in none of them was
the emulator's budget or the explorer's loop the reason. Each was a question
the program put to the machine, answered wrongly
([12-hooking-the-right-thing.md](12-hooking-the-right-thing.md) has the
detail):

- **"Which adapter is this?"** The Ancient Art of War asks four ways and quits
  without an EGA, VGA or Tandy. `--adapter ega` or `tandy` answers, and draws
  mode 0Dh or 9. Read how the program asks before choosing what to answer:
  Rampage asks nothing, and its menu chooses.
- **"Is there a key?" -- by which path.** A key queued blind goes to whatever
  reads first, and a start-up flush reads first. `--at ADDR=KEY` gives it at
  the wait itself, through the BIOS's buffer or the program's own INT 09h as
  the program reads at that moment, in any `--keyboard` mode, and the run says
  which path each key took. The Dam Busters' title flushes the buffer, then
  takes any key.
- **"Which processor?"** `lock nop` is a delay on an 8088 and an invalid
  opcode to Unicorn; a divide error goes to the program's own handler and
  returns past the divide. `--cpu 8088`, the default, models both.
- **"How fast, and where is the beam?"** A program that latches the 8253 or
  sets the light pen latch reads back the machine's state, which an
  alternating port answer cannot be; both are modelled now, on the clock the
  timer already uses.

A run that ends early with a message the program printed, or in a loop over
a port, is a question unanswered before it is a budget too small.

## The rule

> **Bound every exploration loop, flush every progress print, and
> use different collections for observations vs. decisions.**

Any of the three fixed alone would have prevented the v1 hang.
All three together turn a fragile explorer into a repeatable
tool.
