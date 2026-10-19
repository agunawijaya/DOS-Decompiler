# Prior art, and where this package sits

This was built before checking what already existed. That was a mistake, and
the honest result is that one project overlaps substantially. Read this before
starting work — some of it you should use instead of reimplementing.

## mzretools — the closest thing to this package

<https://github.com/neuviemeporte/mzretools>

Same target exactly: MS-DOS MZ executables containing 8086 opcodes. The
overlap with this package is large:

| mzretools | here | what it does |
|---|---|---|
| `mzhdr` | `mzinfo.py` | MZ header, relocations, load module layout |
| `mzmap` | `RecoverFunctions.java` | scans code to find subroutine boundaries |
| `mzsig` | `libsig.py` | routine signatures with addresses and immediates stripped |
| `mzdup` | `match.py` | finds duplicate routines by edit distance on signatures |
| `mzdiff` | **nothing here** | instruction-level comparison of two executables, tolerating layout differences |

**Its goal is more rigorous than this package's, and it is the right answer to
"can I get source that matches the original".** The method is not to decompile
and hope: it is *iterative reconstruction*. Write source, compile it, run
`mzdiff` against the original, fix what differs, repeat until the comparison
is clean. The author used it to reconstruct a commercial game to
instruction-level identity.

If your goal is a faithful reconstruction rather than a readable one, use
mzretools. If you build on this package instead, `mzdiff` is the piece you
will miss most.

Difference in emphasis worth noting: mzsig strips addresses and immediates to
detect duplicates *within and between the executables you are studying*. This
package's `libsig.py` builds signatures from the actual period C libraries, so
it identifies library code by name rather than merely clustering it. The two
approaches answer different questions.

## dis86 — a better decompiler core, narrower scope

<https://github.com/xorvoid/dis86>

A real decompiler for 16-bit real-mode DOS: disassembly to SSA IR, IR
optimisation, control-flow synthesis, then C. It deliberately prefers manual
annotation tables over heuristics, on the grounds that a wrong guess produces
broken code.

Its limits are stated plainly by its authors: it takes flat binary regions
rather than MZ files, many 8086 opcodes are unimplemented, control-flow
synthesis handles only while/if/switch, and the output is not meant to be
recompilable.

Where it beats Ghidra it is on semantic care within its supported subset.
Where this package uses Ghidra, it gets full opcode coverage and MZ loading
for free. Reasonable to reach for dis86 on a specific function whose Ghidra
output looks wrong.

## Spice86 — a different axis entirely

<https://github.com/OpenRakis/Spice86>

Dynamic rather than static. It emulates the DOS program, builds a control-flow
graph from what actually executes, generates a runnable C# project from that
graph, and then you replace the mechanical translation function by function —
keeping a working program at every step.

That workflow solves a problem static analysis cannot: code reached only at
run time is *found*, not inferred. Recall the measurement in
`03-what-works.md` — 48 of Sopwith's functions were invisible to Ghidra
because they are only reached through function pointers. Spice86 would have
executed them.

`emuverify.py` here is a narrow slice of the same idea: it runs candidate
functions to decide equivalence. Spice86 does the general version.

If a game resists static analysis, or you want a working port rather than a
readable listing, start there instead.

## rea — an MCP server in front of Ghidra, for the same binaries

<https://github.com/morluto/rea> — "REA: Reverse Engineer Anything". MIT
licensed (its own code; third-party material keeps its licences).

An MCP server and command line, distributed on npm as `rea-agents`, that
connects an agent to analysis tools for native binaries, JavaScript and
Electron apps, .NET assemblies, websites and a long list of other targets.
Native analysis goes through a Hopper, Ghidra or IDA installation the user
supplies. Read on 2026-10-19: its README and `docs/ghidra-dos.md`.

**Where it overlaps.** Its Ghidra adapter analyses DOS MZ executables, and
`.COM` images when the caller selects that interpretation explicitly. It
imports MZ with `MzLoader`, language `x86:LE:16:Real Mode`, compiler spec
`default`, at load segment `0x1000` — the values measured independently here
on Ghidra 12.1.2 (`17-evidence.md`). A `.COM` goes through `BinaryLoader` with
file offset zero at `1000:0100`. Two of its showcases are DOS-era: a DX-Ball
sound-pan routine reconstructed in C that "passes 3,205 original-x86 cases and
reproduces all 63 compiled function bytes", and a bullet-ring calculation from
the PC-98 game TH04.

One convention differs, and it matters when moving addresses between the two:
rea returns **linear** addresses (`0x10000`), and this toolkit's
`functions.json` writes **segment:offset** (`1000:0000`). Same byte.

**Where it stops**, in its own words or by absence from its DOS guide:

- No emulation. "Static decompilation does not execute the target or emulate
  BIOS, DOS interrupts, device ports, or self-modifying code."
- No unpacking. A packed file is analysed as its stub; "analyze a separately
  prepared unpacked copy".
- No function recovery beyond Ghidra's. A function's body is Ghidra's address
  set, "not a proof of original source ownership or exhaustive code
  discovery" — the gap `RecoverFunctions.java` exists for.
- No C runtime signatures; nothing in its DOS documentation identifies library
  code.

**What this series borrows**, as ideas, with no code taken:

- every result carrying its evidence, its limitations and what remains unknown
  (`17-evidence.md`);
- the analysis settings written down as a profile, with a handshake that
  refuses results produced under different ones;
- results tied to the target's size and SHA-256, so a stale one cannot pass
  for a current one;
- checking the loaded image against the file instead of trusting the import;
- a function's extent as inclusive address ranges rather than one size;
- annotation that reads back what it wrote and rolls back if that fails;
- exhaustive comparison of a reconstruction against the original binary's own
  behaviour, the DX-Ball way;
- one MCP server in front of the tools.

The division of labour that falls out: rea is a general, careful front end to
a decompiler; this toolkit is narrow and goes further on the one platform,
because the hard parts of 1980s DOS are upstream and downstream of Ghidra.

## unDRC — not related

<https://github.com/Utodev/unDRC>

Decompiles DAAD text-adventure bytecode (DDB files) back to DSF source. A
different domain: interpreted bytecode for a specific authoring system, not
native 8086 code. Nothing transfers.

Its README does state the general truth about decompilation plainly, and it is
worth repeating here: "you will not get exactly the same code, but one that
will most likely generate the same game."

## What this package still contributes

Being honest about the overlap does not mean there is nothing here:

- **Signature databases built from the actual period compilers** — Microsoft C
  5.0, 5.1 and Open Watcom. Identifying library code *by name*, validated
  held-out at precision 1.000.
- **Behavioural equivalence by emulation** with a measured zero error rate,
  including functions that never return.
- **Measured accuracy with a regression harness.** Every figure quoted comes
  from a linker map used as an answer key, and `regress.py` fails if a change
  makes things worse. Most reverse-engineering tooling is evaluated by
  impression; this is not.
- **The infrastructure to run period toolchains** — `fatextract.py` for raw
  floppy images, `dosrun.ps1` for headless DOSBox-X — which is what made
  building against Microsoft C 5.0 possible at all.

## What to take from the others

1. **Adopt `mzdiff`'s question.** "Does my reconstruction compile to the same
   instructions?" is checkable in a way that "does this look right?" is not.
   This package has no equivalent, and it is the biggest gap.
2. **Dynamic exploration finds what static analysis cannot.** The 48 missing
   functions were recovered here by scanning immediates — a heuristic that
   worked, but running the game would have been evidence.
3. **State limits plainly.** dis86 and unDRC both do, and it makes them easier
   to trust.
