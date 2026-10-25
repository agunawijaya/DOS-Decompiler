# Working on a DOS binary with this toolkit

Instructions for any coding agent — or any person — driving `DOS-Decompiler`.
This file is the method for every agent, Claude Code, Gemini CLI, Codex, Kimi
Code, Antigravity CLI or any other, and the only copy of it, and the prompts
and reports in `prompts/` follow `prompts/00-README.md` whichever agent runs
them. It is kept under 24,000 bytes, the smallest instruction limit measured
(Antigravity CLI's), so that every agent loads it whole; if yours loaded only
part of it, read the file whole before starting. `SKILL.md` and the per-agent
files are pointers here (`knowledge/19-agents.md`). This file holds the rules;
the measurements and cases behind them are in the `knowledge/` file each step
names.

The tools do what must be done by code: parsing headers, emulating 8086,
computing signatures, diffing instruction streams. This file covers the other
half — deciding what the evidence means, and refusing to claim more than it
supports. Every number quoted was measured on **one** program, Sopwith (1984),
whose source survives and is the fixture in `tests/sopwith/`: MZ, C, small
model, unpacked, not overlaid. Outside that shape the figures do not apply,
and some tools mislead rather than fail.

## Running the tools

- `tools/*.py` run on Python 3 and take `--help`; `tools/*.ps1` need
  PowerShell 7+. Copy `env.example.ps1` to `env.ps1` and source it: tool
  locations come from its variables, and every script stops with a clear
  message when one is missing. Set `PYTHON` to the interpreter with capstone
  and unicorn; `pipeline.ps1` and `tests/run-all.ps1` prefer it to whatever
  `python` is first on PATH.
- **When the `dos-decompiler` MCP server is available, prefer its tools**
  (`triage`, `open_binary`, `analyze`, `list_functions`, `function`,
  `coverage`, `anchors`, `apply_names`, `sweep` and the rest). They call the
  same functions as the command line, which is the fallback, and return each
  result as an evidence envelope, a page at a time. The server works on a copy
  of the target and never writes beside the original; `apply_names` is a dry
  run unless asked to write with `confirm`. It reads `env.ps1` itself and says
  at start what it could not find (`knowledge/19-agents.md`).

## What to tell the user before starting

Be explicit about what this can and cannot produce.

| Goal | Realistic? |
|---|---|
| Readable C with recovered control flow | Yes, essentially all functions |
| Meaningful names for functions and data | Partly automatic, mostly by reading |
| Separating C runtime code from game code | precision 1.00, recall 0.76–0.91 |
| Automatic identification against known source | precision 0.94, recall 0.72 |
| Carrying names between two builds of one program | precision 1.00, 110 of 202 |
| **Source resembling the original** | **No** — see below |
| Byte-identical recompilable source | Not from decompilation; see the extended workflow |
| Working, modifiable port | Yes, but that is a rewrite informed by the decompilation |

**Say the "source resembling the original" row out loud**, because everyone
assumes it the other way. The figures are about *identifying which function
is which*. The C has no variable names, no structs (an `OBJECTS *` arrives as
`undefined2 *` and raw offsets), no comments, no macros; hand-written assembly
does not decompile sensibly, and data tables never appear as code. Matching
source is the extended workflow (`knowledge/07-extended-reconstruction.md`).

---

## Step 0 — What were you actually given?

Handed a **folder**, start with `python tools/survey.py path/to/folder`. A
release is rarely one file, and a setup program decompiles as willingly as the
game. `survey.py` triages every executable, reads the batch files for the real
entry point, finds overlays and executables in subfolders, and says which one
looks like the game and why (`knowledge/00-scope.md`). Then triage that one.

## Step 0a — Is that program in scope?

```
python tools/triage.py GAME.EXE --evidence -
```

**Never skip this, and report its verdict before promising anything.** Read
the JSON, not the prose: each finding with the file offset it rests on, the
verdict in `result`, the ids of the findings that set it in
`result.verdict_evidence`, what the checks cannot see in `limitations`, and the
questions the file raised in `unknowns`. **Report the unknowns with the
verdict.** `survey.py` and `mzinfo.py` take the same flag
(`knowledge/17-evidence.md`).

Out of scope, or on another route (`knowledge/00-scope.md` has the matrix,
and which failures are loud and which silent):

- **Packed** (LZEXE, PKLITE, EXEPACK, DIET): run `tools/unpack.py` first.
- **Overlaid**: functions share addresses at different times. Microsoft LINK
  overlays: `tools/overlays.py --views`, one view per module for the pipeline;
  Borland's FBOV: nothing. **Protected-mode extenders**: another format.
- **`.COM` files**: a separate, stronger route (below); one with another name
  (`hunt.ptl`): `--format com` in triage, survey and comrec.
- **Interpreted engines** (Sierra SCI and AGI, SCUMM, DAAD): the executable is
  a virtual machine and the game is in the data files. Decompiling succeeds
  and tells you nothing you wanted. Triage checks for it.
- **Non-small memory models**: `emuverify.py` assumes `SS == DS` and one data
  group, and on a far-pointer program produces nonsense *without saying so*.

### If it is a .COM

```
python tools/comrec.py GAME.COM --out src/game.asm
nasm -f bin -o rebuilt.com src/game.asm     # then compare SHA-256 with the original
```

`comrec.py` rebuilds the file as NASM source and proves it by reassembling:
it prints `BYTE-IDENTICAL` or why not. **Confirm it yourself** with the second
line. Before reporting:

- **It is assembly, not C.** A program with no stack-frame prologues (triage
  reports their density) was written in assembly; say so.
- **Quote the code-region figure, not the whole-file one**: the file is mostly
  artwork and tables (`tests/com/CASE-STUDY.md`).
- An MZ's bytes past its load image are rebuilt as data, and `BYTE-IDENTICAL`
  is printed only after the whole file, header and all, was compared.
- **Look for a stub that reloads CS**, putting half the file on another base.
  comrec follows a far jump to CS + constant and reports a computed one
  ("leaves through a far jump ..."); read that line, and the stub's first
  bytes (`knowledge/08-com-reconstruction.md`).
- Under 10% decoded: run comrun with `--exec-map-json` and give the map to
  `comrec --seeds-from`; a seed that ran at another origin is refused, with
  the `--segment` that would agree.

`tools/comrun.py` runs the program and dumps the framebuffer, to check a
static reading against (its flags: `knowledge/12-hooking-the-right-thing.md`;
give `--timer-isr` an interrupt number, not an address). **The static render
is the deliverable and the emulator the referee.** If a screen resists being
photographed, check whether it can be computed from the file first. A game
with its own INT 09h handler needs `--keyboard hw`; its own INT 08h,
`--timer auto`; one that probes port 0x201 needs `--no-joystick`, or its
"button" is noise. A black screen after INT 10h AH=0Eh needs `--bios-text`.

`tools/comdiff.py KNOWN.COM known.asm GAME.COM game.asm` compares two .COM
programs routine by routine. Instruction-identical pairs are run under
emulation: quote `confirmed` or `differs`, not the instruction match alone.

### If it is packed

```
python tools/unpack.py GAME.EXE -o unpacked.exe
python tools/triage.py unpacked.exe
```

It runs the packer's own decompressor under emulation and dumps the result.
**Verify that it worked**: compare printable-string counts before and after. A
low density of stack frames in the dump is not failure; it usually means
assembly. Only EXEPACK states its entry point; for the others the dump's entry
is 0 on purpose, because a wrong one misleads everything after it
(`knowledge/00-scope.md`, Unpacking). EXEPACK's is an MZ that loads: quote
the layout it read from the stub and the agreement it prints.

If the program is C and you have the compiler's library, do this early:
`python tools/libscan.py unpacked.exe --lib <compiler>\LIB`. It finds the
entry point, the compiler, the runtime's extent and its names. **Pass the
directory, not the `.LIB`**: some toolchains keep the startup object beside
the archive. With the wrong library it reports nothing, so a match means
something. **Read which failure it reports:** "none of the modules loaded
declares a start address" is about what you passed; "X declares a start
address but did not match" is about the binary
(`tests/libscan/CASE-STUDY.md`). Without the library, find `main` with
`anchors.py`.

**Turbo Pascal**: `libscan.py` correctly finds nothing. `python tools/tpscan.py
unpacked.exe` reports the compiler, `DGROUP` (the code/data boundary) and the
units; with Borland's libraries (`--tpl`) it names the version, or refuses
when none wins clearly (`knowledge/02-compiler-fingerprints.md`).

---

## Step 0b — Ask which workflow the user wants

**Ask; do not assume.**

| | **Standard** | **Extended** |
|---|---|---|
| Deliverable | annotated pseudocode + architecture notes | source that rebuilds the binary |
| Verified by | reading it | `bindiff.py`, mechanically |
| Needs the period compiler | no | **yes** |
| Effort | hours to days | weeks, iterative |
| Ends when | you understand it | the diff is clean |

Steps 1–5 are the standard workflow; the extended one continues in
`knowledge/07-extended-reconstruction.md`. Say which rung the result sits on:

| Rung | Oracle | Proves |
|---|---|---|
| 1a | byte-identical **functions**, relocation slots wildcarded | each function's code — **not** which symbols it references |
| 1b | byte-identical **linked image** | the source is right |
| 2 | instruction-identical, layout-tolerant (`bindiff.py`) | the code is right |
| 3s | exhaustive sweep of one routine over a declared domain (`emuverify.py sweep`) | its outputs equal the candidate's on that domain, and nothing outside it |
| 3a | per-function behavioural equivalence (`emuverify.py`) | this function is that function |
| 3b | instruction-trace equivalence under identical input | the same control flow; a divergence localises to one instruction |
| 4 | pixel-identical frames under identical input | the program behaves the same |
| 5 | "looks right" | nothing |

**Do not report 1a as 1b**: with relocation slots wildcarded, a function that
references the wrong symbol still compares identical. **Do not report a
sampled sweep as 3s**, and quote a 3s with its coverage line: it covers only
its domain and the share of the routine the domain reached. A sampled sweep is
3a with more cases.

---

## Step 1 — Establish what the file actually is

`python tools/mzinfo.py GAME.EXE`: packed or not, overlays or data past the
load image, the segments the loader builds, and the true entry point (`CS:IP`
is relative to the load image, not the file). Read FINDINGS; what a note
means depends on the memory model (`knowledge/01-dos-binaries.md`).

---

## Step 2 — Load into Ghidra and recover the missing functions

Run `tools/pipeline.ps1 -Exe GAME.EXE -OutDir out`. It imports without
analysis, corrects the load (`CorrectMzLoad.java`), checks it, analyses,
recovers functions (`RecoverFunctions.java`) and exports
(`ExportDecompiledC.java`); the commands to run it by hand are in
`knowledge/17-evidence.md`, By hand. The rules, by hand or not:

- **Import without analysis, and analyse only after correcting**: analysis
  reads bytes that may be missing until the correction.
- **Run the steps as separate Ghidra invocations**, except the corrector,
  measured safe as a `-postScript` of the import. Keep analysis and recovery
  apart above all: run together, the export changes
  (`knowledge/04-pitfalls.md`).
- **Do not work around the profile handshake.** The pipeline writes
  `profile.json` before import, compares it with what Ghidra did, and on any
  difference stops and writes `handshake.json`. Find out why first. The Step 3
  readers refuse that export; `--accept-profile-drift` is for a person who has
  understood the drift, not for getting past the refusal. By hand, run
  `tools/analysis_profile.py write` before import and `check` after export.
- **Do not work around the load-image check.** The corrector fixes the two
  kinds of MZ Ghidra 12.1.2 loads wrong (a full last page, a duplicated
  relocation) and nothing else; the pipeline then checks that the program
  *is the file* and stops on anything but verified. A mismatch after
  correction is an uncorrected loader problem, not a quirk of the check.
  `-AllowLoadMismatch` is for a person who has read `loadimage.json`.
- **Report a corrected load as corrected**: when `loadimage.json` says
  `"corrections": N` with N not 0, say so and point at
  `load-corrections.json`.
- Between file offsets and addresses, use `python tools/loadimage.py map
  loadimage.json --file 0x...` or `--address ssss:oooo`.

Recovery is needed because Ghidra never follows an integer, and games
dispatch through pointer tables and install handlers by address: on Sopwith
it found 48 real functions analysis had left undisassembled, both ISRs among
them (`tests/sopwith/CASE-STUDY.md`).

---

## Step 3 — Identify what the evidence establishes

Do this first, always. It needs no reference source, and what it finds is fact.

```
python tools/anchors.py OUTDIR/functions.json --exe GAME.EXE \
       --entry <CS:IP from mzinfo> --report anchors.txt --names names.json
```

With `--exe` it refuses a `functions.json` made from another file, as
`libsig.py`, `match.py`, `modcluster.py` and `emuverify.py` do, and they all
refuse one whose `handshake.json` says `mismatch` or `blocked`. **If a tool
refuses, regenerate the export; do not pass a different executable to make it
agree.**

It reports every function with identifying evidence (interrupts, ports,
strings, video constants) and writes names that claim only what was
established: `bios_video_3` executes `INT 10h`; it is not `drawsprite`. Two
independent kinds of evidence earn confidence; one stays provisional, with a
`__maybe` suffix and a warning comment, so the doubt stays visible in the
code. Apply, then re-export with `ExportDecompiledC.java`:

```
python tools/applynames.py names.json OUTDIR --dryrun     # what would be written
python tools/applynames.py names.json OUTDIR              # write it
```

It validates every entry before writing any, writes one transaction, reads it
back and rolls it all back on one difference. Exit 0 applied; 1 rolled back;
3 refused before writing, every failing entry listed; **4 rolled back but the
changes are still there: stop and look.** Ghidra itself accepts duplicate
names, so these checks are the only guard (`knowledge/17-evidence.md`, Names
written into the program).

`python tools/bodies.py OUTDIR/functions.json --evidence bodies.json` reports
bodies and what no function claims (`knowledge/17-evidence.md`, Function
bodies):

- **Do not read a body as everything its function runs, nor as only what it
  owns.** Ghidra never lets bodies overlap: shared code is in
  `body_overlaps`, tail calls in `tail_calls`, and a large claim is usually
  one routine recovery cut into pieces.
- `origin` says whether Ghidra found a function or recovery inferred it.
  **Say so when you name a recovered one**: it rests on weaker evidence.
- An unclaimed range that looks like code is **a question to read, not a
  function to create.**
- For a hand-written program **quote `claimed_of_code_region`, not
  `claimed`**, which is mostly data; the region is a floor.

---

## Step 3b — Identify by matching, when reference source exists

Only when the source genuinely corresponds: a later port, a sibling game,
leaked headers. **Exclude the C runtime first**; it needs no source:

```
python tools/libsig.py apply GAME.EXE OUTDIR/functions.json \
       --db signatures/msc50-16bit-small.json --json lib.json
python tools/srcinv.py SRCDIR --json src.json
python tools/match.py src.json OUTDIR/functions.json --align \
       --exclude-library lib.json [--module-order order.json] --report ident.md
```

Try each database in `signatures/`; the one that matches names the compiler.
If none does and you are sure of the compiler, the program brought its own
runtime and none of it is library noise. **Check the score distribution before
believing any match.** A run where nothing clears 0.7 says the reference is
wrong, not that the binary is hard: against another version of the same game
nothing cleared 0.453 and `main` landed in the wrong place. `modcluster.py`
proposes modules for reading and for a hand-built `--module-order`; it is
deliberately not wired into the matcher, which it made worse
(`knowledge/03-what-works.md`).

---

## Step 4 — Read, name, annotate

This is where the work gets done, and it is not automatable.

**Never commit a name on one source of evidence.** A conclusion from one
source almost always needed correcting; what survived had two
(`knowledge/06-lessons-from-siblings.md`). Observed ways it goes wrong:

- naming a field from its **writer** without reading its **readers**;
- naming a long routine from its **first few lines** — and a plausible *pair*
  of such names seeming to confirm each other;
- naming something from its **effect** rather than its cause, which can invert
  the meaning while sounding reasonable.

In `symbols.json` give the evidence as a list: `annotate.py` refuses a name
without `__maybe` on fewer than two entries. Two entries citing one address,
or the callee's name restating the first, are one observation
(`knowledge/13-naming-hand-written-assembly.md`).

**Find `main` by reading, not by rule** (`anchors.py`'s guess was right on one
of two binaries): a call taking `(argc, argv)` followed by an endless loop.
Then work outward: that loop's body is the game's phase order.

**Check every hypothesis against the fingerprint before committing to it.**
`functions.json` has instruction and call counts, interrupts, ports and
constants; a "collision routine" of 6 instructions and no calls is not one. A
wrong name is worse than none: it survives into every later reading.

Anchors, most reliable first: strings; interrupts (`10h` video, `16h`
keyboard, `21h` DOS, `1Ch` timer hook, `09h` keyboard ISR); ports (`40h–43h`
PIT, `60h` keyboard, `3D4h/3D8h` CGA, `201h` joystick, `388h` AdLib); constants
(`0xB800` CGA, `0xA000` VGA, `0x2000` CGA bank).

---

## Step 5 — Verify, do not assume

Decompiler output is a hypothesis. Confirm the ones that matter.

**With a second binary of the same program, settle it by execution:**
`python tools/emuverify.py known.exe known.map target.exe
OUTDIR/functions.json`. It runs both under emulation on identical inputs and
compares return registers, global reads and writes and call counts: it decides
equivalence rather than scoring resemblance (110 matches on two Sopwith builds,
zero wrong). A name it carries across can be trusted. Its limits:

- Both must implement the *same algorithm*; on a different release it
  correctly finds almost nothing. That loud failure is the point.
- Some functions are behaviourally identical and always will be (`sti; ret`
  and `cli; ret`); it reports them rather than guessing.
- It assumes the small model. stderr says how it found DGROUP; if it fell back
  to the lowest relocated segment and far code sits below the data, give
  `--dgroup-a`/`--dgroup-b` (`knowledge/04-pitfalls.md`).
- Functions that never return are compared only on the globals a bounded run
  touched, and flagged separately.

**With a port or rebuild of one routine, sweep it against the original:**

```
python tools/emuverify.py sweep GAME.EXE 1000:0024 --domain domain.json \
       --candidate port.mjs:muldiv --functions OUTDIR/functions.json
```

It runs the original and the candidate (JavaScript, Python, or a rebuilt
binary) on every input of your domain and stops at the first disagreement;
divide faults are outcomes to reproduce. Report with the verdict: **exhaustive
or sampled** (a sampled pass is not a proof); **the coverage line** and the
ranges never reached; **the DGROUP** and how it was found; **the CPU** (an
8088 by default; `--cpu 386` for a program that needed one). Contract and
examples: `knowledge/18-oracle-sweeps.md`.

Run the game in DOSBox-X and check the behaviour you claim. If Ghidra and
radare2 disagree about an instruction, look at the bytes. **State clearly
which parts of your output are verified and which are inference.**

---

## Validating a change to the toolkit

Run `tests/run-all.ps1` before the change and after it, and keep both tables.
**A skip is not a pass:** say which suites did not run, and whether the change
could move what one of them measures.

Sopwith is the regression fixture; `tests/sopwith/` builds a ground-truth
binary and map, so a change is scored against a known answer:

```
python tests/sopwith/regress.py --build-dir work/build --decompiled work/decomp \
       --source <sopwith-source> --variant-dir work/variant
```

Floors: library detection precision 0.95 (a false positive deletes game code)
and recall 0.80; identification precision 0.85 with a known module order, 0.83
with an inferred one, recall 0.52; emulation precision 1.0 with at least 100
matches. **Below any of them the change made things worse: do not ship it.**

**A test has to be able to fail.** After changing code that decides
`verified` against `mismatch` (`tools/evidence.py`, the load-image comparison,
`bodies.py`'s classification, the sweep's comparison and coverage, the
handshake, triage's verdict), run `tests/mutation/run.ps1 -Only <target>`.
Answer every new survivor with a test that kills it; a survivor goes in
`tests/mutation/known.toml` only when the changed code behaves identically,
with the reason in one sentence. A test that compares the code's output with
itself cannot fail, nor can one that checks only an exit code (a mismatch and
a traceback both exit 1): check the message. A test that needs Ghidra is out
of the tool's reach: inject a fault by hand once, see it fail, put it back
(`tests/mutation/README.md`).

**Measure; do not reason.** Three confident predictions here were contradicted
by measurement (`knowledge/06-lessons-from-siblings.md`, §6). Watch a second
metric: a passing test does not mean nothing got worse.

---

## Reference

`knowledge/`: `00-scope` (what is handled; unpacking), `01-dos-binaries`,
`02-compiler-fingerprints` (Turbo Pascal too), `03-what-works` (measured,
failures too), `04-pitfalls`, `05-prior-art` (for a faithful rather than a
readable reconstruction, mzretools is the better start),
`06-lessons-from-siblings`, `07-extended-reconstruction`,
`08-com-reconstruction`, `12-hooking-the-right-thing`,
`15-adventure-engine-shape` (and not reading Huffman-coded text as vector
graphics), `16-emulator-driven-exploration`, `17-evidence`,
`18-oracle-sweeps`, `19-agents`, `ghidra-upstream-mzloader`. Worked through:
`tests/sopwith/CASE-STUDY.md` (wrong turns included), `tests/com/CASE-STUDY.md`.
