# Pitfalls, and the fix for each

Every entry was hit for real while building this method. None are theoretical.

## Tooling

**Chaining two `-postScript` flags in one headless run loses the first
script's work.** `RecoverFunctions` reported creating 100 functions; the
exporter that ran immediately after saw 232, the pre-recovery count. Run each
script as its own `analyzeHeadless` invocation against the saved project.

*Measured again on Ghidra 12.1.2 (2026-10-19), it did not reproduce.* With a
fixture recovery adds two functions to, chaining both scripts on `-import` and
on `-process -noanalysis` each exported all seven functions, the same as
separate invocations. The version that lost them was not recorded. The
pipeline keeps the separate invocations, which cost nothing; what it now
checks instead is in `17-evidence.md` — whether recovery ran, by a mark the
script leaves in the program.

**Ghidra's MZ loader drops the last page when the header says it is full.**
Bytes-on-last-page 0 means the last 512-byte page is full; FreeDOS and DOSBox
both size the image as `pages * 512 - header`. Ghidra 12.1.2's `MzLoader`
computes `(pages - 1) * 512 + bytes_on_last_page` and so loses the entire last
page. Measured on a two-page fixture: `module.coverage` failed with
`file 0x200..0x3ff not loaded`. A linker writes 0 whenever the file is an exact
multiple of 512 bytes, so a real game can hit this.

**Ghidra's MZ loader applies a duplicated relocation once.** DOS adds the load
segment once per relocation entry, so a word listed twice gets it twice:
FreeDOS `*spot += start_seg;`, DOSBox
`mem_writew(address, mem_readw(address)+relocate);`. Ghidra writes
`0x1000 + the file's word` for each entry instead of adding, so the second
write changes nothing. Measured: `1006:0016: 0x1004 not 0x2004`. It keeps both
relocation records, so only the word itself shows the difference.

*Both are now corrected by default.* `tools/ghidra_scripts/CorrectMzLoad.java`
runs straight after import: it maps the missing page from the file's own bytes,
joined to the block before it, and writes each duplicated word as DOS would.
The load-image check then compares the corrected program with the file exactly
as before, so a correction that went wrong is still a mismatch. Every
correction, with its value before and after, is in `load-corrections.json`, and
`loadimage.json` and `functions.json` carry the count: `"status": "verified",
"corrections": 1`. Nothing else is corrected. A relocation *inside* the missing
page gets its word fixed, but Ghidra's record for it says `FAILURE` and no API
rewrites a relocation record. Since prompt 03 the verifier accepts that record
only when the word in memory is the file's after the fixup, under a
corrections record whose provenance holds, and says so in a check of its own,
`relocations.status_after_correction` (`17-evidence.md`). To see Ghidra's own
load, run the pipeline with `-NoLoadCorrection`: the two fixtures then stop
with prompt 02's mismatches, word for word. The upstream report is drafted in
`ghidra-upstream-mzloader.md`.

**A headless script already runs inside a transaction, and its own is only a
sub-transaction.** Measured on Ghidra 12.1.2 with a probe script, on the bodies
fixture:

- **Inside a `-postScript`**, `getCurrentTransactionInfo()` names an open
  transaction the framework started for the script (`'TxProbe' status=NOT_DONE`).
- **`startTransaction`, or the `openTransaction` AutoCloseable, opens a
  sub-transaction of it** (`isSubTransaction=true`).
- **Ending the sub-transaction with commit=false aborts the outer one.**
  `endTransaction` returns `false`, and the outer status becomes
  `NOT_DONE_BUT_ABORTED`.
- **Nothing is undone at that moment.** Names read back changed, and later
  changes are accepted. When the script ends, *every* change of the run is
  discarded: the ones made before the sub-transaction began, inside it, and
  after it. A second run reads the original names.
- **"Save succeeded" is printed even then.**
- **A script that throws keeps its changes.** A rename followed by an
  uncaught exception was saved, and the headless run exited 0
  (`ERROR REPORT SCRIPT ERROR` is only a log line).
- **Committing the sub-transaction keeps its changes**, though
  `endTransaction(tx, true)` also returns `false`.

So inside a headless script, an all-or-nothing batch is a sub-transaction
ended with commit=false on any failure. Every exception has to be caught and
turned into that abort: one that escapes commits the half-done batch.
`ApplyNames.java` works this way. Its exit status comes from
`tools/applynames.py`, because the headless run's own exit code says nothing.

**Ghidra accepts names it should not.** In the same probe, `Function.setName`
accepted a second function named exactly like the first, `a:b`, and
`FUN_1000_9999` for a function at another address. It rejected only `has
space` (`InvalidInputException`). An empty name was accepted and quietly
reverted to the default. Anything that must not be stored has to be refused
before the setter is called.

**Plate and PRE comments reach `decompiled.c`; EOL and repeatable comments do
not.** Measured by setting one of each on a function and re-exporting. The
plate comment prints above the function, the PRE comment at the entry prints
at the top of its body, and the other two do not appear.

**`=` splits a headless script argument on Windows.** `analyzeHeadless.bat`
passes arguments through cmd.exe, which treats `=` as a separator:
`load_image_status=verified` reached the script as two arguments, and the
field it was meant to set never appeared. Pass `key:value` instead.

**`getImageBase()` is not the load segment.** Ghidra's MZ loader puts image
byte 0 at `1000:0000`, and `Program.getImageBase()` returns `0000:0000` for the
same program (measured, Ghidra 12.1.2). The `image_base` field in
`functions.json` has always been that value. Read it as the load segment and
every address is `0x10000` out. `observed_profile.load_segment` is the real
one, worked out from where the file's bytes landed.

**The first `python` on PATH may not be the one you installed into.** On the
machine the evidence work was done on, `python` in one shell resolved to the
copy Inkscape bundles (3.12.12), which has neither capstone nor unicorn, while
the interpreter that had both (3.11.9) sat further down PATH. Every suite that
needs either died with an `ImportError`, which reads like a bug in the tool.
Set `PYTHON`: `pipeline.ps1` and `tests/run-all.ps1` use it first, and
`run-all.ps1` names the interpreter it used on its first line.

**Ghidra's MZ loader marks every segment executable, including data.** Any
scan that trusts `block.isExecute()` will happily create functions inside
sprite bitmaps. Filter to blocks that contain the entry point or already
contain defined functions.

**Ghidra auto-analysis under-reports functions on game binaries.** It follows
control flow, and games dispatch through function pointers in data. Expect to
lose roughly a third of the functions, concentrated in the gameplay code, and
recover them explicitly.

**`RecoverFunctions.java` does not find routines reached through a table in
data.** It follows calls, immediates in instructions and prologues. A table of
handler addresses stored as data, read by an indirect call, gives it none of
those. On Crimson Crown (small model, 0.9 prologues per KB; Microsoft C by the
sibling project's notes) `bodies.py` found 1,011 bytes in 10 runs that nothing
claims and that read as code, among
them a block of three-instruction condition handlers, `call`/`je`/`inc
byte ptr`/`ret`, one after another.

**Ghidra never lets two function bodies overlap.** `Function.setBody` and
`FunctionManager.createFunction` both throw `OverlappingFunctionException`
(measured, 12.1.2). So code two functions share is never in two bodies. Two
functions jumping to one epilogue come out as three functions, the epilogue its
own. A jump into the middle of a neighbour stays in the neighbour's body, and
the jumper's body ends at its jump. Read a body as what Ghidra assigned, not as
what the function runs. `body_overlaps` in `functions.json` lists the code a
function reaches in another's body (`17-evidence.md`).

**A jump to another function's entry looks like a call to Ghidra.** It
overrides the jump's flow to a call-return, and the reference type follows. So
"is this function called?" has to be answered from the calling instruction's
mnemonic. By reference type, measured by mutation, the fixture's shared
epilogue looks called, and the jumps into it look like tail calls rather than
shared code.

**An entry's offset is not its address.** `libsig.py` and `emuverify.py` found
a function by the offset half of its `ssss:oooo` entry, which is right only in
the segment the image starts in. On the real programs, 17 functions sit in
another segment (adventur 6, Ootopos 2, Talisman 5, Transylvania 4), and both
tools read the wrong code for every one of them. Talisman's `2629:80b2` was
read at file `0x82b2`, all zeros. adventur's far routine at `1f77:0010` was
profiled as 3,535 writes by whatever sits at `1000:0010`. Since prompt 03a
both put the whole entry through the verified load mapping
(`loadimage.locate_entries`), and `tests/farcall/` holds a far function in a
second segment open.

**RecoverFunctions' `enter` pattern fires in data.** It treats `C8 xx xx 00`
as a prologue, and in a program's data that is just four bytes. Every one of
the 11 functions outside the first segment in Ootopos, Talisman and
Transylvania is such a match. Their mnemonics include `AAA`, `ARPL`, `BOUND`
and `FISTTP`, and Transylvania's `2616:1274` starts
`enter 0x404f, 0` followed by `hlt`. They read as `recovered-prologue`, and
`origin` is there so a later tool can discount them.

**emuverify guessed DGROUP as the lowest relocated segment.** That is right
for a small-model C program, where the relocations are the startup loading
DGROUP. In a program with far code placed before its data, it is a code
segment: the far-call fixture's guess was its far segment, 0x0003, where
DGROUP is 0x0005. Since prompt 05 it runs the startup instead, under
comrun.py's loader, and takes the first segment loaded into DS that the
loader relocated; the old guess is the fallback, and stderr says which was
used. Measured on the six real programs: five startups load DS within 220
instructions, each agreeing with the old guess. adventur.exe is EXEPACK'd: its
decompressor loads its own code segment, 0x0f77, into DS after five
instructions. Nothing relocated that segment -- the file has no relocations
at all -- so it is passed over, and adventur is refused as before. The
condition that the value be relocated is what keeps a packer's segment from
being taken for the program's data.

What `AGENTS.md` said of this before prompt 09a, kept here: a function in
another code segment runs at its own `segment:offset`, with a far return
address if it ends in `RETF`, taken from a `functions.json` and from a linker
map whose segment table calls that segment `CODE`. DGROUP comes from the map,
or from the segment the startup loads into `DS`; stderr says which (under
`--quiet`, only when the old guess would have differed). When the startup
loads nothing the loader relocated, it falls back to the lowest relocated
segment, which is a code segment when far code sits below the data: give
`--dgroup-a`/`--dgroup-b` then.

**Ghidra gives `INT` and `CALL` a fall-through.** `int 0x21` with `AH=4Ch`
never returns, but in Ghidra's flow model the instruction after it follows.
The first version of the overlap walk followed it, and claimed that the
fixture's startup "fell through" into `main`. A fall-through is evidence of
running on only after an ordinary instruction, or after a call that returns
into the body it was made from.

**In a hand-written program, "inside a block that holds functions" is not
"inside code".** The program is often one block of code and data together.
Testing a word for "points into code" by the block made every word in
Talisman's data land in code, and 63,792 bytes of it read as pointer tables.
Test against function bodies instead.

**The Open Watcom Windows installer crashed twice** (heap corruption, then an
access violation), leaving a half-populated tree without `wcc` or `lib286` —
the 16-bit pieces. The `ow-snapshot.tar.xz` release asset contains the same
build as a plain archive and extracts cleanly. Prefer it.

## 1980s source archaeology

**Ctrl-Z (0x1A) inside source files.** `SWDEVE.H` ends with a DOS end-of-file
marker followed by more bytes. Period compilers stopped reading at it; modern
ones do not, and report a syntax error on a line that looks blank. Strip from
the first 0x1A onward.

**Duplicate `EQU` definitions.** `SW.HA` defines `K_ASYNACK equ 40H` twice,
two lines apart. MASM 5 tolerated it; `wasm` rejects it. Stack-frame offsets
that are legitimately redefined per procedure (`OB equ @AB`) need the
redefinable form `=` instead.

**Mixed `return;` and `return(value);` in one function.** Standard K&R
practice, an error for a modern compiler. Decide what the bare `return` was
returning — usually nothing the caller reads — and make it explicit.

**Files the release forgot.** Sopwith's GPL drop is missing `SW.LNK` (the link
script), `mixed.inc` (an assembly include), and the whole "BMB" block-I/O
library (`bopen`/`bread`/`bwrite`/`bseek`/`bioerr`, referenced but defined
nowhere). Reconstruct what you can — `SW.MAK` listed its objects in link
order, which *is* the content of `SW.LNK` that matters — and stub the rest,
loudly.

**Some source files contain no code at all.** `SWPLANES.C`, `SWSYMBOL.C`,
`SWGROUND.C` and `SWGAMES.C` are ~60 KB of pure data tables: sprite bitmaps,
terrain, game configurations. Do not go looking for their functions. Do find
their data in the binary — a distinctive table is a reliable landmark. The
16-entry sine table in `SWMAIN.C` was located by byte pattern in seconds and
confirmed the data segment's position.

**The shipped binary may not match the source you were given.** Sopwith's
`SOPWITH.EXE` decompiles to a `main()` with five calls in its loop; the source
drop's `main()` has `malloc`, `setjmp`, a `movetick` busy-wait and a
print-screen block that are simply absent from the binary. They are different
versions. Rebuild from source to get a binary whose mapping you can trust, and
keep the shipped one as the realistic no-source test case.

## Toolchain conventions

**Calling convention decides symbol decoration.** Microsoft C put the
underscore in front (`_swmove`); Open Watcom's default register convention
puts it behind (`swmove_`). Mixing them produces a wall of undefined
references. Compiling with `-ecc` (`__cdecl`) restores the Microsoft
convention and made every C-to-assembly reference in Sopwith resolve at once.

**`#pragma aux` functions emit no linkable symbol.** They inline. If another
module calls one, wrap it in a real function.

**wasm parses `push CS:label` as an immediate push** (a 186+ instruction) where
MASM read it as `PUSH m16`. Write `push word ptr CS:label`. The same applies
to `push variable`.

## Confidence reporting

**Do not report an internal weight as a confidence.** The sequence alignment
pins anchor pairs to a similarity of 1.0 so the alignment stays attached to
what the greedy pass already believes. An early version then reported that
pinned value as the match's confidence, which turned "the greedy pass picked
this" into "this is certain". On the shipped Sopwith it produced 28 matches at
exactly 1.000 while `main` — the one answer independently verified by reading
the code — was mapped wrongly at 0.268. The pinned value now drives the
dynamic program only; the reported score is the unpinned similarity.

The symptom is recognisable: a run where many matches share an identical top
score is reporting a constant, not a measurement.

## Testing the tests

Measured by mutation testing (`tests/mutation/`) in prompt 07: the code that
decides `verified` against `mismatch` was changed in small ways, one change at
a time, and each suite run against it. Before any new test, 1,658 of 2,708
changes were noticed (61.2%).

**A test that compares the code's output with the same code's output cannot
fail.** The evidence suite checked that each envelope was canonical by
comparing it with `evidence.dumps` of itself. A change to `dumps` changed both
sides, and four changes to the form files are written in (unsorted keys,
non-ASCII, another indent) went unnoticed. Write the rule out in the test, as
the `profile_id` test already did. The same suite never made an id without a
target, or two items one id apart, and 34 changes to those went unnoticed.

**An exit code cannot tell a mismatch from a crash.** `analysis_profile.py
check` exits 1 on a drift, and Python exits 1 on an uncaught exception. Eleven
changes that turned the drift message into a `TypeError` passed every test,
because the record was written before the message and the test looked at the
exit code and the record. Check the message, and that there is no traceback.

**The tests that need Ghidra carry most of the comparison code.** Without
Ghidra the load-image suite left 415 of 1,049 changes to the comparison
unnoticed, and the bodies suite 366 of 857: the cases that exercised them ran
the pipeline. Synthetic dumps and exports, with every check's answer written
down (`tests/loadimage/expected-checks.json`,
`tests/bodies/expected-analyse.json`), now cover them without Ghidra.

**A check no input reaches is as good as no check.** comrec's whole-file
comparison runs after every instruction has matched its own encoding, so with
an honest assembler it never saw a difference, and its byte loop could go.
What reaches it was found by measuring, not reasoning: every spelling
Capstone gives the one-byte opcodes, the x87 escapes and the group opcodes,
2,794 of them, assembled one at a time. Two assembled to nothing
(`08-com-reconstruction.md`), and the fixtures built on them kill the loop's
removal and both of its one-sided comparisons.

**A rule tested only far from its threshold passes wherever the threshold
is.** Prompt 08's cases pinned triage's verdict for thirteen file shapes, and
59 of its 315 mutants still survived (on a loaded machine, so some of the
kills were timeouts). Nearly every survivor was a threshold moved or flipped
where no fixture sat on it: 2.0 prologues per KB, 0x400 bytes from the entry,
two relocations, a data file four times the image.
`tests/evidence/fixtures/numbers.asm` takes each of triage's numbers from
NASM's command line, so the suite builds it once per threshold with the number
exactly on it. With those builds every one of the 295 mutants that is not
equivalent is killed. The same held for the 8088's rule in the sweep: its
fixtures divided by 7, a divisor too small to show a register read at the
wrong width, and it took divisors that need all sixteen bits to show it.

**A timed-out test's children run on.** cosmic-ray kills the test process at
its timeout, and only that process. A tool the test started -- `comrec.py`,
looping on a mutant of its round trip -- keeps running. Twenty were found
still running hours after two runs had ended, a core each. Every
measurement taken meanwhile shared the machine with them, and a loaded
machine turns slow tests into timeouts, which count as kills: one triage run,
with Ghidra exports running beside it, counted 38; the next, without them,
none. `mutate.py` now ends such processes after each target. Do not run
anything heavy beside a mutation run.

**cosmic-ray's baseline does not run under the HTTP distributor.** Asked for a
baseline with no worker listening, it reported success in 3.4 seconds without
running a test. `tests/mutation/mutate.py` runs the unmutated suite itself.

**cosmic-ray splits the test command the POSIX way.** On Windows a path with
backslashes loses them. Pass forward slashes.

**mutmut cannot see these tests.** It decides which tests reach a mutant by
recording calls inside the pytest process, and names mutants by their package
path (`tools.analysis_profile`); the toolkit imports its modules flat
(`analysis_profile`) and the suites run tools as command lines. On the
handshake it made 371 mutants and found a test for none of them, with or
without a shim that imported the modules under mutmut's names.

## Driving a program under emulation

**A queue of keystrokes vanishes in one screen.** The Oregon Trail consumed 88
keys in 88 reads without ever pausing. Turbo Pascal opens most prompts with
`while KeyPressed do ReadKey` to throw away type-ahead, and an emulator that
answers "yes, a key is waiting" hands that loop the entire queue. Answering
"no" instead hangs the opposite idiom, `repeat until KeyPressed`. Both are
`INT 16h AH=01` and no fixed answer is right — what separates them is
persistence, so `--poll-patience N` says "nothing waiting" until the question
has been repeated N times since the last blocking read. Feeding *more* keys
makes it strictly worse, which is the wrong direction to reach for first.

**Two screens can look like one broken one.** Every hunting-screen capture came
back with two screens overlapping and the text unreadable, which reads like a
renderer bug. It was not: the program was frozen mid-redraw, and the give-away
was that three runs with different budgets and different keystrokes produced
**pixel-identical** images. A frozen frame is a symptom to trace, not a picture
to publish.

**Raising the budget is almost never the fix.** If a longer run produces the
same distinct-address count, the same read count and the same frame, it stopped
making progress long before either limit. Report *where* the budget ran out,
not just that it did — the difference between "budget exhausted" and "budget
exhausted at 15FD:1784" was three runs and four and a half billion instructions
against one disassembly.

**Do not enter a compiled routine in the middle to look at its screen.** It gets
you the code without the state. The Oregon Trail's hunting routine, called
directly with every plausible variable poked, died in a far call through a null
driver vector — because the BGI driver is installed on the way in, and there is
no way in but the menu. The general form: a `--call` gives you a routine whose
caller never ran, and the failures it produces are all consequences of that one
fact.

**A Unicorn instance remembers the last fault.** `emuverify.py sweep` runs
thousands of cases in one instance, and a divide fault is ended by calling
`emu_stop` from the interrupt hook. Measured on Unicorn 2.1.4, the next divide
fault in that instance arrived as interrupt 8, a double fault, and the one
after that as no interrupt at all: the CPU still believed it was delivering
the first. The first version therefore called the second fault of a sweep a
"cpu" fault. Save the context once after setup (`context_save`) and restore it
at the start of every case; it costs 0.4 microseconds. A tool that makes a
fresh instance per run never sees this, which is why the comparison never did.

**`emuverify.py`'s comparison previously had a wall-clock limit.** Each run used
`emu_start(..., timeout=2_000_000)`: two seconds, then it stopped, and a
function stopped that way was dropped as unrunnable. On a busy machine that
wobbled the count. In prompt 11 (commit `f79b2c5`), this was replaced with a
deterministic instruction budget of 50,000 instructions and `timeout=0`. The
budget was derived from measuring the slowest legitimate returning routine on
Sopwith (`movedata_` at 32,787 instructions, providing 52% headroom), and tested
under a 5.17x CPU load variation (112.15 s vs 580.25 s) to prove 100% bit-for-bit
identical profiles and matches.

## Analysis

**Small model explains suspiciously few relocations.** Sopwith has 2
relocations for a 60 KB image, which looks like a packer until you notice both
sit within a few bytes of the entry point: they are the startup code loading
`DGROUP` and the stack segment. Code that never forms a far pointer needs no
fixups. Check where the relocations are before concluding anything.

**A linker map lists data symbols alongside functions.** Scoring
identification accuracy against the raw map understates it badly — of 330
symbols in Sopwith's map, 183 are variables. Filter to names the source
declares as functions.

**Ghidra addresses are biased.** Its MZ loader places the image at segment
`0x1000`, while a linker map numbers segments from zero. Add the bias before
comparing, or nothing will line up and the cause is not obvious.

**Asking for callers of an address in the middle of a routine always answers
none.** This document's own author published "the joystick routine at 0x425E,
and nothing in the image calls it" — a finding on both counts, and wrong on
both. `0x42EC` was not an entry point at all; it was a `call` instruction
*inside* the routine that begins at `0x42D1`, so a scan for `E8` displacements
landing on it could only ever return zero. And `0x425E` was not the joystick:
it writes ports `0x3BA` and `0x3BF`, which is Hercules display detection.

Before concluding that nothing reaches an address, check that the address is
somewhere anything *could* reach — a prologue, a jump target, or a word
appearing in the data. An interior address is none of those, and "no callers"
about one is not a finding, it is a category error.

**A counter's meaning is in what it is compared against, not what sets it.**
Two globals in Karateka are both initialised to 32 and both decremented, which
reads as a pair of hit-point counters and was written up as one twice. They are
a timer: the branch above them is `cmp ax, 0x14a` — a distance of 330 pixels —
and no health counter cares how far away the other fighter is. The assignment
and the decrement are the two least informative instructions about a variable;
the comparison is where the meaning is.

**A table's address may never appear in the program.** Two games here have hit
this, in two different languages, six years apart. If a subscript range does not
start at zero — `array[3..8] of string[10]` in Pascal, or the same trick written
by hand in assembly — the compiler folds the lower bound into the base *once*,
at compile time, so indexing costs a multiply and an add instead of a multiply,
a subtract and an add. What the code then contains is `base − low × stride`,
which points at nothing:

    0013C61  mov al, [bp-0x103]        ; The Oregon Trail: an illness code, 3..8
    0013C67  mov dx, 0x000B / mul dx
    0013C6E  add di, 0x0CB5            ; the table is at 0x0CD6 -- 33 bytes later

`0x0CB5` lands in the middle of the previous string. Searching the image for
`0x0CD6` finds nothing at all, and the natural conclusion — that the table is
unused — is wrong. Zaxxon does the same with two tables, four bytes early, and
its notes say *"it looks like a bug and is not."*

**So enumerate the mechanism, not the address.** Scan for the *stride* instead:
every `mov dx, <n> / mul dx` followed by an `add di, imm16` is a table access,
and the list is short enough to read — 42 of them in a 200 KB program, with the
answer sitting in plain sight. The same move solved a second problem in the same
binary, where a whole missing segment made a subsystem look as though it
addressed its data by magic.

The general rule, and it is worth more than either case: **when a search with a
good positive control still comes back empty, change the question rather than
the thresholds.** A control proves the search works; it cannot tell you the
search is asking for the right thing.
