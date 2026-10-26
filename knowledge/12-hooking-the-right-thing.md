# 12 — Hooking the right thing

Running a program under `comrun.py` and watching what it touches is the method
that has settled every hard question in this toolkit: Hard Hat Mack's scanline
table, Karateka's sprite format, and now Karateka's fight AI. It is also the
method that wastes the most time when the hook is chosen badly, and the two
cases sit close enough together to compare.

## The bad hook and the good one, on the same program

**"Who draws sprites?"** — hook the sprite dispatcher, record the caller.

```
2,176 sprite draws, 2 distinct callers
  0x00C0A   2172
  0x00F39      4
```

One routine, and it taught nothing, because *everything* draws sprites. The
answer was true and useless: the dispatcher is a funnel, and a funnel tells you
about the funnel. Walking back up the stack gave five-deep trails and a slightly
larger fog.

**"Who writes the move cursor?"** — hook one two-byte global.

```
280 move changes
  0x0245C   82  advances the player one frame
  0x025C8   82  advances the guard one frame
  0x0248B   64  starts a guard move
  0x0234D   38  starts a player move
```

Four instructions, and two of them had the AI call sitting directly above them.
The question was answered in a single run.

## What made the difference

Not effort, and not the tooling — both hooks are six lines. The second variable
**can only be written for one reason.** A frame cursor changes when, and only
when, a move starts or advances; nothing else in the program has any use for it.
The sprite dispatcher, by contrast, is reached for every reason the program has.

So the rule is not "hook the interesting routine". It is:

> **Hook the narrowest piece of state that can only change for one reason, and
> record who changed it.**

A corollary that saved a second run: pick something whose *value* is
self-identifying. The cursor holds a byte-code offset, and the index table maps
offsets back to move numbers, so every event decoded itself into "actor X
started move 19" with no further work.

## Three practical notes

**Hook the emit, not the buffer.** To find where a compiler puts its output,
hooking the one instruction that writes an opcode — `mov byte [si], 0x14` — beats
working out which argument of which caller holds the destination. One address,
no reasoning.

**A hook fires at an instant, and the instant may be off by a stage.** Sampling
the frame cursor at the moment x changed gave 58% agreement with the frame's own
travel byte, which looks like a failed hypothesis and was not: the cursor had
already been bumped. Restricting to samples whose bytes were still in phase gave
**38 of 40**. When a check comes back at "mostly", ask whether the sampling is
out of step before you doubt the reading.

**Two passes cost nothing.** Run once to learn an address, run again to watch
it. Trying to do both in one pass means wrapping the DOS handler and guessing at
register conventions; two runs of the same twenty seconds needs neither.

## And the cheapest hook of all is `head`

Karateka's fighting was recorded as unread through four documents. Three of the
files beside the executable are **plain ASCII**. Nobody looked, because the
sprite format next door had been genuinely hard and set the expectation.

Before any of this: open the file.

## The follow-up: three tiny globals beat one big routine

The same handle, turned three more times, read the rest of Karateka's fight:

* **`[0xD5AE]` and `[0xD5B0]`** — each written once and *pushed* once. Two grep
  hits apiece, and the push sites were the hit test's call sites. A routine of
  450 bytes had resisted reading; a variable with two references gave it up.
* **`[0x116]`** — assigned three literals, 13, 12 and 10, in three consecutive
  branches. A constant repeated at a difficulty fork is a difficulty setting,
  and the `dec` that follows it elsewhere is damage.
* **`[0x156]`** — four references: set to 1 on one path, 0 on the other, tested
  twice. Which of two choosers is the human's was a one-line question once the
  right line was found.

The pattern is the same each time: **a global with few references is worth more
than a routine with many instructions**, because each reference is a sentence
about what the global means and there are few enough of them to read.

`grep -c` on a variable name is a two-second triage. Under about six hits, read
them all; over about fifty, the variable is infrastructure and will not
localise anything.

## And a claim can be wrong twice before it is right

`[0x118]` and `[0x11A]` were called health here, twice, on the strength of both
being set to 32 and both being decremented. They are a patience timer: they
count down while the *player stays away* and reset when he closes. What settled
it was neither the assignment nor the decrement but the branch above them —
`cmp ax, 0x14a`, a distance of 330 pixels — which no health counter would care
about.

**Read what a counter is compared against, not only what sets it.** The
comparison is where the meaning is.

## Identify a library by calling it, not by looking at it

Karateka's forty library routines had no discriminating shape -- no FILE
pointers, no format-string walks, no divides -- and this repository recorded
that as "cannot be named without a copy of Lattice C 2.1". That was one
question too early. Reading a routine answers *what does this look like*;
calling it answers *what does this do*, and only the second can be wrong in a
way you notice.

`probelib.py` pushes what `strlen` would take and checks that 5 comes back for
"hello", 3 for "abc" and 0 for "". Nine routines fell out in an afternoon --
strlen, strcpy, strcat, strcmp, strncmp, a bounded copy, two allocators -- and
the call sites then confirmed them: `strcpy` and `strcat` are called in pairs
from four places, each one building `"ks0"` + `".dat"`, and `strncmp` is called
from the script compiler matching its fourteen command names.

**A probe must be able to fail, and three of the first ones could not.**

* *Two calls returning two different non-zero values* matched six routines as
  `malloc`. Every counter passes it. Demanding non-overlapping blocks and a
  refusal for a large enough request cut it to one.
* Six routines matched `max` because every pair in the battery had `x > y`, so
  *returns its first argument* passed. One reversed pair fixed it.
* `stricmp` matched a routine that is case-*sensitive*: the test pushed two
  arguments, the routine was `strncmp`, and the third argument it read off the
  stack was garbage that happened to mean "compare zero bytes". **If the family
  has a three-argument member, push three.**

And a harness bug that produced fifty-nine confident wrong answers at once:
`comrun.call` writes its return sentinel at `BASE + SP`, which is segment zero.
Karateka's SS after start-up is 0x16DA, so every routine returned into nothing
and reported a fault at the same address. **Fifty-nine identical failures are a
fact about the harness, never about fifty-nine routines.**

The thirty that still have no name are printf's internal helpers and their kin.
They take state blocks rather than arguments a specification names, so there is
nothing to probe them against. That is a different and much smaller claim than
the one this file used to make.

## And when there is no specification to probe against, watch it work

Probing settled nine of Karateka's library routines and stalled on the rest,
which I wrote up as "printf's internal helpers take state blocks, not arguments
a specification names, so there is nothing to test them against". True, and
still the wrong conclusion: those routines are *called*, every second, by a
program that works. The arguments they actually receive are evidence nobody has
to invent.

Hooking each one's entry and recording the three words above the return address
named twenty-six more in a single twenty-million-instruction run:

```
0x05E33   4806 calls   a0 varies (2440 of them text), a1 = 0x5879 constant
0x05879  16496 calls   -- 3.4 per call to 0x5E33
0x04B0A   2602 calls   a0 text, a1 = 0x0050, a2 = 0xE1DA
```

`0x5E33` takes a *constant* as its second argument, and that constant is another
routine called once per character. That is `_doscan(string, getchar_fn)` and
nothing else. `0x4B0A` is handed a buffer, the number 80, and a pointer that
sits exactly on slot 3 of the FILE table — `fgets`, 2,602 times, once per line
of script the compiler read.

Three signals do most of the work:

* **A constant argument is a pointer to something.** A function pointer, a mode
  string, a FILE. Follow it.
* **Call counts have ratios.** 16,496 to 4,806 is characters per string.
* **An argument that lands on a table's stride boundary is an element of that
  table.** `0xE1DA - 0xE1B0 = 42 = 3 x 14`, and the stride is 14.

The general rule, and the reason this section exists after two rounds of giving
up: **"there is nothing to test it against" is a statement about the test you
thought of, not about the routine.** A routine with no specification still has
callers, and callers are a specification written by someone who knew.

## Name a global by what its values do, not only by who writes them

Who-touches-what named 134 of Karateka's globals and stalled. A global used
twice gives two data points and no shape. But the attract sequence is the demo
*playing the game* -- `[0x156]` selects the AI chooser and the whole fight
machinery runs -- so every one of them is being exercised. What was missing was
not access to the program; it was watching the *values* rather than the
instructions.

Recording every write and classifying the sequence separates the kinds cheaply:

    flag         two values, one of them zero
    counter      rises by one and resets
    countdown    falls by one and reloads to the same number
    coordinate   small steps in both directions
    pointer      large, always inside one span
    constant     written repeatedly with the same value -- a reset, not a store

The shape does not name anything by itself. It cuts the candidates down far
enough that the routines touching it decide, which is what the previous pass
could not do.

**Two traps, and the second is the more useful.**

`SS` and `DS` had the same base -- `0x16DA << 4` is exactly the data segment --
so a hook on "the data segment" caught every stack push. Seventeen thousand
addresses of noise. Track only what the code names as an *absolute* global,
which is a fixed list you can extract from the listing first.

And the finding that moved the number most was not a naming technique at all.
Fourteen "globals" were only ever written with `0x5555` or `0x2055`, at
addresses eighty bytes apart. Those are CGA pixel patterns and eighty is a
scanline: `DS:0x0337` is a **16,000-byte off-screen frame**, and it ends at
`0x4217`, exactly where the blitter's own globals begin. Forty addresses that
looked like separate variables were rows inside one buffer.

**When a set of addresses share a stride and a value vocabulary, they are one
object.** `[di + 0x337]` is not a global with a displacement; it is the screen.

## Where to stop

113 of Karateka's globals are still unnamed and 94 of them are referenced twice
or fewer. That is the honest floor: two uses cannot distinguish a flag from a
counter, let alone say what it counts.

Quote both figures whenever you quote either. 64% of the addresses and 90% of
the references are the same fact seen from two ends, and the gap between them
is the shape of what is left.

## The enumerator has to match the language, and a blind one reports zero

Karateka is Lattice C and its routines open `push bp`. That enumerator, pointed
at the other three games in this repository, finds **none** -- and `probelib.py`
duly reported *0 of 0 matched a specification*, which reads exactly like "there
is no C library in here" and is a different statement altogether. It had nothing
to probe.

| | prologues | call targets |
|---|---|---|
| Karateka (Lattice C) | 120 | — |
| Hard Hat Mack | **0** | 250 |
| Zaxxon | **0** | 87 |
| ParaTrooper | **0** | 28 |

All three are hand-written assembly, and Hard Hat Mack is a mechanical 6502
translation on top of that -- 427 `cmc` instructions to reconcile two processors
that disagree about the carry flag. Enumerating by *call target* instead finds
their routines, and probing those 250 gives a clean **0 of 250**: a real
negative result. There is no C runtime in it.

That prediction was written down before the run, which is the only reason the
zero means anything. `probelib.py` now says which case it is in rather than
printing a zero that could be either.

**A tool built on one program's conventions will fail silently on the next one,
and the failure will look like a measurement.** Check that the enumerator found
candidates before believing what the battery says about them.

## Count bytes, not references

Karateka's globals reached "312 of 312 addresses named, all 1,642 references"
and I reported it as complete. It was true and it was the wrong denominator.

The data segment is 59,670 bytes. Naming every address the code *mentions* says
nothing about the bytes *between* those mentions, and measured by byte the
segment was **40% accounted for** at the moment the reference count hit 100%.

Mapping it as spans took it to 98.7%, and the shape of what was missing is the
lesson:

| | |
|---|---|
| 31,392 bytes | pure zero — buffers files are read into |
| 16,000 | the off-screen frame, already known |
| ~5,000 | byte code, tables, strings |
| 1,447 | genuinely unidentified, in gaps under 200 bytes |

**Half the data segment is empty.** The largest single object in the program is
24,260 bytes of nothing, waiting for sprites. Empty is *finished*; unread is
*work*; and a reference count cannot tell them apart because nothing references
the middle of a buffer.

Two rules, and the second is the one that keeps catching me:

- **A percentage needs its denominator stated in the same sentence.** "100% of
  references" and "40% of bytes" were simultaneously true of the same program.
- **When a metric reaches 100%, that is the moment to ask what it is measuring**
  — not the moment to stop. Every completion claim in this repository that had
  to be withdrawn was a real number with an unstated denominator.

## Hook the difference, not the total

The referee that compares a static reading against the running program had been
saying this for three sessions:

```
overall: 172 of 193 placements reproduced -- recall 89%, precision 93%
missed (13):
   x1  ('place', 28, 191, 0)
   x1  ('place', 20, 191, 0)
   ...
```

Twenty-one wrong placements, listed by value. Correct, checkable, and nothing
was done about it for three sessions, because a list of coordinates is not a
list of anything you can go and read. It was written up as "three groups: four
rivets along a bottom row, a vertical run of five, and a column of three" —
which is a description of the *picture*, and the picture is not where the bug
is.

The hook already stopped at the drawing routine's first instruction. At that
point the return address is one word down `SS:SP`, before anything has been
pushed, and the routine that owns it is a lookup in the symbol file. Six extra
lines:

```
missed (13), by the routine that made them:
   x4  draw_beams
   x4  draw_rivets
   x3  draw_toolboxes
   x1  spawn_lunchbox
   x1  draw_hoist_car
```

Five names. Three sessions of "twenty-one placements" became an afternoon, and
eight bugs in the static extractor came out of it:

- **A counted loop that runs up.** `mov bl, 1` / `mov byte [V], bl` … `inc byte
  [V]` / `cmp bl, 5` was read as the count-down shape every other loop in the
  program uses. Indices 1 and 0 instead of 1, 2, 3, 4. Every iteration still
  produced *a* placement, so no error was raised and the coverage metric did
  not move.
- **A zero immediate written in decimal.** NASM prints `mov word [sel], 0`, not
  `mov word [sel], 0x0000`, and the store pattern required the `0x` form. One
  routine sets its shape that way and nothing else, so four beams took whatever
  shape the previous routine had left behind.
- **A global that outlives the routine that set it.** Callee state was
  deliberately isolated from the caller — with good reason, an earlier bug had
  two calls to the same routine reading each other's leftovers — so a routine
  that writes no shape selector had none at all. It is now carried in walk
  order, separately from the isolated state, because walk order is the order
  the program writes it in.

- **A loop kept entirely in memory.** `draw_conveyor` counts down in one
  variable and steps across in another, and never puts either in a register
  except to index a table. With no `mov bl, imm` there is no loop to see, so
  one of its four segments was drawn and three were not.
- **…and a placement that is in that loop without touching the index.** A
  `place_pair` erases the previous cell before drawing the new one, and the
  erase reads only the stepped column and two constants. Deciding whether to
  unroll on "does this use BX" unrolled the draw four times and the erase once.
- **Callee state that is game state.** Writes inside a callee were isolated
  from the caller wholesale, to stop two calls to the same routine reading each
  other's leftovers. But the thing being protected against is *scratch* — the
  drawer's parameter block, written fresh before every call — and `hoist_y` is
  not scratch: one routine sets it and another reads it three calls later. The
  rule has to be by address, not by direction.

- **AL never reached the index registers.** `shl al, 1`, `mov bl, al` and
  `inc bl` were all unrecognised, so BL kept whatever the caller had left.
- **A stored value that still depended on a register that then moved.** Stores
  keep the expression rather than the number, so that one call site inside a
  loop can be evaluated once per iteration. A routine that stores its column,
  does `inc bl`, and stores its row is storing the same expression twice —
  both then resolve with the later BL, and the sprite comes out at its own row
  twice over. Collapse a stored value when its register changes.

None of the eight would have been found from the coordinates. All eight are
obvious in the twenty instructions of the routine that the caller attribution
names.

**Where it ended.** 172 of 193 placements to 186, recall 89% to 96%. The last
two bugs did not move that number at all -- the shape they concern is
unreadable either way -- and they were worth fixing, because the reading had
been putting a sprite at the wrong place on every screen and now puts it at the
right one. A number that does not change is not the same as a change that did
not happen; the referee compares tuples, and a tuple can be wrong in one field
for a reason and in another for a bug. The seven
that remain are one fact: a routine picks its shape with `random() & 3` from a
table of four *different* entries, so there is no shape in the file to read,
and a second routine that writes no selector of its own inherits that pick.
That is the boundary of static extraction — and the point is that it is now
*established per placement* rather than asserted about the method. It had been
asserted through two revisions of an architecture document while six ordinary
bugs sat behind it.

**The rule.** When a comparison produces a difference, spend the next hook on
attributing the difference rather than on measuring the total more precisely.
A total tells you how far you have to go. An attribution tells you where to
stand. And the cost is usually a stack read: the caller is already on the
stack at the moment you are already stopped.

## When the program supplies its own hardware

Every hook above reads what the program does. This one is about what the
program *expects*, and it is a different failure: the emulator was faithful
everywhere except one place, and the one place was load-bearing.

The Oregon Trail's hunting mini-game would not run. It was entered, it drew,
its allocator and its overlap test both executed — and its hunter never took a
step. Raising the instruction budget from 1.5 to 3 billion changed nothing at
all: **the same 18,900 distinct addresses, the same 103 keyboard reads, the
same picture.** A longer run that is byte-identical is not a run that needs
more time.

`comrun.py` did not say where the budget ran out, only that it had, so the only
move left was to raise it again. It says now, and the answer was five
instructions:

```nasm
000764F  cmp word [0x16B4], 0       ; the high word of a 32-bit counter
0007654  jg 0x765F
0007656  jl 0x764F
0007658  cmp word [0x16B2], 1       ; the low word
000765D  jb 0x764F                  ; no tick yet -- go round again
```

and the only thing that moves that counter is at `0x10441`:

```nasm
0010441  push ax..bp
001044C  mov ax, 0x3348 / mov ds, ax   ; DGROUP, hardcoded -- an ISR does this
0010451  les ax, [0x16B2] / add ax, 1 / adc dx, 0
001046F  iret
```

The game **hooks the timer itself** — `SetIntVec(0x1C, …)` at nine call sites,
two of them wrapped around the mini-game — and an emulator that ticks the BIOS
word at `0040:006C` serves programs that read `0040:006C`, which this one does
not. `--timer-isr INT[,N]` now delivers the interrupt to whatever handler the
program installed, pushing a real `FLAGS/CS/IP` frame so the handler's `iret`
resumes where it left off.

**Three things had to be right, and each was wrong first.** They are worth
listing because the same three will recur on any program that hooks anything.

| | |
|---|---|
| **Take an interrupt number, not an address.** | The game ships packed. Early on, the handler's address still holds compressed bytes; jumping there gave 99,999 deliveries into rubbish — no interrupts requested, no ports written, no keys read. Reading the vector at each delivery waits for the program to install its handler, with no need to know when unpacking finishes. |
| **Respect `IF`.** | Hardware does not deliver a maskable interrupt while interrupts are disabled, and Turbo Pascal's `Crt` closes `cli` around the port writes in `Sound` and `Delay`. Fixing that exposed a second fault underneath: **Unicorn starts with `FLAGS` at `0x0002`** — a state no DOS program has ever been handed — so every delivery was then correctly refused. Invisible until something first tried to deliver one. |
| **Move `CS` with the jump.** | Unicorn keeps a segment base and a 16-bit `IP` separately. Restarting at the handler's linear address while `CS` still names the interrupted segment leaves the two disagreeing, and when the handler sits *below* that base the `IP` underflows and it never runs. One delivery ended the run at 26,900,030 instructions, at the same instruction every time; every 20,000 crashed after two deliveries and every 200,000 after one, so frequency was never the variable. |

**What transfers, and it is not about timers.** An emulator is a set of
promises, and a program only notices the ones it depends on. This toolkit had
already learned that once — Turbo Pascal reaches DOS by far-calling through the
vector table rather than executing `int`, so a zeroed table sends the program
to `0000:0000` in silence. This is the same lesson from the other side: the
table was filled in, and the *stubs in it were never invoked*. When a run stops
making progress, ask which promise the program is relying on, not how much
longer it needs.

**And a report that names a place is worth more than one that names a
symptom.** "Budget exhausted" led to three runs and four and a half billion
instructions. "Budget exhausted at 15FD:1784 (image 0x007654)" led to the
answer in one disassembly.

### The keyboard, the joystick and the screen are hardware too

Rollo and Moon Bugs (Windmill Software, 1983) never call `INT 16h`. Each
writes its own handler into the INT 09h slot of the vector table -- directly,
not through DOS -- reads the scancode from port 0x60 when IRQ 1 fires, keeps a
flag per key, and acknowledges the PIC itself. A `--keys` queue that only
`INT 16h` consumes never reached either, and both runs stopped in their title
loops. `--keyboard hw` makes a key what it is on the machine: a make code
latched in port 0x60 and an interrupt through whatever vector 9 holds, then
the break code the same way, `--key-every` instructions apart (200,000 by
default: a press shorter than a frame is never seen by a game that polls its
flags once a frame). Port 0x64 says when a scancode is waiting, for a program
that polls with IRQ 1 masked; the PIC's mask (port 0x21) and end-of-interrupt
(port 0x20) are kept, so a second scancode waits until the handler has
acknowledged the first. A key that reaches the BIOS's own handler -- vector 9
never replaced, or a handler that chains to the one it replaced -- goes on
into the `INT 16h` buffer as the same AX `--keys` gave. `--keyboard auto`
starts on `INT 16h` and switches the keys not yet read to the hardware at the
instruction that writes vector 9. It watches the write rather than looking
now and then: a program that installs its handler and reads its first key
forty instructions later has used both keys through `INT 16h` before any
periodic look notices. Five NASM fixtures in `tests/comrun/fixtures/` hold the
shapes: the handler written into the table, polling with IRQ 1 masked, a
handler that chains to the BIOS, the ordinary `INT 16h` reader, and a handler
that never acknowledges (its next scancode is held, not nested).

**The first key can be lost, and that is the program, not the harness.**
Rollo clears its last-scancode byte when its title loop starts, at about
342,000 instructions; a key delivered at 200,000 is wiped. A person presses
after seeing the title, and so should a run: `--key-every 400000` or more.

**Then the joystick took the game away from the keyboard.** Rollo probes for
a joystick by firing port 0x201 and counting how long its bits stay set, and
the alternating value every port read gets -- the answer that keeps timing
loops moving -- passes the probe. Its title loop reads the "fire button"
before the keyboard, and the noise sometimes held it down: an Esc, which in
Rollo only moves the menu, appeared to start a game, because the keyboard
handler's own port reads had shifted the noise. Zaxxon did the same, and a
comment in `comrun.py` beside the port reads records it; now there is a
switch: `--no-joystick` answers port
0x201 with 0xFF, as a PC with no game adapter does, the probe times out, and
the keyboard alone decides. Measured with it, over 20 million instructions:

| keys (`--keyboard hw --no-joystick`) | title checks | first play step | menu |
|---|---:|---:|---|
| none | 2,003 | 3,741,829 (the attract demo, after the menu times out) | one player |
| Esc, space | 1,084 | 1,682,310 | one player |
| Esc, Esc, space | 227 | 2,709,998 | two players |

(The first key of each row is the one lost above.) With only a space Rollo
stops on "PRESS ANY KEY" with the roller where it started; with arrows after
it the roller leaves its place and paints a trail.
Moon Bugs is driven the same way: a space leaves its "PRESS ANY KEY", and
"right, right" and "left, left" leave its ship in different places, one of
them exploded.

**What is on the screen is the adapter's business, not only memory's.** The
same 16 KB at B800:0 is 320 by 200 four-colour pixels in one mode and eighty
columns of character-and-attribute pairs in another, and the mode is in the
CGA's registers: mode control at 0x3D8, colour select at 0x3D9, the CRTC's
columns, rows, scanlines per row and start address behind 0x3D4/0x3D5.
Moon Bugs plays in eighty-column text with two scanlines a row and a
right-hand half block (0xDE) in every cell -- each cell two pixels, its
attribute's background on the left and foreground on the right, 160 by 100
in sixteen colours. Drawn as mode 4, as `comrun` always drew, that was
vertical stripes: the capture Kimi took of it, and 121,560 of 128,000 pixels
wrong on the fixture that reproduces it. `comrun` now keeps those registers,
and the BIOS's mode and palette calls, which write the same registers, and
draws from them once the program has touched any; a program that never does
is drawn as before, and one that sets mode 4 through the BIOS gets a
byte-identical picture. It also moved Rollo: its own `INT 10h` calls select
palette 0 at low intensity -- green, red, brown -- where the old capture
showed cyan, magenta and white.

**Text needs a font, and one ships now.** The CGA's is in IBM's ROM, so until
prompt 14 text came out as boxes -- Moon Patrol's first screen, forty-column
text, was 512 of them. `tools/fonts/cp437-8x8.txt` is code page 437 from
unscii-8 by viznut, which is in the public domain (the README beside it has the
source, the licence text and the date). It is not a copy of IBM's ROM: 54 of the
250 characters both fonts have are identical, 17 of those box drawing, and the
median character differs from IBM's in 11 of its 64 pixels. It has 252 of the
256 characters, every block, shade and box-drawing one among them; 0x0F, 0x7F,
0xA9 and 0xF9 are not in unscii-8, are drawn as hollow boxes, and the cells
holding them are counted. With it Moon Patrol's first screen reads "Game
Options", its keys ("F 1 Start a game with 1 player") and its settings ("Level:
Beginner", "Input: Keyboard"); 7 of its cells hold one of the four. `--font`
still takes 2,048 bytes of any other, a dump of the user's own adapter for
instance. Two fixtures, `text40.asm` and `text80.asm`, put every character on
the screen in both widths and the suite compares each pixel with the font's
own bitmaps, read by a parser of its own.

### The timer is hardware too

`--timer-isr INT[,N]` sends one interrupt straight to the handler that holds
its vector, every N instructions, and that is all it does. It ignores the
PIC's mask, never waits for an end-of-interrupt, and a handler that passes the
tick on to the vector it replaced -- as nearly every one does, so the BIOS can
keep the time of day -- reaches a stub that does nothing: the BIOS never
counts the tick and never raises INT 1Ch. Moon Patrol (1983) replaces vector 8
with exactly such a handler, `inc word ss:[0x5a] / jmp far ss:[0xc]`.

`--timer hw` makes IRQ 0 what it is on the machine: a frame pushed and a jump
through whatever vector 8 holds, every `--timer-every` instructions (20,000 by
default, the same as the tick written to 0040:006C without it), masked by bit
0 of port 0x21, held while IF is clear or an IRQ 0 is still in service, and
ranked above IRQ 1. When it reaches the BIOS -- vector 8 never replaced, or a
handler that jumps on to the one it replaced -- the BIOS's own INT 08h runs:
the tick at 0040:006C, INT 1Ch to whatever holds that vector, the
acknowledgement. The tick at 0040:006C is then counted only there, so a
program that takes vector 8 and never passes it on stops the time of day, as
it does on the machine. `--timer auto` starts as the default does and switches
at the write that replaces vector 8 or 1Ch. The fixture `irq0.asm` masks IRQ 0
for 65,536 instructions, then counts six ticks of its own and passes every
other one on, with INT 1Ch hooked as well. It prints `06030300` under `--timer
hw` and `auto`; under `--timer-isr 8` it prints `0D00000D` (13 ticks taken while
masked, none reaching INT 1Ch or the BIOS), and with no timer it waits for ever.

On Moon Patrol, `--timer auto` decides at instruction 46; over 40,000,000
instructions IRQ 0 is raised 1,999 times, every one taken by its handler and
passed on to the BIOS's. It is not what Moon Patrol needed to reach play,
though: F1 and a space bring a frame of play -- buggy, crater, tank, score
002200 -- at 40,000,000 instructions with the timer and without it, the terrain
a few pixels apart. The timer was what the run lacked as a measurement of the
program, not as a way past it.

**Writing a vector could run the instruction twice.** Both `auto` modes used
to stop the emulator inside the memory write that decides them, and Unicorn
then runs the writing instruction a second time. An install by `mov` survives
that; Moon Patrol installs by `xchg es:[bx+2], dx`, saving the old segment as it
writes the new, and the second swap left its own segment where the BIOS's
should have been saved -- so its handler passed every tick on to 1020:0020, in
its own data. The decision is now noticed between slices of at most 1,000
instructions instead; a test installs by `xchg` under both `auto` modes and
reads back 0F00, the BIOS's segment.

**And what Alley Cat waited for was a key.** Kimi's six captures of Alley Cat
(1984) were one black frame, the run spinning on `cmp ax, [0693h] / jz`, then
`test byte [06C1h], 80h`. Every instruction naming `[0x693]` in its code: two
`inc word es:[0x693]`, in its INT 09h handler and in its second entry, on every
make code -- it is a count of key presses, not of ticks. `[0x6C1]` and
`[0x6C2]` are the up-flags of the eleventh and twelfth scancodes in its table at
`[0x6A1]`, 0x15 and 0x31: Y and N. The loop waits for a key and then for one of
those two; Kimi sent a space. And the screen was black because the question --
"Do you want to use a joystick (Y/N)?", 36 characters, 36 calls -- is written
through `INT 10h AH=0Eh`, which comrun did not draw. Alley Cat never touches
vector 8 or 1Ch (`--timer auto` says so); it keeps time by calling INT 1Ah,
357,394 times in 40 million instructions (keys N, K and a space, 400,000
instructions apart). With `N`, `K` for Kitten and a space
the run passes the question, the skill menu and the page of instructions, and
reaches its alley under the "IBM PRESENTS Alley Cat" title, the cat on the
fence.

### Text through the BIOS

`--bios-text` draws what a program writes through `INT 10h` -- AH=09h and 0Ah at
the cursor, AH=0Eh as a teletype with carriage return, line feed, backspace and
the scroll at the bottom, AH=02h and 03h for the cursor (kept where the BIOS
keeps it, at 0040:0050), AH=0Fh answered with the mode, and a mode set clearing
the screen as the BIOS does. In a text mode the character goes into the
framebuffer; in graphics it is drawn from the font over the whole 8x8 cell in
the colour BL gives, bit 7 exclusive-or. It is off by default, and without it a
program that set up the adapter and then wrote text through the BIOS gets one
line saying how many characters went undrawn: Alley Cat's 36. Fixtures:
`biostext.asm` on a 320-wide screen, every pixel compared, and `biostty.asm` in
eighty columns, with a scroll.

### A software interrupt is hardware's too, once the program owns the vector

Unicorn hands every `int n` to comrun's hook instead of going through the
vector table, so a vector the program had replaced was never used. IRQ 0 and
IRQ 1 were made to go through the table (above); a program's own `int n` was
not, and Tapper (1983) is built on one. Its crack installs an INT 80h that turns
a disk read -- AH=02h, cylinder, sector, head, as the original's `int 13h` took
them -- into a seek and a read of `Tapper.Dat`, and the game calls `int 80h`
for every sector. comrun answered it by doing nothing, the read never
happened, and the run ended on the game's disk-error message with `Tapper.Dat` opened and never
read.

Now an `int n` goes where the CPU sends it whenever vector n no longer holds
comrun's stub: FLAGS, CS and the return IP pushed, IF and TF cleared, the
program's handler. An `int` from the stub itself -- a handler passing the call
on to the vector it replaced, which is the stub -- is answered by comrun as
before, so a program that hooks INT 21h and chains to DOS is answered by DOS,
once. Vectors the program never touched are answered exactly as they were, and
a CPU exception is not taken for an `int`. The run's report gains a line,
printed only when one went to the program, naming the vectors it replaced and
how many `int`s each handler took. The fixture `swint.asm` installs INT 80h
through DOS, writes INT 60h into the table and hooks INT 21h with a handler
that counts and chains: it prints three lines; under the old comrun it prints
nothing.

Two more were found by doing it. **A read over code already run ran the old
code.** Unicorn keeps its translation of code it has executed, and a file read
written from the hook, outside the guest, did not throw it away: the overlay
fixture's second call ran module 1's code from the cache over module 2's bytes.
The range a read writes is now dropped from the cache. **And the disk reset
did nothing.** Tapper's shim returns through `iret`, so its caller's carry is
whatever it was before `int 80h` -- set, on the first read of a span, by a
`cmp` before it. The caller retries four times and then calls `INT 13h AH=00h`,
the disk reset, whose return with carry clear is what lets the next read pass,
on the machine. comrun's answer left the carry set, so all twelve attempts
failed. A reset with no disk to reset now succeeds, as the BIOS's does.

With all three, Tapper reads `Tapper.Dat` through its own INT 80h (65 times in
2,000,000 instructions, 76 by 12,000,000) and gets past its disk-error screen
to a frame showing its select screen -- joystick or keyboard, one or two
players, three levels, sound on or off, and a prompt to press the button or the
space bar -- over its logo, and, with K and a space, to a frame showing four
bars in perspective, beer taps, two customers in hats and "50" at the top left. The overlaid fixture
calls its modules 1, 2 and 1 again through its own INT 3Fh manager. And The
Ancient Art of War, unpacked, gets through its first `int 3Fh` into overlay 1,
which stops at its own check for an EGA, VGA or Tandy -- an adapter comrun did
not have until `--adapter` (below).

### The adapter is the program's question, then its screen

Two games of prompt 16 wanted more than a CGA, and they ask differently.
**Rampage (1986) asks nothing**: it prints a one-line menu of the three
adapters and draws as it is told -- mode 4 and `.P4` files, mode 0Dh and
`.P16` files, or Tandy mode 9 and the same `.P16` files. **The Ancient Art of
War (1987) asks four times**, in overlay 1 at 19E1:0095 of the unpacked root,
read from its code and seen in a run: `INT 11h` (it keeps the equipment word,
and later rewrites 0040:0010's video bits on the EGA path); `INT 10h
AX=1A00h`, a VGA if AL comes back 1Ah; else `INT 10h AH=12h BL=10h`, an EGA if
BL changes, and only 3, 256 KB, will do; then the word at F000:C000, a Tandy
1000 if its low byte is 0x21. Nothing else is asked, and the machine byte at
F000:FFFE is not read.

`--adapter ega` and `tandy` answer those as the adapter's BIOS and ROM would:
an EGA changes BL to 3 (BH 0, CL 9) and has the equipment word 000Dh, its
video bits 00; a Tandy has 0x21 at F000:C000 and 002Dh; both 0xFF at
F000:FFFE; AX=1A00h goes unanswered on all three, which is how a BIOS without
VGA support leaves it. `cga`, the default, answers exactly as comrun always
has -- AH=12h and AX=1A00h unanswered, as a CGA's BIOS leaves them, nothing
written to the equipment word or the ROM -- and when a program asks for an EGA
or a VGA it says so under the run, with `--adapter ega` named.

**The EGA's picture is not in memory at all.** Mode 0Dh keeps four planes of
64 KB behind the one window at A000, and what a byte written there does is the
graphics controller's business: the sequencer's map mask picks the planes; in
write mode 0 the byte is rotated, or replaced by the set/reset colour on the
planes enable set/reset names, combined with the latches by the function
(replace, and, or, xor), and the bit mask chooses bit by bit between that and
the latches; write mode 1 stores the latches; write mode 2 spreads a colour.
A read loads all four latches and returns one plane (read mode 0) or a
colour-compare mask (read mode 1). comrun keeps the planes outside Unicorn's
memory, and hooks A000: a write goes through that logic, and a read is
answered by writing the result into memory in the hook, which runs before the
read -- measured, a word read and a `movsb` from A000 to A000 included. The
picture is the planes from the CRTC's start address, the offset register
apart, each pixel through the attribute controller's palette (3C0, or `INT
10h AH=10h`), read in a 200-line mode as RGBI from bits 0-2 and 4.

What the two games use, counted register by register in a run: Rampage writes
one plane at a time (map mask 1, 2, 4, 8, write mode 0, replace, bit mask
FFh), clears with set/reset on all four, reads each plane through read map
select, flips pages with the CRTC's start address and loads its palette with
AX=1002h; The Ancient Art of War writes 4.7 million bytes in 30 million
instructions with a partial bit mask after a read that loads the latches, uses
the xor function (data rotate 18h), map masks 1, 2, 4, 8, E and F, read mode 0
on every map, and flips pages at 4000h. Neither uses write modes 1 or 2, read
mode 1, rotation, and/or, or the attribute controller's port; the fixture
`ega0d.asm` uses all of them, and the suite works out every pixel from the
fixture's own arithmetic. Not modelled, and refused rather than drawn wrong:
odd/even addressing (the run stops at the access and says which register),
write mode 3, which an EGA does not have, the CGA-style shift register,
horizontal panning and a split screen (the picture is not drawn, and no PNG is
left). Rampage writes `out dx, ax` with AX 00CDh at 3CEh once -- index 0Dh,
which the EGA does not have -- and the write is ignored, as the EGA ignores
it, and counted under the screen.

**The Tandy's picture is part of the machine's RAM**, in 16 KB pages, and two
registers in port 3DF say which: the CRT page is shown, the CPU page is what
the window at B800 reaches. Rampage draws on one and shows the other, through
`INT 10h AH=05h AL=81h` and `83h`; comrun keeps the eight pages and swaps the
window when the CPU page changes, and draws the CRT page: lines in four banks
of 8 KB, two pixels a byte, high nibble first, each through the video gate
array's palette (3DA index 10h-1Fh, 3DE, or `INT 10h AH=10h`), four bits RGBI.
`tandy9.asm` draws on page 2 while page 6 is shown and then flips.

**Two models agreeing is the best check there is without the hardware.**
Rampage's EGA and Tandy character screens come from the same `.P16` files
through different code: planes against nibbles, and palettes that are each
other's bits reversed (EGA register 1 is blue, 01h; Tandy register 8 is blue,
1). The two captures are identical in 64,000 of 64,000 pixels.

### A key at the moment the program reads it, by the way it reads it

`--at ADDR=KEY` hands a key over when the program reaches an image offset, and
was refused with `--keyboard hw` and `auto`, because those send keys through
port 0x60 on a schedule and `--at` used the BIOS's buffer. And it was read
after the start-up run, so it had only ever reached a routine run by `--call`:
The Dam Busters' title would not have taken one in any mode. Now `--at` works
from the start in every mode and goes the way the program reads the keyboard
at that moment, whatever `--keyboard` says about the `--keys` queue: into the
BIOS's buffer while vector 9 is the BIOS's, as a make code and IRQ 1 through
the program's own INT 09h once it has one (the run stops before the
instruction at ADDR, raises IRQ 1 at once, and the instruction runs when the
handler returns), and in the buffer as well when that handler passes the key
on. The run says which, a line per key. `atkeys.asm` reads a key each way.

**Read what the program compares before choosing a key.** The Dam Busters
(1984) at its title: `call 0xD255` empties the BIOS's buffer (`while a key is
waiting, read it`) -- which is where Antigravity's blind space went -- then
0xD22E waits for any key through `INT 16h` AH=01h and 00h, comparing it with
nothing, or for its INT 1Ch counter to reach 0x301. Its own INT 09h (D271) and
INT 0 (D445) are installed only after the title, at 0x0065. The next screen,
a menu of three starting positions, waits at the same 0xD22E and takes AL
minus '1' from 0 to 9, or AH minus 3Bh (F1-F10). With `--at
D22E=0x3920,D22E=0x0231` -- a space for the title, '1' for the menu, each
through the BIOS's buffer -- the run reaches its map: a region's name beside
a compass, over a grey map of black lines, cyan lakes and magenta and cyan
symbols.

### The processor is an 8088

**LOCK.** Jungle Hunt (1983) times port writes with `lock nop` and loops with
`lock loop`, and Unicorn refused the first: invalid opcode at 0x49ED. It got
there legitimately: `call 0x49C0` at 0x0633, straight after its title, a
routine that puts its own handler in vector 8 and then finds the beam through
the light pen (below). comrec's walk stopped at the same byte, because
capstone 5 refuses `lock nop` too. An 8088 asserts its LOCK pin for any
instruction and runs it; a 386 refuses LOCK on anything but a read-modify-write
of memory, and Unicorn on less -- measured, on `nop` and on arithmetic into a
register (add, inc, not, cmp), with or without a segment override, while
`lock mov`, `lock loop`, `lock out` and the memory forms run with the prefix
ignored. `--cpu 8088`, comrun's default as the sweep's, steps over a LOCK in
an instruction Unicorn refuses: from Unicorn's invalid-instruction hook, the
instruction restarted one byte on, or with the LOCK replaced by a copy of the
prefix before it when another prefix comes first, put back once it has run.
The run says how many. `--cpu 386` leaves Unicorn as it is, which is not quite
a 386 (`lock mov` runs). The sweep does the same under its `--cpu 8088`.

**The CPU's exceptions go through the vector.** A divide error went to
comrun's answer, which did nothing, even where the program had a handler.
Asked to go on, Unicorn ran the divide again and called it a double fault
(INT 8), and the third time stopped with no hook called -- and the run
reported its budget exhausted at the divide. The reason is QEMU's: it keeps
the exception it is delivering until its own code has delivered it, and a hook
that delivers it is not that code (the sweep met the same, and restores a
saved context before each case). comrun now sends a divide error -- DIV, IDIV
or AAM -- to the program's INT 0 handler when it has one, stops the slice,
and restores a context saved before the run with every register written back
(FPU included), which clears the record: measured, five divide errors in a row
arrive as five INT 0. Where it returns is the 8088's: "Divide exceptions on
the 80386 always leave the saved CS:IP value pointing to the instruction that
failed. On the 8086/8088, the CS:IP value points to the next instruction"
(Intel, 80386 Programmer's Reference Manual, 1986, section 14.7, "Differences
From 8086", item 2, read in the HTML copy MIT's 6.828 course keeps,
`readings/i386/s14_07.htm`). So `--cpu 8088` pushes the address after the divide,
from its decoded length, and `386` the divide itself. The trap flag's INT 1,
which Unicorn raises after each instruction as an 8088 does, goes to the
program's handler too, and `int3` and `into` reach its INT 3 and 4 as `int n`
does. A divide error with no handler of the program's ends the run, saying
that DOS's handler prints "Divide overflow" and ends the program.
`except.asm` divides six ways (ModRM mod 0 to 3, a direct address, and AAM),
traps three instructions and raises INT 3 and 4: "6 3 1 1" on an 8088, its
handler given the address after each divide.

### Hardware the program reads back

Two of the four games read the hardware's state, which the alternating answer
every port read gets cannot be:

- **The 8253's count.** The Ancient Art of War, past its adapter check,
  measures the processor: counter 2 in mode 2 from 7950h, its gate opened,
  latched (port 0x43, 80h) and read back until the count is below 100, the
  loops counted. Two consecutive alternating reads never are. A count the
  program latched is now answered from a model -- what it loaded, counted down
  at 1,193,182 Hz, which in this harness's time is 65,536 counts to a timer
  tick of `--timer-every` instructions -- and a read with no latch is answered
  as before, so a game that reads port 0x40 for a random number runs as it
  ran. `pit.asm` is a calibration loop of its own (6000h, the gate opened
  after loading, down to 200): 828 loops, as the arithmetic says.
- **The light pen.** Jungle Hunt finds the CRT beam by clearing the light pen
  latch (3DBh), setting it (3DCh), reading the address it took from CRTC
  registers 10h and 11h, dividing by forty, and waiting for row 99. The noise
  made that divide overflow. Setting the latch now takes the address the 6845
  would be reading, from a beam that sweeps the CRTC's total once a frame,
  912 x 262 dots, 19,912 of the 8253's counts. `lightpen.asm` finds row 99.

And one byte of ROM a program names: Jungle Hunt switches INT 1Ch off by
pointing it at F000:FF53, where the IBM BIOS keeps an `iret`; the first tick
the BIOS's INT 08h passed on ran into the empty memory at F000. A vector
holding F000:FF53 is now no handler -- for `int`, the BIOS's tick and IRQs --
and the memory is left as it was, so a run that wanders through F000 goes as
it always went.

With these, Jungle Hunt passes 0x49ED (LOCK stepped over 2,256 times in 12
million instructions), comes back to its title, and with F1 given at 0x3780
(`--at 3780=0x3B00`) plays: the score line with the time at 4540, the player
hanging on a vine under the canopy. And The Ancient Art of War, unpacked,
under `--adapter ega`, passes its check and its calibration and, with no key,
runs on into a battle: an island with a fort and soldiers, two lines of
alerts, and a command bar.

## The referee is not the deliverable

The hunting screen was chased for hours as a photograph — drive the game to it,
dump the framebuffer — and every frame came back a half-drawn mess, because the
program was frozen mid-redraw at exactly the point above. Three runs with
different budgets and different keystrokes produced **pixel-identical** images,
which should have been read as evidence rather than shown as a result.

It did not need running at all. The field is a generator, and all of it is
static in the file: sprite tables of `(srcX, srcY, w, h)` with a stride of 8, a
per-region list of permitted kinds, `Random(4) + 5` objects, `x = Random(318 −
w)`, `y = Random(199 − h)`, redraw on overlap. Sixty lines of Python reading
those tables draws the screen — with its animals, whose entry rule is a
separate routine — and the *execution map from the emulator then confirms that
all eight routines it reimplements actually ran*.

That is the correct division of labour, and it is stated at the top of
`comrun.py` itself: the static render is the deliverable, this is the referee.
It has just enough BIOS to get a game to its first frame, including a keyboard
queue (`--keys`) and a clock that advances, both there because without them a
title screen waits forever; `--stop-at ADDR --stop-after N` stops on the Nth
arrival, to look at a frame other than the first. Its flags for programs
that supply their own hardware, `--poll-patience` (`04-pitfalls.md`),
`--timer-isr`, `--timer`, `--keyboard`, `--no-joystick`, `--bios-text` and
`--adapter` (above), are off by default; `--cpu` is an 8088 unless told
otherwise, which changes nothing for a program with no LOCK and no exception.
Reversing them cost most of a session. When a screen resists being
photographed, check whether it can be *computed* first — and if the answer
involves a table and a `Random`, it can.

## The referee that ships

Everything above was found by running Hard Hat Mack. That referee cannot ship:
it needs a copyrighted game, so on any other machine `placements.py` -- the
most valuable tool here and the one that took ten fixes in a session -- had
nothing checking it at all.

`tests/placements/` is the same referee on a program the repository owns. One
`.COM` fixture: a drawer, and one builder per shape that was once read wrongly
-- counts down, counts up, two variables, a per-slot guard, a routine that
writes no selector, a zero immediate. It is checked twice: against a table
written out by hand from the fixture's own data, and against the fixture run
under `comrun.py` with the drawer hooked. Two independent references, and if
they disagree the test says which one to doubt.

**It earned itself on the first run, and not in the way expected.** The
conditional-evaluation fix -- decide a branch, skip the arm that does not run
-- was written against Hard Hat Mack and measured against Hard Hat Mack, where
it removed six invented placements and broke nothing. It was wrong. Deciding a
condition during the linear walk settles *every* iteration of the loop by the
first one, and the reason the game did not notice is that its slot tables are
all zero: skipping every slot was the right answer by accident. The fixture's
table alternates 1, 0, 1, 0, and the bug was visible immediately.

Then the fix for the fix was wrong too, in the same shape: the guard was
carried to the call site and evaluated per iteration, but only ever against
zero -- and one routine draws a slot whose state is *not 2*. Hard Hat Mack
caught that one, because four toolboxes vanished. The two tests fail on
different things.

**What transfers.** A real program is a biased sample of its own patterns. It
exercises the shapes its author used, with the data that author chose, and a
tool tuned against one is tuned against that bias -- including the places where
two wrongs happen to cancel. A fixture is where you write the case the game
does not contain. Neither is sufficient: the game is the only proof the tool
works on real code, and the fixture is the only proof it works for the right
reason.
