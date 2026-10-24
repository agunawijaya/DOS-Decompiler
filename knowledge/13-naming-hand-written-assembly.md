# 13 — Naming hand-written assembly

Karateka was compiled C. Everything the toolkit learned there — prologues,
library signatures, a FILE table with a stride — assumed a compiler had been
through the code first. ParaTrooper, Zaxxon and Hard Hat Mack were written by
hand. Between them they have zero `push bp` prologues and no runtime, so
`probelib.py` returns nothing on all three: 0 of 250 entry points in Hard Hat
Mack, which is a measurement, not a failure.

What follows is what worked instead.

## The caller count is not evidence, and it fails the same way every time

Across the three games, fourteen routine names had been assigned from how many
callers a routine had. **Every one of them was wrong.** Not most: all of them.

| game | the name | what the bytes do |
|---|---|---|
| ParaTrooper | `draw_sprite`, 7 callers | `state = state * 0x7781 + 0x64C9` — an LCG |
| ParaTrooper | `move_actor` | walks eight countdown timers and pokes port 0x42 |
| ParaTrooper | `spawn` | ten rows of a bitmap into video memory |
| Zaxxon | `draw_cell`, 13 callers | returns a pointer to the current player's context |
| Zaxxon | `port_write` | zeroes 0x2000 words of the frame buffer |
| Zaxxon | `level_step` | prints a string |
| Hard Hat Mack | `shift_history`, 16 callers | saves the position in a tune |

The failure is structural, not careless. A high caller count means a routine is
*central*, and a plausible story about what a central routine does is easy to
write and impossible to check. The name then propagates: `input_latch` and
`input_latch_2` in Hard Hat Mack were named after `shift_history` wrote to them,
so one guess produced three wrong names and a wrong mental model of the sound
code, which is in fact a software pulse-width modulator on a one-bit speaker.

Name from what a routine does to what. If you cannot say that, leave it
unnamed — `symbols.json` supports an `_unread` list for exactly this, and a
count of 35 honest names reads better than 221 dishonest ones.

## Two sources, and what makes them two

AGENTS.md says never to commit a name on one source of evidence. Rollo
(Windmill, 1983) was named with 97 of its 103 routine names committed, each
on one free-text string, and nothing could count them. Moon Bugs, named next
by the same agent, gave every name a list of two -- and the lists show that
two entries are not two sources.

**Two observations are independent when either could have been wrong while
the other was right.** In practice they are of different kinds:

- what the routine does to what: the ports it touches, the memory it writes
  and reads, the interrupt it raises;
- what the rest of the program does with it: who calls it with which
  arguments, which reader consumes what it writes, which table holds its
  address;
- what another program shows: a routine `comdiff.py` finds
  instruction-identical to one already named, *and* confirmed by running both
  -- which carries over the other program's evidence, so it is worth only as
  much as that name was;
- what a run shows: the routine observed doing it under `comrun.py`;
- what the program says about itself: a string it prints, a table of its own
  variables.

**Not two: one instruction described twice.** Two entries that cite one
address are usually one `mov` read once for what it stores and once for
where. Name the reader as the second source instead.

**Not two: the callee's name restating the description.** Moon Bugs'
top-level routine was "installs the keyboard ISR, sets up the video, runs the
game loop" and, as its second source, "calls install_keyboard_isr". The
second entry is the first, read off a name this same session gave the
callee. If that name was wrong, both entries were.

**Not two: a pair of names that confirm each other.** The key handlers'
second entries were "paired with" the handler for the opposite edge of the
same key. That is where the two sit in the dispatch table, which is one fact;
the names on both sides came from the same reading. The handlers whose only
other entry was "reached from the dispatch table" were rightly left
`__maybe`.

**Not two: how something is reached, for what it does.** Rollo's
"require the CGA or die" routine was committed on one string: it calls the
error printer, and it is used when the adapter check fails. The first is
what it calls and the second where it is called from; neither says anything
about the half of the name that claims the program stops.

**Two, and worth copying.** Moon Bugs' saved data segment was named from its
writer (the install routine stores DS there) and its reader (the interrupt
handler loads DS from it) -- two instructions in two routines, and the reading
confirms the purpose the writing only suggests (`12-hooking-the-right-thing.md`
names globals the same way). Its keyboard handler stands on what it does --
reads port 0x60, stores the scancode, acknowledges the PIC -- and on being
instruction-identical to Rollo's, confirmed by running both.

**And identity is not sameness.** The routine that looks a scancode up in the
handler table has the same instructions in both games, but counts 21 entries
in Rollo and 15 in Moon Bugs, and running both shows it: the name carries,
"the same routine as Rollo's" does not. A claim made from the instruction
comparison alone would have been wrong about the behaviour.

### What `annotate.py` checks

When a symbol file gives a name's evidence as a list -- `"0x062F1":
["keyboard_isr", ["reads port 0x60 ...", "instruction-identical to ..."]]` --
`annotate.py` counts it before writing anything:

- a name without `__maybe` and with fewer than two non-blank entries is
  **refused**, every such name listed, and nothing is written;
- two entries that cite the same address (other than the entry's own), or the
  same routine of the symbol file, are **warned** about;
- an entry citing a routine whose name's words all appear in another entry's
  prose is **warned** about as the same observation twice. Identifiers are
  taken out of the prose first: the saved data segment's "saved by
  install_keyboard_isr" and "restored by keyboard_isr" are a writer and a
  reader, although the first identifier holds every word of the second.

On the two games' symbol files: Moon Bugs' 70 names pass the count and draw
one warning, the top-level routine above. Rollo's 198 give their evidence as
one string each, which cannot be counted; that form is still accepted, with
one warning saying how many. Counting is necessary and not sufficient: two
entries can be independent and wrong, and three can restate one guess in
words no check will match. The warnings are where to look; the judgement is
still yours.

## Find the program's own account of its variables

ParaTrooper's start-up zeroes its state from a table at `ds:0x1A30`: seventeen
`(address, length)` pairs. Every entry landed on something already named from
behaviour, with the matching width. That table turned a reading into a
cross-check, and it cost nothing to look for.

Programs of this era almost always have one, because clearing the BSS by hand
is cheaper than clearing it in code. Look for a short run of ascending word
pairs where the first of each pair is a plausible data address, near the
start-up path.

## A table usually ends where the thing it points into begins

Zaxxon's tile table starts at `cs:0x1FDD` and its first entry is `cs:0x2099`.
Ninety-four entries later the table ends — at `cs:0x2099`. The sprite table at
`cs:0x2613` ends at `cs:0x269B`, which is its own first bitmap. Neither
boundary was chosen; both were measured, and their agreeing is what makes the
extents facts rather than estimates.

This gives a free length for any pointer table whose targets follow it, which
in hand-written assembly is most of them. It also gives a check: if the count
you derive from the first entry disagrees with the largest index the code can
produce, one of the two is wrong.

## Two segments mean two namespaces

Zaxxon patches its own `mov ax, imm16` at load time so DS sits 0x5200 bytes
past CS — past the end of the 20,736-byte file. Every table it reads is
`[cs:...]` and inside the image; every variable it writes is `[...]` and in
memory the file never described. `[0x0055]` and `[cs:0x0055]` are two different
addresses.

`annotate.py` now takes a segment prefix on a key (`"cs:0x04E8"`), and a
prefixed reference matches only a prefixed key. Without that, one name would
have covered both — a lie that still assembles, which is the specific kind of
mistake the byte-identity rule exists to catch and cannot.

It also now names `[bx + 0x052d]`. Compiled code addresses a global directly;
hand-written code puts the base in a register, so the bare-bracket form the
tool started with matched almost nothing in these three games. Hard Hat Mack's
`scanline_table` had been in its symbol file for a whole session without ever
being substituted. BP- and SP-relative displacements are excluded, because
`[bp + 0x08]` is an argument and not whatever global happens to live at 8.

## Data that decodes is still data

Six bracketed constants in Hard Hat Mack survived every other check and are
not addresses. `and bx, word [0x001E]` is a run of table bytes that happens to
encode as an instruction, inside a run comrec classified as code because it
decoded cleanly all the way through. NASM re-emits the same bytes, so
byte-identity says nothing about it either way.

This is the mirror of the question `knowledge/11` answers. There: are unreached
bytes code? Here: are reached bytes that decode actually data? Both come down to
what refers to them, and nothing referred to these. The reason it matters is
that a naming pass will happily invent a variable for each one, and six
plausible variables in a symbol file are six things the next reader will
believe.

The tell is that the "address" is referenced exactly once, from inside a run
with no incoming branch, and nothing writes it.

## Count call targets, not prologues

Karateka is compiled C, and its symbol file said "nothing is unnamed" against
the only denominator that seemed natural: 120 `push bp` prologues, all named.
The listing has **165 call targets**. Fifty-six routines the program calls had
no name while the figure read 100%.

They were not exotic. Lattice C's runtime is hand-written assembly with no
prologue at all -- `lmul`, the console poll, the CRTC programming -- and the
compiler generates tail entry points inside its own functions that are called
directly and never prologued. A prologue count sees none of it.

This is the denominator problem from `knowledge/12` in a second costume, and it
is worth stating as a rule: **the set you must cover is the set of addresses
something transfers control to.** Direct calls, jump-table entries, and the
targets of any `call word [...]` your reconstruction resolved. Prologues are a
way of *finding* routines, never a way of counting them.

The check is two lines against the listing, and it belongs in the build:

    calls = {addr for every `call L_xxxxx`}
    unnamed = calls - set(symbols["routines"])

## Corollary: check what coordinate a key is in

The same `scanline_table` entry was recorded as `0x042d`, its **file offset**,
while every other key in that file was an **address**. It was also recorded as
600 words when the loops that walk it count 200. Nothing caught either, because
a symbol that never substitutes cannot fail loudly.

Add the check to the build: every routine key should match a label in the
listing, and every bracketed address in the listing should either have a name
or be on a list of ones you decided not to name.

## One address, two prefixes, one variable

Hard Hat Mack's keyboard handler reads `[cs:0x0781]` while everything else
reads `[0x0781]`. The game sets DS = CS, so those are one variable, and the
prefix is there only because an interrupt cannot trust DS. Zaxxon's `cs:` and
bare addresses, by contrast, are genuinely different memory.

So the duplicate-name check has to be on the *number*, not the prefix: two keys
may share a name when they resolve to the same address, and must not when they
do not. Getting that backwards either forces two names onto one variable or
lets one name cover two.
