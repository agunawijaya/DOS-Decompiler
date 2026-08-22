# 15 — Recognising adventure-engine shape

The 1980s adventure-game template is a specific and recognisable
architecture, and this toolkit needs to be able to read it without
being fooled by the two things it is easiest to be fooled by:
compressed text that looks like graphics command streams, and data
regions that Ghidra insists on disassembling as code. Both mistakes
happened in one project (Transylvania, in the sibling `retro-ports-2`
repo, 2026-08-21). One survived for **five decompilation sessions**
before being caught. This document is what would have caught it in
one afternoon.

## The pattern, in one paragraph

A late-1980s illustrated adventure engine will typically have:

- A **byte-code virtual machine** with 40–100 opcodes, dispatched
  through a magic-byte lookup table (not a dense `switch`).
- A **parser pipeline** — tokeniser → grammatical classifier →
  combinatorial parser → rule-table walker → VM.
- **Compressed text** stored in one or more banks, decoded through
  a **Huffman-family bit-stream decoder** with three small primitive
  functions (byte-fetch, bit-test, fetch-and-mask).
- **Vector graphics** stored as pen-command streams, one record per
  scene or per object, drawn by a separate interpreter.
- A **container format** shared by most data files: two-byte header
  size, WORD offset table, variable-length records.

If you find any three of these five, expect the other two. That is
worth writing down because it turns *"what am I looking at?"* from a
scan of the whole binary into a hypothesis to test.

## The mistake that survived five sessions

Transylvania's room files (`Ra`, `Rb`, `Rc`) hold 39 records that
open with the byte `0xF3`, followed by bodies that use the
high-nibble values `0x80`, `0xA0`, `0xC0`, `0xE0`. Session 2
concluded they were **Graphics Magician vector command streams** on
those two grounds: the `0xF3` looked like a "stream type" marker,
and the `80/A0/C0/E0` pattern matched the shape of period vector
formats where the high nibble names a command family (move / line /
fill / colour).

Sessions 3–6 built on that assumption. Session 6 wrote a first-pass
renderer, which produced garbage. Session 7 walked
`FUN_1000_1d5d` — the loader that reads a message bank embedded in
the executable — and found that **its sub-records also start with
`0xF0..0xF6`** and are read by the same decoder function
(`FUN_1000_0710`) as the R records. If the same decoder feeds
both, and one of them is unambiguously text (the message bank is
called by the message displayer), then both are text.

The rendering attempts had been decoding compressed characters as
vector coordinates. That is why they produced garbage — not because
of an incomplete command grammar, but because there was no grammar
to complete. There is only bit-packed English prose.

## The rule that would have caught it

> **When two data streams feed the same decoder, they are the same
> kind of data. Follow the code path that consumes a stream before
> hypothesising about its content.**

The specific check, in practice: for every candidate data format
you are decoding, find the routine that reads it and note **what
other data that routine also reads**. If it reads two visibly
different things and treats them identically, the classification
you gave them is wrong.

A tool that would have surfaced this automatically: a **decoder-map
report** that clusters data files (and embedded data regions) by
the last routine that touched them. In Transylvania's case, R
records and segment-2616 sub-records would have clustered together
because both are terminated by `FUN_1000_0710`'s call, and the
mismatch with the *"one is graphics, one is text"* interpretation
would have flagged the misreading. This is worth building.

## Compressed-text stream markers: the `0xF?` family

Every compressed stream in Transylvania starts with one byte in the
range `0xF0..0xF6`. The distribution across ~230 messages
concentrates on `0xF5` (~40%), with `0xF2`, `0xF6`, `0xF0`, `0xF4`,
`0xF3` filling in. The high nibble `1111_` is fixed; the low nibble
selects a decoder variant.

**The reason for this design** is straightforward: any ASCII byte
in the range `0x20..0x7E` has its high nibble in `0x2..0x7`, and no
control character has it in `0xF`. A stream marker in `0xF0..0xFF`
therefore cannot be confused with the first character of decoded
output. Comprehend's designer picked `0xF0..0xF6` (7 of the 16
available codes) to leave the other 9 free for future variants.

**Recognising it in a strange binary**: if a data file or embedded
region opens with a byte in `0xF0..0xFF` and the following bytes
have high entropy (near 8 bits per byte, no obvious repeating
structure), it is probably a compressed text stream. Contrast this
with vector graphics command streams, which have low entropy
(specific opcode bytes repeat often) and structured coordinate
distributions.

**A cheap test**: compute the byte-frequency distribution of the
record body. If a small set of bytes (10 or so) accounts for >50%
of the record, it is likely vector graphics. If no byte accounts
for more than ~1.5% (uniform-ish distribution), it is likely
compressed text.

## The bit-stream decoder shape (Huffman OR fixed-width)

Once you suspect a routine is a bit-stream decoder, the shape is
recognisable in three small primitives that surround a larger
decoder function:

- **A byte fetcher** — 15–25 bytes, reads `[stream_base +
  index]`. In Transylvania: `FUN_1000_0830`, 18 bytes.
- **A bit-tester** — 20–30 bytes, tests one bit in a bitmap using
  a precomputed 8-entry mask table. In Transylvania:
  `FUN_1000_0842`, 24 bytes. The mask table `0x80, 0x40, 0x20,
  0x10, 0x08, 0x04, 0x02, 0x01` is the telltale — no other data
  structure uses that specific sequence.
- **A fetch-and-mask** — 25–35 bytes, reads from a *second*
  stream and ANDs with a stored mask. In Transylvania:
  `FUN_1000_085a`, 31 bytes.

The main decoder function is 200–400 bytes, mostly a chain of
comparisons against known-constant state values, calling the three
primitives repeatedly.

**A cheap identification test**: search for the mask table `80 40
20 10 08 04 02 01` as consecutive bytes in the data segment. In
Transylvania it is at DS offset `0x33d3`. If found, follow the
references to that address; the routines that read it are the
bit-tester and (transitively) a bit-stream decoder.

### Don't assume Huffman — verify

**The three-primitive pattern does not uniquely mean Huffman.**
Session 8 of Transylvania's decompilation established this the
expensive way: the primitives above were assumed to feed a Huffman
decoder for four sessions before disassembly of `FUN_1000_1643`
(the actual character-producing routine) revealed a **fixed-width
5-bit-packed encoding with three shift states** — closer in spirit
to Baudot code than to Huffman. The primitive pattern was there,
but the primitives were called by a **message-selector**
(`FUN_1000_0710`) that picks which message ID to display based on
game state, not by the decoder itself.

Two distinguishing tests to run before committing to a Huffman
hypothesis:

1. **Look for a codebook tree in the data.** Huffman decoders need
   a codebook — either an explicit tree structure, a canonical-length
   table, or a lookup table indexed by bit patterns. If no such
   structure is present in the interpreter's initialised data, the
   format is probably not Huffman.
2. **Simulate the extraction on real input and count output group
   sizes.** If every N input bytes produce exactly M output values,
   the format is fixed-width (probably `M × log2(alphabet_size)` bits
   per group). Huffman would produce variable numbers of output
   values per input byte.

Transylvania's format produced exactly 8 output values per 5 input
bytes, invariably — the tell of fixed-width 5-bit packing (5×8=40=8×5).

### The shift-chain algorithm (Comprehend-specific)

The bit-extraction algorithm in Comprehend's `FUN_1000_1643` is not
a straightforward "extract 8 fields of 5 bits from 40 bits" — it
uses a specific SHR + RCR × 7 sliding-window shift that produces
its 8 output values via a permutation of the input bit positions.
The algorithm is documented in detail in
`transylvania/docs/08-huffman-decoder.md` (filename retained for
URL continuity despite the corrected format identification).

If you encounter a similar shift-chain-plus-extraction pattern in
another 1980s adventure engine, expect it to be a fixed-width
packed encoding, not Huffman — the shift-chain would be pointlessly
elaborate for Huffman (which walks a tree one bit at a time), but
is exactly the tool for permuted fixed-width extraction.

### Character-set shift codes

Once you know a text stream is fixed-width bit-packed, look for
**escape values** that switch character sets. Baudot uses 0x1B
(SHIFT-OUT) and 0x1F (SHIFT-IN). Comprehend uses 0x1E and 0x1F to
switch between three shift states (lowercase, uppercase, digits +
punctuation). RAD-50 does something similar. The pattern is:

- Small alphabet (~30 values) that fits in 5 bits per character.
- Two or three shift codes to expand to ~90 characters total.
- Shift codes are usually the *largest* values in the alphabet
  (0x1E, 0x1F for 5-bit) because those values are reachable only
  by explicit encoder choice, not by accident.

The character-set table is small (30–100 bytes total, split into
2–3 banks of 28–32 characters each). Search for consecutive runs
of printable ASCII in the load image: an alphabet run of 26+ letters
followed by another run of 26+ letters is almost certainly a
shift-state character table.

## Ghidra's blind spot on data-as-code

Segment 2616 in Transylvania has 12,300 bytes of data. Ghidra
recognises **four "functions"** inside it, at addresses `2616:1274`,
`2616:141a`, `2616:1c05`, `2616:2112`. All four are wrong. The
tell is:

```
2616:1274:  enter 0x404f, 0
            hlt
2616:141a:  enter 0x404f, 0
            cmc
            mov  [0x4fc8], ax
            ...
2616:1c05:  enter -0x39b1, 0
            ...
2616:2112:  enter -0x1900, 0
            ...
```

**Every "function" starts with `ENTER imm16, 0`** using an absurd
immediate (`0x404F` = 16463 bytes of stack allocation is nonsense
for a 12 KB program). The disassembler took the byte `0xC8`
(`ENTER` opcode) at data positions where a `0xC8` byte happened
to appear, and interpreted the following two bytes as its
immediate. Every subsequent instruction inherits from that wrong
start.

**A cheap identification test for data-in-code-region**: look for
`ENTER imm16, 0` where `imm16 > 0x1000` (larger than any
plausible stack frame). Every function in Transylvania's segment
2616 disassembly matches. In real code, `ENTER` is exceedingly
rare — used mostly by Pascal compilers for deeply nested scopes,
and even then the immediate is usually under 256. A hit on this
pattern is a strong signal that Ghidra chose the wrong boundary.

**The tool this would justify**: a post-Ghidra pass that flags
suspected data-in-code segments by scanning for anomalous `ENTER`
immediates, and reports what percentage of a segment is
"function starts" that fit this pattern. If a segment has 4
"functions" all opening with `ENTER 0x????, 0`, treat it as data
until proved otherwise.

## The two-tier container format

Transylvania's R and O files, and its embedded segment 2616, all
share a container format:

- Bytes 0–1: `header_size` as a WORD (16 for segment 2616, 34 for
  R/O files, 130 for segment-2616 sub-records — different values,
  same convention).
- Bytes 2 to `header_size - 1`: an array of WORD offsets, each
  pointing to a record start within the file (or within the parent
  container).
- The last offset in the array is a **file-end sentinel** — it
  equals the file's total size. This lets the reader compute the
  last record's length as `sentinel - offsets[N-1]` without
  knowing the file size separately.
- Records at the pointed offsets have their own format, which may
  itself be another container of the same shape.

Two things to know about this format:

- **Stale offsets past the last valid record.** Comprehend's file
  writer reused a scratch buffer across files without clearing it,
  so files with fewer records than the header can hold contain
  garbage in the unused offset slots. In Transylvania: `Rc` has 9
  real records; slots 10–15 hold offsets from `Rb` byte-for-byte.
  **A reader that trusts every slot will index into garbage.** The
  correct check is *"is `offset[i+1] > offset[i]` and
  `offset[i+1] <= file_size`?"*; the first slot that fails marks
  the end of valid records.
- **Nesting is allowed.** Segment 2616 is a container of 4 banks;
  each bank is itself a container of 63 sub-records. The same
  `header_size + offset_table` pattern works at both levels
  because there is no self-referential magic — just an offset
  table.

**Recognising the format in a strange file**: read the first WORD.
If it is a small even value (16, 20, 32, 34, 64, 128, 130), treat
it as a candidate header size. Read the next `(header_size - 2) /
2` WORDs. If they are monotonically increasing and the last equals
the file size, you have found the format. This test succeeds on
seven out of seven Comprehend files without false positives.

## What to check first, in order, for a new adventure binary

1. **Prologue density** (`triage.py` reports it). Adventure
   engines from this era are almost always hand-written assembly
   (0 prologues/KB). If you see 10+ prologues/KB, it is compiled
   C — the analysis is different.
2. **The mask table `80 40 20 10 08 04 02 01`** in the data
   segment. A hit means there is a Huffman-family decoder.
3. **The first WORDs of any data file**. If they look like
   monotonically increasing offsets ending in the file size, you
   have the two-tier container format above.
4. **The byte-code dispatcher pattern**. Look for a small (15–20
   byte) function containing `cmp al, [di + imm]; jne short-back;
   shl di, 1; mov ax, [di + imm2]; call ax`. That is a
   magic-byte-lookup byte-code dispatcher, and the two immediates
   are the addresses of the magic-byte table and the fn-pointer
   table.
5. **Which routines write to the video segment.** In Transylvania
   the video segment is stored in a state variable, not used as
   an immediate, so a scalar search for `0xB800` or `0xB000`
   comes up empty. Instead look for hardware detection code that
   writes those constants **once** during setup — the routine
   containing the write is where the video-mode dispatch lives.
6. **Which routines feed which decoders.** For each stream-fetcher
   pattern (a routine that reads from a base pointer and
   increments it), list who calls it. If two visibly different
   data sources feed the same fetcher, they are the same kind of
   data — regardless of what their first-byte patterns suggested.

The last item is the one worth acquiring tool support for. In
retrospect it would have saved five decompilation sessions.

## What this means for the toolkit

Concrete additions worth writing:

- **A stream-clustering report.** Given a set of data files (or
  in-executable regions) and a set of routines that read them,
  cluster the streams by which routine last touched them. A stream
  that shares its consumer with a known-text stream is text; one
  that shares with a known-graphics stream is graphics.
- **A data-in-code detector.** A post-Ghidra pass that scans
  recognised functions for `ENTER imm16, 0` with `imm16 > 0x1000`
  or other anomalous instruction patterns, and reports segments
  where the "function" density is dominated by these. Recommend
  reclassifying the segment as data.
- **A Huffman-decoder locator.** Search the data segment for the
  8-byte mask table `80 40 20 10 08 04 02 01` and, if found,
  trace back to find the three primitive functions and the main
  decoder. Report their locations as a hypothesis.
- **A container-format detector.** For each data file in the
  target's folder, test whether the first WORD is a plausible
  header size and whether the following WORDs form an increasing
  offset table ending in the file size. Report matches.

Each of these is a one-file Python script of 50–150 lines. All
four together would turn what took Transylvania seven sessions
into what a smart afternoon should be able to do.

## The rule

> **A stream's format is defined by what consumes it, not by what
> it looks like.** Before deciding a byte pattern is graphics
> commands, verify that no other visibly-different stream feeds
> the same decoder. If one does, both streams are one kind of
> data, and *"this looks like a `move-to (X, Y)` command"* is a
> false positive on a Huffman-encoded character.

## Extracting a room map without decompiling the byte-code

For an adventure-game engine that stores movement rules inside its
byte-code (rather than in a static room-connection table), the map
seems inaccessible without naming the byte-code opcodes first. That
naming is genuinely weeks of work.

**There is a shortcut**: a minimal Unicorn-based emulator plays
the game and captures its own text output. Every room description
mentions its exits ("*A path leads north*", "*Paths lead west and
south*"). The room graph falls out of parsing that prose.

Applied to Transylvania in session 10 (2026-08-22) with roughly
**250 lines of Python**:

- **MZ loader** — parse header, apply relocations, load image
  into simulated 8086 memory.
- **PSP setup** — allocate a fake PSP segment with `INT 20h` at
  offset 0.
- **INT 21h stubs** — 3D open, 3F read, 3E close, 42 seek, 4C
  exit, 30 get-version. Filesystem emulated from a directory.
- **INT 16h stubs** — 00 wait-for-key fetches from a script queue;
  01 check-key reports emptiness. When queue empty on 00, stop
  emulation so driver injects more keys and resumes.
- **INT 1Ah timer stub** — return advancing tick count. Necessary
  for games with real-time animation or death timers.
- **Port I/O hooks** — `0x3DA` and `0x3BA` return retrace-bit flip
  in case the game syncs on CGA/Hercules vertical retrace.
- **Memory-write hook on the text-output buffer** — captures every
  character the game's word-wrap emitter writes. That buffer's
  address is identified from disassembly of the emitter routine
  (in Transylvania: `DS:0x3416`).

**With this in place, playing the game is just scripting**: feed
keystrokes and read what emerges. Parse for room descriptions
(*"You are ..."*), for exit hints (*"A path leads"*, *"Paths
lead"*), and for object mentions (*"A ... lies on the"*). Build a
map from the observations.

Cost of the emulator vs the alternatives, measured:

| approach | time to first map fragment | prerequisite |
|---|---|---|
| Naming byte-code opcodes | weeks | full opcode-table walk |
| DOSBox debugger interactive | hours | human player |
| **Unicorn scripted emulator** | **half a day** | disassembly of the text-output routine |

The Unicorn approach also captures **text that no static analysis
can produce**. Session 10's first live output revealed the IBM PC
port programmer's name, which is embedded in the compressed
credits screen and only decodes when the decoder runs on it under
emulation. Every claim about credits, dialog, and per-room text
becomes checkable by running the game.

### Traps in emulator-based mapping

- **Real-time death traps.** If the game kills the player on a
  wrong move, the emulator sees the death message and a restart
  prompt. Detect these (*"restart"*, *"game over"*, specific
  fiction) and inject the restart key. Then resume from a
  known-safe path.
- **The keyboard-empty stop is essential.** If the emulator's
  keyboard queue empties and `INT 16h AH=00` (blocking read) is
  called, the emulator must STOP execution — not spin forever
  waiting for a key that will never arrive. The Python driver
  detects the stop and either injects more keys or terminates the
  session.
- **Timer-driven events fire.** Games with a real-time deadline
  will eventually kill the player from waiting, regardless of
  what commands are sent. Cap the tick rate at something the
  game accepts.
- **The word-wrap buffer is not the same as the actual video
  buffer.** Hooking `0xB800` or `0xB000` would capture only the
  glyph writes to VRAM — every character rendered as pixels, not
  as ASCII. Hook the pre-glyph buffer instead, where the emitter
  places the character byte before rendering.

### When it does not work

- **When the game requires video refresh timing** beyond simple
  retrace-bit toggling — some 1985 games do proper animation
  frames tied to real hardware.
- **When copy protection needs a working disk or dongle** — the
  emulated filesystem serves file bytes but does not model
  low-level disk timing.
- **When the game reads absolute memory addresses that only real
  DOS provides** — some programs read from `0000:0000..0400` (the
  interrupt vector table) to check whether specific handlers are
  installed.

None of these applied to Transylvania. They may apply to Sierra
AGI or LucasArts SCUMM titles, which are more hardware-aware.
Budget extra hours for stubs if attempting those.
