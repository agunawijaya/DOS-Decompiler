# 18 — Sweeping a routine against the original

A port of a 1984 game reimplements the original's arithmetic, and it goes
wrong at single inputs. A product that should wrap at 16 bits, a shift that
should be unsigned, a comparison one step off. Nobody thinks to try those
inputs, and a game played for an hour may never reach them.

`emuverify.py` already runs functions under emulation, but on four input
vectors chosen to make a function branch. That is the right shape for its job,
carrying names from one binary to another, and more vectors measurably made
that job worse (`03-what-works.md`). It is the wrong shape for proving a port.
The DX-Ball case study that came with rea showed the other shape. It ran the
original x86 routine on every input of a domain — every screen position 0 to
640, at five scales, 3,205 cases — against the new implementation.

`emuverify.py sweep` does that for any routine of an MZ program. The
candidate is a rebuilt binary, a Python reference or a JavaScript port. It
runs every case of a declared domain on both sides and stops at the first
input where they disagree. It also says how much of the routine the domain
reached.

## Where it sits on the ladder

| Rung | Oracle | Proves |
|---|---|---|
| 2 | instruction-identical, layout-tolerant — `bindiff.py` | the code is right |
| **3s** | **exhaustive sweep over a declared domain — `emuverify.py sweep`** | **this routine's compared outputs equal the candidate's on every input of that domain, and nothing outside it** |
| 3a | per-function behavioural equivalence — `emuverify.py` | this function is that function |

**A passing exhaustive sweep sits below rung 2 and above rung 3a, for that
routine, over that domain.**

- *Above 3a:* rung 3a runs four vectors chosen to make a function branch,
  and concludes identity from agreement on them. An exhaustive sweep leaves no
  input of its domain unchecked. Every output it compares — return registers,
  every global's final value, every call and its arguments, every fault — is
  checked for every case.
- *Below 2:* an instruction-identical rebuild is right for every input there
  is, for every output, by construction. A sweep says nothing about an input
  outside its domain, an output it was not told to compare, or a callee, which
  it stubs. Nor does it say anything about the code its domain never reached.
  The coverage line says how much of the routine that is.
- *A sampled sweep is not on rung 3s.* It is rung 3a with more cases: agreement
  on the inputs tried, boundary values first. The output says "sampled", with
  the seed.

## Running one

The examples below use `tests/sweep/fixtures/`. `sweep.asm` is the original;
`ref.py` and `port.mjs` hold the candidates. The entries are the ones the
pipeline's `functions.json` gives the assembled fixture. Run the pipeline on
the original first: the sweep reads the routine's `body` from its
`functions.json`, to measure coverage against it.

```
python tools/emuverify.py sweep ORIGINAL.EXE SEG:OFF --domain domain.json
       (--candidate ref.py:fn | --candidate port.mjs:fn
        | --candidate-exe REBUILT.EXE --candidate-entry SEG:OFF)
       [--functions out/functions.json] [--all] [--trace-on-divergence N]
       [--evidence result.json] [--dgroup PARA] [--max-cases N] [--seed S]
       [--cpu 8088|386]
```

Exit 0 verified, 1 mismatch, 3 blocked: the domain or the candidate could not
be read, or the candidate answered outside the contract.

### The Python example, complete

`muldiv` is `int muldiv(int a, int b, int c) { return (a * b) / c; }`. It is
compiled the way a C compiler of the period does it: `IMUL`, keep the low
word, `CWD`, `IDIV`. The product wraps at 16 bits. `IDIV` faults when `c` is
0, and when the wrapped product is -32768 and `c` is -1, because +32768 does
not fit. On an 8088, the sweep's default CPU, it also faults when that product
meets `c = 1`: the quotient -32768 fits, and an 8088 refuses it all the same
(below, "The CPU").

The domain, `muldiv.json`:

```json
{
  "args": [
    {"name": "a", "range": [-300, 300]},
    {"name": "b", "list": [1, 3, 128]},
    {"name": "c", "range": [-3, 3]}
  ],
  "compare": ["ax"],
  "max_cases": 20000
}
```

The candidate, in `ref.py`:

```python
def int16(value):
    """The low 16 bits, read as signed: what a 16-bit register holds."""
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def idiv(dividend, divisor):
    """IDIV's quotient, truncated toward zero, where Python's // rounds down."""
    quotient = abs(dividend) // abs(divisor)
    return -quotient if (dividend < 0) != (divisor < 0) else quotient


def muldiv(args, ctx):
    a, b, c = args
    product = int16(a * b)                  # IMUL, of which C keeps AX
    if c == 0 or not -32768 < idiv(product, c) <= 32767:
        return {"fault": "divide"}          # zero, out of range, or -32768 on an 8088
    return {"ax": idiv(product, c)}
```

The run, verbatim:

```
> python tools/emuverify.py sweep SWEEP.EXE 1000:0024 --domain muldiv.json \
         --candidate tests/sweep/fixtures/ref.py:muldiv --functions out/functions.json
original   SWEEP.EXE 1000:0024, near; DGROUP 0x000c (the segment the startup loads into DS, at 1000:0003)
candidate  ref.py:muldiv (Python 3.11.9, in this process)
domain     a range -300..300, b list of 3, c range -3..3; 12,621 cases in all
cases      12,621 run of 12,621 (exhaustive)
compared   ax, and faults
cpu        8088: IDIV faults on a quotient of -32768 or -128
agree      12,621 (1,807 divide faults on both sides)
coverage   8 of 8 instructions in the body (100.0%)
time       0.88 s, 14,375 cases/s

VERIFIED over 12621 cases (exhaustive), 100.0% of the body exercised
```

The 1,807 faults can be checked by hand. `c = 0` faults for every `a` and
`b`: 601 × 3 = 1,803. A wrapped product of -32768 with `c = -1` happens only
at `b = 128` and `a = ±256`, because 256 × 128 = 32768 wraps to -32768: 2 more.
The same product with `c = 1` is the 8088's two: 1,807. Under `--cpu 386`,
with a candidate that divides as a 386 does, it is 1,805.

### The JavaScript example, complete

A JavaScript number is a 64-bit float, and its bitwise operators work on
32-bit signed integers. A 16-bit machine is neither, so a port has to say
where it wraps:

| The 8086 | JavaScript |
|---|---|
| the low 16 bits, signed (what `CWD` and `IMUL` keep) | `(v << 16) >> 16` |
| the low 16 bits, unsigned | `v & 0xffff` |
| `SHR`, an unsigned shift of a 16-bit value | `(v & 0xffff) >>> n` |
| `SAR`, a signed one | `((v << 16) >> 16) >> n` |
| a product (exact where `a * b` may not be) | `Math.imul(a, b)` |
| `IDIV`'s quotient, toward zero | `Math.trunc(p / q)` |
| a divide fault | `return { fault: "divide" }`; JavaScript divides by zero without complaint |
| the quotients an 8088's word `IDIV` returns | `-32768 < q && q <= 32767`; -32768 is a fault (-128 for a byte) |

`clamp_store` uses two globals, presets a third and shifts unsigned:

```c
void clamp_store(int x)
{
    if (x > g_limit) { g_over = x - g_limit; g_hits++; }
    else             g_under = (unsigned)x >> 2;
}
```

The domain, `clamp_store.json`. `g_limit` is swept like an argument, `g_hits`
is preset before every case, and `g_over` and `g_under` are named so that
writes to them compare by name:

```json
{
  "args": [{"name": "x", "range": [-50, 50]}],
  "globals": [
    {"name": "g_limit", "offset": "0x0000", "list": [-60, 10]},
    {"name": "g_over",  "offset": "0x0002"},
    {"name": "g_hits",  "offset": "0x0004", "value": 5},
    {"name": "g_under", "offset": "0x0006"}
  ],
  "compare": ["writes", "calls"]
}
```

The candidate, in `port.mjs`, with `muldiv` beside it for the wrapping:

```js
const int16 = (v) => (v << 16) >> 16;

// IDIV on an 8088: null for the divide fault, else the quotient.
const idiv8088 = (dividend, divisor, low, high) => {
  if (divisor === 0) return null;
  const q = Math.trunc(dividend / divisor);
  return low < q && q <= high ? q : null;
};

export function muldiv([a, b, c], ctx) {
  const product = int16(Math.imul(a, b));          // IMUL, of which C keeps AX
  const q = idiv8088(product, c, -32768, 32767);
  return q === null ? { fault: "divide" } : { ax: q };
}

export function clampStore([x], ctx) {
  const limit = ctx.globals.g_limit;
  if (x > limit) {
    return { writes: { g_over: x - limit, g_hits: ctx.globals.g_hits + 1 } };
  }
  return { writes: { g_under: (x & 0xffff) >>> 2 } };  // SHR
}
```

The run:

```
> python tools/emuverify.py sweep SWEEP.EXE 1000:0033 --domain clamp_store.json \
         --candidate tests/sweep/fixtures/port.mjs:clampStore --functions out/functions.json
original   SWEEP.EXE 1000:0033, near; DGROUP 0x000c (the segment the startup loads into DS, at 1000:0003)
candidate  port.mjs:clampStore (Node v22.17.0, one process for the sweep)
domain     x range -50..50, g_limit list of 2; 202 cases in all
cases      202 run of 202 (exhaustive)
compared   writes, calls, and faults
cpu        8088: IDIV faults on a quotient of -32768 or -128
agree      202
coverage   14 of 14 instructions in the body (100.0%)
time       0.03 s, 7,703 cases/s

VERIFIED over 202 cases (exhaustive), 100.0% of the body exercised
```

The same port with `x >> 2`, `SAR` where the original has `SHR`, run with
`--all`:

```
first divergence, case 2:
  input      x=-50 g_limit=10
  original   writes g_under=0x3ff3, calls none
  candidate  writes g_under=0xfff3, calls none
  differs    writes

MISMATCH at case 2: x=-50 g_limit=10: writes differs -- original writes g_under=0x3ff3, calls none; candidate writes g_under=0xfff3, calls none
```

`--all` counts 50 such cases. That is every negative `x` with the limit at
10, and none with the limit at -60, where every `x` is above it.

## The contract

Exactly as `tools/sweep.py` states it.

**Python**, `path/to/ref.py:function_name`, is imported into the sweep's own
process. **JavaScript**, `path/to/port.mjs:functionName`, runs in one Node
process for the whole sweep (`tools/sweep_harness.mjs`), which reads cases as
JSON lines on stdin and writes one result line each on stdout. Node is not
started per case: the result records how many processes answered, and the
tests check it is one. A `console.log` in a port goes to stderr, so it cannot
corrupt the stream.

Both receive `(args, ctx)`:

- **`args`**: one number per argument, as the domain writes it. An `int16`
  argument arrives as -32768..32767, a `uint16` one as 0..65535. The original
  receives the same value as a 16-bit word, and a 32-bit argument as two.
- **`ctx.globals`**: read only. Every declared global's value for this case:
  the swept or preset value as the domain writes it, otherwise what the image
  holds (signed when the global says `"signed": true`).
- **`ctx.call(target, ...args)`**: records a call the routine makes and returns
  its stub. `target` is a name from the domain's `callees`, or an address for a
  target not listed. The stubs are the original's: the n-th call of a case
  returns `(0x1234 + 7n) & 0xFFFF`, unless `stubs` names another.

Both return an object, or a bare number, which means `{ax: number}`. The
object holds any of:

| field | meaning |
|---|---|
| `ax`, `dx` | 16-bit; compared modulo 65536, so -1 and 65535 agree |
| `"dx:ax"` | a 32-bit result, instead of `ax` and `dx` |
| `carry` | 0 or 1, or a boolean |
| `writes` | `{name: value}` for the globals the routine changed, compared modulo their size. A global not mentioned keeps its `ctx.globals` value. A byte no global names is `"0x0123"`. |
| `fault` | `"divide"`, `"hang"` or `"cpu"`: what the original did instead of returning. Nothing else is compared on such a case. In Python a `ZeroDivisionError` counts as `"divide"`. |

These count as divergences, at the input where they happen:

- a compared field left out;
- a fraction where the machine holds an integer, the port that forgot
  `Math.trunc` (`ax '-9045.333333333334, not an integer'`);
- an exception.

A field the contract does not know, or a value that is not a number, stops the
sweep instead: those are almost always a misspelling (`{"Ax": 7}`), and
comparing nothing would look like agreement.

**A candidate that never returns is a hang, not a sweep that never ends.**
Past `--case-timeout` seconds on one case (default 10), the candidate's
outcome for that case is `hang`, compared like any other: a port that loops
where the original returns diverges there. A Python candidate is interrupted
by an exception raised into its loop, between bytecodes, so it must be
looping in Python; one blocked inside a C call runs on until the call
returns. A Node process stuck in a case is killed, and a new one takes the
cases after it. That happens once: the second time a Node process stops
answering, by a hang or by dying, the sweep is `blocked`, because a port that
loops on many inputs would otherwise cost a timeout and a Node start each.
Before this, a candidate that looped on one input stopped the sweep for good:
measured, the code before the timeout was still waiting at case 17 after 60
seconds. The timeout costs nothing measurable. Old and new code alternating
over five rounds of the 65,536-case `rare` sweep gave best times of 3.83 s
against 3.84 s for Python (+0.3%) and 4.40 s against 4.40 s for JavaScript.
The runs themselves spread far wider than that difference: the old code's
five Python runs took 3.83 to 4.80 s, and its JavaScript runs 4.40 to 5.60 s.

**Writes are compared as their effect.** That is the final value of every
declared global, and every other byte of DGROUP the original changed, below
the stack frame at 0xF000. A port does not write bytes, it sets variables. So
"the routine wrote 5 where 5 already was" and "the routine did not write" are
the same answer.

**A binary candidate** (`--candidate-exe`, `--candidate-entry`) runs exactly
as the original does. It has its own DGROUP, found the same way; its own
global offsets (`candidate_offset`); and its own callee addresses
(`callees.<name>.candidate`). A rebuild seldom keeps either where the original
had it.

## What the original does that a port must match

**A divide fault is an outcome, not a crash.** `IDIV` by zero, and a quotient
that does not fit — -32768 / -1 for a word — end the case as `divide`, and on
an 8088 so does a quotient of exactly -32768 (below). The candidate must say
`fault: "divide"` for exactly the same inputs. Forgetting the second condition
is the classic port error. In the tests a Python
candidate that knows only about zero fails at case 941, `a=-256 b=128 c=-1`:

```
first divergence, case 941:
  input      a=-256 b=128 c=-1
  original   divide fault at 1000:002e
  candidate  ax=0x8000 (-32768)
```

**16-bit wraparound.** A port that computes `a * b` without wrapping it agrees
on every case until the product leaves 16 bits. Here that is case 15,
`a=-300 b=128 c=-3`, where -38400 wraps to 27136:

```
first divergence, case 15:
  input      a=-300 b=128 c=-3
  original   ax=0xdcab (-9045)
  candidate  ax=0x3200 (12800)
  differs    ax

the original's last 6 instructions on case 15:
  1000:0027  mov ax, word ptr [bp + 4]
  1000:002a  imul word ptr [bp + 6]
  1000:002d  cdq
  1000:002e  idiv word ptr [bp + 8]
  1000:0031  pop bp
  1000:0032  ret
```

(`cdq` is capstone's name for byte 99 in 16-bit mode, which is `CWD`. Unicorn
executes it as `CWD`; only the name is wrong.)

**Signed versus unsigned shifts and comparisons.** `SHR` against `SAR` above;
`JGE` against `JAE` in `caller`, where a port comparing unsigned makes one
call fewer at `a=-2 b=0`.

**Interrupts are skipped,** as in `emuverify.py`: an `INT` does nothing. A
routine that depends on DOS or the BIOS is compared with that dependency
removed, and the envelope's `limitations` says so.

### The CPU: an 8088, unless `--cpu 386`

Unicorn implements `IDIV` as the 80386 does. Intel's own list of the
differences says: "The 80386 can generate the largest negative number as a
quotient for the IDIV instruction. The 8086/8088 causes exception zero
instead." ([*Intel 80386 Programmer's Reference Manual*, §14.7, "Differences
From 8086"](https://flint.cs.yale.edu/cs422/readings/i386/s14_07.htm).)
[Ken Shirriff's reading of the 8086's divide
microcode](http://www.righto.com/2023/04/reverse-engineering-8086-divide-microcode.html)
explains why: it divides unsigned and fixes the sign afterwards, so a quotient
of -32768 counts as an overflow. Left to Unicorn, `-32768 / 1` returns -32768
(measured: no interrupt, AX = 0x8000), where an 8088 raises the divide fault.
A port matched against that would match a 386, not the PC the game shipped
for.

So the sweep is an 8088 by default (prompt 08). A hook on every `IDIV` reads
the divisor from its operand -- a register, or memory through the
instruction's own segment, base, index and displacement -- takes the dividend
from `DX:AX` (a word divide) or `AX` (a byte divide), and works the quotient
out, truncated toward zero. When it is exactly -32768 for a word or -128 for a
byte, the case ends as `divide` on that `IDIV`, after the same number of
instructions as a fault Unicorn raises itself. Division by zero and a
quotient that fits neither CPU are left to Unicorn. `DIV` is not touched: the
two CPUs agree on it. The prose says which CPU it was, on a line of its own,
and so do the envelope's `result.cpu` and its `limitations`. The original's
fault says why when only an 8088 would raise it:

```
first divergence, case 9:
  input      n=-229382
  original   divide fault at 1000:00af (an 8088 refuses the quotient -32768)
  candidate  ax=0x8000 (-32768)
  differs    fault
```

`--cpu 386` is the old behaviour, for a program known to have needed a 286 or
later. A binary candidate runs on the same CPU as the original. The
comparison mode of `emuverify.py` is not touched: its output on three runs
was byte-identical to that from before the change.

**What a candidate has to do.** Divide as an 8088 does. A quotient is a divide
fault when it is out of range or exactly the most negative value:

```python
def idiv(dividend, divisor):
    quotient = abs(dividend) // abs(divisor)        # toward zero, not down
    return -quotient if (dividend < 0) != (divisor < 0) else quotient

def quot7(args, ctx):
    (n,) = args
    if not -32768 < idiv(n, 7) <= 32767:            # -32768 included: an 8088 refuses it
        return {"fault": "divide"}
    return {"ax": idiv(n, 7)}
```

```js
// IDIV on an 8088: null for the divide fault, else the quotient.
const idiv8088 = (dividend, divisor, low, high) => {
  if (divisor === 0) return null;
  const q = Math.trunc(dividend / divisor);
  return low < q && q <= high ? q : null;          // -32768 < q <= 32767 for a word
};

export function quot7([n], ctx) {
  const q = idiv8088(n, 7, -32768, 32767);
  return q === null ? { fault: "divide" } : { ax: q };
}
```

For a byte divide the bounds are -128 and 127. The comparison is `low < q`,
not `low <= q`: written the 386's way, the port verifies under `--cpu 386`
and fails under the default at the first input whose quotient is the most
negative value, which is what the tests check.

**The fixture.** `tests/sweep/fixtures/sweep.asm` has `quot7(long n)`, `n /
7` by a word `IDIV` of `DX:AX` by `CX`, and `quot7b`, the same by a byte
`IDIV` of `AX` by `BL`. Swept over the 21 values either side of the boundary,
7 × -32768 = -229,376:

| n | quotient | 8088 | 386 |
|---|---|---|---|
| -229,390 .. -229,383 (cases 1-8) | below -32768 | fault | fault |
| -229,382 .. -229,376 (cases 9-15) | -32768 | **fault** | 0x8000 |
| -229,375 .. -229,370 (cases 16-21) | -32767 | 0x8001 | 0x8001 |

Under the default, a candidate that models the 8088 verifies with 15 faults
on both sides; one that divides as a 386 does fails at case 9, `n=-229382`.
Under `--cpu 386` the reverse: 8 faults, and the 8088 candidate fails at case
9 with the original returning 0x8000. The byte form gives the same table at n
= -910 .. -890, around 7 × -128 = -896. `muldiv` meets the rule too, through
a memory operand: its wrapped product -32768 divided by 1 is two more faults
on an 8088, 1,807 where a 386 has 1,805.

The same section of Intel's list notes a second difference, which does not
reach a sweep: "On the 8086/8088, the CS:IP value points to the next
instruction", where the 386 saves the one that failed. It matters only to a
program with its own `INT 0` handler, and the sweep stops at the fault. Other
ways an 8088 differs from a 386 are not modelled either.

## Exhaustive and sampled

The domain is the product of every swept argument and global. When it holds at
most `max_cases` cases, all of them run, the first dimension slowest. The
output says `exhaustive`. A domain of exactly `max_cases` cases is exhaustive;
one more and it is sampled. The tests check both edges.

Otherwise it says `sampled`, with the seed, and runs:

1. **Every boundary value of every dimension.** These are min, max, 0, ±1, and
   each power of two with one either side. That takes in the sign boundaries:
   0x7FFF and 0x8000 for a `uint16`, -32768 and 32767 for an `int16`. A
   list's every value counts as a boundary. If every combination of these fits
   in `max_cases`, all combinations run. Otherwise each boundary value runs
   once, with the other dimensions at boundary values the seed picks.
2. **Seeded random cases**, up to `max_cases`, none repeated.

Three `int16` arguments at `max_cases` 3000 and seed 7 gave 261 boundary cases
— 87 per argument — then 2,739 random ones. A sampled sweep that passes ends
`VERIFIED over 3000 cases (sampled, seed 7)`. It never says exhaustive, and
its `unknowns` asks what the routine does on the inputs it did not run.

## Coverage

Every instruction the original executes, across the whole sweep, is recorded.
The routine's `body` in `functions.json` (prompt 03) says which instructions
it has, so the sweep reports the share it exercised and lists the ranges it
never reached:

```
> python tools/emuverify.py sweep SWEEP.EXE 1000:0055 --domain rare.json \
         --candidate tests/sweep/fixtures/ref.py:rare --functions out/functions.json
original   SWEEP.EXE 1000:0055, near; DGROUP 0x000c (the segment the startup loads into DS, at 1000:0003)
candidate  ref.py:rare (Python 3.11.9, in this process)
domain     x range 0..1000; 1,001 cases in all
cases      1,001 run of 1,001 (exhaustive)
compared   ax, and faults
cpu        8088: IDIV faults on a quotient of -32768 or -128
agree      1,001
coverage   8 of 10 instructions in the body (80.0%)
             never reached: 1000:0060..1000:0064 (2 instructions)
time       0.06 s, 17,794 cases/s

VERIFIED over 1001 cases (exhaustive), 80.0% of the body exercised
```

`rare` returns 7 for 0x1234 and `x & 0xFF` otherwise. The domain 0..1000 does
not include 4660, so the two instructions of that branch never ran. The sweep
proved the other eight, and says so on the line that says VERIFIED. Over every
`int16`, 65,536 cases, it reaches all ten.

Without `--functions` the sweep still runs and still compares. It reports how
many instructions it executed, says it had no body to measure against, and
lists that as an unknown.

## The output

Prose, ending with one line:

```
VERIFIED over <n> cases (<exhaustive|sampled, seed s>), <c>% of the body exercised
MISMATCH at case <k>: <inputs>: <fields> differs -- original ...; candidate ...
```

And `--evidence` writes the envelope (`17-evidence.md`): tool
`emuverify sweep`, status `verified` or `mismatch` (`blocked` when it could
not start). The `result` holds:

- the original and candidate, with each one's DGROUP and how it was found;
- `cpu`, `8088` or `386`;
- the domain, with each dimension's boundary values;
- `mode`, `seed`, `cases_run` and `agree`;
- `faults_on_both_sides`;
- `first_divergence`: inputs, both outputs, the fields that differ;
- `coverage`, with `unreached` ranges.

`--all` runs every case and groups the divergences by field, three examples
each. `--trace-on-divergence N` re-runs the first divergent case and lists the
last N instructions the original executed.

## Measured

On the machine this was built on (Windows 11, Python 3.11.9, Unicorn 2.1.4,
Node 22.17.0): the arithmetic fixture's `muldiv` (12,621 cases, exhaustive)
and `rare` over every `int16` (65,536 cases), each run twice, without
`--functions`. The rate is the sweep's own `time` line, cases only. Measured
again in prompt 08, on an 8088, the default:

| candidate | muldiv, cases/s | 65,536 cases, s |
|---|---|---|
| Python | 13,349 – 14,611 | 4.05 – 4.11 |
| JavaScript, one Node process | 12,607 – 13,049 | 4.36 – 4.52 |
| binary (two emulations a case) | 7,732 – 8,045 | 6.90 – 7.26 |

Before the 8088 (prompt 05) the muldiv rates were 16,774 – 16,899, 13,896 –
14,790 and 8,626 – 8,668. The difference is the 8088's hook: muldiv runs one
`IDIV` a case, and three runs of each measured 14,050 – 14,198 cases a second
under `--cpu 8088` against 16,602 – 17,177 under `--cpu 386`, about 12 µs an
`IDIV`. `rare` has no `IDIV` and runs as fast as before.

Most of the cost is the emulation, not the candidate: a binary candidate,
which runs the emulator a second time per case, takes about twice as long as
a Python one. Node's rate is lower on a short sweep, where its start-up is a
larger share (202 cases at about 7,700 a second).

**One emulator instance serves a whole sweep, and that has a trap,
measured.** A divide fault ended with `emu_stop`
leaves Unicorn 2.1.4 believing it is still delivering that exception. The
next divide fault in the same instance arrived as interrupt 8, a double
fault, and the one after as no interrupt at all. Saving the CPU context once
after setup and restoring it at the start of every case (0.4 µs) puts it
right. A tool that creates a new instance per run, as `emuverify.py`'s
comparison does, never sees this.

## What it does not do

- **Follow calls.** Each is skipped and stubbed, so the comparison stops at
  the routine's edge. Compare a callee by sweeping it.
- **Raise interrupts**, or model the hardware.
- **See self-modifying code.** An instruction is decoded once, the first time
  it runs.
- **Compare what it was not told to.** Memory the routine reads, flags other
  than carry, and registers other than AX and DX are not compared.
- **Say anything outside the domain.** An exhaustive sweep over 0..1000 is
  silent about 1001.
