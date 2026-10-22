"""Python candidates for sweep.asm's routines, for `emuverify.py sweep`.

Each takes (args, ctx) -- the arguments as the domain writes them, and ctx
with the globals (read only) and call(target, *args) -- and returns what the
routine leaves behind: {"ax": ...}, {"writes": {...}}, or {"fault": ...}.

The ones whose names end in a description of a mistake are wrong on purpose,
each at one boundary; tests/sweep/regress.py expects the sweep to stop at
exactly the first input where that mistake shows. Every divide is modelled as
an 8088 does it, the sweep's default CPU; the ones that divide as a 386 does
say so in their names, and are right under --cpu 386.
"""


def int16(value):
    """The low 16 bits, read as signed: what a 16-bit register holds."""
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def idiv(dividend, divisor):
    """IDIV's quotient, truncated toward zero, where Python's // rounds down."""
    quotient = abs(dividend) // abs(divisor)
    return -quotient if (dividend < 0) != (divisor < 0) else quotient


def muldiv(args, ctx):
    """As an 8088 divides: the divide fault on a zero divisor, on a quotient
    that does not fit, and on the quotient -32768, which fits and which an
    8088 refuses all the same."""
    a, b, c = args
    product = int16(a * b)                  # IMUL, of which C keeps AX
    if c == 0 or not -32768 < idiv(product, c) <= 32767:
        return {"fault": "divide"}
    return {"ax": idiv(product, c)}


def muldiv_as_a_386_divides(args, ctx):
    """Returns -32768 for -32768 / 1, as a 386 does: right under --cpu 386,
    and wrong at that input for an 8088."""
    a, b, c = args
    product = int16(a * b)
    if c == 0 or not -32768 <= idiv(product, c) <= 32767:
        return {"fault": "divide"}
    return {"ax": idiv(product, c)}


def muldiv_without_overflow_fault(args, ctx):
    """Knows about division by zero, not about -32768 / -1."""
    a, b, c = args
    product = int16(a * b)
    if c == 0:
        return {"fault": "divide"}
    quotient = abs(product) // abs(c)
    if (product < 0) != (c < 0):
        quotient = -quotient
    return {"ax": quotient}


def quot7(args, ctx):
    """n / 7 by a word IDIV, as an 8088 divides: the divide fault when the
    quotient does not fit a word, and when it is -32768."""
    (n,) = args
    if not -32768 < idiv(n, 7) <= 32767:
        return {"fault": "divide"}
    return {"ax": idiv(n, 7)}


def quot7_as_a_386_divides(args, ctx):
    """Returns -32768 where an 8088 faults: right under --cpu 386, and wrong
    at n = -229,382, the first such input, for an 8088."""
    (n,) = args
    if not -32768 <= idiv(n, 7) <= 32767:
        return {"fault": "divide"}
    return {"ax": idiv(n, 7)}


def quot7b(args, ctx):
    """n / 7 by a byte IDIV, as an 8088 divides: the divide fault when the
    quotient does not fit a byte, and when it is -128. CBW widens the rest."""
    (n,) = args
    if not -128 < idiv(n, 7) <= 127:
        return {"fault": "divide"}
    return {"ax": idiv(n, 7)}


def quot7b_as_a_386_divides(args, ctx):
    """Returns -128 where an 8088 faults: wrong at n = -902 for an 8088."""
    (n,) = args
    if not -128 <= idiv(n, 7) <= 127:
        return {"fault": "divide"}
    return {"ax": idiv(n, 7)}


def clamp_store(args, ctx):
    (x,) = args
    limit = ctx.globals["g_limit"]
    if x > limit:                           # signed, as JLE is
        return {"writes": {"g_over": x - limit, "g_hits": ctx.globals["g_hits"] + 1}}
    return {"writes": {"g_under": (x & 0xFFFF) >> 2}}     # SHR: unsigned


def rare(args, ctx):
    (x,) = args
    return {"ax": 7 if x == 0x1234 else x & 0xFF}


def rare_masking_seven_bits(args, ctx):
    """Masks with 0x7F where the original masks with 0xFF: right below 128."""
    (x,) = args
    return {"ax": 7 if x == 0x1234 else x & 0x7F}


def rare_loops_at_sixteen(args, ctx):
    """Never returns for x = 16. Behind the sweep's case timeout that is a
    hang at one input, not a sweep that never ends."""
    (x,) = args
    while x == 16:
        pass
    return {"ax": 7 if x == 0x1234 else x & 0xFF}


def rare_misspelt(args, ctx):
    """Answers in a field the contract does not have. The sweep stops rather
    than compare nothing."""
    (x,) = args
    return {"Ax": 7 if x == 0x1234 else x & 0xFF}


def caller(args, ctx):
    a, b = args
    r = ctx.call("helper", a, b)
    if a < b:                               # signed, as JGE is
        r += ctx.call("helper", b, 1)
    return {"ax": r}
