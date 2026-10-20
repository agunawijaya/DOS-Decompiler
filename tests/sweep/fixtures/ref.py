"""Python candidates for sweep.asm's routines, for `emuverify.py sweep`.

Each takes (args, ctx) -- the arguments as the domain writes them, and ctx
with the globals (read only) and call(target, *args) -- and returns what the
routine leaves behind: {"ax": ...}, {"writes": {...}}, or {"fault": ...}.

The ones whose names end in a description of a mistake are wrong on purpose,
each at one boundary; tests/sweep/regress.py expects the sweep to stop at
exactly the first input where that mistake shows.
"""


def int16(value):
    """The low 16 bits, read as signed: what a 16-bit register holds."""
    value &= 0xFFFF
    return value - 0x10000 if value & 0x8000 else value


def muldiv(args, ctx):
    a, b, c = args
    product = int16(a * b)                  # IMUL, of which C keeps AX
    if c == 0 or (product == -32768 and c == -1):
        return {"fault": "divide"}          # IDIV: zero, or a quotient that does not fit
    quotient = abs(product) // abs(c)       # IDIV truncates toward zero;
    if (product < 0) != (c < 0):            # Python's // rounds down
        quotient = -quotient
    return {"ax": quotient}


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
