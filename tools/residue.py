#!/usr/bin/env python3
"""
residue.py -- What bytes that nothing claims as code actually look like.

Shared by the two routes that ask the question. `comrec.py` asks it of the
bytes in a .COM's code region that no decoded instruction covers;
`bodies.py` asks it of the bytes in an MZ's code segments that no function's
body covers. Both must answer the same way, so the rules live here once.

How a run is classified
-----------------------
In this order, the first that fits, with comrec's thresholds (knowledge/11
has how each was arrived at):

  zero     nine tenths zero: padding, or a table not filled in yet
  text     three fifths printable, four bytes or more
  table    three words or more, seven tenths of them landing in code
  code     the caller's test, built on `decode_run` and `plausible` below
  other    everything else, which is mostly artwork

"It disassembles" is worth nothing on its own -- every byte sequence does --
so `plausible` refuses what a 1980s real-mode program has no reason to
contain, and `decode_run` refuses a run any instruction of which is not
plausible, does not decode, or runs past the end. What counts as code beyond
that differs by route, so each caller passes its own test: comrec wants some
control flow anywhere in the run; bodies.py wants a run that ends in a return
or an unconditional jump.

What it does not do
-------------------
It never decides that bytes *are* code, only what they look like. Nothing
here changes what either tool claims or emits.
"""

# Real-mode instructions a 1980s game has no reason to contain. Meeting one
# while sweeping unreferenced bytes means the sweep has wandered into data.
IMPLAUSIBLE = {
    "insb", "insw", "outsb", "outsw", "arpl", "bound",
    "into", "salc", "aam", "aad", "xlatb", "lock",
}

# Instructions the 8088 does not have: `pushaw` is 80186, `fisttp` is SSE3.
# Both turned up in Zaxxon, which is an 8088 game.
NOT_8088 = {"pushaw", "popaw", "pushal", "popal", "enter", "leave",
            "fisttp", "movsx", "movzx", "bt", "bts", "btr", "shld",
            "shrd", "setne", "sete", "cmovne", "cpuid"}

# Control flow. Real code branches, calls or returns.
FLOW = {"jmp", "call", "ret", "retf", "int", "iret", "loop", "loope",
        "loopne", "jcxz"}

# Where a run of code can end without falling into whatever follows it.
TRANSFER = {"ret", "retf", "iret", "jmp"}


def plausible(insn):
    """Could a 1983 game contain this instruction, here?

    No instruction the target CPU does not have, no x87 (nothing here uses
    it), and no `add byte ptr [bx + si], al`: that is `00 00`, what a run of
    zeroes looks like through a disassembler. Four of Hard Hat Mack's five
    candidates were padding reading as arithmetic."""
    m = insn.mnemonic
    if m in IMPLAUSIBLE or m in NOT_8088 or m.startswith("f"):
        return False
    if m == "add" and insn.op_str == "byte ptr [bx + si], al":
        return False
    return True


def decode_run(md, data, address):
    """The instructions `data` decodes to, read from its first byte to its
    last, with the first at `address` -- or None when one does not decode,
    runs past the end, or is not plausible."""
    insns, off = [], 0
    while off < len(data):
        insn = next(md.disasm(bytes(data[off:off + 16]), address + off), None)
        if insn is None or off + insn.size > len(data):
            return None
        if not plausible(insn):
            return None
        insns.append(insn)
        off += insn.size
    return insns


def has_flow(insns):
    """Does any instruction branch, call, return or interrupt?"""
    return any(i.mnemonic in FLOW or (i.mnemonic.startswith("j") and len(i.mnemonic) <= 4)
               for i in insns)


def kind(body, word_in_code, looks_like_code):
    """One of zero, text, table, code, other, for the bytes `body`.

    `word_in_code(w)` says whether a 16-bit word, read as a near pointer,
    lands in the code; `looks_like_code()` is the caller's own test and is
    asked only when nothing before it fits."""
    n = len(body)
    if body.count(0) >= 0.9 * n:
        return "zero"
    if sum(1 for x in body if 0x20 <= x < 0x7F) >= 0.6 * n and n >= 4:
        return "text"
    w = [body[i] | (body[i + 1] << 8) for i in range(0, n - 1, 2)]
    hit = sum(1 for x in w if word_in_code(x))
    if len(w) >= 3 and hit >= 0.7 * len(w):
        return "table"
    if looks_like_code():
        return "code"
    return "other"
