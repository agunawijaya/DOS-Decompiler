#!/usr/bin/env python3
"""Checks for comrun: its keyboard and --poll-patience first, then the timer,
the CGA's registers, the shipped font, text through the BIOS and the exec map.

The case that motivated these: a queue of keystrokes meant to drive a whole
game vanished in a single screen. The Oregon Trail consumed 88 keys in 88
reads without ever pausing, because Turbo Pascal opens most prompts with

    while KeyPressed do ReadKey;        { throw away type-ahead }

and an emulator that answers "yes, a key is waiting" hands the flush loop the
entire queue. Answering "no" instead breaks the opposite idiom,

    repeat until KeyPressed;            { wait for the player }

which then spins for ever. Both loops ask the same question and want opposite
answers, so no fixed answer is right.

What separates them is persistence: a flush asks a few times and gives up, a
wait asks until the answer changes. --poll-patience answers "nothing waiting"
until the question has been repeated N times since the last real read. These
build both loops as tiny .COM programs and check each one gets what it needs.
"""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
import comrun                                                # noqa: E402

CASES = []
KEY = 0x41                       # what INT 16h hands out, and what we look for
WHERE = 0x0200                   # where the program stores what it read


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


# Both programs end in `jmp $`, so the run stops on the budget rather than on
# an exit; 200,000 instructions is far more than either needs and far less
# than a spin would consume before the test noticed.
FLUSH = bytes((
    0xB4, 0x01, 0xCD, 0x16,      # 0100  mov ah,1 / int 16h   -- KeyPressed
    0x74, 0x06,                  # 0104  jz 010C              -- nothing there
    0xB4, 0x00, 0xCD, 0x16,      # 0106  mov ah,0 / int 16h   -- eat it
    0xEB, 0xF4,                  # 010A  jmp 0100
    0xB4, 0x00, 0xCD, 0x16,      # 010C  mov ah,0 / int 16h   -- the real read
    0xA3, 0x00, 0x02,            # 0110  mov [0200], ax
    0xEB, 0xFE,                  # 0113  jmp $
))

WAIT = bytes((
    0xB4, 0x01, 0xCD, 0x16,      # 0100  mov ah,1 / int 16h   -- KeyPressed
    0x74, 0xFA,                  # 0104  jz 0100              -- keep waiting
    0xB4, 0x00, 0xCD, 0x16,      # 0106  mov ah,0 / int 16h   -- then read
    0xA3, 0x00, 0x02,            # 010A  mov [0200], ax
    0xEB, 0xFE,                  # 010D  jmp $
))


def run(image, patience=None, budget=200_000):
    m = comrun.Machine(image, keys=[KEY])
    if patience is not None:
        m.poll_patience = patience
    m.run(budget=budget)
    got = int.from_bytes(m.uc.mem_read(comrun.BASE + WHERE, 2), "little")
    return got, m


@case("a flush loop swallows the queue when every poll says yes")
def _():
    got, m = run(FLUSH)
    if got == KEY:
        raise AssertionError("the fixture does not reproduce the bug at all")
    if got != 0:
        raise AssertionError(f"expected nothing to be read, got {got:#06x}")
    return f"read {m.keys_read} keys, stored nothing -- the bug, reproduced"


@case("--poll-patience gets the key past the flush loop")
def _():
    got, _ = run(FLUSH, patience=8)
    if got != KEY:
        raise AssertionError(f"the key did not survive the flush: {got:#06x}")
    return f"stored {got:#04x}"


@case("a wait loop still terminates under --poll-patience")
def _():
    got, _ = run(WAIT, patience=8)
    if got != KEY:
        raise AssertionError(
            "the wait loop never saw a key -- patience starved it")
    return f"waited, then stored {got:#04x}"


@case("patience is off by default, so old runs are unchanged")
def _():
    m = comrun.Machine(b"\xEB\xFE", keys=[KEY])
    if m.poll_patience is not None:
        raise AssertionError(f"default patience is {m.poll_patience}, not None")
    return "None"


@case("the poll counter is reset by a real read, not by the run")
def _():
    # Otherwise the first prompt would be patient and every later one would
    # not, which is the shape of bug that looks like flaky input.
    _, m = run(WAIT, patience=8)
    if m.polls != 0:
        raise AssertionError(f"polls left at {m.polls} after a blocking read")
    return "reset to 0"


# A program that waits on a word only an interrupt handler ever changes. This
# is The Oregon Trail's hunting loop in miniature: it hooks the timer, its
# handler increments a counter, and the game spins until the counter moves.
# Ticking 0040:006C does nothing for it, because nothing reads 0040:006C.
SPIN = bytes((
    0x83, 0x3E, 0x00, 0x02, 0x00,   # 0100  cmp word [0200], 0
    0x74, 0xF9,                     # 0105  je 0100
    0xEB, 0xFE,                     # 0107  jmp $
)) + bytes(0x17) + bytes((
    0xFF, 0x06, 0x00, 0x02,         # 0120  inc word [0200]
    0xCF,                           # 0124  iret
))


TIMER = 0x1C                     # the BIOS user timer tick


def spin_run(with_isr, budget=200_000, hooked=True):
    m = comrun.Machine(SPIN)
    if hooked:
        # What the program itself would do: put the handler in the vector.
        m.uc.mem_write(TIMER * 4,
                       struct.pack("<HH", comrun.LOAD + 0x20, comrun.SEG))
    if with_isr:
        m.isr_vector = TIMER
        m.isr_every = 5_000
    m.run(budget=budget)
    counter = int.from_bytes(m.uc.mem_read(comrun.BASE + 0x200, 2), "little")
    return counter, m


@case("a program waiting on its own timer handler spins for ever")
def _():
    counter, m = spin_run(with_isr=False)
    if counter:
        raise AssertionError("the counter moved with no handler running")
    return "counter 0, as the bug behaves"


@case("--timer-isr delivers the interrupt and the wait ends")
def _():
    counter, m = spin_run(with_isr=True)
    if counter == 0:
        raise AssertionError("the handler never ran")
    if m.isr_fired == 0:
        raise AssertionError("isr_fired was not counted")
    return f"counter {counter}, {m.isr_fired} interrupts delivered"


@case("the iret frame resumes the interrupted instruction")
def _():
    # If FLAGS/CS/IP were pushed in the wrong order the iret returns to
    # rubbish, and the give-away is that the program never reaches its
    # jmp $ -- so check the counter stopped growing once it escaped.
    counter, m = spin_run(with_isr=True, budget=400_000)
    ip = m.uc.reg_read(comrun.UC_X86_REG_IP)
    if ip != 0x107:
        raise AssertionError(f"resumed wrong: IP is {ip:#06x}, not 0x0107")
    return "back at jmp $, so the frame was correct"


@case("nothing is delivered until the program hooks the vector")
def _():
    # The Oregon Trail ships packed. Twenty thousand instructions in, the
    # handler's address still holds compressed bytes, and an earlier version
    # that took an address rather than an interrupt number jumped into them:
    # 99,999 interrupts delivered, no interrupts requested, no ports written,
    # no keys read, and a run that left the image.
    counter, m = spin_run(with_isr=True, hooked=False)
    if m.isr_fired:
        raise AssertionError(
            f"{m.isr_fired} interrupts sent to an unhooked vector")
    if counter:
        raise AssertionError("the counter moved with no handler installed")
    return "0 delivered, as it must be"


@case("a handler below the interrupted segment is entered correctly")
def _():
    """The geometry that actually breaks, and it took a second attempt to find.

    An earlier fixture put the handler in a segment *above* the code it
    interrupted and passed whether or not comrun moved CS with the jump --
    a check that cannot fail, wearing the name of a guard. This one puts the
    interrupted code at 2000:0000 and the handler at 1000:0130, which is the
    real program's arrangement: the handler's linear address is BELOW the
    interrupted CS base, so leaving CS alone underflows Unicorn's EIP and
    the handler never runs. The counter stays at zero and execution wanders
    out of the image -- which is what The Oregon Trail did, at 26,900,030
    instructions, every time.
    """
    HIGH = 0x2000
    m = comrun.Machine(bytes((0xEB, 0xFE)))
    m.uc.mem_write(HIGH << 4, bytes((
        0x83, 0x3E, 0x00, 0x02, 0x00,   # cmp word [0200], 0
        0x74, 0xF9,                     # je  back  -- wait for the handler
        0xEB, 0xFE)))                   # jmp $     -- escaped
    m.uc.mem_write(comrun.BASE + 0x130, bytes((
        0xFF, 0x06, 0x00, 0x02,         # inc word [0200]
        0xCF)))                         # iret
    m.uc.mem_write(TIMER * 4, struct.pack("<HH", 0x130, comrun.SEG))
    for r in (comrun.UC_X86_REG_DS, comrun.UC_X86_REG_SS):
        m.uc.reg_write(r, comrun.SEG)
    m.uc.reg_write(comrun.UC_X86_REG_CS, HIGH)
    m.uc.reg_write(comrun.UC_X86_REG_SP, 0xFFFE)
    m.isr_vector, m.isr_every = TIMER, 3_000
    m.run(start=(HIGH << 4) - comrun.BASE - comrun.LOAD, budget=60_000)

    counter = int.from_bytes(m.uc.mem_read(comrun.BASE + 0x200, 2), "little")
    if counter == 0:
        raise AssertionError(
            "the handler never incremented -- CS did not move with the jump")
    if m.uc.reg_read(comrun.UC_X86_REG_IP) != 0x0007:
        raise AssertionError("the program did not escape its wait loop")
    return f"counter {counter}, escaped to jmp $"


@case("--no-joystick: port 0x201 reads 0xFF, and alternates without it")
def _():
    # in al, dx with DX = 0x201, twice, each stored: 0201 and 0202.
    probe = bytes((0xBA, 0x01, 0x02,            # mov dx, 0x201
                   0xEC, 0xA2, 0x01, 0x02,      # in al, dx / mov [0x201], al
                   0xEC, 0xA2, 0x02, 0x02,      # in al, dx / mov [0x202], al
                   0xEB, 0xFE))                 # jmp $
    seen = {}
    for absent in (False, True):
        m = comrun.Machine(probe)
        m.no_joystick = absent
        m.run(budget=1_000)
        seen[absent] = bytes(m.uc.mem_read(comrun.BASE + 0x201, 2))
    if seen[True] != b"\xff\xff":
        raise AssertionError(f"with no joystick the port read {seen[True].hex()}")
    if seen[False][0] == seen[False][1]:
        raise AssertionError(f"without it the reads did not alternate: {seen[False].hex()}")
    return f"0xFF twice; {seen[False].hex(' ')} by default, as before"


@case("no timer ISR by default")
def _():
    m = comrun.Machine(b"\xEB\xFE")
    if m.isr_vector is not None:
        raise AssertionError(f"default vector is {m.isr_vector}")
    return "None"


# ---------------------------------------------------------------- NASM fixtures
#
# The cases below run programs written for the purpose in fixtures/, assembled
# here. Without NASM they are skipped, and say so; the cases above still run.

FIXTURES = Path(__file__).resolve().parent / "fixtures"
NASM_CASES = []
_built = {}


def nasm_case(name):
    def wrap(fn):
        NASM_CASES.append((name, fn))
        return fn
    return wrap


def find_nasm():
    import os
    import shutil
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    return nasm if nasm and Path(nasm).exists() else None


def build(name):
    """A fixture's .COM bytes, assembled once."""
    if name not in _built:
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / f"{name}.com"
            r = subprocess.run([find_nasm(), "-f", "bin", "-o", str(out),
                                str(FIXTURES / f"{name}.asm")],
                               capture_output=True, text=True)
            if r.returncode != 0:
                raise AssertionError(f"{name}.asm does not assemble: {r.stderr.strip()}")
            _built[name] = out.read_bytes()
    return _built[name]


def run_keys(name, keyboard, keys, budget=3_000_000):
    m = comrun.Machine(build(name), keys=[ord(k) for k in keys])
    m.keyboard = keyboard
    if keyboard == "hw":
        m.hw_keys, m.keys = m.keys, []
    why = m.run(budget=budget)
    return "".join(m.output), why, m


@nasm_case("a program with its own INT 09h handler hangs on INT 16h keys")
def _():
    # The bug, reproduced: Rollo and Moon Bugs stop in their title loops.
    printed, why, m = run_keys("kbdisr", "bios", "ab")
    if printed or "budget exhausted" not in why:
        raise AssertionError(f"the fixture did not hang: printed {printed!r}, {why}")
    return "budget exhausted, nothing printed -- as Rollo did"


@nasm_case("--keyboard hw: the handler gets two make codes from port 0x60")
def _():
    printed, why, m = run_keys("kbdisr", "hw", "ab")
    if printed != "1E30":
        raise AssertionError(f"printed {printed!r} ({why}); 'a' is 1E and 'b' is 30")
    if m.kbd_log["irq"] < 3 or m.kbd_log["eoi"] < 3:
        raise AssertionError(f"IRQ 1 or the EOI not counted: {m.kbd_log}")
    return f"printed {printed}, {m.kbd_log['irq']} IRQ 1, {m.kbd_log['eoi']} EOI"


@nasm_case("--keyboard auto sees the vector written and switches")
def _():
    printed, why, m = run_keys("kbdisr", "auto", "ab")
    if printed != "1E30" or m.kbd_route != "hardware":
        raise AssertionError(f"printed {printed!r}, route {m.kbd_route} ({why})")
    # The fixture writes the vector in its ninth instruction. A periodic look
    # would decide thousands of instructions later; the write hook decides
    # there.
    if m.kbd_hooked[0] > 20:
        raise AssertionError(f"decided at instruction {m.kbd_hooked[0]}, not at the write")
    return f"route decided at instruction {m.kbd_hooked[0]}"


@nasm_case("no scancode is delivered while IRQ 1 is still in service")
def _():
    # The PIC will not raise IRQ 1 again until the last one is acknowledged.
    # With one already in service and no EOI ever coming, every scancode has
    # to wait, counted as held, rather than nest into the handler.
    m = comrun.Machine(build("kbdisr"), keys=[ord("a")])
    m.keyboard, m.hw_every = "hw", 1_000
    m.hw_keys, m.keys = m.keys, []
    m.in_service.add(1)                  # an IRQ 1 already in service
    m.run(budget=20_000)
    if m.kbd_log["irq"] != 0 or m.kbd_log["held"] == 0:
        raise AssertionError(f"delivered while IRQ 1 was in service: {m.kbd_log}")
    return f"held {m.kbd_log['held']} times, delivered none"


@nasm_case("--keyboard hw: polling port 0x64 with IRQ 1 masked")
def _():
    printed, why, m = run_keys("kbdpoll", "hw", "ab")
    if printed != "1E30":
        raise AssertionError(f"printed {printed!r} ({why})")
    if m.kbd_log["irq"] or not m.kbd_log["masked"]:
        raise AssertionError(f"an IRQ was raised although masked: {m.kbd_log}")
    return f"printed {printed}, no IRQ raised"


@nasm_case("a handler that chains to the BIOS puts the keys in INT 16h")
def _():
    printed, why, m = run_keys("kbdchain", "hw", "ab")
    # 'a' and 'b' read through INT 16h, then the count of scancodes the
    # handler saw: make a, break a, make b -- the break of b comes after the
    # program has exited.
    if printed != "ab3":
        raise AssertionError(f"printed {printed!r} ({why})")
    return f"printed {printed}"


@nasm_case("INT 16h: the same keys arrive by every route")
def _():
    # The program reads INT 16h and nothing else. Whichever way the keys go
    # in, it has to print the same: the character and the scancode's high
    # digit, which for a --keys character is 0 -- as it always was.
    seen = {}
    for mode in ("bios", "auto", "hw"):
        seen[mode], _, _ = run_keys("int16", mode, "ab")
    if len(set(seen.values())) != 1 or seen["bios"] != "a0b0":
        raise AssertionError(f"different output by route: {seen}")
    return f"{seen['bios']} by bios, auto and hw"


# The CGA's colours, written out again here rather than imported, so that a
# wrong entry in comrun's table cannot agree with itself.
CGA_COLOURS = [(0, 0, 0), (0, 0, 170), (0, 170, 0), (0, 170, 170),
               (170, 0, 0), (170, 0, 170), (170, 85, 0), (170, 170, 170),
               (85, 85, 85), (85, 85, 255), (85, 255, 85), (85, 255, 255),
               (255, 85, 85), (255, 85, 255), (255, 255, 85), (255, 255, 255)]


def graphics_byte(start, row, col, scan, half):
    """The byte the CRTC reads in graphics mode, filled as its offset's low
    byte by every fixture: word address start + row * 40 + col, doubled, the
    odd scanline from the second bank."""
    word = start + row * 40 + col
    return ((((word * 2) & 0x1FFF) | (scan << 13)) + half) & 0xFF


def expected_320(x, y, start, colours):
    row, scan = y >> 1, y & 1
    v = graphics_byte(start, row, x // 8, scan, (x % 8) // 4)
    return colours[(v >> (6 - 2 * (x % 4))) & 3]


def expected_640(x, y):
    row, scan = y >> 1, y & 1
    v = graphics_byte(0, row, x // 16, scan, (x % 16) // 8)
    return CGA_COLOURS[14] if (v >> (7 - x % 8)) & 1 else CGA_COLOURS[0]


def expected_160(x, y):
    """Eighty columns of character 0xDE, two scanlines a row: the left four
    pixels of each cell are its background, the right four its foreground."""
    attr = ((y >> 1) * 80 + x // 8) & 0xFF
    return CGA_COLOURS[attr & 0x0F] if x % 8 >= 4 else CGA_COLOURS[attr >> 4]


def compare_png(name, width, height, across, expected, render="cga"):
    """Run a fixture, draw it, and count the pixels that disagree, each
    sampled at the middle of its scaled block."""
    import tempfile
    from PIL import Image
    m = comrun.Machine(build(name))
    m.run(budget=200_000)
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "screen.png"
        comrun.draw_screen(m, str(path), render)
        img = Image.open(path).convert("RGB")
        size = img.size
        px = img.load()
        wrong = []
        for y in range(height):
            for x in range(width):
                sx, sy = x * across + across // 2, y * 3 + 1
                if sx >= size[0] or sy >= size[1] or px[sx, sy] != expected(x, y):
                    wrong.append((x, y))
    return size, wrong


@nasm_case("320-wide graphics set through the ports: every pixel")
def _():
    colours = [CGA_COLOURS[4], CGA_COLOURS[3], CGA_COLOURS[5], CGA_COLOURS[7]]
    size, wrong = compare_png("cga320", 320, 200, 3,
                              lambda x, y: expected_320(x, y, 0x14, colours))
    if size != (960, 600) or wrong:
        raise AssertionError(f"{size}, {len(wrong)} wrong pixels, first {wrong[:3]}")
    return "64,000 of 64,000, start address and low-intensity palette 1 on red"


@nasm_case("the 160x100 text arrangement Moon Bugs uses: every pixel")
def _():
    size, wrong = compare_png("cga160", 640, 200, 2, expected_160)
    if size != (1280, 600) or wrong:
        raise AssertionError(f"{size}, {len(wrong)} wrong pixels, first {wrong[:3]}")
    return "128,000 of 128,000, all 256 attributes, blink off"


@nasm_case("drawn as mode 4, the 160x100 screen is the stripes Kimi saw")
def _():
    # The bug, reproduced: --render mode4 is the old renderer.
    size, wrong = compare_png("cga160", 640, 200, 2, expected_160, render="mode4")
    if not wrong:
        raise AssertionError("the old renderer drew it right; the fixture tests nothing")
    return f"{len(wrong):,} of 128,000 pixels wrong, as expected"


@nasm_case("640-wide graphics, with registers written a word at a time")
def _():
    size, wrong = compare_png("cga640", 640, 200, 2, expected_640)
    if size != (1280, 600) or wrong:
        raise AssertionError(f"{size}, {len(wrong)} wrong pixels, first {wrong[:3]}")
    return "128,000 of 128,000, yellow on black"


@nasm_case("INT 10h palette calls: palette 0, intensified, on green")
def _():
    colours = [CGA_COLOURS[2], CGA_COLOURS[10], CGA_COLOURS[12], CGA_COLOURS[14]]
    size, wrong = compare_png("biospal", 320, 200, 3,
                              lambda x, y: expected_320(x, y, 0, colours))
    if wrong:
        raise AssertionError(f"{len(wrong)} wrong pixels, first {wrong[:3]}")
    return "64,000 of 64,000"


@nasm_case("mode 4 through INT 10h draws exactly what the old renderer drew")
def _():
    import tempfile
    m = comrun.Machine(build("int16"), keys=[ord("a"), ord("b")])
    m.run(budget=200_000)
    if not m.cga.programmed:
        raise AssertionError("INT 10h AH=00 did not reach the CGA model")
    with tempfile.TemporaryDirectory() as td:
        new, old = Path(td) / "new.png", Path(td) / "old.png"
        comrun.draw_screen(m, str(new))
        comrun.to_png(m.framebuffer(), str(old), "1")
        if new.read_bytes() != old.read_bytes():
            raise AssertionError("the PNG differs from the old renderer's")
    return "byte-identical PNG"


@nasm_case("a program that never touches the adapter is drawn as before")
def _():
    m = comrun.Machine(build("kbdpoll"))
    m.run(budget=200_000)
    if m.cga.programmed:
        raise AssertionError("the CGA counts as programmed by a program that never was")
    return "not programmed, so mode 4 as always"


# ---------------------------------------------------------------- the timer
#
# irq0.asm keeps its own time: its INT 08h handler counts ticks and passes
# every other one on to the vector it replaced; it hooks INT 1Ch as well, and
# masks IRQ 0 for a while first. It prints its ticks, the INT 1Ch calls, how
# far 0040:006C moved and the ticks that came while masked, as hex bytes.

def run_timer(timer=None, isr=None, budget=3_000_000, every=5_000):
    m = comrun.Machine(build("irq0"))
    if timer:
        m.timer, m.timer_every = timer, every
    if isr:
        m.isr_vector, m.isr_every = isr, every
    why = m.run(budget=budget)
    return "".join(m.output), why, m


@nasm_case("a program with its own INT 08h handler waits for ever without a timer")
def _():
    printed, why, m = run_timer()
    if printed or "budget exhausted" not in why:
        raise AssertionError(f"the fixture did not hang: printed {printed!r}, {why}")
    return "budget exhausted, nothing printed"


@nasm_case("--timer-isr 8 ignores the PIC's mask, and a tick passed on reaches nothing")
def _():
    # What the old delivery does, kept as it is: the reason --timer exists.
    printed, why, m = run_timer(isr=0x08)
    if printed[:2] == "06" or printed[2:6] != "0000" or printed[6:] == "00":
        raise AssertionError(f"printed {printed!r}: the old delivery behaves differently "
                             f"from what this test documents")
    return f"printed {printed}: {int(printed[6:], 16)} ticks while masked, no INT 1Ch"


@nasm_case("--timer hw: IRQ 0 through the vector, the mask, the BIOS's INT 08h and 1Ch")
def _():
    printed, why, m = run_timer("hw")
    if printed != "06030300":
        raise AssertionError(f"printed {printed!r} ({why}); 6 ticks, 3 INT 1Ch, "
                             f"3 BIOS ticks, 0 while masked is 06030300")
    log = m.timer_log
    if log["to_program"] != 6 or log["to_bios"] != 3 or log["int1c"] != 3 or not log["masked"]:
        raise AssertionError(f"the counts disagree with what was printed: {log}")
    return f"printed {printed}; {log['masked']} masked, {log['eoi']} EOI from the handler"


@nasm_case("--timer auto sees vector 8 written and switches")
def _():
    printed, why, m = run_timer("auto")
    if printed != "06030300" or m.timer_route != "hardware":
        raise AssertionError(f"printed {printed!r}, route {m.timer_route} ({why})")
    step, vector, _, _ = m.timer_hooked
    if vector != 0x08 or step > 30:
        raise AssertionError(f"decided by vector {vector:02X}h at instruction {step}")
    return f"decided by INT 08h at instruction {step}"


@nasm_case("no IRQ 0 is raised while one is still in service")
def _():
    m = comrun.Machine(build("irq0"))
    m.timer, m.timer_every = "hw", 1_000
    m.in_service.add(0)                  # an IRQ 0 nobody acknowledged
    m.run(budget=200_000)
    if m.timer_log["irq"] or not m.timer_log["held"]:
        raise AssertionError(f"raised while IRQ 0 was in service: {m.timer_log}")
    return f"held {m.timer_log['held']} times, raised none"


# Karateka's wait, in miniature: the BIOS tick at 0040:006C read directly.
TICK_WAIT = bytes((
    0x31, 0xC0, 0x8E, 0xD8,         # 0100  xor ax, ax / mov ds, ax
    0xBB, 0x6C, 0x04,               # 0104  mov bx, 0x46c
    0x8B, 0x37, 0x46,               # 0107  mov si, [bx] / inc si
    0x3B, 0x37, 0x75, 0xFC,         # 010A  cmp si, [bx] / jne 010A
    0xEB, 0xFE))                    # 010E  jmp $


@nasm_case("--timer auto: a program that never takes the timer ticks 0040:006C as before")
def _():
    m = comrun.Machine(TICK_WAIT)
    m.timer = "auto"
    m.run(budget=100_000)
    if m.uc.reg_read(comrun.UC_X86_REG_IP) != 0x10E or m.timer_route is not None:
        raise AssertionError(f"IP {m.uc.reg_read(comrun.UC_X86_REG_IP):#x}, route "
                             f"{m.timer_route}: the tick did not come")
    if "neither INT 08h nor INT 1Ch" not in m.timer_summary():
        raise AssertionError(m.timer_summary())
    return "the wait ended on the tick; the summary says nothing was replaced"


@nasm_case("--timer hw: a handler on INT 1Ch alone is raised by the BIOS's INT 08h")
def _():
    m = comrun.Machine(SPIN)
    m.uc.mem_write(TIMER * 4, struct.pack("<HH", comrun.LOAD + 0x20, comrun.SEG))
    m.timer, m.timer_every = "hw", 5_000
    m.run(budget=200_000)
    counter = int.from_bytes(m.uc.mem_read(comrun.BASE + 0x200, 2), "little")
    ticks = int.from_bytes(m.uc.mem_read(0x46C, 4), "little")
    if not counter or m.timer_log["int1c"] != counter or ticks != m.timer_log["to_bios"]:
        raise AssertionError(f"counter {counter}, 0040:006C {ticks}, {m.timer_log}")
    return f"counter {counter}, 0040:006C {ticks}, every IRQ 0 through the BIOS"


@nasm_case("the timer is bios by default")
def _():
    m = comrun.Machine(b"\xEB\xFE")
    if m.timer != "bios" or m._timer_wait() is not None:
        raise AssertionError(f"default timer {m.timer}")
    return "bios, no IRQ 0 scheduled"


# Moon Patrol (1983) installs its handlers by exchanging the vector for the
# old one: `xchg es:[bx], cx / xchg es:[bx+2], dx`. Stopping the emulator
# from inside the memory write that decides --keyboard or --timer auto made
# Unicorn run that instruction twice, and the second swap left the program's
# own segment where the BIOS's should be saved.
def xchg_install(vector):
    return bytes((
        0x31, 0xC0, 0x8E, 0xC0,             # xor ax, ax / mov es, ax
        0xBF, vector * 4, 0x00,             # mov di, vector * 4
        0xBE, 0x00, 0x02,                   # mov si, 0x200 (a handler)
        0x8C, 0xC8,                         # mov ax, cs
        0x26, 0x87, 0x35,                   # xchg es:[di], si
        0x26, 0x87, 0x45, 0x02,             # xchg es:[di+2], ax
        0x89, 0x36, 0x00, 0x03,             # mov [0x300], si
        0xA3, 0x02, 0x03,                   # mov [0x302], ax
        0xEB, 0xFE))                        # jmp $


@nasm_case("an install with xchg saves the BIOS's vector under auto, keyboard and timer")
def _():
    saved = {}
    for name, vector in (("keyboard", 9), ("timer", 8)):
        m = comrun.Machine(xchg_install(vector), keys=[ord("a")])
        setattr(m, name, "auto")
        m.run(budget=5_000)
        off, seg = struct.unpack("<HH", bytes(m.uc.mem_read(comrun.BASE + 0x300, 4)))
        route = m.kbd_route if name == "keyboard" else m.timer_route
        if (seg, off) != (comrun.STUBS >> 4, vector * 4) or route != "hardware":
            raise AssertionError(f"{name}: saved {seg:04X}:{off:04X}, route {route}")
        saved[name] = f"{seg:04X}:{off:04X}"
    return f"keyboard {saved['keyboard']}, timer {saved['timer']}, both decided"


# ---------------------------------------------------------------- the font
#
# The shipped font, read here with a parser of its own, so that a wrong
# reading in comrun cannot agree with itself. A "-" is a glyph the font lacks,
# drawn as the hollow box, which is written out again here too.

FONT_FILE = Path(__file__).resolve().parents[2] / "tools" / "fonts" / "cp437-8x8.txt"
BOX = (0x00, 0x7E, 0x42, 0x42, 0x42, 0x42, 0x7E, 0x00)


def font_rows():
    rows = {}
    for line in FONT_FILE.read_text(encoding="ascii").splitlines():
        if line and not line.startswith("#"):
            byte, glyph, _ = line.split()
            rows[int(byte, 16)] = (BOX if glyph == "-" else
                                   tuple(int(glyph[i:i + 2], 16) for i in range(0, 16, 2)))
    return rows


def expected_text(cols):
    """text40.asm and text80.asm: cell n is character n mod 256 in attribute
    (n * 7 + 0x1E) mod 128; blink is on, so the background is three bits."""
    rows = font_rows()

    def pixel(x, y):
        n = (y // 8) * cols + x // 8
        ch, attr = n % 256, (n * 7 + 0x1E) % 128
        lit = (rows[ch][y % 8] >> (7 - x % 8)) & 1
        return CGA_COLOURS[attr & 0x0F] if lit else CGA_COLOURS[(attr >> 4) & 7]
    return pixel


@nasm_case("the shipped font covers 252 of 256 characters and says which it lacks")
def _():
    rows = font_rows()
    lacking = sorted(b for b, g in rows.items() if g == BOX)
    font, missing = comrun.shipped_font()
    if len(rows) != 256 or lacking != [0x0F, 0x7F, 0xA9, 0xF9] or list(missing) != lacking:
        raise AssertionError(f"{len(rows)} lines, lacking {lacking}, comrun says {missing}")
    if any(font[b * 8:b * 8 + 8] != bytes(g) for b, g in rows.items()):
        raise AssertionError("comrun's reading of the font differs from this one")
    return "lacking 0x0F, 0x7F, 0xA9, 0xF9, drawn as boxes"


@nasm_case("forty-column text: every pixel against the font's own bitmaps")
def _():
    size, wrong = compare_png("text40", 320, 200, 3, expected_text(40))
    if size != (960, 600) or wrong:
        raise AssertionError(f"{size}, {len(wrong)} wrong pixels, first {wrong[:3]}")
    return "64,000 of 64,000, all 256 characters"


@nasm_case("eighty-column text: every pixel against the font's own bitmaps")
def _():
    size, wrong = compare_png("text80", 640, 200, 2, expected_text(80))
    if size != (1280, 600) or wrong:
        raise AssertionError(f"{size}, {len(wrong)} wrong pixels, first {wrong[:3]}")
    return "128,000 of 128,000, all 256 characters"


@nasm_case("without the font, eighty-column text is the boxes it was")
def _():
    # The bug, reproduced: the old renderer had no font to draw with.
    import tempfile
    from PIL import Image
    m = comrun.Machine(build("text80"))
    m.run(budget=200_000)
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "screen.png"
        _, notes = comrun.render_cga(m.framebuffer(), m.cga)
        comrun.render_cga(m.framebuffer(), m.cga)[0].save(path)
        px = Image.open(path).convert("RGB").load()
    pixel = expected_text(80)
    wrong = sum(1 for y in range(200) for x in range(640)
                if px[x * 2 + 1, y * 3 + 1] != pixel(x, y))
    if not wrong or not any("boxes" in n for n in notes):
        raise AssertionError(f"{wrong} pixels wrong, notes {notes}")
    return f"{wrong:,} of 128,000 pixels wrong without a font, as expected"


def biostext_pixel():
    """biostext.asm under --bios-text: "Hi!" at row 1 from column 2 in colour
    2, "ok" at row 2 from column 0 in colour 3, and 'X' exclusive-ored in
    colour 1 onto the two blank cells after it; palette 1, bright, on black."""
    rows = font_rows()
    cells = {(1, 2): ("H", 2), (1, 3): ("i", 2), (1, 4): ("!", 2),
             (2, 0): ("o", 3), (2, 1): ("k", 3), (2, 2): ("X", 1), (2, 3): ("X", 1)}
    colours = [CGA_COLOURS[0], CGA_COLOURS[11], CGA_COLOURS[13], CGA_COLOURS[15]]

    def pixel(x, y):
        ch, colour = cells.get((y // 8, x // 8), (" ", 0))
        lit = (rows[ord(ch)][y % 8] >> (7 - x % 8)) & 1
        return colours[colour if lit else 0]
    return pixel


@nasm_case("--bios-text: AH=0Eh and 09h on a 320-wide screen, from the font")
def _():
    import tempfile
    from PIL import Image
    m = comrun.Machine(build("biostext"))
    m.enable_bios_text()
    m.run(budget=200_000)
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "screen.png"
        comrun.draw_screen(m, str(path))
        px = Image.open(path).convert("RGB").load()
    pixel = biostext_pixel()
    wrong = [(x, y) for y in range(200) for x in range(320)
             if px[x * 3 + 1, y * 3 + 1] != pixel(x, y)]
    if wrong:
        raise AssertionError(f"{len(wrong)} wrong pixels, first {wrong[:3]}")
    return "64,000 of 64,000: two colours, a new line, exclusive-or"


@nasm_case("without --bios-text the same screen is black, and the characters counted")
def _():
    m = comrun.Machine(build("biostext"))
    m.run(budget=200_000)
    # "Hi!", a carriage return and a line feed, "ok": seven AH=0Eh calls;
    # and AH=09h with CX=2.
    if any(m.framebuffer()) or m.bios_chars != 9:
        raise AssertionError(f"framebuffer drawn on, or {m.bios_chars} characters counted")
    return "black; 9 characters counted for the hint"


@nasm_case("--bios-text in eighty-column text: attributes, the cursor, a scroll")
def _():
    m = comrun.Machine(build("biostty"))
    m.enable_bios_text()
    m.run(budget=200_000)
    fb = bytes(m.framebuffer())

    def cell(row, col):
        at = (row * 80 + col) * 2
        return fb[at], fb[at + 1]
    seen = {"top": cell(0, 0), "x": cell(23, 78), "y": cell(23, 79), "z": cell(24, 0)}
    want = {"top": (0x20, 0x07), "x": (ord("x"), 0x07), "y": (ord("y"), 0x07),
            "z": (ord("z"), 0x07)}
    cursor, mode = struct.unpack("<HH", bytes(m.uc.mem_read(comrun.BASE + 0x200, 4)))
    if seen != want or cursor != 0x1801 or mode != 0x5003:
        raise AssertionError(f"cells {seen}, cursor {cursor:#06x}, mode {mode:#06x}")
    return "AAA scrolled away, xy on row 23, z on row 24, cursor 24:1, mode 3 of 80"


# ---------------------------------------------------------------- the exec map

@nasm_case("--exec-map-json: CS:IP for each instruction, and code changed after loading")
def _():
    # mov byte [patch], 0x90 / patch: inc ax / jmp $ -- the inc runs as a nop.
    prog = bytes((0xC6, 0x06, 0x05, 0x01, 0x90, 0x40, 0xEB, 0xFE))
    m = comrun.Machine(prog)
    m.exec_where = set()
    loaded = comrun.loaded_image(m)
    m.run(budget=50)
    data = comrun.exec_map_json(m, loaded, "patch.com")
    rows = {row[0]: row for row in data["executed"]}
    if data["columns"] != ["image_offset", "cs", "ip", "size", "changed"]:
        raise AssertionError(f"columns {data['columns']}")
    if rows.get(0) != (0, comrun.SEG, 0x100, 5, 0):
        raise AssertionError(f"the first instruction: {rows.get(0)}")
    if rows.get(5) != (5, comrun.SEG, 0x105, 1, 1) or rows[6][4] != 0:
        raise AssertionError(f"the patched one {rows.get(5)}, the jump {rows.get(6)}")
    return "1000:0100 as offset 0, and the patched instruction marked changed"


def main():
    failures = 0
    cases = list(CASES)
    nasm = find_nasm()
    if nasm:
        cases += NASM_CASES
    for name, fn in cases:
        try:
            print(f"  PASS  {name:<62} {fn()}")
        except AssertionError as e:
            print(f"  FAIL  {name:<62} {e}")
            failures += 1
    print()
    if not nasm:
        print(f"{len(NASM_CASES)} checks skipped: NASM not found (set NASM or put it on PATH)")
    if failures:
        print(f"{failures} of {len(cases)} checks failed.")
        return 1
    print(f"All {len(cases)} comrun checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
