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


# ---------------------------------------------------------------- the program's own vectors

@nasm_case("an `int` reaches the handler the program put in its vector")
def _():
    # Tapper's INT 80h, in three forms: installed through DOS, written into
    # the table, and an INT 21h of the program's own that passes calls on.
    m = comrun.Machine(build("swint"))
    why = m.run(budget=100_000)
    printed = [line for line in "".join(m.output).splitlines() if line]
    if len(printed) != 3 or "int 0x21 exit" not in why:
        raise AssertionError(f"printed {printed}, stopped: {why}")
    counts = {n: c for n, (c, _) in m.dispatched.items()}
    if counts != {0x21: 4, 0x60: 1, 0x80: 1}:
        raise AssertionError(f"dispatched {counts}")
    line = m.vector_summary()
    if "replaced INT 21h, INT 60h, INT 80h" not in line or "INT 80h 1 time to" not in line:
        raise AssertionError(line)
    return "3 lines; INT 21h 4 times through the program's, passed on each time"


@case("an `int` through a vector the program never touched is answered here")
def _():
    # mov ah, 30h / int 21h / mov [0200], ax / jmp $: DOS's version, as always.
    prog = bytes((0xB4, 0x30, 0xCD, 0x21, 0xA3, 0x00, 0x02, 0xEB, 0xFE))
    m = comrun.Machine(prog)
    m.run(budget=100)
    got = int.from_bytes(m.uc.mem_read(comrun.BASE + WHERE, 2), "little")
    if got != 0x1E03 or m.dispatched:
        raise AssertionError(f"AX {got:#06x}, dispatched {m.dispatched}")
    return "3.30 from the harness, nothing dispatched"


@case("code read from a file over code already run is the code that runs")
def _():
    # call target; store AL; read PATCH.BIN over target; call it again; store.
    import tempfile
    prog = bytes((0xE8, 0x1F, 0x00,            # 0100  call 0122
                  0xA2, 0x00, 0x03,            # 0103  mov [0300], al
                  0xBA, 0x25, 0x01,            # 0106  mov dx, name
                  0xB8, 0x00, 0x3D,            # 0109  mov ax, 3D00h
                  0xCD, 0x21,                  # 010C  int 21h
                  0x89, 0xC3,                  # 010E  mov bx, ax
                  0xBA, 0x22, 0x01,            # 0110  mov dx, target
                  0xB9, 0x03, 0x00,            # 0113  mov cx, 3
                  0xB4, 0x3F,                  # 0116  mov ah, 3Fh
                  0xCD, 0x21,                  # 0118  int 21h
                  0xE8, 0x05, 0x00,            # 011A  call 0122
                  0xA2, 0x01, 0x03,            # 011D  mov [0301], al
                  0xEB, 0xFE,                  # 0120  jmp $
                  0xB0, 0x01, 0xC3)            # 0122  target: mov al, 1 / ret
                 ) + b"PATCH.BIN\0"
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "PATCH.BIN").write_bytes(bytes((0xB0, 0x02, 0xC3)))
        m = comrun.Machine(prog, files=td)
        m.run(budget=200)
    first, second = bytes(m.uc.mem_read(comrun.BASE + 0x300, 2))
    if (first, second) != (1, 2):
        raise AssertionError(f"AL was {first}, then {second}: the old code ran again")
    return "AL 1, then 2 -- an overlay loaded over another runs"


# ---------------------------------------------------------------- EGA and Tandy
#
# ega0d.asm and tandy9.asm draw pictures whose every pixel follows from the
# fixture's own arithmetic, written out again here, so that a wrong reading in
# comrun's models cannot agree with itself.

def ega_colour(value):
    """An EGA palette register at 200 lines: blue, green, red in bits 0-2,
    the intensity in bit 4."""
    return CGA_COLOURS[(value & 7) | (8 if value & 0x10 else 0)]


def expected_ega0d():
    palette = [0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
               0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x04, 0x39]

    def band_a(line, column, bit):
        planes = (0x55, 0x33, 0x0F, (column * 8 + line) & 0xFF)
        return sum(((plane >> bit) & 1) << p for p, plane in enumerate(planes))

    def index(x, y):
        column, pixel = x // 8, x % 8
        bit = 7 - pixel
        if y < 20:
            return band_a(y, column, bit)
        if y < 40 or y >= 180:
            return column & 15
        if y < 60:
            return 1 if pixel < 4 else 12
        if y < 80:
            return 10 if pixel < 2 else 5
        if y < 90:
            return 0 if pixel < 4 else 15
        if y < 100:
            return 15 if pixel < 4 else 0
        if y < 120:
            return band_a(y - 100, column, bit)
        if y < 140:
            return column & 15 if pixel % 2 else 3
        if y < 160:
            return 15 if band_a(y - 140, column, bit) & 7 == 5 else 0
        return band_a(y - 160, column, bit) >> 3

    return lambda x, y: ega_colour(palette[index(x, y)])


def run_adapter(name, adapter, budget=3_000_000):
    m = comrun.Machine(build(name))
    if adapter:
        m.set_adapter(adapter)
    why = m.run(budget=budget)
    return m, why


def compare_adapter_png(m, expected):
    """The picture comrun draws of a 320x200 screen, against `expected`,
    sampled at the middle of each 3x3 block: (size, wrong pixels, lines)."""
    import tempfile
    from PIL import Image
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "screen.png"
        lines = comrun.draw_screen(m, str(path))
        if not path.exists():
            return None, [], lines
        img = Image.open(path).convert("RGB")
        px = img.load()
        wrong = [(x, y) for y in range(200) for x in range(320)
                 if px[x * 3 + 1, y * 3 + 1] != expected(x, y)]
        return img.size, wrong, lines


@nasm_case("--adapter ega: mode 0Dh through every register path, every pixel")
def _():
    m, why = run_adapter("ega0d", "ega")
    size, wrong, lines = compare_adapter_png(m, expected_ega0d())
    if "int 0x21 exit" not in why or size != (960, 600) or wrong:
        raise AssertionError(f"{why}; {size}, {len(wrong)} wrong pixels, first {wrong[:3]}; "
                             f"{lines}")
    if not lines or "start 0x2000" not in lines[0]:
        raise AssertionError(f"the screen lines do not say page 1: {lines}")
    return "64,000 of 64,000: ten bands, page 1 by the CRTC, palette by BIOS and 3C0"


@nasm_case("without --adapter ega, mode 0Dh is the stripes of mode 4, as before")
def _():
    # The bug, reproduced: the old renderer drew mode 4 from B800.
    m, why = run_adapter("ega0d", None)
    size, wrong, lines = compare_adapter_png(m, expected_ega0d())
    if len(wrong) < 50_000 or "does not model" not in lines[0] or "--adapter ega" not in lines[1]:
        raise AssertionError(f"{len(wrong)} wrong pixels; {lines}")
    return f"{len(wrong):,} of 64,000 pixels wrong, and the line names --adapter ega"


def expected_tandy9():
    palette = [(7 * i) % 16 for i in range(16)]
    palette[3], palette[5] = 15, 0

    def pixel(x, y):
        b = x // 2
        return CGA_COLOURS[palette[(b + 3 * y + (5 if x % 2 else 0)) % 16]]
    return pixel


@nasm_case("--adapter tandy: mode 9 on page 2, shown while page 6 is drawn on")
def _():
    m, why = run_adapter("tandy9", "tandy")
    size, wrong, lines = compare_adapter_png(m, expected_tandy9())
    if "int 0x21 exit" not in why or size != (960, 600) or wrong:
        raise AssertionError(f"{why}; {size}, {len(wrong)} wrong pixels, first {wrong[:3]}; "
                             f"{lines}")
    if "CRT page 2, CPU page 6" not in lines[0]:
        raise AssertionError(f"the screen lines do not name the pages: {lines}")
    return "64,000 of 64,000: four banks, two nibbles a byte, the shown page, three palettes"


@nasm_case("without --adapter tandy, mode 9 is drawn as mode 4 from B800, wrong")
def _():
    m, why = run_adapter("tandy9", None)
    size, wrong, lines = compare_adapter_png(m, expected_tandy9())
    if len(wrong) < 50_000 or "--adapter tandy" not in lines[1]:
        raise AssertionError(f"{len(wrong)} wrong pixels; {lines}")
    return f"{len(wrong):,} of 64,000 pixels wrong, and the line names --adapter tandy"


def mode_0d(*body):
    """A .COM that sets mode 0Dh, runs `body` (bytes), then exits."""
    return (bytes((0xB8, 0x0D, 0x00, 0xCD, 0x10)) + b"".join(body)
            + bytes((0xB8, 0x00, 0x4C, 0xCD, 0x21)))


GC_ODD_EVEN = bytes((0xBA, 0xCE, 0x03, 0xB8, 0x05, 0x10, 0xEF))   # GC 5 = 10h
WRITE_A000 = bytes((0xB8, 0x00, 0xA0, 0x8E, 0xC0,                  # mov es, A000
                    0x26, 0xC6, 0x06, 0x00, 0x00, 0x01))           # mov byte [es:0], 1


@case("--adapter ega: odd/even addressing stops the run at the write, and says so")
def _():
    m = comrun.Machine(mode_0d(GC_ODD_EVEN, WRITE_A000))
    m.set_adapter("ega")
    why = m.run(budget=1_000)
    if "odd/even" not in why or "not modelled" not in why or m.ega.written:
        raise AssertionError(f"{why}; {m.ega.written} writes reached the planes")
    return why.split(": ", 1)[1][:60] + "..."


@case("--adapter ega: panning is refused at the picture, and no PNG is left")
def _():
    import tempfile
    pan = bytes((0xBA, 0xDA, 0x03, 0xEC,                # in al, 3DAh: the flip-flop to index
                 0xBA, 0xC0, 0x03, 0xB0, 0x13, 0xEE,    # attribute 13h ...
                 0xB0, 0x04, 0xEE))                     # ... = 4: pan by four pixels
    m = comrun.Machine(mode_0d(pan))
    m.set_adapter("ega")
    m.run(budget=1_000)
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "screen.png"
        path.write_bytes(b"an earlier run's")
        lines = comrun.draw_screen(m, str(path))
        left = path.exists()
    if left or "not drawn: horizontal panning (04h)" not in " ".join(lines):
        raise AssertionError(f"PNG left: {left}; {lines}")
    return "not drawn: horizontal panning (04h) is not modelled; the old PNG removed"


@case("--adapter ega: a write to a register the EGA lacks is ignored, and counted")
def _():
    # Rampage's `out dx, ax` with AX 00CDh at 3CEh: index 0Dh, which has no register.
    m = comrun.Machine(mode_0d(bytes((0xBA, 0xCE, 0x03, 0xB8, 0xCD, 0x00, 0xEF))))
    m.set_adapter("ega")
    m.run(budget=1_000)
    if m.ega.ignored != {(0x3CF, 0x0D): 1} or m.ega.gc != comrun.EGA.GC_0D:
        raise AssertionError(f"ignored {m.ega.ignored}, graphics controller {m.ega.gc}")
    return "3CFh index 0Dh: 1 write, nothing changed"


# What a program asks to learn the adapter: INT 11h, INT 10h AH=12h BL=10h,
# INT 10h AX=1A00h, and the bytes at F000:C000 and F000:FFFE, each stored.
ASK = bytes((
    0xCD, 0x11, 0xA3, 0x00, 0x02,                   # int 11h / mov [0200], ax
    0xB4, 0x12, 0xB3, 0x10, 0xCD, 0x10,             # ah 12h, bl 10h / int 10h
    0x89, 0x1E, 0x02, 0x02,                         # mov [0202], bx
    0xB8, 0x00, 0x1A, 0xCD, 0x10, 0xA3, 0x04, 0x02, # ax 1A00h / int 10h / mov [0204], ax
    0x1E, 0xB8, 0x00, 0xF0, 0x8E, 0xD8,             # push ds / mov ds, F000
    0xA0, 0x00, 0xC0, 0x88, 0xC4,                   # mov al, [C000] / mov ah, al
    0xA0, 0xFE, 0xFF, 0x1F,                         # mov al, [FFFE] / pop ds
    0xA3, 0x06, 0x02,                               # mov [0206], ax
    0xEB, 0xFE))                                    # jmp $


@case("each adapter answers the questions as its BIOS and ROM would")
def _():
    seen = {}
    for adapter in comrun.ADAPTERS:
        m = comrun.Machine(ASK)
        m.uc.reg_write(comrun.UC_X86_REG_AX, 0x5555)
        m.set_adapter(adapter)
        m.run(budget=200)
        equipment, ega, vga, rom = struct.unpack("<HHHH", bytes(m.uc.mem_read(comrun.BASE + 0x200, 8)))
        seen[adapter] = (equipment, ega & 0xFF, vga & 0xFF, rom >> 8, rom & 0xFF)
    want = {"cga": (0x5555, 0x10, 0x00, 0x00, 0x00),    # as comrun always answered
            "ega": (0x000D, 0x03, 0x00, 0x00, 0xFF),
            "tandy": (0x002D, 0x10, 0x00, 0x21, 0xFF)}
    if seen != want:
        raise AssertionError(f"{seen}")
    return "cga as before; ega BL 3 and equipment 000Dh; tandy 21h at F000:C000"


@case("the summary names the questions the program asked")
def _():
    m = comrun.Machine(ASK)
    m.set_adapter("ega")
    m.run(budget=200)
    line = m.adapter_summary()
    want = ("INT 10h AH=12h 1 time, INT 10h AH=1Ah 1 time, INT 11h 1 time, "
            "read F000:C000 1 time, read F000:FFFE 1 time")
    if not line.endswith(want):
        raise AssertionError(line)
    cga = comrun.Machine(ASK)
    cga.run(budget=200)
    if "--adapter ega" not in (cga.adapter_summary() or ""):
        raise AssertionError(f"cga says {cga.adapter_summary()!r}")
    return "five questions; under cga a pointer to --adapter ega"


@case("a vector at F000:FF53, the BIOS's `iret`, is no handler, for `int` or the tick")
def _():
    # Vector 1Ch to F000:FF53, as Jungle Hunt switches it off; `int 1Ch`;
    # mov [0200], 1; then wait for the tick with IRQ 0 running.
    prog = bytes((0x31, 0xC0, 0x8E, 0xC0,                         # xor ax, ax / mov es, ax
                  0xBF, 0x70, 0x00,                               # mov di, 70h
                  0xB8, 0x53, 0xFF, 0xAB,                         # mov ax, FF53h / stosw
                  0xB8, 0x00, 0xF0, 0xAB,                         # mov ax, F000h / stosw
                  0xCD, 0x1C,                                     # int 1Ch
                  0xC6, 0x06, 0x00, 0x02, 0x01,                   # mov byte [0200], 1
                  0xEB, 0xFE))                                    # jmp $
    m = comrun.Machine(prog)
    m.timer, m.timer_every = "hw", 5_000
    m.run(budget=30_000)
    if (m.uc.mem_read(comrun.BASE + 0x200, 1)[0] != 1 or m.dispatched
            or m.timer_log["int1c"] or not m.timer_log["to_bios"] or 0x1C in m.replaced_vectors()):
        raise AssertionError(f"{m.stopped}; dispatched {m.dispatched}, {m.timer_log}")
    return f"the int came back; {m.timer_log['to_bios']} ticks raised no INT 1Ch"


@nasm_case("--cpu 8088: LOCK stepped over on nop and inc, first and behind 1, 2, 3 prefixes")
def _():
    m = comrun.Machine(build("lock"))
    m.exec_map = set()
    why = m.run(budget=10_000)
    printed = "".join(m.output)
    sites = [0x03, 0x08, 0x0F, 0x12, 0x16]
    # Each instruction where it starts, and not the byte after a LOCK it was
    # restarted at: below 0x1B are the eight before `mov cx, 3`.
    starts = sorted(a for a in m.exec_map if a < 0x1B)
    if starts != [0x00, 0x03, 0x05, 0x08, 0x0A, 0x0F, 0x12, 0x16]:
        raise AssertionError(f"executed {[hex(a) for a in starts]}")
    if printed != "6 8 0 6" or m.lock_steps != 5 or sorted(m.lock_sites) != sites:
        raise AssertionError(f"printed {printed!r}, {why}; {m.lock_steps} at {m.lock_sites}")
    # Counted by hand from the fixture: 9 to the loop, 3 times round it, 11
    # for each of three digits with a space and 6 for the last, 2 to exit.
    if m.steps != 56:
        raise AssertionError(f"{m.steps} instructions, not 56: a LOCK stepped over was "
                             f"counted twice, or an instruction not at all")
    if bytes(m.uc.mem_read(comrun.BASE + comrun.LOAD + 0x0F, 12)) != bytes.fromhex(
            "2ef0902e26f09026" "2e36f040"):
        raise AssertionError("a LOCK replaced to run its instruction was not put back")
    return "printed 6 8 0 6; 5 stepped over, at 0x3, 0x8, 0xF, 0x12, 0x16; 56 instructions"


@nasm_case("--cpu 386: Unicorn's LOCK -- refused on nop and inc reg, run on mov")
def _():
    seen = {}
    for name, offset in (("nop", 0x03), ("mov", 0x05), ("inc bx", 0x08), ("cs: nop", 0x0F),
                         ("cs: es: nop", 0x12), ("es: cs: ss: inc ax", 0x16)):
        m = comrun.Machine(build("lock"))
        m.cpu = "386"
        why = m.run(start=offset, budget=1)
        seen[name] = "refused" if "Invalid instruction" in why else "ran"
    if seen != {"nop": "refused", "mov": "ran", "inc bx": "refused", "cs: nop": "refused",
                "cs: es: nop": "refused", "es: cs: ss: inc ax": "refused"}:
        raise AssertionError(f"{seen}")
    return "every refused form refused; mov run, the prefix ignored"


# Each divide's address plus its length, from NASM's listing of except.asm;
# its handler keeps them in `returns`, at image 0xDA.
EXCEPT_RETURNS = {"8088": [0x133, 0x13A, 0x143, 0x14C, 0x152, 0x159], "386": [0x131] * 6}


def except_returns(m):
    return list(struct.unpack("<6H", bytes(m.uc.mem_read(comrun.BASE + 0x100 + 0xDA, 12))))


@nasm_case("--cpu 8088: six divide errors to the program's INT 0, each after its divide")
def _():
    m = comrun.Machine(build("except"))
    why = m.run(budget=10_000)
    returns = except_returns(m)
    printed = "".join(m.output)
    if printed != "6 3 1 1 " or returns != EXCEPT_RETURNS["8088"]:
        raise AssertionError(f"printed {printed!r}, returns {[hex(r) for r in returns]}, {why}")
    if any(n == 8 for n, _ in m.ints) or m.exceptions[0][0] != 6 or m.exceptions[1][0] != 3:
        raise AssertionError(f"a double fault, or counts {m.exceptions}")
    return "printed 6 3 1 1; ModRM mod 0-3 and a prefixed AAM, each returned to past it; no INT 8"


@nasm_case("--cpu 386: a divide error returns to the divide, which divides again")
def _():
    m = comrun.Machine(build("except"))
    m.cpu = "386"
    m.run(budget=2_000)
    returns = except_returns(m)
    if returns != EXCEPT_RETURNS["386"] or m.exceptions[0][0] < 6:
        raise AssertionError(f"returns {[hex(r) for r in returns]}, {m.exceptions}")
    return f"0x131 every time, {m.exceptions[0][0]} deliveries in 2,000 instructions"


@case("--cpu 8088: one LOCK is said as one; a refusal with no LOCK still faults")
def _():
    m = comrun.Machine(bytes((0xF0, 0x90, 0xEB, 0xFE)))         # lock nop / jmp $
    m.run(budget=20)
    line = m.cpu_summary() or ""
    if not line.endswith("a LOCK prefix stepped over 1 time, at 0x0"):
        raise AssertionError(line)
    m = comrun.Machine(bytes((0x0F, 0x0B, 0xEB, 0xFE)))         # a later x86's UD2
    why = m.run(budget=20)
    if "Invalid instruction" not in why or m.lock_steps or m.cpu_summary() is not None:
        raise AssertionError(f"{why}; {m.lock_steps} stepped over")
    return "1 time; 0F 0B refused as before"


@case("a LOCK stepped over at CS:FFFE runs the instruction at FFFF")
def _():
    # lock inc ax at 2000:FFFE: the instruction after the prefix is at IP
    # FFFF, the segment's last byte, and must run there, not at IP 0.
    m = comrun.Machine(b"\xEB\xFE")
    high = 0x2000
    m.uc.mem_write((high << 4) + 0xFFFE, b"\xF0\x40")
    m.uc.mem_write(high << 4, b"\xEB\xFE")                    # jmp $, were IP 0 reached
    m.uc.reg_write(comrun.UC_X86_REG_AX, 5)
    m.uc.reg_write(comrun.UC_X86_REG_CS, high)
    m.run(start=(high << 4) + 0xFFFE - comrun.BASE - comrun.LOAD, budget=3)
    ax = m.uc.reg_read(comrun.UC_X86_REG_AX)
    if ax != 6 or m.lock_steps != 1:
        raise AssertionError(f"AX {ax}, {m.lock_steps} stepped over")
    return "AX 5 to 6: the increment at FFFF ran"


@case("a divide error with no handler of the program's ends the run, and says so")
def _():
    # mov ax, 1234 / xor bl, bl / div bl / jmp $
    m = comrun.Machine(bytes((0xB8, 0xD2, 0x04, 0x30, 0xDB, 0xF6, 0xF3, 0xEB, 0xFE)))
    why = m.run(budget=1_000)
    if (not why.startswith("divide error at 1000:0105 (image 0x000005); the program has "
                           "no INT 00h handler of its own") or "Divide overflow" not in why):
        raise AssertionError(why)
    return why[:44] + "..."


# divide_length and lock_prefix on encodings written out here: a divide's
# length is its prefixes, the opcode, ModRM and the displacement ModRM asks
# for (mod 0: two bytes if r/m is 6; mod 1: one; mod 2: two; mod 3: none).
DIVIDES = [
    ("div bl", "f6f3", 2), ("idiv word [1234h]", "f73e3412", 4),
    ("div byte [bp+2]", "f67602", 3), ("div byte [bx+300h]", "f6b70003", 4),
    ("div byte [bx]", "f637", 2), ("idiv word [bx+si]", "f738", 2),
    ("div byte [si+12h]", "f67412", 3), ("aam 0", "d400", 2),
    ("cs: div bl", "2ef6f3", 3), ("cs: es: aam 0", "2e26d400", 4),
    ("cs: es: ss: div byte [bx+300h]", "2e2636f6b70003", 7),
    ("cs: div byte [bp+2]", "2ef67602", 4), ("cs: es: div bl", "2e26f6f3", 4),
    ("div bl, no more bytes", "f6f3", 2),
    ("test bl, 1 (f6 /0)", "f6c301", None), ("mul bl (f6 /4)", "f6e3", None),
    ("neg bl (f6 /3)", "f6db", None), ("nop", "90", None), ("aad 0", "d500", None),
    ("add al, 0 (below d4)", "0400", None),
    ("an opcode and nothing after it", "f6", None), ("a prefix alone", "2e", None),
    ("a prefix and an opcode", "2ef6", None), ("fifteen prefixes", "2e" * 15, None),
]
LOCKS = [("f090", 0), ("2ef090", 1), ("2e26f090", 2), ("f3f090", 1), ("f390", None),
         ("90f0", None), ("2e2e", None), ("f2f3f0f040", 2)]


@case("a divide's length and a LOCK's place, read from the bytes")
def _():
    wrong = []
    for name, raw, length in DIVIDES:
        try:
            got = comrun.divide_length(bytes.fromhex(raw))
        except Exception as e:                                 # noqa: BLE001
            got = f"{type(e).__name__}"
        if got != length:
            wrong.append(f"{name}: {got}, not {length}")
    for raw, at in LOCKS:
        if comrun.lock_prefix(bytes.fromhex(raw)) != at:
            wrong.append(f"lock_prefix({raw}): {comrun.lock_prefix(bytes.fromhex(raw))}")
    if wrong:
        raise AssertionError("; ".join(wrong))
    return f"{len(DIVIDES)} encodings, {len(LOCKS)} prefix runs"


def far_segment_program():
    """A program at 2345:0FF0, a segment whose base shares bits with its
    offsets, so that an address made with | or ^ instead of + is wrong: its
    INT 0 handler at 0E00 keeps each return IP at 0E80 on, its INT 3 handler
    at 0E40 counts at 0E90. Main: the vectors, `lock nop`, `int3`, `int 3`
    in its two-byte form, a divide by zero, the same behind thirteen prefixes
    (15 bytes), `jmp $`."""
    seg = 0x2345
    code = {
        0x0E00: bytes((0x56, 0x55, 0x89, 0xE5,                  # push si / push bp / mov bp, sp
                       0x2E, 0x8B, 0x36, 0x7E, 0x0E,            # mov si, [cs:0E7E]
                       0x8B, 0x46, 0x04,                        # mov ax, [bp+4]
                       0x2E, 0x89, 0x84, 0x80, 0x0E,            # mov [cs:si+0E80], ax
                       0x2E, 0x83, 0x06, 0x7E, 0x0E, 0x02,      # add word [cs:0E7E], 2
                       0x5D, 0x5E, 0xCF)),                      # pop bp / pop si / iret
        0x0E40: bytes((0x2E, 0xFE, 0x06, 0x90, 0x0E, 0xCF)),    # inc byte [cs:0E90] / iret
        0x0FF0: bytes((0x31, 0xC0, 0x8E, 0xC0,                  # xor ax, ax / mov es, ax
                       0x26, 0xC7, 0x06, 0x00, 0x00, 0x00, 0x0E,  # mov word [es:0], 0E00h
                       0x26, 0x8C, 0x0E, 0x02, 0x00,            # mov [es:2], cs
                       0x26, 0xC7, 0x06, 0x0C, 0x00, 0x40, 0x0E,  # mov word [es:0Ch], 0E40h
                       0x26, 0x8C, 0x0E, 0x0E, 0x00,            # mov [es:0Eh], cs
                       0xF0, 0x90,                              # 100C: lock nop
                       0xCC,                                    # 100E: int3
                       0xCD, 0x03,                              # 100F: int 3
                       0x30, 0xDB, 0xF6, 0xF3))                 # 1011: xor bl, bl / 1013: div bl
                 + b"\x2E" * 13 + bytes((0xF6, 0xF3))           # 1015: 15 bytes, div bl
                 + bytes((0xEB, 0xFE)),                         # 1024: jmp $
    }
    return seg, code


@case("a segment whose base shares bits with IP: LOCK, int 3 both ways, two divides, each where it is")
def _():
    seg, code = far_segment_program()
    m = comrun.Machine(b"\xEB\xFE")
    for off, data in code.items():
        m.uc.mem_write((seg << 4) + off, data)
    m.uc.reg_write(comrun.UC_X86_REG_CS, seg)
    why = m.run(start=(seg << 4) + 0x0FF0 - comrun.BASE - comrun.LOAD, budget=400)
    returns = list(struct.unpack("<2H", bytes(m.uc.mem_read((seg << 4) + 0x0E80, 4))))
    breakpoints = m.uc.mem_read((seg << 4) + 0x0E90, 1)[0]
    lock_site = (seg << 4) + 0x100C - comrun.BASE - comrun.LOAD
    if (returns != [0x1015, 0x1024] or breakpoints != 2 or m.lock_sites != {lock_site}
            or m.exceptions.get(0, (0, []))[1] != [(seg, 0x0E00)]
            or m.dispatched.get(3, (0, []))[0] != 2):
        raise AssertionError(f"{why}; returns {[hex(r) for r in returns]}, int 3 {breakpoints}, "
                             f"LOCK at {[hex(a) for a in m.lock_sites]}, {m.exceptions}, "
                             f"{m.dispatched}")
    return "returned to 1015 and 1024, both int 3s to its handler, the LOCK at its own address"


@case("a divide error with no handler, in a segment of its own, names its place in the image")
def _():
    # xor bl, bl / div bl at 2345:1000: the divide at image 0x14352, beyond
    # twice the image's base, so the offset made with % or ^ is another.
    seg = 0x2345
    m = comrun.Machine(b"\xEB\xFE")
    m.uc.mem_write((seg << 4) + 0x1000, bytes((0x30, 0xDB, 0xF6, 0xF3)))
    m.uc.reg_write(comrun.UC_X86_REG_CS, seg)
    why = m.run(start=(seg << 4) + 0x1000 - comrun.BASE - comrun.LOAD, budget=20)
    if not why.startswith("divide error at 2345:1002 (image 0x014352); the program has no "):
        raise AssertionError(why)
    return why[:44] + "..."


@case("a divide ending at the segment's last byte returns to FFFF; a trap with no handler goes on")
def _():
    seg, code = far_segment_program()
    m = comrun.Machine(b"\xEB\xFE")
    m.uc.mem_write((seg << 4) + 0x0E00, code[0x0E00])
    m.uc.mem_write(0, struct.pack("<HH", 0x0E00, seg))           # vector 0 to the handler
    m.uc.mem_write((seg << 4) + 0xFFFD, bytes((0xF6, 0xF3)))     # div bl at FFFD
    m.uc.reg_write(comrun.UC_X86_REG_BX, 0)
    m.uc.reg_write(comrun.UC_X86_REG_CS, seg)
    m.run(start=(seg << 4) + 0xFFFD - comrun.BASE - comrun.LOAD, budget=12)
    back = struct.unpack("<H", bytes(m.uc.mem_read((seg << 4) + 0x0E80, 2)))[0]
    # pushf / pop ax / or ah, 1 / push ax / popf / nop / nop / jmp $: TF set,
    # and vector 1 still the BIOS's, whose INT 1 is an iret.
    t = comrun.Machine(bytes((0x9C, 0x58, 0x80, 0xCC, 0x01, 0x50, 0x9D,
                              0x90, 0x90, 0xEB, 0xFE)))
    why = t.run(budget=40)
    if back != 0xFFFF or not why.startswith("budget exhausted") or t.exceptions:
        raise AssertionError(f"returned to {back:#x}; the trap run: {why}, {t.exceptions}")
    return "FFFF, not 0; the trap run reached its jmp $ and delivered nothing"


@case("--call after a divide error that went to the program's handler returns")
def _():
    # 0100: install INT 0 at 0120 through DOS, then jmp $. 0110: a routine that
    # divides by zero, stores 1 at [0300] and returns. 0120: the handler, iret.
    prog = bytearray(0x30)
    prog[0x00:0x0A] = bytes((0xBA, 0x20, 0x01, 0xB8, 0x00, 0x25, 0xCD, 0x21, 0xEB, 0xFE))
    prog[0x10:0x19] = bytes((0x30, 0xDB, 0xF6, 0xF3, 0xC6, 0x06, 0x00, 0x03, 0x01))
    prog[0x19] = 0xC3
    prog[0x20] = 0xCF
    m = comrun.Machine(bytes(prog))
    m.run(budget=50)
    why = m.call(0x10, budget=1_000)
    if why != "returned" or m.uc.mem_read(comrun.BASE + 0x300, 1)[0] != 1:
        raise AssertionError(why)
    return "returned, past the divide, the store done"


@nasm_case("--at: one key each way -- the BIOS's buffer, IRQ 1, and both")
def _():
    seen = {}
    for mode in ("bios", "hw", "auto"):
        m = comrun.Machine(build("atkeys"))
        m.keyboard = mode
        m.at_keys = {0x10: [ord("a")], 0x30: [ord("b")], 0x50: [ord("c")]}
        why = m.run(budget=2_000_000)
        seen[mode] = "".join(m.output)
        paths = [path for _, _, _, path in m.at_log]
        if (len(paths) != 3 or not paths[0].startswith("the BIOS's buffer")
                or not paths[1].startswith("port 0x60 and IRQ 1")
                or "INT 16h too" in paths[1] or "INT 16h too" not in paths[2]):
            raise AssertionError(f"{mode}: {paths}; {why}")
    if set(seen.values()) != {"a 30 c 2E "}:
        raise AssertionError(f"{seen}")
    return "a 30 c 2E by bios, hw and auto; each path named"


@nasm_case("--at from the command line: before the start-up run, in any --keyboard")
def _():
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        com = Path(td) / "atkeys.com"
        com.write_bytes(build("atkeys"))
        r = subprocess.run([sys.executable, str(Path(comrun.__file__)), str(com), "--keyboard",
                            "auto", "--at", "10=a,30=b,50=c", "--budget", "2000000"],
                           capture_output=True, text=True)
    if r.returncode or "a 30 c 2E" not in r.stdout or "key at 0x30" not in r.stdout:
        raise AssertionError(f"exit {r.returncode}: {(r.stdout + r.stderr)[-400:]}")
    return "printed a 30 c 2E, and a line for each key"


@nasm_case("--cpu 8088 and 386 from the command line, as the model has them")
def _():
    # The value is argv's string, not a literal the code compares by identity.
    import subprocess
    import tempfile
    seen = {}
    with tempfile.TemporaryDirectory() as td:
        for name in ("lock", "except"):
            com = Path(td) / f"{name}.com"
            com.write_bytes(build(name))
            for cpu in ("8088", "386"):
                r = subprocess.run([sys.executable, str(Path(comrun.__file__)), str(com),
                                    "--cpu", "".join(cpu), "--budget", "3000"],
                                   capture_output=True, text=True)
                seen[(name, cpu)] = r.stdout
    if ("6 8 0 6" not in seen[("lock", "8088")] or "6 3 1 1" not in seen[("except", "8088")]
            or "Invalid instruction" not in seen[("lock", "386")]
            or "returning to its divide, as a 386's does" not in seen[("except", "386")]):
        raise AssertionError(f"{seen}")
    return "8088: 6 8 0 6 and 6 3 1 1; 386: refused, and back to the divide"


def pit_loops(reload=0x6000, every=20_000):
    """pit.asm's loop count, from the 8253's arithmetic: 65,536 counts to a
    tick of `every` instructions. Counting starts at the program's ninth
    instruction, which opens the gate; the first latch is its thirteenth, and
    a loop is nine."""
    now = lambda steps: steps * 65536 // every          # noqa: E731
    loops = 0
    while True:
        loops += 1
        count = reload - (now(13 + 9 * (loops - 1)) - now(9)) % reload
        if count <= 200:
            return loops


@nasm_case("a latched count of the 8253 counts down: pit.asm's calibration ends")
def _():
    m = comrun.Machine(build("pit"))
    why = m.run(budget=200_000)
    loops = int.from_bytes(m.uc.mem_read(comrun.BASE + 0x100 + len(build("pit")) - 2, 2), "little")
    if "int 0x21 exit" not in why or loops != pit_loops() or m.pit.latches != loops:
        raise AssertionError(f"{why}; {loops} loops, {m.pit.latches} latches, "
                             f"{pit_loops()} expected")
    return f"{loops:,} loops, as 65,536 counts a tick say"


@case("the 8253's counter 2 holds while its gate is closed, and a read with no latch alternates")
def _():
    pit = comrun.PIT()
    pit.control(0xB4, 0)                     # counter 2, low then high, mode 2
    pit.write(2, 0x00, 0)
    pit.write(2, 0x10, 0)                    # 1000h
    pit.control(0x80, 500)                   # latched with the gate closed
    held = pit.read(2) | (pit.read(2) << 8)
    pit.gate(True, 600)
    pit.control(0x80, 700)
    running = pit.read(2) | (pit.read(2) << 8)
    if (held, running, pit.read(2)) != (0x1000, 0x1000 - 100, None):
        raise AssertionError(f"held {held:#x}, running {running:#x}")
    return "1000h held, F9Ch 100 counts after the gate opened, then no latch"


def pen_row_column(every=20_000):
    """lightpen.asm's answer from the 6845's arithmetic: mode 4's CRTC (57
    columns, 128 rows of two lines and 6 more, 40 shown), a frame of 912 x
    262 / 12 counts of the 8253, 65,536 counts to `every` instructions. The
    latch is set by the program's sixth instruction, and a pass is 21."""
    frame, lines = 912 * 262 // 12, 128 * 2 + 6
    steps = 6
    while True:
        t = steps * 65536 // every % frame
        line, column = t * lines // frame, (t * lines % frame) * 57 // frame
        address = (line // 2) * 40 + column
        if address // 40 == 99:
            return 99, address % 40
        steps += 21


@nasm_case("the light pen latch takes the beam's address: lightpen.asm finds row 99")
def _():
    m = comrun.Machine(build("lightpen"))
    why = m.run(budget=200_000)
    printed = "".join(m.output)
    row, column = pen_row_column()
    if "int 0x21 exit" not in why or printed != f"{row:02X}{column:02X}":
        raise AssertionError(f"printed {printed!r} ({why}); expected row {row} column {column}")
    return f"printed {printed}: row 99, column {column}, after {m.pen_presets} presets"


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
