#!/usr/bin/env python3
"""Checks for annotate.py's count of the evidence behind each name.

The rule is AGENTS.md's, Step 4: never commit a name on one source of
evidence. Rollo (Windmill, 1983) was named with 97 of its 103 routine names
committed, many on one observation, because a symbol file gave each name one
free-text string and nothing could count it. Moon Bugs gave each name a list,
two entries for every committed one -- and in one of them the second entry
was the first again: "installs keyboard ISR" and "calls install_keyboard_isr".

So when the evidence is a list, annotate.py refuses a committed name (no
`__maybe`) with fewer than two entries, and warns when two entries cite the
same address or the same routine, or when one cites a routine whose name is
what another entry says. The old string form is accepted with a warning.

These build symbol files for each case and check the decision and the message.
The last case runs the whole tool on a comrec listing of a test fixture, which
needs NASM and capstone, and skips without them.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import annotate                                              # noqa: E402

CASES = []


def case(name):
    def wrap(fn):
        CASES.append((name, fn))
        return fn
    return wrap


def symbols(routines=None, globals_=None):
    return {"routines": routines or {}, "globals": globals_ or {}}


def check(raw):
    return annotate.check_evidence(raw)


@case("two independent entries: accepted, nothing to say")
def _():
    r, w = check(symbols({"0x00100": ["read_joystick", [
        "times bit 0 of port 0x201 after writing it",
        "its result is compared with the calibration stored at 0x2c4"]]}))
    if r or w:
        raise AssertionError(f"refusals {r}, warnings {w}")
    return "no refusal, no warning"


@case("a committed name on one entry is refused, by name")
def _():
    r, _ = check(symbols({"0x0018B": ["require_cga_or_die", [
        "calls print_error_string"]]}))
    if len(r) != 1 or "require_cga_or_die" not in r[0] or "1 evidence entry" not in r[0]:
        raise AssertionError(f"refusals {r}")
    return r[0][:60] + "..."


@case("a committed name on no entries is refused")
def _():
    r, _ = check(symbols(globals_={"0x1eb6": ["action4_down", []]}))
    if len(r) != 1 or "0 evidence entries" not in r[0]:
        raise AssertionError(f"refusals {r}")
    return "refused: 0 entries"


@case("a committed global is held to the same count as a routine")
def _():
    r, _ = check(symbols(globals_={"0x13c7": ["last_scancode", ["written by the ISR"]]}))
    if len(r) != 1 or r[0].split()[0] != "global":
        raise AssertionError(f"refusals {r}")
    return "refused, as a global"


@case("blank entries are not evidence")
def _():
    r, _ = check(symbols({"0x00100": ["reboot", ["writes 0x1234 to 40:72", "   "]]}))
    if len(r) != 1:
        raise AssertionError(f"a blank second entry was counted: {r}")
    return "a blank entry does not make two"


@case("a __maybe name on one entry is accepted: the doubt is visible")
def _():
    r, w = check(symbols({"0x0053A": ["sprite_draw_stretched__maybe", [
        "sets up sprite table entry 0x20 and calls L_0071D"]]}))
    if r or w:
        raise AssertionError(f"refusals {r}, warnings {w}")
    return "accepted"


@case("every refusal is listed, not only the first")
def _():
    r, _ = check(symbols({"0x00100": ["one", ["a"]], "0x00200": ["two", ["b"]]},
                         {"0x0300": ["three", ["c"]]}))
    if len(r) != 3:
        raise AssertionError(f"{len(r)} refusals for three names: {r}")
    return "3 of 3"


@case("two entries citing one address are warned about")
def _():
    _, w = check(symbols({"0x00B31": ["keyboard_isr", [
        "stores the scancode at [0x13c7]",
        "the dispatch routine reads [0x13c7] to choose a handler"]]}))
    if w != ["routine 0x00B31 keyboard_isr: entries 1 and 2 both cite 0x13C7 -- one "
             "observation, or two?"]:
        raise AssertionError(f"warnings {w}")
    return w[0][:60] + "..."


@case("the entry's own address is not a shared citation")
def _():
    _, w = check(symbols({"0x00B31": ["keyboard_isr", [
        "the code at 0x00B31 reads port 0x60",
        "the vector written at start-up holds 0x00B31 + 0x100"]]}))
    if w:
        raise AssertionError(f"warned about the entry's own address: {w}")
    return "no warning"


@case("two entries citing one routine are warned about")
def _():
    _, w = check(symbols({
        "0x00AEF": ["install_keyboard_isr", ["writes vector 9", "saves the old vector"]],
        "0x00099": ["main_program", ["calls install_keyboard_isr first",
                                     "install_keyboard_isr is called before the loop"]]}))
    if w != ["routine 0x00099 main_program: entries 1 and 2 both cite install_keyboard_isr "
             "-- one observation, or two?"]:
        raise AssertionError(f"warnings {w}")
    return w[0][:60] + "..."


@case("Moon Bugs' main_program: the second entry restates the first")
def _():
    _, w = check(symbols({
        "0x062AF": ["install_keyboard_isr", ["writes vector 9", "saves the old vector"]],
        "0x00099": ["main_program", [
            "top-level routine: installs keyboard ISR, inits video, runs game loop",
            "calls install_keyboard_isr and the CGA init routine"]]}))
    if w != ["routine 0x00099 main_program: entry 2 cites install_keyboard_isr, and entry 1 "
             "says what that name says -- the same observation twice"]:
        raise AssertionError(f"warnings {w}")
    return "warned: the same observation twice"


@case("a writer and a reader named in prose are two observations")
def _():
    # Moon Bugs' saved_data_seg: the first identifier holds every word of the
    # second, which is not the second restated.
    _, w = check(symbols(
        {"0x062AF": ["install_keyboard_isr", ["writes vector 9", "saves the old vector"]],
         "0x062F1": ["keyboard_isr", ["reads port 0x60", "identical to Rollo's"]]},
        {"cs:0x5f2e": ["saved_data_seg", ["DS value saved by install_keyboard_isr",
                                          "restored by keyboard_isr"]]}))
    if w:
        raise AssertionError(f"warnings {w}")
    return "no warning"


@case("a one-word routine name is too weak to call a restatement")
def _():
    _, w = check(symbols({
        "0x00E01": ["reboot", ["writes 0x1234 to 40:72", "far jumps to F000:FFF0"]],
        "0x063F3": ["cheat_combo", ["tests three flags then calls reboot",
                                    "a reboot follows the combination"]]}))
    if any("says what that name says" in x for x in w):
        raise AssertionError(f"warnings {w}")
    return "no restatement claimed"


@case("the old string form is accepted with one warning that counts it")
def _():
    r, w = check(symbols({"0x00000": ["entry_stub", "first instruction"],
                          "0x00072": ["setup_stack_and_exit", "reloads SP"]},
                         {"0x0000": ["saved_sp", "stored by the stub"]}))
    if r or len(w) != 1 or not w[0].startswith("3 names give their evidence as one string"):
        raise AssertionError(f"refusals {r}, warnings {w}")
    return w[0][:60] + "..."


@case("three entries are accepted: two is a floor, not a count")
def _():
    r, w = check(symbols({"0x00100": ["reboot", [
        "writes 0x1234 to 40:72", "far jumps to F000:FFF0", "reached after the key combination"]]}))
    if r or w:
        raise AssertionError(f"refusals {r}, warnings {w}")
    return "accepted"


@case("a name with no evidence at all counts as the old form, and does not crash")
def _():
    r, w = check(symbols({"0x00000": ["start"]}))
    if r or w != ["1 names give their evidence as one string, which cannot be counted "
                  "(first: start); write it as a list of independent observations"]:
        raise AssertionError(f"refusals {r}, warnings {w}")
    return "one warning"


@case("entries that are not text are not evidence")
def _():
    r, _ = check(symbols({"0x00100": ["reboot", [12, "writes 0x1234 to 40:72"]]}))
    if r != ["routine 0x00100 reboot: 1 evidence entry; a name without __maybe needs two "
             "independent observations"]:
        raise AssertionError(f"refusals {r}")
    return "a number does not count"


@case("shared addresses: which entries, and every address, in order")
def _():
    _, w = check(symbols({"0x00100": ["middle", [
        "reads [0x2000]", "writes 0x13C9 and 0x13c7", "reads 0x13c7, then 0x13C9"]]}))
    want = ["routine 0x00100 middle: entries 2 and 3 both cite 0x13C7, 0x13C9 -- one "
            "observation, or two?"]
    if w != want:
        raise AssertionError(f"warnings {w}")
    return "entries 2 and 3, 0x13C7, 0x13C9"


@case("a global's own address is not a citation, prefix and all")
def _():
    _, w = check(symbols(globals_={"cs:0x0781": ["key_state", [
        "the handler writes [cs:0x0781]", "the game reads [0x0781] each frame"]]}))
    if w:
        raise AssertionError(f"warnings {w}")
    return "no warning"


@case("shared routines: which entries, and every routine, sorted")
def _():
    _, w = check(symbols({
        "0x00100": ["middle", ["calls alpha_one and zeta_two", "writes a flag",
                               "zeta_two and alpha_one are called in turn; middle loops"]],
        "0x00200": ["alpha_one", ["x", "y"]], "0x00300": ["zeta_two", ["x", "y"]]}))
    want = ["routine 0x00100 middle: entries 1 and 3 both cite alpha_one, zeta_two -- one "
            "observation, or two?"]
    if w != want:
        raise AssertionError(f"warnings {w}")
    return "entries 1 and 3, before and after its own name in sort order"


@case("shared routines between the second and third entries are numbered so")
def _():
    _, w = check(symbols({
        "0x00100": ["middle", ["writes a flag", "calls alpha_one", "alpha_one returns here"]],
        "0x00200": ["alpha_one", ["x", "y"]]}))
    want = ["routine 0x00100 middle: entries 2 and 3 both cite alpha_one -- one "
            "observation, or two?"]
    if w != want:
        raise AssertionError(f"warnings {w}")
    return "entries 2 and 3"


@case("a global named like a routine is not cited by its own name")
def _():
    # Two equal names as two different string objects, as two places in a
    # JSON file are: the exclusion has to be by value.
    routine_name, global_name = "".join(["fl", "ag"]), "".join(["f", "lag"])
    _, w = check(symbols({"0x00100": [routine_name, ["x", "y"]]},
                         {"0x0200": [global_name, ["flag is set here", "flag is read there"]]}))
    if w:
        raise AssertionError(f"warnings {w}")
    return "no warning"


@case("a routine's own name in two entries is not a shared citation")
def _():
    _, w = check(symbols({"0x00100": ["middle", ["middle reads the port",
                                                 "middle is called from the ISR"]]}))
    if w:
        raise AssertionError(f"warnings {w}")
    return "no warning"


@case("restated, the citing entry first: the warning names both, in order")
def _():
    _, w = check(symbols({
        "0x00B31": ["keyboard_isr", ["reads port 0x60", "acknowledges the PIC"]],
        "0x00099": ["main_program", ["calls keyboard_isr at start",
                                     "the keyboard ISR is where input comes from"]]}))
    want = ["routine 0x00099 main_program: entry 1 cites keyboard_isr, and entry 2 says what "
            "that name says -- the same observation twice"]
    if w != want:
        raise AssertionError(f"warnings {w}")
    return "a two-word name, entry 1 then entry 2"


@case("an entry that cites a routine and explains it is not a restatement of itself")
def _():
    _, w = check(symbols({
        "0x062AF": ["install_keyboard_isr", ["writes vector 9", "saves the old vector"]],
        "0x00099": ["main_program", [
            "calls install_keyboard_isr to install the keyboard ISR", "then loops"]]}))
    if w:
        raise AssertionError(f"warnings {w}")
    return "no warning"


@case("a four-letter word matches its longer forms; a three-letter one only itself")
def _():
    base = {"0x00200": ["init_video", ["x", "y"]], "0x00300": ["set_palette", ["x", "y"]]}
    _, w4 = check(symbols(dict(base, **{"0x00100": ["start", [
        "calls init_video", "initialises the video"]]})))
    _, w3 = check(symbols(dict(base, **{"0x00100": ["start", [
        "calls set_palette", "sets the palette"]]})))
    if len(w4) != 1 or w3:
        raise AssertionError(f"init: {w4}; set: {w3}")
    return "'init' in 'initialises' counts, 'set' in 'sets' does not"


@case("__maybe is not a word of the name it marks")
def _():
    _, w = check(symbols({
        "0x00200": ["draw_box__maybe", ["x"]],
        "0x00100": ["start__maybe", ["calls draw_box__maybe", "draws a box"]]}))
    want = ["routine 0x00100 start__maybe: entry 1 cites draw_box__maybe, and entry 2 says "
            "what that name says -- the same observation twice"]
    if w != want:
        raise AssertionError(f"warnings {w}")
    return "restated without 'maybe' in the text"


@case("the string-form warning names the first three, and counts all")
def _():
    _, w = check(symbols({"0x00001": ["a1", "x"], "0x00002": ["b2", "x"],
                          "0x00003": ["c3", "x"], "0x00004": ["d4", "x"]}))
    want = ["4 names give their evidence as one string, which cannot be counted (first: a1, "
            "b2, c3); write it as a list of independent observations"]
    if w != want:
        raise AssertionError(f"warnings {w}")
    return "4, first three named"


@case("named(): warnings through warn, each marked; why as text in every form")
def _():
    said = []
    routines, globals_ = annotate.named(symbols(
        {"0x00000": ["start", ["one", "two"]], "0x00010": ["old", "a string"],
         "0x00020": ["bare"]},
        {"cs:0x0040": ["flag", ["set here", "read there"]], "0x0050": ["bare_global"]}),
        warn=said.append)
    if said != ["  warning: 3 names give their evidence as one string, which cannot be "
                "counted (first: old, bare, bare_global); write it as a list of independent "
                "observations"]:
        raise AssertionError(f"said {said}")
    want_r = {0x0: ("start", "one; two"), 0x10: ("old", "a string"), 0x20: ("bare", "")}
    want_g = {("cs", 0x40): ("flag", "set here; read there"), (None, 0x50): ("bare_global", "")}
    if routines != want_r or globals_ != want_g:
        raise AssertionError(f"routines {routines}, globals {globals_}")
    return "3 routines, 2 globals, 1 warning"


@case("named(): the refusal lists every name, and says what to do")
def _():
    try:
        annotate.named(symbols({"0x00000": ["start", ["one"]]},
                               {"0x0040": ["flag", []]}), warn=lambda _: None)
    except SystemExit as e:
        want = ("2 names are committed on fewer than two observations:\n"
                "  routine 0x00000 start: 1 evidence entry; a name without __maybe needs "
                "two independent observations\n"
                "  global 0x0040 flag: 0 evidence entries; a name without __maybe needs two "
                "independent observations\n"
                "  Add the second observation, or add __maybe to the name so the doubt "
                "stays visible. Nothing was written.")
        if str(e) != want:
            raise AssertionError(f"message: {e}")
        return "both named"
    raise AssertionError("not refused")


@case("a refusal stops the run before anything is written")
def _():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "s.json").write_text(json.dumps(symbols({"0x00000": ["start", ["one"]]})))
        (td / "in.asm").write_text("L_00000:\n    ret\n")
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "annotate.py"),
                            "--asm", str(td / "in.asm"), "--symbols", str(td / "s.json"),
                            "--out", str(td / "out.asm")], capture_output=True, text=True)
        if r.returncode == 0 or (td / "out.asm").exists():
            raise AssertionError(f"exit {r.returncode}, output written: "
                                 f"{(td / 'out.asm').exists()}")
        if "committed on fewer than two observations" not in r.stderr \
                or "Nothing was written" not in r.stderr:
            raise AssertionError(f"message: {r.stderr.strip()[:200]}")
    return "exit 1, no file, the reason said"


@case("list evidence is written into the listing as text")
def _():
    routines, _, _, _ = annotate.load_symbols(
        _write(symbols({"0x00000": ["start", ["first thing", "second thing"]]})),
        warn=lambda _: None)
    text, _ = annotate.routine_comments("start:\n    ret\n", routines)
    if "; first thing; second thing" not in text or "['" in text:
        raise AssertionError(f"comment: {text!r}")
    return "'; first thing; second thing'"


def _write(raw):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(raw, f)
    return path


@case("named with list evidence, a comrec listing still rebuilds exactly")
def _():
    nasm = os.environ.get("NASM") or shutil.which("nasm")
    try:
        import capstone  # noqa: F401
    except ImportError:
        return "skipped: capstone is not installed"
    if not nasm or not Path(nasm).exists():
        return "skipped: NASM not found"
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        com, asm = td / "plain.com", td / "plain.asm"
        subprocess.run([nasm, "-f", "bin", "-o", str(com),
                        str(ROOT / "tests" / "com" / "fixtures" / "plain.asm")], check=True)
        subprocess.run([sys.executable, str(ROOT / "tools" / "comrec.py"), str(com),
                        "--out", str(asm), "--nasm", nasm], check=True, capture_output=True)
        (td / "s.json").write_text(json.dumps(symbols(
            {"0x00000": ["start", ["the program's entry", "prints the banner with AH=09"]]})))
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "annotate.py"),
                            "--asm", str(asm), "--symbols", str(td / "s.json"),
                            "--out", str(td / "named.asm"), "--nasm", nasm,
                            "--original", str(com)], capture_output=True, text=True)
        if r.returncode != 0 or "BYTE-IDENTICAL after naming" not in r.stdout:
            raise AssertionError(f"exit {r.returncode}: {r.stdout[-300:]} {r.stderr[-300:]}")
    return "BYTE-IDENTICAL after naming"


def main():
    failures = 0
    skipped = 0
    for name, fn in CASES:
        try:
            note = fn()
            if note.startswith("skipped"):
                skipped += 1
            print(f"  PASS  {name:<66} {note}")
        except AssertionError as e:
            print(f"  FAIL  {name:<66} {e}")
            failures += 1
    print()
    if skipped:
        print(f"{skipped} checks skipped (see above)")
    if failures:
        print(f"{failures} of {len(CASES)} checks failed.")
        return 1
    print(f"All {len(CASES)} annotate checks pass.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
