#!/usr/bin/env python3
"""
triage.py -- Decide whether these tools suit a given DOS program, before
spending hours finding out they do not.

The pipeline here targets one class of binary: 16-bit real-mode MZ, compiled
from C, small memory model, unpacked, not overlaid. Plenty of DOS games are
that. Plenty are not, and a few of the "not" cases waste the most time because
the tools appear to work: they will happily decompile a packer's decompressor,
or a game engine's interpreter, and produce something correct and useless.

This reads the binary and reports what it is, what that implies, and which
parts of the toolkit are worth running.

With --evidence it also writes the same findings as an evidence envelope
(knowledge/17-evidence.md): every finding with the file offset it rests on,
the verdict and the ids of the findings that set it (`verdict_evidence`),
what the checks cannot see and what they raised but could not settle. The
prose report and --json are unchanged by it.

Usage:
    python triage.py GAME.EXE
    python triage.py GAME.EXE --json triage.json
    python triage.py GAME.EXE --evidence -          # the envelope alone, on stdout
"""

import argparse
import json
import re
import struct
import sys
from collections import Counter
from pathlib import Path

import evidence
import overlays

# Engines whose executable is an interpreter and whose game lives in the data
# files. Decompiling these gets you a virtual machine, not a game.
ENGINE_MARKERS = {
    b"SCUMM": "LucasArts SCUMM",
    b"scumm": "LucasArts SCUMM",
    b"LFL": "Sierra AGI / LucasArts (LFL resource files)",
    b"RESOURCE.MAP": "Sierra SCI",
    b"RESOURCE.000": "Sierra SCI",
    b"VOL.0": "Sierra AGI",
    b"LOGDIR": "Sierra AGI",
    b"DAAD": "DAAD adventure system",
    b"ZORK": "Infocom Z-machine",
    b"Inform": "Inform / Z-machine",
}

PACKERS = {
    b"LZ91": "LZEXE 0.91", b"LZ09": "LZEXE 0.90", b"PKLITE": "PKLITE",
    b"diet": "DIET", b"UPX!": "UPX", b"aPLib": "aPLib",
    # EXEPACK carries no vendor string. Its decompressor's error message is the
    # distinctive marker, and unlike a two-letter signature it cannot collide
    # with ordinary data. Found by building a packed/unpacked pair with
    # Microsoft LINK /EXEPACK and comparing them -- the literal "EXEPACK" this
    # table used to look for appears nowhere in the file.
    b"Packed file is corrupt": "Microsoft EXEPACK",
}

# A C prologue. Its density separates compiled code from hand-written assembly
# far more reliably than any string search.
PROLOGUE = bytes([0x55, 0x8B, 0xEC])


def read_mz(path):
    data = Path(path).read_bytes()
    if len(data) < 28 or data[:2] not in (b"MZ", b"ZM"):
        return None, data
    (_, last, pages, nreloc, hdr_paras, minalloc, maxalloc,
     ss, sp, _, ip, cs, reloc_off, overlay) = struct.unpack_from("<2sHHHHHHHHHHHHH", data, 0)
    hdr = hdr_paras * 16
    end = (pages - 1) * 512 + (last if last else 512) if pages else len(data)
    relocs = []
    for i in range(nreloc):
        pos = reloc_off + i * 4
        if pos + 4 <= len(data):
            off, seg = struct.unpack_from("<HH", data, pos)
            relocs.append(hdr + (seg << 4) + off)
    return {
        "header_size": hdr, "image_start": hdr, "image_end": min(end, len(data)),
        "relocations": nreloc, "reloc_positions": relocs,
        "entry": hdr + (cs << 4) + ip, "cs": cs, "ip": ip, "ss": ss, "sp": sp,
        "overlay_number": overlay, "trailing": len(data) - end,
        "minalloc": minalloc, "maxalloc": maxalloc,
    }, data


def guess_memory_model(mz, image_len):
    """Infer the memory model from relocation count and placement.

    Small and tiny model code never forms a far pointer, so only the startup
    needs segment fixups -- a handful, all clustered near the entry point.
    Anything with far pointers needs one relocation per far reference, which
    spreads them across the image and multiplies the count.
    """
    n = mz["relocations"]
    kb = image_len / 1024.0
    if n == 0:
        return "tiny or packed", ("no relocations at all: either a single-segment "
                                  "program or a packed one")
    near_entry = sum(1 for p in mz["reloc_positions"] if abs(p - mz["entry"]) < 0x60)
    if n <= 8 and near_entry >= n - 1:
        return "small", (f"{n} relocations, all beside the entry point: the "
                         f"startup loading DGROUP and the stack, nothing else "
                         f"needing a fixup")
    density = n / max(1.0, kb)
    if density < 0.5:
        return "small or medium", (f"{n} relocations over {kb:.0f} KB "
                                   f"({density:.2f}/KB): few far references")
    return "compact, large or huge", (
        f"{n} relocations over {kb:.0f} KB ({density:.2f}/KB): far pointers "
        f"throughout, so more than one code or data segment")


def prologue_density(data, start, end):
    n = data.count(PROLOGUE, start, end)
    kb = max(1.0, (end - start) / 1024.0)
    return n, n / kb


def looks_like_engine(path, data):
    """Two signals: engine names in the binary, and big opaque siblings."""
    hits = []
    for marker, name in ENGINE_MARKERS.items():
        if data.find(marker) != -1:
            hits.append(name)

    siblings = []
    try:
        d = Path(path).parent
        exe_size = Path(path).stat().st_size
        for f in d.iterdir():
            if not f.is_file() or f.samefile(path):
                continue
            if f.suffix.lower() in (".exe", ".com", ".bat", ".txt", ".doc"):
                continue
            if f.stat().st_size > exe_size:
                siblings.append((f.name, f.stat().st_size))
    except OSError:
        pass
    siblings.sort(key=lambda s: -s[1])
    return sorted(set(hits)), siblings[:5]


def _at(offset):
    return {"file_offset": f"0x{offset:x}"}


def _int3f(data, mz):
    """The root's `int 3Fh` calls, or None when it is packed and they cannot
    be seen: EXEPACK's "RB" before the entry."""
    if data[max(0, mz["entry"] - 2):mz["entry"]] == b"RB":
        return None
    return overlays.int3f_calls(data[mz["image_start"]:mz["image_end"]])


def _linked_value(data, mz, linked):
    calls = _int3f(data, mz)
    return {"modules": [{"overlay": m["overlay"], "file_offset": f"0x{m['file_offset']:x}",
                         "image_bytes": m["image_bytes"], "relocations": m["relocations"]}
                        for m in linked["modules"]],
            "bytes_after_last": linked["after"],
            "int3f_calls": None if calls is None else len(calls)}


def _linked_detail(path, data, mz, linked):
    mods = linked["modules"]
    calls = _int3f(data, mz)
    text = (f"Overlay modules {', '.join(str(m['overlay']) for m in mods)}, each an MZ with "
            f"its overlay number, on the 512-byte pages after the root, found as LINK's "
            f"overlay manager finds them (file 0x{mods[0]['file_offset']:X} to "
            f"0x{mods[-1]['end'] - 1:X}). Each is loaded at the same place when called, so "
            f"their code shares addresses, and one flat disassembly of the file is "
            f"nonsense. ")
    if calls is None:
        text += ("The root is packed, so its int 3Fh calls into them cannot be read yet. "
                 "Unpack it first -- unpack.py carries the overlays across -- and then "
                 "`python tools/overlays.py UNPACKED.EXE --views DIR` ")
    else:
        text += (f"The root's image holds {len(calls)} int 3Fh calls, found by bytes. "
                 f"`python tools/overlays.py {Path(path).name} --views DIR` ")
    text += ("writes one view per module -- the root with that module in place -- and the "
             "pipeline takes each.")
    if linked["after"]:
        text += f" {linked['after']:,} bytes follow the last module."
    return text


LINKED_LIMITATION = (
    "Microsoft LINK's overlays are found by walking MZ headers from the start of the "
    "file, a page count at a time, as its overlay manager does. Borland's FBOV "
    "overlays and overlays kept in files of their own are other formats; int 3Fh "
    "calls are counted by bytes, and which module each reaches is not read.")


def analyse(path, observations=None, decisions=None):
    """Triage one file. Returns the dict that --json writes.

    Pass a list as `observations` and it receives, for every finding and in
    the same order, what the finding rests on: a kind, where in the file it
    was seen, and the value measured. The evidence envelope is built from
    that. The returned dict is unchanged by it, so --json and the prose
    report stay exactly what they were.

    Pass a list as `decisions` and it receives one (field, finding) pair
    each time a finding sets `in_scope` or `confidence`, `finding` being its
    index in `observations`. It is written by the statement that sets the
    value, so it cannot say one thing while the verdict says another. A
    field no finding set kept its default: in scope, high confidence.
    """
    mz, data = read_mz(path)
    findings = []
    verdict = {"in_scope": True, "confidence": "high"}

    def found(level, title, detail, kind, location=None, value=None):
        findings.append((level, title, detail))
        if observations is not None:
            observations.append({"level": level, "kind": kind, "claim": title,
                                 "detail": detail, "location": location,
                                 "value": value})
        return len(findings) - 1

    def decide(field, value, because):
        verdict[field] = value
        if decisions is not None:
            decisions.append((field, because))

    if mz is None:
        suffix = Path(path).suffix.lower()
        if suffix == ".com":
            # A .COM has no header to disagree with: the whole file is the
            # image, loaded at 0x100. That makes it the easiest thing here to
            # reconstruct exactly, so it gets its own route rather than a
            # refusal -- comrec.py rebuilds it to a byte-identical .asm.
            com = found("route", "raw .COM image",
                  "No MZ header, and none needed. The file loads at "
                  "offset 0x100 as a single segment. Use comrec.py, "
                  "which reassembles to a byte-for-byte copy and "
                  "proves it, rather than the MZ pipeline.",
                  "format", _at(0), "COM")
            found("note", "next step",
                  f"python tools/comrec.py \"{path}\" "
                  f"--out src/{Path(path).stem.lower()}.asm",
                  "next-step")
            # Both settled by the missing header alone, and certainly.
            decide("in_scope", True, com)
            decide("confidence", "high", com)
            verdict["route"] = "comrec"
            return {"file": str(path), "format": "COM",
                    "verdict": verdict, "findings": findings}
        not_mz = found("blocker", "not an MZ executable",
                       "No MZ signature. Not a DOS executable, or a container "
                       "of some other kind.",
                       "format", _at(0), data[:2].hex())
        decide("in_scope", False, not_mz)
        decide("confidence", "high", not_mz)
        return {"file": str(path), "format": "not-MZ",
                "verdict": verdict, "findings": findings}

    image_len = mz["image_end"] - mz["image_start"]

    # Packing. Checked first: everything downstream is meaningless if the code
    # you are looking at is a decompressor.
    #
    # Proximity to the entry point alone is too weak a test. PKLITE puts its
    # marker in the header area, well away from the code, and a real 1988 game
    # (Bantam's Creative Contraptions) was only warned about rather than
    # blocked. The corroborating evidence is decisive and cheap: a packed file
    # has almost no relocations, because the compressed payload has not been
    # relocated yet, and almost no stack-frame prologues, because the visible
    # code is a decompressor rather than compiled C.
    packer_prologues, packer_density = prologue_density(
        data, mz["image_start"], mz["image_end"])

    # EXEPACK's packed-header structure ends with the ASCII bytes "RB",
    # immediately before the entry point. Two letters are far too common to
    # search for on their own; at exactly entry-2 they are conclusive.
    if data[max(0, mz["entry"] - 2):mz["entry"]] == b"RB":
        exepack = found("blocker", "packed with Microsoft EXEPACK",
              "The signature 'RB' sits exactly two bytes before the "
              "entry point, which is where EXEPACK's packed header "
              "ends. The entry point is its decompressor. "
              "`tools/unpack.py` handles this format with the "
              "original entry point read from the packer's own "
              "header, and recovers the image to 99.7% of a "
              "known-good unpacked build.",
              "packer-marker", _at(mz["entry"] - 2), "RB")
        decide("in_scope", False, exepack)

    for sig, name in PACKERS.items():
        pos = data.find(sig)
        if pos == -1:
            continue
        near = abs(pos - mz["entry"]) < 0x400
        stripped = mz["relocations"] <= 2 or packer_density < 0.2
        measured = {"packer": name, "signature": sig.decode("latin-1"),
                    "near_entry": near, "relocations": mz["relocations"],
                    "prologues_per_kb": round(packer_density, 2)}
        if near or stripped:
            why = ("adjacent to the entry point" if near else
                   f"{mz['relocations']} relocations and "
                   f"{packer_density:.1f} prologues/KB -- the visible code is a "
                   f"decompressor, not the program")
            packed = found("blocker", f"packed with {name}",
                  f"Signature at 0x{pos:X}, {why}. Unpack before "
                  f"doing anything else, or you will decompile the "
                  f"decompressor: correct, and useless. Try "
                  f"`python tools/unpack.py {Path(path).name} -o "
                  f"unpacked.exe`, which runs the decompressor under "
                  f"emulation and dumps the result.",
                  "packer-signature", _at(pos), measured)
            decide("in_scope", False, packed)
        else:
            found("warn", f"{name} signature present",
                  f"Found at 0x{pos:X}, but the file has "
                  f"{mz['relocations']} relocations and normal frame "
                  f"density, so it does not look packed. Possibly "
                  f"incidental; confirm before acting on it.",
                  "packer-signature", _at(pos), measured)

    # Overlays.
    fbov = data.find(b"FBOV")
    linked = overlays.find(data)
    if fbov != -1 or mz["overlay_number"] != 0:
        overlaid = found("blocker", "overlaid program",
              "Overlaid code is swapped into a shared region, so "
              "several functions occupy the same addresses at "
              "different times. Nothing here handles that; each "
              "overlay needs its own address space.",
              "overlay", _at(fbov if fbov != -1 else 0x1A),
              {"overlay_number": mz["overlay_number"],
               "fbov_marker": fbov != -1})
        decide("in_scope", False, overlaid)
    elif linked and linked["modules"]:
        # Microsoft LINK's own overlays, appended as MZ modules: handled, one
        # view per module, but the measured figures are for a program whose
        # code is all in one address space, so they do not transfer.
        overlaid = found("warn", f"{len(linked['modules'])} Microsoft LINK overlays "
                                 f"after the load image",
              _linked_detail(path, data, mz, linked),
              "overlay-modules", _at(linked["modules"][0]["file_offset"]),
              _linked_value(data, mz, linked))
        decide("confidence", "low", overlaid)
    elif mz["trailing"] > 1024:
        found("warn", f"{mz['trailing']} bytes past the load image",
              "Could be appended data, could be overlays. The "
              "disassembler will not see it unless told to.",
              "trailing-data", _at(mz["image_end"]), mz["trailing"])

    # Memory model.
    model, why = guess_memory_model(mz, image_len)
    level = "info" if model == "small" else "warn"
    model_found = found(level, f"memory model looks {model}", why, "memory-model",
          {"relocation_targets": [f"0x{p:x}" for p in mz["reloc_positions"]]},
          {"model": model, "relocations": mz["relocations"],
           "image_bytes": image_len})
    if model.startswith(("compact", "small or medium")) and model != "small":
        found("warn", "emuverify.py assumes small model",
              "It sets SS = DS and maps one 64 KB data group. On a "
              "far-pointer program it will run functions with the "
              "wrong stack segment and produce nonsense without "
              "saying so. modcluster.py and match.py's data "
              "fingerprints make the same assumption.",
              "model-assumption", None, model)
        # The warning is about the tools, so the envelope lists it under
        # limitations; what lowered the confidence is the model it names.
        decide("confidence", "low", model_found)

    # Compiled C versus hand-written assembly.
    count, density = prologue_density(data, mz["image_start"], mz["image_end"])
    span = {"file_offset": f"0x{mz['image_start']:x}",
            "file_end": f"0x{mz['image_end']:x}"}
    frames = {"prologues": count, "per_kb": round(density, 2),
              "pattern": PROLOGUE.hex(" ")}
    if density >= 2.0:
        found("info", f"compiled C likely ({count} stack prologues, "
                      f"{density:.1f}/KB)",
              "Dense frame setup is what a period C compiler emits. "
              "Function recovery and library signatures both work "
              "well here.",
              "prologue-density", span, frames)
    elif density >= 0.5:
        found("warn", f"mixed or frame-pointer-free ({count} prologues, "
                      f"{density:.1f}/KB)",
              "Either a lot of hand-written assembly, or a compiler "
              "omitting frame pointers under optimisation. Function "
              "boundary recovery will miss more than usual.",
              "prologue-density", span, frames)
    else:
        few = found("warn", f"few stack frames ({count} prologues, "
                      f"{density:.1f}/KB)",
              "Two very different programs look like this: "
              "hand-written assembly, and C built by a compiler that "
              "omits frame pointers under optimisation (Open Watcom "
              "does, Microsoft C 5.x does not). Tell them apart by "
              "running libsig.py with each shipped database -- a "
              "compiled program will match a C runtime, assembly will "
              "not. Either way, expect function boundary recovery to "
              "miss more than the measured figures suggest.",
              "prologue-density", span, frames)
        decide("confidence", "low", few)

    # Interpreter engines -- the expensive mistake.
    engines, siblings = looks_like_engine(path, data)
    if engines:
        markers = {m.decode("latin-1"): f"0x{data.find(m):x}"
                   for m, name in ENGINE_MARKERS.items() if name in engines
                   and data.find(m) != -1}
        engine = found("blocker", "interpreted engine: " + ", ".join(engines),
              "The executable is an interpreter; the game is bytecode "
              "and assets in the data files. Decompiling it yields a "
              "virtual machine, not the game. Look for an "
              "engine-specific tool instead.",
              "engine-marker", {"markers": markers}, engines)
        decide("in_scope", False, engine)
    elif siblings and siblings[0][1] > 4 * max(1, image_len):
        found("warn", "large opaque data files alongside",
              "Biggest: " + ", ".join(f"{n} ({s:,} bytes)"
                                      for n, s in siblings[:3])
              + ". A small executable next to much larger data often "
                "means an interpreter with the content elsewhere. "
                "Check whether the game's text lives in the binary or "
                "in those files before committing.",
              "data-siblings", {"beside": Path(path).name},
              [{"name": n, "size": s} for n, s in siblings])

    return {
        "file": str(path), "format": "MZ",
        "image_bytes": image_len, "relocations": mz["relocations"],
        "entry": f"{mz['cs']:04X}:{mz['ip']:04X}",
        "memory_model_guess": model,
        "prologues": count, "prologue_density": round(density, 2),
        "verdict": verdict, "findings": findings,
    }


def report(r):
    out = [f"File   : {r['file']}", f"Format : {r['format']}"]
    if r["format"] == "MZ":
        out += [f"Image  : {r['image_bytes']:,} bytes, {r['relocations']} relocations",
                f"Entry  : {r['entry']}"]
    out.append("")

    order = {"blocker": 0, "route": 1, "warn": 2, "info": 3, "note": 4}
    tag = {"blocker": "BLOCKER", "route": "ROUTE  ", "warn": "WARN   ",
           "info": "INFO   ", "note": "NEXT   "}
    # Two independent checks can identify the same packer; say it once.
    seen, unique = set(), []
    for f in sorted(r["findings"], key=lambda f: order[f[0]]):
        if f[1] in seen:
            continue
        seen.add(f[1])
        unique.append(f)
    for level, title, detail in unique:
        out.append(f"[{tag[level]}] {title}")
        for line in _wrap(detail, 68):
            out.append(f"           {line}")
        out.append("")

    out.append(verdict_line(r["verdict"]))
    return "\n".join(out)


def verdict_line(v):
    if v.get("route") == "comrec":
        return ("VERDICT: in scope, by the .COM route. Run comrec.py as "
                "shown above; it either produces a byte-identical rebuild "
                "or says why not.")
    if v["in_scope"] and v["confidence"] == "high":
        return "VERDICT: in scope. Run tools/pipeline.ps1."
    if v["in_scope"]:
        return ("VERDICT: probably workable, with caveats above. Expect the "
                "measured accuracy figures not to hold.")
    return ("VERDICT: out of scope. See the blockers above and "
            "knowledge/00-scope.md.")


# What triage cannot see, said once per kind of file. These are true of every
# run, which is what makes them limitations rather than unknowns: they bound
# how far the verdict can be trusted, whatever the file.
LIMITATIONS = {
    "MZ": [
        "The memory model is inferred from how many relocations there are and "
        "where they sit, not read from the file; a program that builds its "
        "segment values at run time looks smaller than it is.",
        "Packers are recognised by signature, and EXEPACK by its 'RB' marker. "
        "A packer with no signature in triage.py's table is not detected; "
        "few relocations with few stack frames is the only other hint.",
        "Stack frames are counted as the bytes 55 8B EC anywhere in the load "
        "image, without disassembling. The other encoding of mov bp,sp "
        "(89 E5) and ENTER are not counted, and the same bytes inside data "
        "are.",
        "Interpreted engines are recognised by engine names in the binary and "
        "by the size of the files beside it. An engine that names nothing and "
        "keeps its data elsewhere passes as an ordinary program.",
    ],
    "COM": [
        "Nothing in a .COM is disassembled here: triage only notices that "
        "there is no header. Whether the file is code, and what kind, is "
        "comrec.py's to establish.",
    ],
    "not-MZ": [
        "Only MZ executables and .COM files are recognised; NE, PE and LE "
        "executables, archives and data files are all reported as not MZ.",
    ],
}


def _unknown_for(o):
    """The question a finding raises, when it raises one."""
    kind, value = o["kind"], o["value"]
    if kind == "packer-signature" and o["level"] == "warn":
        return (f"whether the {value['packer']} signature at "
                f"{o['location']['file_offset']} is incidental, or a packer "
                f"triage did not otherwise recognise")
    if kind == "trailing-data":
        return (f"what the {value} bytes past the load image are: appended "
                f"data, overlays, or a packer's payload")
    if kind == "overlay-modules":
        return ("which int 3Fh call reaches which overlay module: the overlay "
                "manager's tables say, and triage does not read them")
    if kind == "memory-model" and value["model"] != "small":
        return {
            "tiny or packed": "whether the program is a single segment or "
                              "packed; no relocations fits both",
            "small or medium": "whether the memory model is small or medium; "
                               "the relocations fit both",
        }.get(value["model"], "which far-pointer model this is, and how many "
                              "code and data segments it has")
    if kind == "prologue-density" and o["level"] == "warn":
        return ("whether this is hand-written assembly or C compiled without "
                "frame pointers; libsig.py with each shipped database tells "
                "them apart")
    if kind == "data-siblings":
        return ("whether the game's text lives in the executable or in the "
                "data files beside it")
    return None


def envelope(path):
    """The evidence envelope for one file: everything the report says,
    structured, with where each observation was made."""
    observations, decisions = [], []
    try:
        r = analyse(path, observations, decisions)
        target = evidence.target_identity(path)
    except OSError as e:
        return evidence.envelope(
            "triage", {"path": str(Path(path).resolve()), "size": None,
                       "sha256": None},
            status="error", result={"file": str(path), "error": str(e)},
            limitations=["The file could not be read, so nothing about it was "
                         "established."])

    items = []
    if r["format"] == "MZ":
        mz, _ = read_mz(path)
        items += [
            {"kind": "format", "claim": "MZ executable", "location": _at(0),
             "value": "MZ"},
            {"kind": "load-image",
             "claim": f"load image of {r['image_bytes']:,} bytes",
             "location": {"file_offset": f"0x{mz['image_start']:x}",
                          "file_end": f"0x{mz['image_end']:x}"},
             "value": r["image_bytes"]},
            {"kind": "relocation-count",
             "claim": f"{r['relocations']} relocation"
                      + ("" if r["relocations"] == 1 else "s"),
             "location": _at(6), "value": r["relocations"]},
            {"kind": "entry-point",
             "claim": f"entry point {r['entry']}, file offset "
                      f"0x{mz['entry']:X}",
             "location": _at(mz["entry"]), "value": r["entry"]},
        ]

    limitations = list(LIMITATIONS[r["format"]])
    unknowns = []
    result = {k: v for k, v in r.items() if k != "findings"}
    result["verdict_text"] = verdict_line(r["verdict"])
    item_of = {}
    for index, o in enumerate(observations):
        if o["level"] == "note":
            result["next_step"] = o["detail"]
            continue
        if o["kind"] == "model-assumption":
            # Not a fact about the file: a fact about the tools downstream,
            # triggered by what this file looks like.
            limitations.append(f"{o['claim']}: {o['detail']}")
            continue
        if o["kind"] == "overlay-modules":
            limitations.append(LINKED_LIMITATION)
        item = {k: v for k, v in o.items() if v is not None}
        items.append(item)
        item_of[index] = item
        question = _unknown_for(o)
        if question:
            unknowns.append(question)

    env = evidence.envelope("triage", target, status="ok", result=result,
                            evidence=items, limitations=limitations,
                            unknowns=unknowns)
    # The ids exist only once the envelope has numbered its items, and an
    # item repeated with identical content was kept once, so each deciding
    # finding is looked up by its content.
    id_of = {evidence.canonical({k: v for k, v in i.items() if k != "id"}): i["id"]
             for i in env["evidence"]}
    verdict_evidence = {"in_scope": [], "confidence": []}
    for field, index in decisions:
        ev_id = id_of[evidence.canonical(item_of[index])]
        if ev_id not in verdict_evidence[field]:
            verdict_evidence[field].append(ev_id)
    env["result"]["verdict_evidence"] = verdict_evidence
    return env


def _wrap(text, width):
    words, line, lines = text.split(), "", []
    for w in words:
        if len(line) + len(w) + 1 > width:
            lines.append(line)
            line = w
        else:
            line = f"{line} {w}".strip()
    if line:
        lines.append(line)
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exe")
    ap.add_argument("--json", help="write the findings here")
    ap.add_argument("--evidence", metavar="FILE",
                    help="write the evidence envelope here (knowledge/"
                         "17-evidence.md); '-' prints it instead of the report")
    args = ap.parse_args()

    # With '-' the envelope is the whole of stdout, so a program reading it
    # gets JSON and nothing else; --json is still written, silently.
    if args.evidence == "-":
        env = envelope(args.exe)
        if args.json and env["status"] != "error":
            Path(args.json).write_text(json.dumps(analyse(args.exe), indent=2),
                                       encoding="utf-8")
        evidence.write(env, "-")
        if env["status"] == "error":
            return 2
        return 0 if env["result"]["verdict"]["in_scope"] else 1

    r = analyse(args.exe)
    print(report(r))
    if args.json:
        Path(args.json).write_text(json.dumps(r, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    if args.evidence:
        evidence.write(envelope(args.exe), args.evidence)
        print(f"\nwrote {args.evidence}")
    return 0 if r["verdict"]["in_scope"] else 1


if __name__ == "__main__":
    sys.exit(main())
