#!/usr/bin/env python3
"""
profile.py -- The analysis profile the pipeline imports under, and the
handshake that refuses an export produced under anything else.

Why this exists
---------------
Every address in functions.json, every fingerprint, every name carried across
by emuverify.py rests on settings nobody wrote down: which loader Ghidra
picked, which language and compiler spec, which segment it loaded the image
at, whether RecoverFunctions.java ran. Change one -- a Ghidra upgrade that
picks a different default, a project reused from another import, recovery
silently lost to chained -postScript flags (knowledge/04-pitfalls.md) -- and
the output still looks like output. Nothing downstream can tell.

So the settings are a *profile*, written to profile.json before import, and
the export writes down what Ghidra actually did. pipeline.ps1 compares the
two and stops on any difference, naming the field.

The profile is an expectation, not an instruction. pipeline.ps1 still lets
Ghidra choose the loader and language, exactly as before, and then checks that
it chose these. Passing them to the import instead would make Ghidra agree by
construction and hide the very drift this exists to catch.

What is in it
-------------
  loader              Ghidra's name for the format it loaded
  language            language id
  compiler_spec       compiler spec id
  image_base          what Program.getImageBase() says
  load_segment        the segment Ghidra put image byte 0 at
  address_convention  the form of every address in functions.json
  ghidra_version      read from the Ghidra installation at write time
  toolkit_version     git short hash of this toolkit (evidence.py)
  recovery            whether RecoverFunctions.java ran, and which version of
                      it (the SHA-256 of the script's own source)

profile_id is the SHA-256 of the profile's canonical JSON (evidence.canonical),
computed without the profile_id key itself. It names the settings, not the
target: two executables analysed the same way share a profile_id.

The measured values
-------------------
Measured on Ghidra 12.1.2 by importing tests/evidence/fixtures/smallc.asm with
pipeline.ps1 and reading the program back with a read-only script
(knowledge/17-evidence.md has the transcript). Two of them are worth knowing:

  * The image is loaded at segment 0x1000 -- rea's documentation says the
    same -- but Program.getImageBase() returns 0000:0000. The image_base field
    functions.json has always carried is therefore not the load segment, and
    reading it as one puts every address 0x10000 out.
  * Ghidra names the loader "Old-style DOS Executable (MZ)"; that is what
    Program.getExecutableFormat() returns, and what is compared.

Test hook
---------
DOS_DECOMPILER_FORCE_DRIFT=field=value[,field=value] makes `write` expect a
wrong value, so a test can prove the handshake fails. Dotted fields reach into
`recovery` (recovery.ran=false). It announces itself on stderr; never set it
for real work.

Usage:
    python profile.py write --exe GAME.EXE --ghidra $GHIDRA_HOME --out out/profile.json
    python profile.py write ... --skip-recovery
    python profile.py check --profile out/profile.json --functions out/functions.json \\
                            [--evidence out/handshake.json]
    python profile.py show --ghidra $GHIDRA_HOME
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import evidence  # noqa: E402

SCHEMA = "dos-decompiler/profile/1"
DRIFT_VARIABLE = "DOS_DECOMPILER_FORCE_DRIFT"
RECOVERY_SCRIPT = Path(__file__).resolve().parent / "ghidra_scripts" / "RecoverFunctions.java"

# Measured, not remembered: see the docstring.
LOADER = "Old-style DOS Executable (MZ)"
LANGUAGE = "x86:LE:16:Real Mode"
COMPILER_SPEC = "default"
IMAGE_BASE = "0000:0000"
LOAD_SEGMENT = "0x1000"
ADDRESS_CONVENTION = "ssss:oooo"

# The fields the export can observe, in the order they are reported.
COMPARED = ("loader", "language", "compiler_spec", "image_base", "load_segment",
            "address_convention", "ghidra_version", "recovery.ran",
            "recovery.script_sha256")

LIMITATIONS = [
    "The expected values were measured once, on Ghidra 12.1.2 with one "
    "fixture. Another Ghidra version may choose differently; finding that out "
    "is what the handshake is for, so a drift after an upgrade is a "
    "measurement to make, not an error to suppress.",
    "The profile is an expectation, not an instruction: Ghidra still chooses "
    "the loader and language at import, and the handshake checks afterwards "
    "that it chose these.",
    "toolkit_version is not observed by the export, so it is recorded but not "
    "compared.",
]


def ghidra_version(ghidra_home):
    """application.version from the installation, or 'unknown'."""
    if not ghidra_home:
        return "unknown"
    props = Path(ghidra_home) / "Ghidra" / "application.properties"
    try:
        for line in props.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("application.version="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def script_sha256(path=RECOVERY_SCRIPT):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def expected_profile(ghidra_home, skip_recovery=False):
    return {
        "loader": LOADER,
        "language": LANGUAGE,
        "compiler_spec": COMPILER_SPEC,
        "image_base": IMAGE_BASE,
        "load_segment": LOAD_SEGMENT,
        "address_convention": ADDRESS_CONVENTION,
        "ghidra_version": ghidra_version(ghidra_home),
        "toolkit_version": evidence.toolkit_version(),
        "recovery": {"ran": not skip_recovery,
                     "script_sha256": None if skip_recovery else script_sha256()},
    }


def profile_id(profile):
    body = {k: v for k, v in profile.items() if k != "profile_id"}
    return hashlib.sha256(evidence.canonical(body).encode("ascii")).hexdigest()


def with_id(profile):
    out = dict(profile)
    out["profile_id"] = profile_id(profile)
    return out


def _get(d, dotted):
    for part in dotted.split("."):
        if not isinstance(d, dict) or part not in d:
            return None
        d = d[part]
    return d


def _set(d, dotted, value):
    parts = dotted.split(".")
    for part in parts[:-1]:
        d = d.setdefault(part, {})
    d[parts[-1]] = value


def apply_forced_drift(profile, spec):
    """Overwrite fields of the expected profile from field=value pairs."""
    applied = []
    for pair in filter(None, (p.strip() for p in spec.split(","))):
        if "=" not in pair:
            raise SystemExit(f"profile.py: {DRIFT_VARIABLE} wants field=value, "
                             f"not {pair!r}")
        field, value = (x.strip() for x in pair.split("=", 1))
        if _get(profile, field) is None and field not in COMPARED:
            raise SystemExit(f"profile.py: {DRIFT_VARIABLE} names {field!r}, "
                             f"which is not a profile field")
        parsed = {"true": True, "false": False, "null": None}.get(value, value)
        _set(profile, field, parsed)
        applied.append(f"{field}={value}")
    return applied


def write(args):
    profile = expected_profile(args.ghidra, args.skip_recovery)
    forced = []
    spec = os.environ.get(DRIFT_VARIABLE)
    if spec:
        forced = apply_forced_drift(profile, spec)
        print(f"profile.py: {DRIFT_VARIABLE} is set, so this profile expects "
              f"{', '.join(forced)} instead of the measured value. That is a "
              f"test hook; unset it for real work.", file=sys.stderr)
    profile = with_id(profile)
    env = evidence.envelope(
        "profile", evidence.target_identity(args.exe), status="ok",
        result={"profile_id": profile["profile_id"], "forced_drift": forced},
        limitations=LIMITATIONS, profile=profile)
    evidence.write(env, args.out)
    print(f"profile {profile['profile_id'][:16]}  ({profile['loader']}, "
          f"{profile['language']}:{profile['compiler_spec']}, load segment "
          f"{profile['load_segment']}, Ghidra {profile['ghidra_version']}, "
          f"recovery {'on' if profile['recovery']['ran'] else 'off'}) -> {args.out}")
    return 0


def compare(expected_env, functions):
    """[(field, expected, observed)] for every compared field, target first."""
    profile = expected_env.get("profile") or {}
    observed = functions.get("observed_profile")
    rows = []
    want, got = expected_env.get("target") or {}, functions.get("target") or {}
    rows.append(("target.sha256", want.get("sha256"), got.get("sha256")))
    rows.append(("target.size", want.get("size"), got.get("size")))
    for field in COMPARED:
        rows.append((field, _get(profile, field),
                     _get(observed, field) if observed else "(no observed_profile)"))
    return rows


def check(args):
    expected_env = json.loads(Path(args.profile).read_text(encoding="utf-8"))
    functions_path = Path(args.functions)
    if not functions_path.is_file():
        print(f"profile handshake: {functions_path} does not exist; the export "
              f"did not run, so there is nothing to check.", file=sys.stderr)
        _record(args, expected_env, "blocked", [], [str(functions_path)])
        return 2
    functions = json.loads(functions_path.read_text(encoding="utf-8"))

    rows = compare(expected_env, functions)
    drift = [(f, e, o) for f, e, o in rows if e != o]
    _record(args, expected_env, "mismatch" if drift else "verified", rows,
            [f for f, _, _ in drift])

    pid = (expected_env.get("profile") or {}).get("profile_id", "?")
    if drift:
        for field, want, got in drift:
            print(f"profile drift: {field}: expected {_show(want)}, "
                  f"observed {_show(got)}")
        print(f"{functions_path} was not produced under profile {pid[:16]}. "
              f"Do not use it until the difference is understood"
              + (f"; the record is in {args.evidence}." if args.evidence else "."))
        return 1
    print(f"profile handshake: verified, {len(rows)} fields agree "
          f"(profile {pid[:16]})")
    return 0


def _show(v):
    return "(absent)" if v is None else str(v)


def _record(args, expected_env, status, rows, drifted):
    if not args.evidence:
        return
    items = []
    for field, want, got in rows:
        agree = want == got
        items.append({"kind": "profile-field",
                      "level": "info" if agree else "mismatch",
                      "claim": f"{field}: expected {_show(want)}, observed "
                               f"{_show(got)}",
                      "location": {"field": field},
                      "value": {"expected": want, "observed": got}})
    env = evidence.envelope(
        "profile-check", expected_env.get("target"), status=status,
        result={"compared": len(rows), "drift": drifted,
                "functions": str(Path(args.functions).resolve())},
        evidence=items, limitations=LIMITATIONS,
        profile=expected_env.get("profile"))
    evidence.write(env, args.evidence)


def show(args):
    profile = with_id(expected_profile(args.ghidra, args.skip_recovery))
    sys.stdout.write(evidence.dumps(profile))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("write", help="write the expected profile before import")
    w.add_argument("--exe", required=True)
    w.add_argument("--ghidra", default=os.environ.get("GHIDRA_HOME"),
                   help="Ghidra installation, to read its version")
    w.add_argument("--out", required=True)
    w.add_argument("--skip-recovery", action="store_true",
                   help="the pipeline will not run RecoverFunctions.java")

    c = sub.add_parser("check", help="compare an export with the profile")
    c.add_argument("--profile", required=True)
    c.add_argument("--functions", required=True)
    c.add_argument("--evidence", help="write the comparison as an envelope here")

    s = sub.add_parser("show", help="print the expected profile and its id")
    s.add_argument("--ghidra", default=os.environ.get("GHIDRA_HOME"))
    s.add_argument("--skip-recovery", action="store_true")

    args = ap.parse_args()
    return {"write": write, "check": check, "show": show}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
