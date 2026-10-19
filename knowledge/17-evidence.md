# Evidence envelopes, analysis profiles, and results that know where they came from

Every tool here prints prose for a person. That is the right default and it
stays, but it fails an agent in a specific way: the agent reads the prose back
and guesses at its structure, and the guess is where findings get lost — a
warning wrapped over three lines, a blocker printed once although two checks
found it, an open question indistinguishable from a settled one.

A second failure was worse because nothing showed it: a result carried no
record of which file, or which analysis settings, produced it. A
`functions.json` from last week's import could be read against this week's
executable and every tool would carry on.

The fix, borrowed as an idea from [rea](05-prior-art.md#rea--an-mcp-server-in-front-of-ghidra-for-the-same-binaries)
and built here from nothing, has these parts (the first four from prompts 01
and 02, the rest added since):

1. An **evidence envelope**: a result's own shape, carrying each observation
   behind it, what the method cannot see, and what it raised but could not
   settle — tied to the target's size and SHA-256.
2. An **analysis profile**: the Ghidra settings the pipeline expects, written
   down before import and checked against what the export observed.
3. **Load-image verification**: right after import, a check that Ghidra's
   program is the file — the same bytes, at the addresses the header implies,
   every relocation applied once per entry (prompt 02). Before it, the two
   loads Ghidra is known to get wrong are corrected, and every correction is
   recorded (prompt 02a); the check does not take the corrector's word.
4. **Stale-result protection**: every tool that reads `functions.json` beside
   an executable checks that the export was made from that executable.
5. **Function bodies as address ranges**: each function's body as Ghidra holds
   it, ends inclusive, where the function came from, and which bytes more
   than one function claims; `bodies.py` says which code no function claims
   and what it looks like (prompt 03).
6. **Names checked after they are written**: a mapping is validated whole
   before anything is written, every name and comment is read back, and a
   batch that fails is rolled back; `applynames-result.json` says what became
   of each entry (prompt 04).

## The envelope

`tools/evidence.py` builds it; `triage.py`, `survey.py` and `mzinfo.py` emit
it with `--evidence FILE`, or `--evidence -` for the envelope alone on stdout.
`tools/analysis_profile.py` writes two more: `profile.json` and `handshake.json`.
`tools/loadimage.py` writes `loadimage.json`. `load-corrections.json`, written
by `CorrectMzLoad.java`, is a record of its own (schema
`dos-decompiler/load-corrections/1`), not an envelope: it states what the script
did, and nothing in it is a finding.

| field | what it holds |
|---|---|
| `schema` | `dos-decompiler/evidence/1`. A consumer refuses a schema it does not know. |
| `tool` | which tool wrote it: `triage`, `survey`, `mzinfo`, `analysis_profile` (profile.json), `analysis_profile check` (handshake.json), `loadimage` (loadimage.json), `bodies` (bodies.json), `applynames` (applynames-result.json) |
| `tool_version` | the toolkit's git short hash, with `-dirty` if `tools/` has uncommitted or untracked changes, or `unknown` outside a checkout |
| `target` | `path` (absolute), `size`, `sha256` of the file examined. For a folder: `kind: "directory"`, `files`, total `size`, and one `sha256` over a manifest of every file's relative path, size and hash. `size` and `sha256` are `null` only in an `error` envelope for a file that could not be read |
| `profile` | the analysis profile the result was produced under, with its `profile_id`; `null` for a tool that runs no analysis |
| `status` | one of the six below |
| `result` | the tool's answer. For survey and mzinfo, exactly what `--json` writes (survey adds `next_step`); for triage, what `--json` writes less its `findings` list, whose entries are evidence items instead, plus `verdict_text` and, for a `.COM`, `next_step` |
| `evidence` | the observations the result rests on, one item each |
| `limitations` | what the method cannot see, true of every run |
| `unknowns` | what this run raised about this target and could not settle |

An **evidence item**:

| field | |
|---|---|
| `id` | deterministic; see below |
| `kind` | a short slug: `entry-point`, `packer-signature`, `memory-model`, `profile-field`, ... |
| `claim` | what is claimed, in one line. For a finding a report prints, its title |
| `location` | where it was seen: `{"file_offset": "0x1c"}`, a range with `file_end`, a list of relocation targets, a relative `path` inside a surveyed folder, or a profile `field` |
| `value` | what was measured there |
| `level` | optional: `info`, `warn`, `blocker`, `route`, `mismatch` |
| `detail` | optional: the explanation the report prints under the title |

### Statuses, and who may use them

| status | means | used by |
|---|---|---|
| `ok` | ran to completion; the result describes the target. Nothing was compared against an oracle, so nothing is proved | triage, survey, mzinfo, `analysis_profile.py write`, `loadimage.py expected`, `bodies.py`, `applynames.py` when the batch was applied |
| `verified` | compared with an independent oracle, and they agree | `analysis_profile.py check`, `loadimage.py verify` |
| `mismatch` | compared, and they disagree; the evidence says where | `analysis_profile.py check`, `loadimage.py verify` |
| `unsupported` | the target is a kind of input the tool does not handle, and it says so instead of producing something | mzinfo on a file that is not MZ; `loadimage.py` on a header that fails its bounds |
| `blocked` | something outside the target is missing, or a precondition refused the run | `analysis_profile.py check` when there is no export to check; `loadimage.py verify` when there is no dump; `applynames.py` when validation refused the batch, or a readback rolled it back (the exit code tells them apart) |
| `error` | the tool failed; nothing in the result is to be trusted | all, for a file that cannot be read |

A tool may use only the statuses it can honestly reach. A tool that compares
nothing never says `verified`, and `ok` never means "checked". triage's verdict
is not its status: a packed file is triaged `ok`, with `in_scope: false` in the
result, because triage did its job.

### Evidence ids

```
ev-43f63130-3b35384d
   ^^^^^^^^ ^^^^^^^^
   target   the item
```

The first half is the start of the target's SHA-256. The second hashes the
item's `kind`, `claim`, `location` and `value` in canonical form — not its
`detail` or `level`, and not its position in the list. So:

- the same claim about the same bytes has the same id in every run, from any
  folder, under any file name (tested: a fixture copied elsewhere under another
  name keeps all six ids);
- rewording an explanation, or reordering a report, changes no id;
- changing what is claimed, or what was measured, does.

Two different items that would collide get `-2`, `-3` in the order given. An
item listed twice with identical content is kept once: it is one observation,
and repeating it would read as corroboration it is not.

### Canonical form

Keys sorted, ASCII only (anything else escaped), integers as integers, floats
in Python's shortest round-trip form, NaN and infinity refused, `\n` line
endings on every platform. Two runs over the same input compare equal with a
plain `diff` — tested byte for byte on every fixture.

### Limitations and unknowns are different things

Both are things the result does not establish. The difference is whom they are
about.

A **limitation** is about the *tool*. It is true of every file the tool is run
on, so it can be written once: "stack frames are counted as the bytes
`55 8B EC` without disassembling, so the `89 E5` encoding is not counted." It
bounds how far any result from this tool can be trusted. One kind is triggered
by the target but is still about the tools: triage's "emuverify.py assumes
small model" warning is a fact about emuverify, so it is a limitation.

An **unknown** is about *this target*. It is a question this run raised and
could not answer, and something else could: "whether the PKLITE signature at
0xc00 is incidental". It is a to-do, not a caveat. A clean file raises none
(tested: smallc has no unknowns, spread has four).

The test for which one a sentence is: *would it still be true of a different
file?* If yes, limitation. If it is a question someone could go and settle for
this file, unknown.

## A worked example: triage on spread.asm

`tests/evidence/fixtures/spread.asm` is an MZ built so that every triage
finding is a warning — three relocations far from the entry, two stack frames
in two kilobytes, two kilobytes past the load image, and the bytes `PKLITE`
out in that trailing region. Real output, toolkit at `2decd95`:

```console
$ python tools/triage.py SPREAD.EXE
File   : SPREAD.EXE
Format : MZ
Image  : 2,048 bytes, 3 relocations
Entry  : 0000:0000

[WARN   ] PKLITE signature present
           Found at 0xC00, but the file has 3 relocations and normal frame
           density, so it does not look packed. Possibly incidental; confirm
           before acting on it.

[WARN   ] 2048 bytes past the load image
           Could be appended data, could be overlays. The disassembler will not
           see it unless told to.

[WARN   ] memory model looks compact, large or huge
           3 relocations over 2 KB (1.50/KB): far pointers throughout, so more
           than one code or data segment

[WARN   ] emuverify.py assumes small model
           It sets SS = DS and maps one 64 KB data group. On a far-pointer
           program it will run functions with the wrong stack segment and
           produce nonsense without saying so. modcluster.py and match.py's
           data fingerprints make the same assumption.

[WARN   ] mixed or frame-pointer-free (2 prologues, 1.0/KB)
           Either a lot of hand-written assembly, or a compiler omitting frame
           pointers under optimisation. Function boundary recovery will miss
           more than usual.

VERDICT: probably workable, with caveats above. Expect the measured accuracy figures not to hold.
```

```console
$ python tools/triage.py SPREAD.EXE --evidence -
```

```json
{
  "evidence": [
    {"claim": "MZ executable", "id": "ev-43f63130-896e9737", "kind": "format",
     "location": {"file_offset": "0x0"}, "value": "MZ"},
    {"claim": "load image of 2,048 bytes", "id": "ev-43f63130-070d966f",
     "kind": "load-image",
     "location": {"file_end": "0xa00", "file_offset": "0x200"}, "value": 2048},
    {"claim": "3 relocations", "id": "ev-43f63130-edfadbea",
     "kind": "relocation-count", "location": {"file_offset": "0x6"}, "value": 3},
    {"claim": "entry point 0000:0000, file offset 0x200",
     "id": "ev-43f63130-ab0e054c", "kind": "entry-point",
     "location": {"file_offset": "0x200"}, "value": "0000:0000"},
    {"claim": "PKLITE signature present",
     "detail": "Found at 0xC00, but the file has 3 relocations and normal frame density, so it does not look packed. Possibly incidental; confirm before acting on it.",
     "id": "ev-43f63130-3b35384d", "kind": "packer-signature", "level": "warn",
     "location": {"file_offset": "0xc00"},
     "value": {"near_entry": false, "packer": "PKLITE", "prologues_per_kb": 1.0,
               "relocations": 3, "signature": "PKLITE"}},
    {"claim": "2048 bytes past the load image",
     "detail": "Could be appended data, could be overlays. The disassembler will not see it unless told to.",
     "id": "ev-43f63130-749c91ed", "kind": "trailing-data", "level": "warn",
     "location": {"file_offset": "0xa00"}, "value": 2048},
    {"claim": "memory model looks compact, large or huge",
     "detail": "3 relocations over 2 KB (1.50/KB): far pointers throughout, so more than one code or data segment",
     "id": "ev-43f63130-04027752", "kind": "memory-model", "level": "warn",
     "location": {"relocation_targets": ["0x504", "0x509", "0x50e"]},
     "value": {"image_bytes": 2048, "model": "compact, large or huge",
               "relocations": 3}},
    {"claim": "mixed or frame-pointer-free (2 prologues, 1.0/KB)",
     "detail": "Either a lot of hand-written assembly, or a compiler omitting frame pointers under optimisation. Function boundary recovery will miss more than usual.",
     "id": "ev-43f63130-939f73d6", "kind": "prologue-density", "level": "warn",
     "location": {"file_end": "0xa00", "file_offset": "0x200"},
     "value": {"pattern": "55 8b ec", "per_kb": 1.0, "prologues": 2}}
  ],
  "limitations": [
    "The memory model is inferred from how many relocations there are and where they sit, not read from the file; a program that builds its segment values at run time looks smaller than it is.",
    "Packers are recognised by signature, and EXEPACK by its 'RB' marker. A packer with no signature in triage.py's table is not detected; few relocations with few stack frames is the only other hint.",
    "Stack frames are counted as the bytes 55 8B EC anywhere in the load image, without disassembling. The other encoding of mov bp,sp (89 E5) and ENTER are not counted, and the same bytes inside data are.",
    "Interpreted engines are recognised by engine names in the binary and by the size of the files beside it. An engine that names nothing and keeps its data elsewhere passes as an ordinary program.",
    "emuverify.py assumes small model: It sets SS = DS and maps one 64 KB data group. On a far-pointer program it will run functions with the wrong stack segment and produce nonsense without saying so. modcluster.py and match.py's data fingerprints make the same assumption."
  ],
  "profile": null,
  "result": {
    "entry": "0000:0000", "file": "SPREAD.EXE", "format": "MZ",
    "image_bytes": 2048, "memory_model_guess": "compact, large or huge",
    "prologue_density": 1.0, "prologues": 2, "relocations": 3,
    "verdict": {"confidence": "low", "in_scope": true},
    "verdict_text": "VERDICT: probably workable, with caveats above. Expect the measured accuracy figures not to hold."
  },
  "schema": "dos-decompiler/evidence/1",
  "status": "ok",
  "target": {"path": "...\\SPREAD.EXE",
             "sha256": "43f63130d5f339fae53bff0848b33e03179754a00606bca499df7e2d2807e2e6",
             "size": 4608},
  "tool": "triage",
  "tool_version": "2decd95",
  "unknowns": [
    "whether the PKLITE signature at 0xc00 is incidental, or a packer triage did not otherwise recognise",
    "what the 2048 bytes past the load image are: appended data, overlays, or a packer's payload",
    "which far-pointer model this is, and how many code and data segments it has",
    "whether this is hand-written assembly or C compiled without frame pointers; libsig.py with each shipped database tells them apart"
  ]
}
```

(Reflowed for reading, and the absolute path shortened; the tool writes one
key per line.)

Every line of the report has its counterpart:

| report line | envelope |
|---|---|
| `File   : SPREAD.EXE` | `result.file`; `target.path` is the same file, absolute |
| `Format : MZ` | `result.format`; evidence `format` |
| `Image  : 2,048 bytes, 3 relocations` | `result.image_bytes`, `result.relocations`; evidence `load-image`, `relocation-count` |
| `Entry  : 0000:0000` | `result.entry`; evidence `entry-point`, with the file offset |
| `[WARN] PKLITE signature present` + its detail | evidence `packer-signature` (claim, detail, offset `0xc00`); unknown 1 |
| `[WARN] 2048 bytes past the load image` + detail | evidence `trailing-data`; unknown 2 |
| `[WARN] memory model looks compact, ...` + detail | evidence `memory-model`, with the three patched words; unknown 3 |
| `[WARN] emuverify.py assumes small model` + detail | limitation 5 — a fact about emuverify, not about the file |
| `[WARN] mixed or frame-pointer-free ...` + detail | evidence `prologue-density`; unknown 4 |
| `VERDICT: probably workable, ...` | `result.verdict_text`; `result.verdict` |

What the prose never said, and the envelope does: *where* each thing was seen —
`0xc00`, `0x504/0x509/0x50e`, `0x200..0xa00` — and which of the five warnings
are open questions about this file (four) rather than standing caveats (one).

`tests/evidence/regress.py` checks this mapping mechanically — triage on all 18
fixture files, survey on 5 folders, mzinfo on the 7 MZ fixtures: each report
line must match the envelope field that carries it, and a line that matches
nothing fails the suite.

## The analysis profile

`tools/analysis_profile.py write` runs before import and writes `profile.json`, an
envelope whose `profile` is:

| field | measured value | how it is observed after export |
|---|---|---|
| `loader` | `Old-style DOS Executable (MZ)` | `Program.getExecutableFormat()` |
| `language` | `x86:LE:16:Real Mode` | `Program.getLanguageID()` |
| `compiler_spec` | `default` | `CompilerSpec.getCompilerSpecID()` |
| `image_base` | `0000:0000` | `Program.getImageBase()` |
| `load_segment` | `0x1000` | where image byte 0 landed, from the blocks' file offsets |
| `address_convention` | `ssss:oooo` | every function entry matches `[0-9a-f]{4}:[0-9a-f]{4}` |
| `ghidra_version` | read from `Ghidra/application.properties` | `Application.getApplicationVersion()` |
| `toolkit_version` | git short hash | not observed, so not compared; a record only |
| `analysis_code` | per-file hashes of the code the export depends on | not observed, so not compared |
| `recovery` | `{ran, script_sha256}` | a mark `RecoverFunctions.java` leaves in Program Information |
| `export` | `{script_sha256, helper_sha256}` of `ExportDecompiledC.java` and `LoadImageMap.java` | each hashes its own source into `observed_profile` |
| `load_image_dump` | the same for `DumpLoadImage.java` and `LoadImageMap.java` | each hashes its own source into the dump; held to it by `loadimage.py verify`, not the handshake |
| `load_correction` | `{ran, script_sha256, helper_sha256}` of `CorrectMzLoad.java` and `LoadImageMap.java`; `ran: false` and `null` hashes under `-NoLoadCorrection` | a mark `CorrectMzLoad.java` leaves in Program Information, with the count; `ran` and `script_sha256` are compared, and the helper's hash is held by `loadimage.py verify`, which checks the corrections record was written by the copy in this checkout |

`LoadImageMap.java` is a plain class, not a script: the walk over where the
file's bytes landed, and the self-hash, shared by the exporter and the dumper
so each is written once. Ghidra compiles a script directory as one bundle, so a
script can call a class beside it — measured on 12.1.2 before relying on it.

### What `profile_id` covers

`profile_id` is the SHA-256 of the profile's canonical JSON **without
`profile_id` and without `toolkit_version`**. It names the *settings*, not the
file: two executables analysed the same way share it (tested).

`toolkit_version` stays in the profile as a record of which commit wrote it,
but it moves on every commit — one that only edits this document included —
and prompt 06 caches Ghidra's results by target hash plus `profile_id`. An id
that moved with the git hash would throw that cache away on every
documentation change. What stands in for it is `analysis_code`: a hash over the
code that can change what an export contains, and nothing else.

| hashed in `analysis_code` | why |
|---|---|
| `tools/ghidra_scripts/`, every file | Ghidra runs these and they write the export. `ApplyNames.java` is included although the pipeline does not run it, because the names it writes into a project are read back by the next export |
| `tools/pipeline.ps1` | it chooses the import, the stages, their order and their arguments |

| not hashed | why |
|---|---|
| `tools/analysis_profile.py` | its expected values are already fields of the profile, so changing one changes the id anyway; the rest of it only compares |
| `tools/mzinfo.py` | it decides whether the pipeline runs at all, not what an export contains |
| `tools/evidence.py` and the rest of `tools/` | nothing an export depends on |
| `knowledge/`, `README.md`, `AGENTS.md`, `tests/` | documents and tests |

It is computed from file contents, not from git, so it means the same thing in
a copy that is not a checkout, and an uncommitted edit moves it with no `-dirty`
logic needed. Tested on a copy of the toolkit in a git repository of its own: a
commit to `knowledge/17-evidence.md` moved `toolkit_version` (`4b21af0` →
`433afa4` in one run — the throwaway repository's own hashes, different every
run) and left `profile_id` alone; an edit to `tools/evidence.py` made
`toolkit_version` dirty and left it alone; an edit to any one of the hashed
files moved it, and `analysis_code.files` named that file and no other. That
was four files when first measured; the test now edits every file
`analysis_code` lists, seven since prompt 02a added `CorrectMzLoad.java`.

### Line endings

**Source is hashed with CRLF read as LF** (`evidence.source_sha256`), the
recovery script's hash included, on both sides: `analysis_profile.py` folds the
bytes before hashing, and `RecoverFunctions.java` folds its own source the same
way before writing its mark. Only the two-byte pair is folded, as git folds it;
a lone CR is kept. A checkout with `core.autocrlf=true` — this machine's, where
the Ghidra scripts are CRLF on disk — and an LF checkout of the same commit
therefore have one `profile_id`. Tested: every hashed file in a copy flipped to
the other ending, same `profile_id`; and through Ghidra on this CRLF checkout,
the hash the Java side wrote equals the one Python computed.

**Targets are hashed raw.** In an executable `0D 0A` is data.

**The profile is an expectation, not an instruction.** `pipeline.ps1` still
lets Ghidra choose the loader and language, exactly as before, and checks
afterwards that it chose these. Passing them to the import would make Ghidra
agree by construction and hide the drift the check exists to catch — a Ghidra
upgrade that changes a default, or a file Ghidra decides is not MZ at all.

### How the values were measured

Imported `tests/evidence/fixtures/smallc.asm` with the unmodified pipeline on
Ghidra 12.1.2, then read the program back with a read-only script:

```
MEASURE ghidra_version=12.1.2
MEASURE executable_format=Old-style DOS Executable (MZ)
MEASURE language_id=x86:LE:16:Real Mode
MEASURE compiler_spec_id=default
MEASURE image_base=0000:0000 class=SegmentedAddress space=ram
MEASURE block CODE_0 1000:0000..1000:004f size=80 x=true init=true
MEASURE   source 1000:0000 fileBytes=true fileOffset=512
MEASURE block CODE_1 1005:0000..1005:0054 size=85 x=true init=true
MEASURE   source 1005:0000 fileBytes=true fileOffset=592
MEASURE block DATA 1005:0055..1005:0454 size=1024 x=false init=false
MEASURE block HEADER HEADER::00000000..HEADER::000001ff size=512 x=false init=true
MEASURE function 1000:0000 entry
MEASURE function 1000:0015 FUN_1000_0015
```

Two of those are worth knowing on their own:

- **The image loads at segment `0x1000`**, which agrees with rea's
  documentation — file offset 512, the first byte after the 512-byte header,
  is `1000:0000`. **But `getImageBase()` says `0000:0000`.** The `image_base`
  field `functions.json` has always carried is therefore not the load segment,
  and reading it as one puts every address `0x10000` out. The exporter works
  the load segment out from the blocks instead: each block backed by the file
  says which file offset it starts at, subtracting the header size gives the
  image offset, and every block must agree on one load address. If they do not,
  it reports `inconsistent` and the handshake fails rather than picking one.
- **Ghidra's own analysis found all five of smallc's routines**, including one
  reached only through a stored function pointer and one reached by nothing,
  because its function-start patterns know `55 8B EC`. RecoverFunctions added
  none. A routine with no prologue, reached only through an immediate, is what
  it is still needed for: a scratch variant with one added two.

### The handshake

After export, `analysis_profile.py check` compares fifteen fields — the
thirteen the export observes, the exporter's and its helper's own hashes and
the load corrector's mark among them, and the target's SHA-256 and size from
`profile.json` against `functions.json` —
and writes `handshake.json`, status `verified` or `mismatch`, one
`profile-field` evidence item per field. On any difference the pipeline stops:

```
  checking the export against the profile
    profile drift: compiler_spec: expected borland, observed default
    drift\functions.json was not produced under profile e1d1bc5c34f7298b. Do not use it until the difference is understood; the record is in drift\handshake.json.
Exception: E:\Projects\DOS-Decompiler\tools\pipeline.ps1:221
     | profile handshake failed, results in drift are not to be used: profile drift: compiler_spec: expected borland,
     | observed default
```

That run was forced: `DOS_DECOMPILER_FORCE_DRIFT=compiler_spec=borland` makes
`analysis_profile.py write` expect a wrong value, and announces itself on stderr when it
does. It exists so a test can prove the check fails; never set it for real
work. `tests/evidence/` drifts each of the fifteen fields in turn against
hand-written exports and requires each to be refused by name;
`tests/handshake/` forces the drift above through Ghidra itself.

A forced `load_segment` drift no longer gets this far. Since prompt 02 the load
image is verified right after import, against the profile's load segment, and
that stops the run first (below).

An export written before prompt 02a has no `observed_profile.load_correction`.
Checked against a profile written now, it reports drift on
`load_correction.ran`, which is true: the corrector did not run on it. That was
accepted rather than special-cased. Re-run the pipeline. Readers of an old
work folder are unaffected, because they read the `handshake.json` written at
the time.

The run stops; it does not delete anything. `functions.json` is still on disk
after a failed handshake, and `handshake.json` beside it says why — which is
also what stops every reader of it (below).

### What the recovery mark catches, measured

`RecoverFunctions.java` writes the SHA-256 of its own source into the
program's Program Information when it runs; the exporter reads it back. The
profile expects the hash of the `RecoverFunctions.java` in this checkout, or
`ran: false` under `-SkipRecovery`. So the handshake refuses an export from a
project where recovery never ran, or ran an older copy of the script.

It was also meant to catch the loss recorded in `04-pitfalls.md` — chaining
two `-postScript` flags in one run discarding the first script's changes. On
Ghidra 12.1.2 that loss **did not reproduce**. With a scratch fixture recovery
adds two functions to, all three ways of running it exported the same seven
functions and the mark: separate invocations, both scripts chained on
`-import`, and both chained on `-process -noanalysis`. There was nothing there
for the mark to catch. The pipeline keeps its separate invocations, which cost
nothing.

## The load image

The profile says which settings Ghidra used. It does not say that Ghidra's
program *is the file*: the same bytes, at the addresses the MZ header implies,
every relocation applied once per entry. A loader that drops part of the image
or applies a fixup the wrong number of times produces decompiled C that looks
perfectly normal. So stage 4 of the pipeline checks it, right after import and
correction, and before anything is built on the program.

| side | what | where |
|---|---|---|
| expected | from the file alone: the load module's file range (end **inclusive**, `file_end_inclusive`) and digest; every relocation with its target, the word before and after the fixup, and how many entries patch that word; entry `CS:IP` and `SS:SP` as `segment:offset` and linear; anything after the declared image, with its digest, as outside the module | `tools/loadimage.py expected` |
| observed | every block, the file range behind each part of it, its bytes, Ghidra's copy of the file before and after fixups, the relocation table with status and original bytes, the entry points, `SS`/`SP` at the entry | `tools/ghidra_scripts/DumpLoadImage.java`, writing `loadimage-observed/` |
| comparison | one check per property, each with its expected and observed value | `tools/loadimage.py verify`, writing `loadimage.json` |

The expected side parses the header with `mzinfo.py` — one parser for the
format in the toolkit, and it needs nothing but the file — and adds the bounds
mzinfo does not check: header size, page counts, relocation table bounds,
relocation targets inside the module, entry inside the module. A file that
fails one is `unsupported`, with the reason, and never a traceback.

### What "a correct load" means: DOS, not Ghidra

The expected load is what DOS does, and that was read from two independent DOS
loaders rather than remembered (read 2026-10-19):

- **Each relocation entry adds the load segment to the word it names, in table
  order.** FreeDOS, `kernel/task.c`: `*spot += start_seg;` once per entry.
  DOSBox Staging, `src/dos/dos_execute.cpp`:
  `mem_writew(address, mem_readw(address)+relocate);` once per entry. So an
  entry listed twice adds it twice, and a later entry sees what an earlier one
  wrote.
- **A last page with bytes-on-last-page 0 is a full page.** Both loaders size
  the image as `pages * 512 - header`, so a 0 there loads the whole page.

Ghidra 12.1.2's `MzLoader` differs on both — measured, with fixtures:

```
$ python tools/loadimage.py verify DUPLICATED.EXE DUPLICATED\loadimage-observed
load image: mismatch, 4 of 28 checks failed
first failing check: relocations.words: expected each patched word holds its value after every fixup to it, observed ['1006:0016: 0x1004 not 0x2004']
first differing byte: file 0xb7, 1006:0017 (linear 0x10077): expected 0x20, observed 0x10

$ python tools/loadimage.py verify FULL_LAST_PAGE.EXE FULL_LAST_PAGE\loadimage-observed
load image: mismatch, 2 of 28 checks failed
first failing check: module.coverage: expected file 0x40..0x3ff, once, observed ['file 0x200..0x3ff not loaded']
```

Its source says why. It collects the fixups in a set and *writes*
`0x1000 + the word read from the file` for each, rather than adding to what
memory holds: two entries for one word give the same value twice. Ghidra keeps
both relocation records, so the multiplicity check passes and only the word is
wrong. And it computes the image end as `(pages - 1) * 512 + bytes_on_last_page`,
which for a 0 drops the entire last page. A linker writes 0 there whenever the
file size is a multiple of 512.

Both loaders also load whole pages, so bytes after the declared end of the
image but inside its last page do reach memory under DOS. This check keeps the
prompt's definition: the module is the header-declared image, and anything
after it is reported as appended, its digest kept, outside the module.

### Correcting the two, then checking anyway

Refusing such a file left two bad choices: stop, or analyse a load known to be
wrong. So stage 3, `tools/ghidra_scripts/CorrectMzLoad.java`, corrects those
two divergences and nothing else, after import and before anything reads the
program's bytes. It reads the record `loadimage.py expected` writes, whose path
it is given as an argument.

| divergence | what the corrector does |
|---|---|
| the last page is missing (bytes-on-last-page 0, and Ghidra's mapping ends exactly one page short of the module) | maps the missing file range at its expected addresses, from Ghidra's own copy of the file, and joins it to the block before it. Ghidra places the minalloc block right where the page belongs, so that block is moved after the page, with its name, size and permissions. Relocations inside the page are applied as DOS applies them |
| a word listed in several relocation entries | writes the file word plus the load segment once per entry, modulo `0x10000`; the relocation table stays as Ghidra recorded it |

How to restore the page was measured on 12.1.2 rather than chosen. A new
initialised block from the file bytes, at `1006:0160` in the segment of the
block before it, joins to that block: `CODE_3` becomes `1006:0000..035f`, one
block backed by one run of the file. A new block on its own is the fallback.
No fixture needed it, but forced by disabling the join, it verified as well;
only the record says which happened (`a block of its own (CODE_3_page)`).

It changes nothing if the expected record did not come out `ok`, if the program
has no copy of the file, if that copy's hash is not the target's, or if Ghidra
put the image at another load segment than the record expects. Both
corrections are computed from that segment, so under a forced `load_segment`
drift to `0x2000` the corrector would otherwise write `0x4004` where DOS writes
`0x2004`; it refuses, and the load-segment check stops the run (tested). It
corrects nothing it was not written for: a third kind of difference stays a
mismatch for the verifier to report. Each run writes `load-corrections.json`,
with the script's own hash folded as in [line endings](#line-endings). On the
fixture with both divergences:

```json
{"kind": "missing-last-page", "file_start": 512, "file_end_inclusive": 1023,
 "linear_start": 65984, "linear_end_inclusive": 66495, "address": "1006:0160",
 "before": "not loaded",
 "after": "file 0x200..0x3ff mapped at 1006:0160, joined to CODE_3",
 "uninitialized_moved": "DATA 1006:0160 size 256 -> DATA 1006:0360 size 256",
 "fixups": []},
{"kind": "duplicated-relocation", "address": "1006:0016", "linear": 65654,
 "file_offset": 182, "entries": 2, "relocation_records": 2,
 "before": "0x1004", "after": "0x2004"}
```

**The verifier does not trust the corrector.** It checks only where the record
came from: `corrector.script_sha256`, `corrector.helper_sha256` and
`corrector.target`, so a fixture's 28 checks become 31. Everything else is
compared with the file exactly as though no corrector existed. A dump changed
after correction is still a mismatch, tested. The record's corrections are
copied into `loadimage.json` (`corrections`, `corrections_made`,
`correction_record`), and the count reaches `functions.json`:

```json
"load_image": {"status": "verified", "corrections": 2, "mismatch_allowed": false, "record": "loadimage.json"}
```

`corrections` is `null` when the corrector did not run, `0` for a clean load,
and the count otherwise, so a reader can always tell a clean load from a
corrected one. The prose says `load image: verified after 2 corrections (see
load-corrections.json), 31 checks agree`.

On a clean file it corrects nothing and says so. The dump is byte for byte
Ghidra's own (tested on the good fixtures). It still writes one thing into the
program: its mark in Program Information, with the count 0. That is how the
export proves the corrector ran, which copy, and with what result, as
`RecoverFunctions.java`'s mark does.

`-NoLoadCorrection` skips it, to see Ghidra's raw load. The two fixtures then
stop with prompt 02's mismatches, word for word (tested), and the profile
expects `load_correction.ran: false`.

What it cannot correct: the record of a relocation *inside* the missing page.
The corrector restores the page and applies the fixup
(`1006:0172: 0x0004 -> 0x1004` on the `TAIL_RELOCATION` fixture). But the
relocation record Ghidra wrote for it says `FAILURE`, with no original bytes,
and `RelocationTable` has only `add` and `get` methods (checked with `javap` on
12.1.2), so nothing can rewrite that record. Until prompt 03 such a file
failed `relocations.status` and `relocations.original` and stopped.

It now verifies, through a check of its own,
`relocations.status_after_correction`. A `FAILURE` record is accepted only
when all three of these hold:

- the word in memory is the value the verifier computes from the file;
- the address lies inside a range the corrections record says was restored;
- that record passed its provenance checks.

The ranges are the only thing taken from the record, and only to say which
records the check may judge. When it accepts a record, the check lists it, and
the envelope's `limitations` say that Ghidra's relocation table still reads
`FAILURE` there. The check appears only when there is such a record, so
`TAIL_RELOCATION` verifies with 32 checks where the other corrected fixtures
have 31. If the word in memory is changed, the check fails and names both
values (`1006:0172: memory holds 0x1005, not 0x1004`). A `FAILURE` outside
the restored range, or under a record from another corrector, fails as it
always did (tested).

When the page does not fit in the segment of the block before it, the
corrector maps it at its own paragraph instead. `tests/loadimage/fixtures/bigpage.asm`,
one segment just past 64 KB, exercises that: its page at offset `0xFFC0` of
segment `0x1000` goes back at `1ffc:0000`, joins `CODE_0` (which Ghidra then
shows as `1000:0000..2000:01bf`), and the load verifies. Forced into the
segment form by a mutation, the page went in at `1000:ffc0` and verified as
well: Ghidra 12.1.2 accepts a block running past offset `0xFFFF`. So the
paragraph form is a choice, not a necessity, and the test pins it by the exact
record.

**Analysis now runs after verification.** In 02, import ran Ghidra's
auto-analysis, which reads every byte, so the page would have been missing
while functions were found. Import now uses `-noanalysis`, and stage 5 runs the
analysis in its own invocation, then recovery in another. They are separate
because combined, on a 51,904-byte real game, the export came out with one
function more (171, not 170) and 11 of the other records changed: Ghidra
analyses what the script creates. Separately, it matched the
export from before this prompt record for record, and the segments fixture's
export matched too.

### The checks, in the order a failure is reported

| check | holds that |
|---|---|
| `dumper.script_sha256`, `dumper.helper_sha256` | the dump was written by the `DumpLoadImage.java` and `LoadImageMap.java` in this checkout (the profile's `load_image_dump`) |
| `loader`, `load-segment` | Ghidra used the MZ loader, and image byte 0 landed at the profile's load segment |
| `file.size`, `file.original`, `executable.sha256` | Ghidra's copy of the file, and the hash it recorded at import, are the file |
| `header.mapping` | the header, wherever Ghidra keeps it, is outside the analysis address space and unchanged |
| `module.coverage` | every byte of the module is mapped exactly once, and nothing outside it is |
| `module.as-stored` | Ghidra's copy of the module bytes, before fixups, is the file's |
| `relocations.set`, `.multiplicity`, `.status`, `.original` | the same targets, the same number of entries for each, all `APPLIED`, each record's original bytes the file's word |
| `relocations.status_after_correction` | only when a `FAILURE` record lies in a page the corrector restored: its word in memory is the file's after the fixup, the range is one the record says it restored, and the record's provenance holds. Only then is that record left out of `.status` and `.original` |
| `relocations.words` | each patched word holds its value after every fixup to it |
| `mapping <block> <address>.address`, `.digest` | for each range of each block: it sits at load segment × 16 + image offset, and its bytes are the file's with fixups applied |
| `module.loaded`, `file.modified` | the module in memory, and Ghidra's own patched copy of the file, are the file with fixups applied |
| `overlay.excluded` | nothing past the declared image was loaded |
| `entry`, `stack` | `CS:IP` and `SS:SP` as the header gives them |
| `corrector.script_sha256`, `.helper_sha256`, `.target` | only when the corrector ran: `load-corrections.json` was written by the `CorrectMzLoad.java` and `LoadImageMap.java` in this checkout, about this file. Where it came from, never what it says it did |

**A relocated word differs from the file word by design.** Every memory digest
is taken against the file *with the fixups applied*, never the file as stored,
and the relocation checks hold each patched word to its value after the fixup.
`tests/loadimage/` proves both directions. A dump whose memory holds the file's
word at one relocation fails `relocations.words`, and so does a dump of the
file exactly as stored.

On a digest mismatch the first differing byte is located: file offset,
`segment:offset`, linear address, expected and observed value. A tampered dump
gave `byte at file 0x52 (1001:0002): 0x22 -> 0x78`, the byte that was changed.

### `map`

`loadimage.py map loadimage.json --file 0x... | --address ssss:oooo | --linear
0x...` converts through the verified mapping, and refuses a record that did not
verify. `map_address(record, ...)` is importable, for prompt 06's server.

```
$ python tools/loadimage.py map loadimage.json --address 1005:0026
file 0xb6  =  1006:0016  =  linear 0x10076  (CODE_3)
  1005:0026 names the same byte as 1006:0016, the address Ghidra uses
  other segment:offset pairs name this byte too -- any ssss:oooo with ssss*16+oooo equal to the linear address
  inside the relocated word at 1006:0016: memory holds 0x1004, the file 0x0004
$ python tools/loadimage.py map loadimage.json --file 0x10
loadimage: file offset 0x10 is in the MZ header (0x0..0x3f), which is not loaded into the program's address space
```

The canonical address is the one Ghidra uses: the segment of the block the byte
is in. Header bytes, appended bytes, uninitialised memory and unmapped
addresses are refused with what they are. The tests round-trip every
initialised byte, file offset to address to file offset.

### In the pipeline

```
[3/6] Correct the load
  correcting what the loader is known to get wrong
    INFO  CorrectMzLoad.java> CorrectMzLoad: 0 correction(s); Ghidra loaded the image at segment 0x1000, the expected record at 0x2000, so nothing is corrected -> segdrift\load-corrections.json (GhidraScript)
    corrected in 8.3 s; the record is segdrift\load-corrections.json

[4/6] Verify the load image
  dumping what Ghidra loaded
    INFO  DumpLoadImage.java> DumpLoadImage: 6 blocks, 4 relocations, 1 entry point(s) -> segdrift\loadimage-observed (GhidraScript)
    load image: mismatch, 14 of 31 checks failed
    first failing check: load-segment: expected 0x2000, observed 0x1000
    checked in 8.0 s; the record is segdrift\loadimage.json
Exception: E:\Projects\DOS-Decompiler\tools\pipeline.ps1:212
     | load image mismatch, stopping before anything is built on it: load image: mismatch, 14 of 31 checks failed;
     | first failing check: load-segment: expected 0x2000, observed 0x1000. Read segdrift\loadimage.json; pass
     | -AllowLoadMismatch to continue anyway.
```

(That one is the forced `load_segment` drift the handshake used to catch, on
the `tests/loadimage` fixture. The corrector refuses first, because both of its
corrections depend on the load segment. The stage times are from a run while
the machine was busy with other work.)

Anything but `verified` — `mismatch`, `unsupported`, or `blocked` when there is
no dump to compare — stops the run. `-AllowLoadMismatch` goes on with a banner
saying so. The verdict reaches `ExportDecompiledC.java` as a script argument
(`load_image:mismatch`, `load_image:allowed`; not `a=b`, because cmd.exe splits
an argument at `=` and that form never arrived), and lands in
`functions.json`:

```json
"load_image": {"status": "mismatch", "corrections": null, "mismatch_allowed": true, "record": "loadimage.json"}
```

(That is `-NoLoadCorrection -AllowLoadMismatch` on the full-last-page fixture,
so `corrections` is `null`: the corrector did not run.)

Every reader of such a `functions.json` then warns, once, with the first
failing check from the `loadimage.json` beside it. It does not refuse: going on
was someone's explicit decision.

Measured cost, prompt 02: the check took 5.0 to 5.2 s in three runs each on
the two largest fixtures, of a 22 s pipeline. On six real MZ files of 51,904
to 171,917 bytes it took 5.2 to 6.5 s. The Python comparison is 0.17 s of that
on the largest; the rest is starting Ghidra headless once more. All six
verified (24 to 30 checks), one with 340 bytes appended past its image, kept
out of the module.

Measured cost, prompt 02a, in eight runs on three fixtures while the machine
was otherwise quiet: correcting took 4.9 to 5.3 s, checking 4.9 to 5.6 s, and
the whole pipeline 31.6 to 34.9 s, with one run at 38.3 s. That is about 10 s
more than prompt 02's 22 s. The extra time is two more starts of Ghidra
headless: the corrector's, and analysis now running on its own instead of
during import. On the six real files, correcting took 5.0 to 5.6 s. Every one
verified with 0 corrections and 27 to 33 checks, and its dump was identical to
prompt 02's.

## Stale results

`functions.json` now carries `target`: the path Ghidra imported from, the size,
and a SHA-256 the exporter computes over the program's own copy of the file
bytes — what the analysis read, not the import metadata.

Every tool that reads `functions.json` beside an executable checks it:

| reader | executable it checks against |
|---|---|
| `libsig.py apply` | the `exe` argument |
| `emuverify.py` | the executable beside each map that is a `functions.json` |
| `anchors.py`, `match.py`, `modcluster.py` | `--exe`, new and optional; without it, the file recorded in `target.path` |

| case | behaviour |
|---|---|
| hashes agree | silent |
| hashes differ, executable given | refuses, exit 1, naming the `functions.json` to regenerate and both hashes |
| hashes differ, no `--exe`, the recorded file has changed | one warning: the executable was probably rebuilt in place and the pipeline not re-run. A tool given no executable is not reading one, so this does not refuse; `--exe` makes it an error |
| no `target` field | one warning per file per run, then carries on, so old work folders still open |

```
libsig.py: out\functions.json was produced from a different file than spread.exe.
  functions.json target : .../SMALLC.EXE  677 bytes  sha256 7f0599a0bb4dcdb1...
  given                 : spread.exe  4608 bytes  sha256 43f63130d5f339fa...
Regenerate out\functions.json from spread.exe with tools/pipeline.ps1, or pass the executable it was made from.
```

(Paths shortened; the sizes and hashes are the fixtures' own.)

### A failed handshake stops the readers too

The same readers look for a `handshake.json` beside the `functions.json` they
were given, through `evidence.load_functions`:

| `handshake.json` | behaviour |
|---|---|
| absent | as before: a work folder from before the handshake opens |
| `verified` | silent |
| `mismatch` | refuses, exit 1, with each drifted field and what to do |
| `blocked` | refuses: the handshake could not run, there was no export to check |
| about an earlier export | refuses, like `mismatch`, whatever the record's status. The record carries `functions_sha256`, the hash of the export it checked; if `functions.json` has been rewritten since, the export beside the record never went through a handshake. (01a had this warn and read; the architect changed it) |
| unreadable | one warning, and reads |

Real output, on what a forced-drift pipeline run left in `drift\`:

```console
$ python tools/anchors.py drift\functions.json --exe SMALLC.EXE
anchors.py: drift\functions.json did not pass its profile handshake: the handshake found compiler_spec: expected borland, observed default.
The record is drift\handshake.json. Find out why Ghidra did not do what the profile expected, fix it and re-run tools/pipeline.ps1. If you have understood why and want these results anyway, pass --accept-profile-drift.

$ python tools/anchors.py drift\functions.json --exe SMALLC.EXE --accept-profile-drift
anchors.py: --accept-profile-drift: reading drift\functions.json although the handshake found compiler_spec: expected borland, observed default. Everything below rests on settings the rest of the toolkit does not assume.
4 of 5 functions carry identifying evidence
...
```

The first exits 1, the second 0.

`--accept-profile-drift`, on all five readers, reads a drifted export for
someone who has understood why. It says so on stderr every time it takes
effect, naming the drift, so a result produced that way cannot be mistaken for
an ordinary one. `tests/handshake/` runs all five on what a forced drift through
Ghidra left behind: each refuses, each reads with the override and says so,
each reads the verified export silently, and each reads the drifted one as
before once `handshake.json` is removed.

## Function bodies

`functions.json` gave each function an entry and one `size`, and every
consumer read that as one contiguous run of bytes the function owns. Code of
the period is not that tidy: a jump table sits in the middle of a function, two
functions share an epilogue, hand-written assembly jumps into the middle of a
neighbour, and `RecoverFunctions.java` splits functions Ghidra ran together.

### `body`

Every function record now ends with `origin` and `body`:

```json
"body": {"available": true, "provenance": "ghidra-function-body-address-set",
         "ranges": [{"start": "1000:008a", "end": "1000:0098", "start_linear": "0x1008a", "end_linear": "0x10098"},
                    {"start": "1000:009f", "end": "1000:00ad", "start_linear": "0x1009f", "end_linear": "0x100ad"}],
         "total_bytes": 30, "span_bytes": 36, "non_contiguous": true, "contains_entry": true}
```

| field | holds |
|---|---|
| `ranges` | every range of Ghidra's body address set, in address order. **Ends are inclusive**: `1000:008a..1000:0098` is 15 bytes. Each end as Ghidra writes it (`ssss:oooo`) and as a linear address (segment × 16 + offset) |
| `total_bytes` | the addresses in the body |
| `span_bytes` | lowest to highest, inclusive: what one contiguous run from the first byte to the last would hold |
| `non_contiguous` | `total_bytes` differs from `span_bytes`: something that is not this function's sits between its first byte and its last |
| `contains_entry` | the body holds the entry address |
| `available`, `provenance` | whether Ghidra has a body at all, and where it came from: `ghidra-function-body-address-set` |

**`size` is unchanged, and was measured to be the body's address count**,
`getBody().getNumAddresses()`, the same as `total_bytes`. It is not the span.
The two differ for every non-contiguous function: the switch above is
`"size": 30`, its span 36, and the 6 bytes between are its jump table.

What Ghidra 12.1.2 does with each shape, measured on
`tests/bodies/fixtures/bodies.asm`:

| shape | what Ghidra makes of it |
|---|---|
| two functions jumping to one epilogue | **three functions.** Each of the two ends at its own `jmp`, and the epilogue is a function of its own |
| a jump into the middle of a neighbour | the neighbour keeps the tail it falls into; the jumper's body ends at its jump |
| a chunk past another function, reached by an unconditional `jmp` | a function of its own |
| the same chunk reached by a conditional jump | kept in the body: two ranges, the other function between them |
| a jump table in the middle of a function | the table is data, so the body is two ranges, one either side of it |
| two bodies sharing a byte | refused. `Function.setBody` and `FunctionManager.createFunction` both throw `OverlappingFunctionException` |

### `origin`

Why the function exists. A function `RecoverFunctions.java` created is a
hypothesis resting on weaker evidence than Ghidra's flow analysis, and a later
tool should be able to tell:

| origin | evidence |
|---|---|
| `ghidra-analysis` | Ghidra's own analysis. An import without analysis holds no functions (measured), so a function no mark names is analysis's |
| `recovered-call-target` | something calls it |
| `recovered-code-pointer` | an immediate in the code points at it |
| `recovered-split` | a prologue inside another function's body; the function the split shortens keeps its own origin |
| `recovered-prologue` | a prologue no function contained |

`RecoverFunctions.java` records the origin of each function it creates in a
string property map, `DOS-Decompiler function origin`, keyed by entry address.
Its split removes a function and creates it again, so nothing attached to a
function would survive that. A plate comment is printed into `decompiled.c`
(measured in prompt 04), and holds whatever comment a name mapping gives. A
bookmark is something a person clears from the GUI. A property map is saved with the program and
invisible in the listing and in the decompiler's output.

### `body_overlaps`

A top-level list of every byte range more than one function claims, and which
functions. It reports overlaps and does not resolve them.

Ghidra never lets two bodies share a byte, so shared code shows up another way.
One function leaves its own body, by a jump or by falling through, into a body
Ghidra gave another function. So a function claims its `body`, and also what
it reaches from each `jump` or `fallthrough` out of it. That is followed
through jumps and fall-throughs until it returns, comes back into the
function's own body, leaves every function's body, or reaches a tail call
(below):

```json
{"start": "1000:005a", "end": "1000:005d", "start_linear": "0x1005a", "end_linear": "0x1005d", "bytes": 4,
 "functions": [{"entry": "1000:004a", "name": "FUN_1000_004a", "claim": "jump", "via": ["1000:0050"]},
               {"entry": "1000:0052", "name": "FUN_1000_0052", "claim": "jump", "via": ["1000:0058"]},
               {"entry": "1000:005a", "name": "FUN_1000_005a", "claim": "body"}]}
```

That is the shared epilogue: Ghidra's function at `1000:005a`, reached by the
`jmp short` at the end of each of the other two. `via` is the instruction each
claim leaves by.

**A tail call is not a claim** (prompt 03a). When a walk reaches the *entry*
of a function that some instruction calls, that function is a real one, and
the jump is an ordinary tail call. The walk stops, and the jump goes into a
top-level list, `tail_calls`, instead:

```json
"tail_calls": [{"caller": "1000:00de", "caller_name": "FUN_1000_00de", "target": "1000:007d",
                "target_name": "FUN_1000_007d", "via": "1000:00e5", "how": "jump"}]
```

An entry nothing calls is a fragment of whoever runs into it, and is still
claimed and walked. That covers the epilogue Ghidra split off and the
prologue RecoverFunctions cut a fall-through at. A jump into the *middle* of
a body is a claim whether the function is called or not. Before this rule, a
tail jump into a large routine claimed all the code that routine reaches:
`adventur.exe` showed one range claimed by 32 functions (`03-what-works.md`
has the numbers since).

"Called" means some instruction whose mnemonic is a `CALL` refers to the
entry. A pointer in data is not a call, so a routine reached only through a
table counts as uncalled. It is told by mnemonic and not by reference type:
measured by mutation, Ghidra's call-return override on the epilogue's jumps
makes it look called by type, and it drops out of `body_overlaps`. A walk that stops at its limit of 65,536 instructions says so
(`walk_limit_reached`). Body against body is checked as well, so a Ghidra that
allows overlapping bodies would show it here rather than be assumed not to.

Calls are not claims. A fall-through is followed only from an ordinary
instruction, and a call or interrupt is stepped over only when it returns into
the body it was made from. Ghidra gives `int 0x21` a fall-through, and without
that rule the fixture's startup "fell through" from its DOS exit into `main`.
A function that ends in a call to a routine that never returns, and really
does run into the next function, is missed by the same rule.

Jumps are told from calls by mnemonic rather than by Ghidra's flow type.
Ghidra overrides a jump to another function's entry into a call-return, and
that override is exactly the case being looked for.

### `bodies.py`: what no function claims

`tools/bodies.py out/functions.json` reads the bodies and the module layout
`loadimage.json` verified. On the fixture:

```
bodies: BODIES.EXE  (16 functions, load image verified)
code        : 256 bytes in 1 block(s) holding functions (CODE_0 1000:0000..1000:00ff)
claimed     : 220 bytes by some function's body (85.9%)
origins     : 12 ghidra-analysis, 2 recovered-code-pointer, 1 recovered-prologue, 1 recovered-split
non-contiguous: 2
  1000:0070  FUN_1000_0070  2 ranges, 18 of 26 bytes
  1000:008a  FUN_1000_008a  2 ranges, 30 of 36 bytes
claimed by more than one function: 3 range(s), 16 bytes (see body_overlaps)
  1000:005a..1000:005d  1000:004a jump; 1000:0052 jump; 1000:005a body
  1000:006c..1000:006f  1000:005e jump; 1000:0066 body
  1000:00c8..1000:00cf  1000:00c1 fallthrough; 1000:00c8 body
tail calls  : 1 (jumps into a function something calls; see tail_calls)
entry outside body: none
unclaimed   : 36 bytes in 5 range(s): 14 looks like code, 10 padding, 6 pointer table, 6 text
  1000:0099..1000:009e       6  pointer table   3 words, 3 into the code
  1000:00d0..1000:00d5       6  text            100% printable, first string 'BODIES'
  1000:00e8..1000:00e9       2  padding         90 x2
  1000:00ea..1000:00f7      14  looks like code 7 instructions, ending ret
  1000:00f8..1000:00ff       8  padding         00 x8
1 unclaimed range looks like code: 1000:00ea..1000:00f7 (14 bytes)
```

The code is the blocks that hold at least one function's body. The bytes are
the file's with DOS's fixups applied, which is the program Ghidra analysed
when the load verified. A word counts as a near pointer "into the code" when
it lands in some function's body, not merely somewhere in those blocks. In a
hand-written program the one block is code and data together, and with the
block as the test every word of Talisman's data landed "in code" (measured).

Unclaimed runs are classified by `tools/residue.py`, the rules `comrec.py`
classifies its residue by (`11-unreached-code.md`). They were moved there
unchanged: comrec's report, `.asm` and map are byte-identical for every `.COM`
fixture, six real programs and Karateka's `.EXE`. Each route keeps its own
idea of what counts as code. comrec wants some control flow anywhere in the
run. bodies.py wants a run that decodes cleanly from its first byte to its
last, every instruction plausible for an 8088, at least `--min-instructions`
(3) of them, ending in a return or an unconditional jump. A run that is
"other" as a whole is tried again without the `00`/`90` fill at either end,
so a routine followed by alignment padding is still seen.

The last line is in the `.COM` route's words. Each range that looks like code
is also an `unknowns` entry in the envelope (`--evidence`): a question about
the program, not a finding. An export from before bodies is refused, exit 3,
with what to do.

What it measured on real programs is in `03-what-works.md`.

## Names written into the program

`tools/applynames.py MAPPING OUTDIR` writes names into a pipeline's Ghidra
project and records what became of each one (prompt 04). It runs
`ApplyNames.java`, which leaves `applynames-record.json`, and turns that into an
envelope, `applynames-result.json`, with an exit status. It is the same split
as `DumpLoadImage.java` and `loadimage.py`. A headless run's own exit code
cannot carry the outcome: it is 0 even when its script throws (measured).

The mapping is `match.py --json` or `anchors.py --names`; both are
`{"mapping": [{"source", "binary", "score", ...}]}`. In order, the script then:

1. **Validates every entry, and writes nothing if one fails.** The address
   must be a function's entry. A byte inside a body is refused with the
   function it is inside, e.g. `inside the body of FUN_1000_004a (entry
   1000:004a), not a function entry`. The name must be a C identifier, not a C
   keyword (period extensions such as `far` and `interrupt` included),
   accepted by Ghidra's `SymbolUtilities.validateName`, and not of the form
   Ghidra makes up for an address. No two functions may end up with one name,
   whether from two entries of the mapping or from an entry and a function or
   label the program already has. That is `annotate.py`'s rule from the
   `.COM` route.
2. **Writes the batch in one transaction, and reads each write back:** the
   fully qualified name, the plate comment, the end-of-line comment and the
   script's own note. The function's namespace is kept. One difference, or
   one exception, and the transaction is aborted. In a headless script that
   discards every change of the run (`04-pitfalls.md`).

| status | exit | when |
|---|---|---|
| `ok` | 0 | the batch was applied, or a dry run found nothing to refuse |
| `blocked` | 3 | an entry failed validation, the mapping was unreadable, or the script did not run: nothing was written |
| `blocked` | 1 | a write or readback failed and the batch was rolled back: nothing was kept |

Each entry's outcome is `applied`, `would-apply` (dry run),
`skipped-below-floor`, `refused` with the reason, or `rolled-back`. The result
carries what was asked and what was stored: requested and applied name, the
name and comments read back, and the name before. One evidence item per
entry, at `location.address`.

Comments: `comment` sets the plate comment, which is what `ApplyNames.java`
always wrote. `inline_comment` sets the end-of-line comment at the entry. A
string sets it, `""` clears it, and a missing field leaves it alone. The
script's own note on the name moved to the PRE comment at the entry: its
confidence, LOW CONFIDENCE, LONG ROUTINE. `decompiled.c` prints that at the top
of the body, so it stays visible without taking the plate. Measured: plate and
PRE comments are printed, EOL and repeatable ones are not.

`--dryrun` validates and reports `would-apply`, writing nothing.
`DOS_DECOMPILER_APPLYNAMES_FAULT=readback|throw` makes the last write's
readback differ, or its setter throw, so a test can prove the rollback. The
script says so on stderr whenever it is set.

## What this does not do

- **It does not make an observation truer.** An envelope records what a tool
  established, and the tool's own limits are written down beside it. A
  `verified` handshake proves Ghidra used the expected settings; it says
  nothing about whether the decompiled C is right.
- **Only the first-step tools emit envelopes so far** — triage, survey, mzinfo
  — plus the profile, handshake and load-image records, `bodies.py` and
  `applynames.py`.
  Everything else still prints prose.
- **The profile is measured on one Ghidra version and one fixture.** A drift
  after an upgrade is a measurement to make, not an error to suppress.
- **`toolkit_version` is recorded but not compared**, and not part of
  `profile_id`: the export cannot observe it.
- **`analysis_code` as a whole is not observed.** The recovery script, the
  exporter, the dumper and the helper they share each report their own hash
  and are held to it. That the `pipeline.ps1` hashed is the one that ran rests
  on the pipeline running the copy beside `analysis_profile.py`.
- **The load-image check verifies what DumpLoadImage.java writes**: blocks,
  mappings, bytes, relocations, entry and stack. Anything else Ghidra keeps —
  data types, references, comments — is not checked, and uninitialised blocks
  are reported without their contents being verified.
- **The module is `analysis_profile.py`, not `profile.py`.** It was
  `profile.py` for one prompt, which shadowed the standard library's
  `profile` module — and so `cProfile`, which imports it — for every script
  run from `tools/`. `tests/evidence/` now imports `cProfile` with `tools/`
  first on the path, and checks that no module in `tools/` takes a standard
  library name.
