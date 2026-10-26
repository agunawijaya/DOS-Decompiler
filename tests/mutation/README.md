# Mutation testing: can the tests fail?

A test that passes whatever the code does is counted as evidence and is not.
This repo has paid for one already (commit `4928938`, "tests: make the CS
check actually able to fail"). Mutation testing finds the rest: it changes the
code in small ways -- a flipped comparison, a dropped branch, a changed
constant -- runs the tests against each change, and lists the changes no test
noticed.

```powershell
.\tests\mutation\run.ps1 -CosmicRay C:\Applications\cosmic-ray\Scripts\cosmic-ray.exe
.\tests\mutation\run.ps1 -Only handshake          # one target
.\tests\mutation\run.ps1 -Retest <an earlier OUT> # only what survived that run
```

It is not part of `tests/run-all.ps1`, because it is slow (below).

## What it needs

- [cosmic-ray](https://cosmic-ray.readthedocs.io/) 8.7.0, in a virtual
  environment of its own. `run.ps1` finds it through `-CosmicRay`,
  `$env:COSMIC_RAY` or `PATH`:

  ```powershell
  python -m venv C:\Applications\cosmic-ray
  C:\Applications\cosmic-ray\Scripts\pip install cosmic-ray==8.7.0
  ```

- The interpreter the suites already need (capstone, unicorn, Python 3.11 or
  later), Node for the sweep's JavaScript cases, and `NASM`. Ghidra is not
  used: `mutate.py` removes `GHIDRA_HOME`, so each suite's Ghidra half skips.

## What it mutates, and how long it takes

`scope.toml` lists the targets, each a module or a set of its functions, and
the suite that should catch a change there. The first five decide `verified`
against `mismatch`; the rest were added after them.

Measured on Windows 11, an i9-14900HX (24 cores), 24 workers. The first five
rows, placements' and the evidence suite's figures are from before prompt 07's
tests were added, which made those suites slower; the loadimage, bodies,
comrec, triage and 8088 rows are prompt 08's. Its loadimage and comrec runs
shared the machine with orphaned processes (below), so those two times are
high.

| Target | Code | Tests | Mutants | Time |
|---|---|---|---:|---:|
| `evidence` | all of `tools/evidence.py` | `tests/evidence` | 304 | 1,549 s |
| `loadimage` | the comparison in `tools/loadimage.py` | `tests/loadimage` | 1,050 | 1,451 s |
| `bodies` | ranges, classification and the code region in `tools/bodies.py` | `tests/bodies` | 1,202 | 192 s |
| `sweep` | the sweep's comparison and coverage in `tools/sweep.py` | `tests/sweep` | 411 | 1,169 s |
| `handshake` | the profile handshake in `tools/analysis_profile.py` | the handshake cases of `tests/evidence` | 87 | 142 s |
| `placements` | all of `tools/placements.py` | `tests/placements` | 2,182 | 97 s |
| `comrec` | the round trip that proves a rebuild in `tools/comrec.py` | `tests/com` | 295 | 252 s |
| `triage` | the verdict in `tools/triage.py`, and since prompt 09a the envelope that names what set it | the triage cases of `tests/evidence` | 399 | 1,254 s (prompt 09a, 16 workers) |
| `sweep-8088` | the 8088's `IDIV` rule in `tools/sweep.py` | `tests/sweep` | 336 | 1,615 s |
| `annotate` | the count of the evidence behind a name in `tools/annotate.py` | `tests/annotate` | 312 | 24 s (prompt 13, 16 workers) |
| `comdiff` | the routine comparison and its emulation's verdict in `tools/comdiff.py` | `tests/comdiff` | 755 | 128 s (prompt 13, 16 workers) |
| `comrun-8088` | the LOCK step-over, a divide's length and the divide error's delivery in `tools/comrun.py` | `tests/comrun` | 619 | 2,337 s (prompt 16, 16 workers) |

The first five took 58 minutes of wall time together in prompt 07 (the
handshake's 142 s in a run of its own); the last four take about an hour
more, most of it triage's and the 8088's, whose suites build many fixtures
or run many sweeps for every mutant. `-Retest` runs only the survivors of
an earlier run, which is how new tests are checked: on the first five, after
this prompt's tests, it took 29 minutes for their 1,049 survivors.

The scores, as killed out of the mutants that are neither equivalent nor dead
code (`known.toml`):

| Target | Before prompt 07's tests | After prompt 07 | After prompt 08 |
|---|---:|---:|---:|
| `evidence` | 182 / 280 (65.0%) | 280 / 280 | not run again; `evidence.py` did not change |
| `loadimage` | 634 / 1,030 (61.6%) | 1,030 / 1,030 | 1,034 / 1,034: `mappings.failures` replaced the dead count |
| `bodies` | 491 / 787 (62.4%) | 787 / 787 | 1,126 / 1,126, with the code region |
| `sweep` | 302 / 405 (74.6%) | 405 / 405 | not run again; its functions did not change |
| `handshake` | 49 / 87 (56.3%) | 87 / 87 | not run again |
| `placements` | 797 / 2,182 (36.5%), survivors not classified | not worked on | not worked on |
| `comrec` | 193 / 295 (65.4%), survivors not classified | not worked on | 199 / 294 (67.7%): `first_mismatch` done, the rest not classified |
| `triage` | 101 / 315 (32.1%), survivors not classified | not worked on | 295 / 295; after 09a, with `envelope`, 373 / 373 |
| `sweep-8088` | | | 316 / 316 |
| `annotate` | 225 / 368 (61.1%), with `load_symbols` whole (prompt 13) | | 307 / 307 after prompt 13's tests, on `named` instead |
| `comdiff` | 350 / 745 (47.0%) (prompt 13) | | 717 / 717 after prompt 13's tests |
| `comrun-8088` | 527 / 586 (89.9%) (prompt 16) | | 586 / 586 after prompt 16's tests |

Prompt 15 changed triage's verdict (LINK overlays, `--format`, the `.COM`
hint) and gave `loadimage.verify` the view record, and mutated both again,
the new functions added to `scope.toml`, 16 workers: `loadimage` 1,069
mutants in 1,091 s, 3 not explained; `triage` 637 in 3,431 s (sharing the
machine with other runs), 31 not explained. After that prompt's tests, a
`-Retest`: `loadimage` 1,053 / 1,053, `triage` 615 / 615, every survivor left
an equivalent in `known.toml`.

Prompt 16 gave comrun and the sweep one step-over for a LOCK the 8088
ignores, and comrun the divide error on its way to a program's own handler.
`sweep-8088` gained the sweep's new functions; `comrun-8088` is new. 16
workers: `sweep-8088` 382 mutants in 2,378 s, 8 not explained;
`comrun-8088` 619 in 2,337 s, 92 not explained. After that prompt's tests, a
`-Retest` (two for comrun, the second for the seven the first left):
`sweep-8088` 358 / 358, `comrun-8088` 586 / 586. Every survivor left is an
equivalent in `known.toml` but one, an `except` that cannot run, kept as a
code problem.

The scripts, and the suites that need Ghidra, are out of its reach; each of
those tests was shown able to fail once by hand, with an injected fault
(prompt 07's report).

## How it runs

The working tree, as it is on disk, is copied once per worker into a
temporary folder, and a cosmic-ray HTTP worker is started in each copy. A
worker writes a mutation into its own copy, runs the target's tests there, and
puts the file back; the working tree is never written. Before a target's
mutants are sent out, its tests are run once on the unmutated code, and the
target is skipped unless they pass.

Four things about cosmic-ray that cost time to find:

- **Its baseline does not run with the HTTP distributor.** `cosmic-ray
  baseline` sends the unmutated run to the workers like any other, and when no
  worker answers it reports success without having run anything. So
  `mutate.py` runs the baseline itself.
- **It splits the test command the POSIX way**, so a Windows path with
  backslashes loses them. `mutate.py` passes forward slashes.
- **A test it stops at its timeout is killed alone.** A tool the test started
  runs on: in prompt 08, twenty `comrec.py` processes, each looping on a
  mutant of the round trip, were still running hours after two runs ended, a
  core each, and every run after them was slower for it. `mutate.py` now ends
  every process whose command line names its copies, after each target, and
  prints how many (`strays_ended` in `summary.json`).
- **A machine that sleeps breaks a run.** A sleep on battery in prompt 08 left
  the mutants in flight `ABNORMAL`, neither killed nor survived, and the next
  target's worker connections gone. Run it on mains power, and run nothing
  heavy beside it: a loaded machine turns slow tests into timeouts, which
  count as kills.

And two about the suites:

- A test that checks only an exit code cannot tell a mismatch (exit 1) from a
  crash (also exit 1). Eleven survivors in the handshake were exactly that.
- A test that compares the code's output with the same code's output cannot
  fail: the evidence suite checked envelopes against `evidence.dumps` of
  themselves. The rule is now written out in the test.

## Reading the output

One line per target:

```
  handshake        87 mutants    49 killed (0 by timeout)   38 survived    0 equivalent   0 code problem   38 not explained    141.8 s
```

- **mutants**: changes made inside the target's code (cosmic-ray's line
  filter drops the rest).
- **killed**: a test failed. "By timeout" counts the ones that made a suite
  run past five times its unmutated time -- a loop that no longer ends.
- **survived**: no test failed. Each is a gap in the tests, an equivalent
  mutant, or a sign the code does nothing.
- **equivalent / code problem**: survivors `known.toml` explains -- the
  mutated code behaves identically, or the survivor shows code that does
  nothing, listed rather than fixed.
- **not explained**: everything else. These are the ones to act on.

Each target's survivors are in `OUT/<target>.survivors.txt`: the line, the
function, the operator, the diff, and a signature. Answer a new survivor with
a test that kills it. Only when the mutated code behaves identically does it
go in `known.toml`, with that signature, the kind and the reason in one
sentence. The session is in `OUT/<target>.sqlite` for `cr-report --show-diff`
or `cr-html`, and `OUT/summary.json` has every line's numbers.

Exit code: 0 when every survivor is explained, 1 when one is not, 2 when a
target could not be run.

## Why cosmic-ray

Chosen by a pilot on the profile handshake in prompt 07. mutmut 3.8.0 needs
`fork`, so on Windows it runs only inside WSL, and it decides which tests
reach a mutant by recording calls in the pytest process. These suites run the
tools as command lines in subprocesses, and mutmut names a mutant by its
package path (`tools.analysis_profile`) where the toolkit imports
`analysis_profile`: it found a test for none of the 371 mutants it made, with
or without a shim importing the modules under its names. cosmic-ray runs any
test command, runs natively on Windows, and on the same functions made 87
mutants and found the same 38 survivors in 142 s with 24 workers.

Run inside WSL instead, cosmic-ray took 81 s for the same 87 with 12 workers:
these suites start many processes, which costs less on Linux. That is the
faster place to run it, if the tests can run there; `mutate.py` runs under
Linux unchanged.
