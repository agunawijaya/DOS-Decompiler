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
against `mismatch`; the last three were added after them.

Measured on Windows 11, an i9-14900HX (24 cores), 24 workers, before prompt
07's tests were added; the new tests make the evidence, load-image and bodies
suites slower, so a run now takes somewhat longer.

| Target | Code | Tests | Mutants | Time |
|---|---|---|---:|---:|
| `evidence` | all of `tools/evidence.py` | `tests/evidence` | 304 | 1,549 s |
| `loadimage` | the comparison in `tools/loadimage.py` | `tests/loadimage` | 1,049 | 386 s |
| `bodies` | ranges and classification in `tools/bodies.py` | `tests/bodies` | 857 | 75 s |
| `sweep` | the sweep's comparison and coverage in `tools/sweep.py` | `tests/sweep` | 411 | 1,169 s |
| `handshake` | the profile handshake in `tools/analysis_profile.py` | the handshake cases of `tests/evidence` | 87 | 142 s |
| `placements` | all of `tools/placements.py` | `tests/placements` | 2,182 | 97 s |
| `comrec` | the round trip that proves a rebuild in `tools/comrec.py` | `tests/com` | 295 | 185 s |
| `triage` | the verdict in `tools/triage.py` | the triage cases of `tests/evidence` | 315 | 420 s |

The first five took 58 minutes of wall time together (the handshake's 142 s
in a run of its own), the last three 12. `-Retest` runs only the survivors of
an earlier run, which is how new tests are checked: on the first five, after
this prompt's tests, it took 29 minutes for their 1,049 survivors.

The scores, as killed out of the mutants that are neither equivalent nor dead
code (`known.toml`):

| Target | Before prompt 07's tests | After |
|---|---:|---:|
| `evidence` | 182 / 280 (65.0%) | 280 / 280 |
| `loadimage` | 634 / 1,030 (61.6%) | 1,030 / 1,030 |
| `bodies` | 491 / 787 (62.4%) | 787 / 787 |
| `sweep` | 302 / 405 (74.6%) | 405 / 405 |
| `handshake` | 49 / 87 (56.3%) | 87 / 87 |
| `placements` | 797 / 2,182 (36.5%), survivors not classified | not worked on |
| `comrec` | 193 / 295 (65.4%), survivors not classified | not worked on |
| `triage` | 101 / 315 (32.1%), survivors not classified | not worked on |

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

Two things about cosmic-ray that cost time to find:

- **Its baseline does not run with the HTTP distributor.** `cosmic-ray
  baseline` sends the unmutated run to the workers like any other, and when no
  worker answers it reports success without having run anything. So
  `mutate.py` runs the baseline itself.
- **It splits the test command the POSIX way**, so a Windows path with
  backslashes loses them. `mutate.py` passes forward slashes.

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
