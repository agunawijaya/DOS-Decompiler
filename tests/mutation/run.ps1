<#
.SYNOPSIS
    Mutation testing of the comparison code: change it in small ways and check
    that a test notices each change.

.DESCRIPTION
    Runs tests/mutation/mutate.py over the targets in tests/mutation/scope.toml
    with cosmic-ray, and prints one line per target: mutants in scope, killed,
    survived, and how many survivors tests/mutation/known.toml explains. The
    survivors themselves, with their diffs, go to the output folder.

    It is slow -- see README.md here for the times measured -- and is not part
    of tests/run-all.ps1. The working tree is never written: each worker
    mutates its own copy.

    Exit code: 0 when every survivor is explained, 1 when one is not, 2 when a
    target could not be run (its tests fail on the unmutated code, or
    cosmic-ray is missing).

.PARAMETER Python
    The interpreter that runs mutate.py and the tests: it needs capstone and
    unicorn, and Python 3.11 or later. Wins over $env:PYTHON, which wins over
    `python`.

.PARAMETER CosmicRay
    The cosmic-ray executable. Wins over $env:COSMIC_RAY, which wins over
    `cosmic-ray` on PATH.

.PARAMETER Only
    Run just these targets (names from scope.toml).

.PARAMETER Workers
    How many copies of the tree to mutate at once. Default: half the logical
    processors, at most 16.

.PARAMETER Out
    Where the survivor lists and cosmic-ray sessions go. Default: a new folder
    under the system temp folder, printed at the end.

.PARAMETER Retest
    The output folder of an earlier run: run only the mutants that survived
    it, to check tests written since. Refused for a module that has changed
    since that run.

.EXAMPLE
    .\tests\mutation\run.ps1 -Only handshake,bodies

.EXAMPLE
    .\tests\mutation\run.ps1 -Retest $env:TEMP\dosdec-mutation-abc123
#>
[CmdletBinding()]
param(
    [string]$Python = $(if ($env:PYTHON) { $env:PYTHON } else { 'python' }),
    [string]$CosmicRay = $env:COSMIC_RAY,
    [string[]]$Only,
    [int]$Workers = 0,
    [string]$Out,
    [string]$Retest
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$arguments = @((Join-Path $here 'mutate.py'), '--python', $Python)
if ($CosmicRay) { $arguments += @('--cosmic-ray', $CosmicRay) }
foreach ($name in $Only) { $arguments += @('--only', $name) }
if ($Workers -gt 0) { $arguments += @('--workers', $Workers) }
if ($Out) { $arguments += @('--out', $Out) }
if ($Retest) { $arguments += @('--retest', $Retest) }

& $Python @arguments
exit $LASTEXITCODE
