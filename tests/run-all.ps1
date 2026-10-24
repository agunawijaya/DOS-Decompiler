<#
.SYNOPSIS
    Run every regression suite this machine can run, and say plainly which it
    could not.

.DESCRIPTION
    Each tests/<suite>/regress.py is run in turn and reported on one line:
    PASS, FAIL or SKIP, with the seconds it took. A suite is skipped only for a
    stated reason, and a skipped suite is never counted as passed: it is not
    evidence either way, so it is listed, not hidden inside "nothing failed".

    A suite is skipped in one of two ways:

      * something it needs is not on this machine -- NASM, Ghidra, a Python
        package, the Sopwith source -- so it is not started at all. The
        prerequisites are listed below, per suite, because several suites
        fail with an ImportError rather than a message when a package is
        missing, and an ImportError reads like a bug.
      * the suite exits 77 on its own, the automake convention for "skipped",
        and its last line of output is the reason.

    A suite that passes but printed that part of it was skipped is reported
    PASS with that line beside it.

    Suites not listed in $Prerequisites still run, with no arguments; a new
    suite is picked up without editing this file.

    The exit code is 1 if any suite failed, 0 otherwise.

.PARAMETER Python
    Interpreter to run the suites with. Wins over $env:PYTHON, which wins
    over `python`. Worth setting where several are installed: whichever
    `python` is first on PATH may not be the one with capstone and unicorn.
    The one chosen is passed on to the suites as $env:PYTHON, so a suite that
    runs pipeline.ps1 runs it with the same interpreter.

.PARAMETER Only
    Run just these suites (directory names under tests/).

.PARAMETER Log
    Write the complete output of every suite to this file.

.PARAMETER SopwithSource
    The Sopwith source directory. With -SopwithBuild and -SopwithDecompiled
    it enables tests/sopwith; see that suite's docstring for how to produce
    the other two. Defaults to $env:SOPWITH_SOURCE.

.PARAMETER SopwithBuild
    The directory containing the rebuilt sopwith.exe and its map. Defaults
    to $env:SOPWITH_BUILD.

.PARAMETER SopwithDecompiled
    The pipeline output directory for the baseline build. Defaults to
    $env:SOPWITH_DECOMPILED.

.PARAMETER SopwithVariant
    An optional second build directory for cross-binary emulation. Defaults
    to $env:SOPWITH_VARIANT.

.EXAMPLE
    .\tests\run-all.ps1 -Python C:\Python311\python.exe

.EXAMPLE
    $env:SOPWITH_SOURCE = 'C:\sopwith-src'
    $env:SOPWITH_BUILD = 'C:\sopwith-build'
    $env:SOPWITH_DECOMPILED = 'C:\sopwith-decomp'
    .\tests\run-all.ps1
#>
[CmdletBinding()]
param(
    [string]$Python = $(if ($env:PYTHON) { $env:PYTHON } else { 'python' }),
    [string]$Nasm = $env:NASM,
    [string]$Ghidra = $env:GHIDRA_HOME,
    [string]$JavaHome = $env:JAVA_HOME,
    [string]$Watcom = $env:WATCOM,
    [string]$SopwithSource = $env:SOPWITH_SOURCE,
    [string]$SopwithBuild = $env:SOPWITH_BUILD,
    [string]$SopwithDecompiled = $env:SOPWITH_DECOMPILED,
    [string]$SopwithVariant = $env:SOPWITH_VARIANT,
    [string[]]$Only,
    [string]$Log
)

$ErrorActionPreference = 'Stop'
$testsDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# What each suite needs before it can say anything. Measured by running every
# suite under an interpreter with neither capstone nor unicorn installed:
# com, placements and tplist die on capstone, comrun and unpack on unicorn,
# pcxlib and tpscan need neither.
$Prerequisites = @{
    # Reads the agent-specific files only; runs no agent.
    'agents'     = @()
    # Its last case rebuilds a fixture through comrec and skips by itself,
    # saying so, without NASM or capstone.
    'annotate'   = @()
    'applynames' = @('nasm', 'ghidra', 'java')
    # Its Ghidra half skips by itself, as loadimage's does.
    'bodies'     = @('nasm', 'capstone')
    'com'        = @('nasm', 'capstone')
    # The emulation of instruction-identical pairs is part of what it checks.
    'comdiff'    = @('nasm', 'capstone', 'unicorn')
    # Its fixtures for the keyboard and the CGA skip by themselves without
    # NASM, saying so; the rest need only unicorn.
    'comrun'     = @('unicorn')
    'evidence'   = @('nasm')
    # Its Ghidra half skips by itself, as loadimage's does.
    'farcall'    = @('nasm', 'capstone', 'unicorn')
    'handshake'  = @('nasm', 'ghidra', 'java')
    'libscan'    = @('watcom')
    # Its Ghidra half skips by itself, saying so, and this reports that as
    # "partly skipped" beside the PASS.
    'loadimage'  = @('nasm')
    # The MCP server, through the SDK's own client. Its Ghidra half skips by
    # itself, saying so.
    'mcp'        = @('nasm', 'capstone', 'unicorn', 'mcp')
    'pcxlib'     = @()
    'placements' = @('nasm', 'capstone', 'unicorn')
    'sopwith'    = @('sopwith', 'capstone', 'unicorn')
    # Its JavaScript cases skip without Node, and its Ghidra case without
    # Ghidra, each saying so.
    'sweep'      = @('nasm', 'capstone', 'unicorn')
    'tplist'     = @('capstone')
    'tpscan'     = @()
    'unpack'     = @('unicorn')
}

function Resolve-Nasm {
    if ($Nasm) { if (Test-Path $Nasm) { return (Resolve-Path $Nasm).Path } else { return $null } }
    $cmd = Get-Command nasm -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Test-PythonModule([string]$Name) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Python -c "import $Name" 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    } finally {
        $ErrorActionPreference = $previous
    }
}

$nasmPath = Resolve-Nasm
$headless = $null
if ($Ghidra) {
    foreach ($name in 'analyzeHeadless.bat', 'analyzeHeadless') {
        $candidate = Join-Path (Join-Path $Ghidra 'support') $name
        if (Test-Path $candidate) { $headless = $candidate; break }
    }
}

# Every check is answered once, with the reason it failed, so the table can
# quote it.
$missing = @{}
if (-not $nasmPath) {
    $missing['nasm'] = 'NASM not found (pass -Nasm, set NASM, or put nasm on PATH)'
}
if (-not $headless) {
    $missing['ghidra'] = if ($Ghidra) { "no support\analyzeHeadless under $Ghidra" }
                         else { 'Ghidra not configured (pass -Ghidra or set GHIDRA_HOME)' }
}
if (-not $JavaHome -or -not (Test-Path $JavaHome)) {
    $missing['java'] = 'JDK not configured (pass -JavaHome or set JAVA_HOME)'
}
if (-not $Watcom -or -not (Test-Path $Watcom)) {
    $missing['watcom'] = 'Open Watcom not found (pass -Watcom or set WATCOM)'
}
$sopwithNeeded = @()
if (-not $SopwithSource) { $sopwithNeeded += '-SopwithSource' }
if (-not $SopwithBuild) { $sopwithNeeded += '-SopwithBuild' }
if (-not $SopwithDecompiled) { $sopwithNeeded += '-SopwithDecompiled' }
if ($sopwithNeeded) {
    $missing['sopwith'] = 'needs the Sopwith source, a build and its decompilation: pass ' +
                          ($sopwithNeeded -join ', ')
}

$pythonVersion = $null
try {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $pythonExe = (& $Python -c "import sys; print(sys.executable)" 2>$null)
    $pythonVersion = (& $Python -c "import sys; print(sys.executable + ' ' + sys.version.split()[0])" 2>$null)
    # Something that prints and fails is not a Python either.
    if ($LASTEXITCODE -ne 0) { $pythonVersion = $null }
} catch {
} finally {
    $ErrorActionPreference = $previous
}
if (-not $pythonVersion) {
    Write-Host "no Python at '$Python'. Pass -Python or set PYTHON." -ForegroundColor Red
    exit 1
}
foreach ($module in 'capstone', 'unicorn', 'mcp') {
    if (-not (Test-PythonModule $module)) {
        $missing[$module] = "$module not importable by $Python (pip install $module)"
    }
}

# Children inherit the tool locations, so a suite that reads NASM or
# GHIDRA_HOME sees what this script decided rather than what the shell had.
# PYTHON too: tests/handshake runs pipeline.ps1, which reads it, and the
# pipeline has to use the interpreter the suite was run with.
$env:PYTHON = $pythonExe
if ($nasmPath) { $env:NASM = $nasmPath }
if ($Ghidra) { $env:GHIDRA_HOME = $Ghidra }
if ($JavaHome) { $env:JAVA_HOME = $JavaHome }
if ($Watcom) { $env:WATCOM = $Watcom }

$suites = Get-ChildItem -Path $testsDir -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName 'regress.py') } |
    Sort-Object Name
if ($Only) {
    # Under `pwsh -File`, -Only a,b arrives as the one string "a,b".
    $Only = @($Only | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
    $unknown = $Only | Where-Object { $_ -notin $suites.Name }
    if ($unknown) {
        Write-Host "no such suite: $($unknown -join ', ')" -ForegroundColor Red
        exit 1
    }
    $suites = $suites | Where-Object { $_.Name -in $Only }
}

Write-Host "python : $pythonVersion"
Write-Host "nasm   : $(if ($nasmPath) { $nasmPath } else { 'not found' })"
Write-Host "ghidra : $(if ($headless) { $Ghidra } else { 'not found' })"
Write-Host ''

$rows = @()
$failedOutput = @()
$logLines = @()
foreach ($suite in $suites) {
    $name = $suite.Name
    $needs = if ($Prerequisites.ContainsKey($name)) { $Prerequisites[$name] } else { @() }
    $absent = @($needs | Where-Object { $missing.ContainsKey($_) })
    if ($absent) {
        $rows += [pscustomobject]@{ Suite = $name; Result = 'SKIP'; Seconds = 0.0
                                    Note = ($absent | ForEach-Object { $missing[$_] }) -join '; ' }
        continue
    }

    $suiteArgs = @()
    if ($name -eq 'sopwith') {
        $suiteArgs = @('--build-dir', $SopwithBuild, '--decompiled', $SopwithDecompiled,
                       '--source', $SopwithSource)
        if ($SopwithVariant) { $suiteArgs += @('--variant-dir', $SopwithVariant) }
    }

    $script = Join-Path $suite.FullName 'regress.py'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Python $script @suiteArgs 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $timer.Stop()
    $seconds = [math]::Round($timer.Elapsed.TotalSeconds, 1)
    $lines = @($output | Where-Object { $_.Trim() })
    $logLines += "==== $name (exit $code, $seconds s)"
    $logLines += $output

    if ($code -eq 0) {
        $partial = $lines | Where-Object { $_ -match '(?i)\bskipped\b' } | Select-Object -First 1
        $note = if ($partial) { 'partly skipped: ' + $partial.Trim() } else { '' }
        $rows += [pscustomobject]@{ Suite = $name; Result = 'PASS'; Seconds = $seconds; Note = $note }
    } elseif ($code -eq 77) {
        $reason = if ($lines) { $lines[-1].Trim() } else { 'the suite gave no reason' }
        $rows += [pscustomobject]@{ Suite = $name; Result = 'SKIP'; Seconds = $seconds; Note = $reason }
    } else {
        $last = if ($lines) { $lines[-1].Trim() } else { '' }
        $rows += [pscustomobject]@{ Suite = $name; Result = 'FAIL'; Seconds = $seconds
                                    Note = "exit $code. $last" }
        $failedOutput += "---- $name ----"
        $failedOutput += $output
    }
}

$rows | Format-Table -AutoSize -Wrap Suite, Result, @{ Label = 'Seconds'; Expression = { '{0:N1}' -f $_.Seconds }; Align = 'Right' }, Note |
    Out-String -Stream -Width 200 | ForEach-Object { $_.TrimEnd() } |
    Where-Object { $_ } | ForEach-Object { Write-Host $_ }

$passed = @($rows | Where-Object Result -eq 'PASS').Count
$failed = @($rows | Where-Object Result -eq 'FAIL').Count
$skipped = @($rows | Where-Object Result -eq 'SKIP').Count
Write-Host ''
Write-Host "$($rows.Count) suites: $passed passed, $failed failed, $skipped skipped"
if ($skipped) {
    Write-Host 'Skipped suites were not run. They are not evidence that anything works.'
}
Write-Host 'Not run here, because it is slow: tests\mutation\run.ps1, which checks that these tests can fail (tests\mutation\README.md).'

if ($failedOutput) {
    Write-Host ''
    $failedOutput | ForEach-Object { Write-Host $_ }
}
if ($Log) {
    $logLines | Set-Content -Path $Log -Encoding utf8
    Write-Host "full output in $Log"
}
exit $(if ($failed) { 1 } else { 0 })
