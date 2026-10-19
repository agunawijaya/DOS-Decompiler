<#
.SYNOPSIS
    Run the full decompilation pipeline over a DOS executable.

.DESCRIPTION
    Drop a game's .EXE in, get back a structural report, a Ghidra project with
    recovered functions, decompiled C, and a per-function fingerprint file.

    The three Ghidra stages are deliberately separate invocations. Chaining
    -postScript flags in one headless run was once recorded as discarding the
    first script's changes; on Ghidra 12.1.2 (2026-10-19) that did not
    reproduce, but separate runs are known to work and cost little.

    Right after import it checks that Ghidra loaded what the file says:
    DumpLoadImage.java writes down every block, mapping and relocation, and
    tools/loadimage.py compares them with what the MZ header implies, writing
    loadimage.json. On anything but verified it stops and prints the first
    failing check, unless -AllowLoadMismatch is given.

    Before import it writes profile.json: the loader, language, compiler spec,
    load segment and recovery this run expects. After export it compares that
    with what ExportDecompiledC.java observed, writes handshake.json, and stops
    with the field, the expected value and the observed value if any of them
    differ (tools/analysis_profile.py, knowledge/17-evidence.md).

    The Python tools run under $env:PYTHON when it is set, and under the
    first `python` on PATH when it is not.

.PARAMETER Exe
    The DOS executable to analyse.

.PARAMETER OutDir
    Where to write results. Defaults to .\decompile-<exename>.

.PARAMETER Ghidra
    Ghidra installation directory.

.PARAMETER JavaHome
    JDK 21+ installation directory.

.PARAMETER SkipRecovery
    Skip RecoverFunctions.java. Use only to compare against plain
    auto-analysis; it typically loses a third of the functions.

.PARAMETER AllowLoadMismatch
    Continue past a load image that does not verify -- mismatch, unsupported,
    or not checked -- instead of stopping. The run then says so in its output
    and in functions.json, and every reader of that functions.json warns.
    For a person who has read loadimage.json and understood the difference.

.EXAMPLE
    .\pipeline.ps1 -Exe C:\games\GAME.EXE
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [string]$OutDir,
    [string]$Ghidra   = $env:GHIDRA_HOME,
    [string]$JavaHome = $env:JAVA_HOME,
    [switch]$SkipRecovery,
    [switch]$AllowLoadMismatch
)

$ErrorActionPreference = 'Stop'
$toolDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not (Test-Path $Exe)) { throw "executable not found: $Exe" }
$exeItem = Get-Item $Exe
if (-not $OutDir) { $OutDir = Join-Path (Get-Location) ("decompile-" + $exeItem.BaseName) }

if (-not $Ghidra)   { throw "Ghidra directory unknown. Pass -Ghidra or set GHIDRA_HOME." }
if (-not $JavaHome) { throw "JDK directory unknown. Pass -JavaHome or set JAVA_HOME." }

$headless = Join-Path $Ghidra 'support\analyzeHeadless.bat'
if (-not (Test-Path $headless)) { throw "analyzeHeadless.bat not found under $Ghidra" }

# Which Python runs the tools: $env:PYTHON, then whatever `python` is first on
# PATH. Worth setting: on the machine this was written on, the first python
# on PATH in one shell was a copy bundled with another application, without
# capstone or unicorn.
$python = if ($env:PYTHON) { $env:PYTHON } else { 'python' }
if (-not (Get-Command $python -ErrorAction SilentlyContinue)) {
    throw "no Python at '$python'. Set PYTHON to the interpreter that has capstone and unicorn."
}

$env:JAVA_HOME = $JavaHome
New-Item -ItemType Directory -Force $OutDir | Out-Null
$projDir  = Join-Path $OutDir 'ghidra-project'
$scripts  = Join-Path $toolDir 'ghidra_scripts'
$projName = 'target'
New-Item -ItemType Directory -Force $projDir | Out-Null

function Invoke-Headless {
    param([string[]]$HeadlessArgs, [string]$Label)
    Write-Host "  $Label" -ForegroundColor DarkGray

    # Ghidra writes its entire log to stderr. Under $ErrorActionPreference =
    # 'Stop' the first INFO line would be treated as a terminating error and
    # the run would abort with no output at all, so relax it just for the
    # native call.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $headless @HeadlessArgs 2>&1 | ForEach-Object { "$_" }
    } finally {
        $ErrorActionPreference = $previous
    }

    $out | Select-String -Pattern 'ERROR|Exception' |
        Select-Object -First 5 |
        ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    $out | Select-String -Pattern 'RecoverFunctions:|ExportDecompiledC:|DumpLoadImage:|Using Language/Compiler|Import succeeded' |
        ForEach-Object { Write-Host "    $_" -ForegroundColor DarkCyan }
}

Write-Host "`n[1/5] Structure" -ForegroundColor Cyan
$report = Join-Path $OutDir 'mzinfo.txt'
& $python (Join-Path $toolDir 'mzinfo.py') $exeItem.FullName | Tee-Object -FilePath $report
& $python (Join-Path $toolDir 'mzinfo.py') $exeItem.FullName --json |
    Set-Content (Join-Path $OutDir 'mzinfo.json')

# A packed file decompiles into its own decompressor. Stop rather than waste
# an hour producing confident nonsense.
if (Select-String -Path $report -Pattern '\[ERROR\] packer' -Quiet) {
    Write-Host "`nSTOP: this file appears to be packed. Unpack it before decompiling." -ForegroundColor Yellow
    Write-Host "See $report" -ForegroundColor Yellow
    return
}

Write-Host "`n[2/5] Import and analyse" -ForegroundColor Cyan
# The settings this run expects Ghidra to use, written down before import so
# the export can be held to them afterwards. Ghidra still chooses; the
# handshake in step 5 checks that it chose these (tools/analysis_profile.py).
$profileJson = Join-Path $OutDir 'profile.json'
$profileArgs = @('write', '--exe', $exeItem.FullName, '--ghidra', $Ghidra, '--out', $profileJson)
if ($SkipRecovery) { $profileArgs += '--skip-recovery' }
& $python (Join-Path $toolDir 'analysis_profile.py') @profileArgs
if ($LASTEXITCODE -ne 0) { throw "analysis_profile.py could not write $profileJson" }

Invoke-Headless -HeadlessArgs @($projDir, $projName, '-import', $exeItem.FullName, '-overwrite') 'importing'

# Everything after this trusts that the program is the file: the same bytes,
# at the addresses the header implies, every relocation applied once per
# entry. Check it before anything is built on it. Read-only: the dump changes
# nothing in the project.
Write-Host "`n[3/5] Verify the load image" -ForegroundColor Cyan
$loadTimer = [Diagnostics.Stopwatch]::StartNew()
Invoke-Headless -HeadlessArgs @($projDir, $projName, '-process', $exeItem.Name, '-noanalysis',
                  '-readOnly', '-scriptPath', $scripts, '-postScript', 'DumpLoadImage.java',
                  $OutDir) 'dumping what Ghidra loaded'
$loadJson = Join-Path $OutDir 'loadimage.json'
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $verify = & $python (Join-Path $toolDir 'loadimage.py') verify $exeItem.FullName `
        (Join-Path $OutDir 'loadimage-observed') --profile $profileJson --evidence $loadJson 2>&1 |
        ForEach-Object { "$_" }
    $verifyCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previous
}
$loadTimer.Stop()
$loadStatus = switch ($verifyCode) { 0 { 'verified' } 1 { 'mismatch' } 2 { 'unsupported' } default { 'blocked' } }
$verify | ForEach-Object {
    Write-Host "    $_" -ForegroundColor $(if ($verifyCode -eq 0) { 'DarkCyan' } else { 'Red' })
}
Write-Host ("    checked in {0:N1} s; the record is {1}" -f $loadTimer.Elapsed.TotalSeconds, $loadJson) -ForegroundColor DarkGray
if ($verifyCode -ne 0) {
    $first = @($verify | Where-Object { $_ -like 'first failing check:*' -or $_ -like 'load image:*' })
    $what = ($first | Select-Object -First 2) -join '; '
    if (-not $AllowLoadMismatch) {
        throw "load image $loadStatus, stopping before anything is built on it: $what. Read $loadJson; pass -AllowLoadMismatch to continue anyway."
    }
    Write-Host ''
    Write-Host '    ************************************************************' -ForegroundColor Yellow
    Write-Host "    LOAD IMAGE NOT VERIFIED ($loadStatus). Continuing only because" -ForegroundColor Yellow
    Write-Host '    -AllowLoadMismatch was given. Every address and byte from here' -ForegroundColor Yellow
    Write-Host '    on rests on a load that differs from the file.' -ForegroundColor Yellow
    Write-Host "    $what" -ForegroundColor Yellow
    Write-Host '    ************************************************************' -ForegroundColor Yellow
}

if (-not $SkipRecovery) {
    Write-Host "`n[4/5] Recover missed functions" -ForegroundColor Cyan
    Invoke-Headless -HeadlessArgs @($projDir, $projName, '-process', $exeItem.Name, '-noanalysis',
                      '-scriptPath', $scripts, '-postScript', 'RecoverFunctions.java') 'recovering'
} else {
    Write-Host "`n[4/5] Recovery skipped" -ForegroundColor DarkYellow
}

Write-Host "`n[5/5] Decompile and fingerprint" -ForegroundColor Cyan
$exportArgs = @($projDir, $projName, '-process', $exeItem.Name, '-noanalysis',
                '-scriptPath', $scripts, '-postScript', 'ExportDecompiledC.java', $OutDir,
                "load_image:$loadStatus")
if ($verifyCode -ne 0) { $exportArgs += 'load_image:allowed' }
Invoke-Headless -HeadlessArgs $exportArgs 'exporting'

# Expected against observed. Any difference means these results were not
# produced under the settings every later tool assumes, so stop here rather
# than let them be read as though they were.
Write-Host "  checking the export against the profile" -ForegroundColor DarkGray
$handshake = Join-Path $OutDir 'handshake.json'
# Relaxed for the same reason as in Invoke-Headless: a line on stderr must not
# abort the run before its exit code has been read.
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $check = & $python (Join-Path $toolDir 'analysis_profile.py') check --profile $profileJson `
        --functions (Join-Path $OutDir 'functions.json') --evidence $handshake 2>&1 |
        ForEach-Object { "$_" }
    $checkCode = $LASTEXITCODE
} finally {
    $ErrorActionPreference = $previous
}
$check | ForEach-Object {
    Write-Host "    $_" -ForegroundColor $(if ($checkCode -eq 0) { 'DarkCyan' } else { 'Red' })
}
if ($checkCode -ne 0) {
    $drift = @($check | Where-Object { $_ -like 'profile drift:*' })
    $what = if ($drift) { $drift -join '; ' } else { $check -join '; ' }
    throw "profile handshake failed, results in $OutDir are not to be used: $what"
}

Write-Host "`nResults in $OutDir" -ForegroundColor Green
Get-ChildItem $OutDir -File | ForEach-Object {
    "  {0,-18} {1,10:N0} bytes" -f $_.Name, $_.Length
}
Write-Host @"

Next:
  * read mzinfo.txt findings before trusting anything else
  * decompiled.c holds the pseudocode; every line is a hypothesis
  * functions.json holds per-function fingerprints for tools/match.py
  * with reference source:  python tools/srcinv.py SRCDIR --json src.json
                            python tools/match.py src.json functions.json --align
"@ -ForegroundColor DarkGray
