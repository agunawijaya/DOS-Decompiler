<#
.SYNOPSIS
    Run the full decompilation pipeline over a DOS executable.

.DESCRIPTION
    Drop a game's .EXE in, get back a structural report, a Ghidra project with
    recovered functions, decompiled C, and a per-function fingerprint file.

    The Ghidra stages are separate invocations, with one exception. Chaining
    -postScript flags in one headless run was once recorded as discarding the
    first script's changes; on Ghidra 12.1.2 (2026-10-19) that did not
    reproduce, but separate runs are known to work and cost little. The
    exception is the corrector, which runs as a -postScript of the import:
    measured byte-identical either way, and one Ghidra start shorter.

    The order is import and correct, verify, analyse and recover, export.
    Import runs without analysis. CorrectMzLoad.java puts right the two loads
    Ghidra 12.1.2 is measured to get wrong -- a full last page it drops, a
    duplicated relocation it applies once -- and records each correction in
    load-corrections.json. Then the load is checked against the file:
    DumpLoadImage.java writes down every block, mapping and relocation, and
    tools/loadimage.py compares them with what the MZ header implies, writing
    loadimage.json, without trusting the corrector. On anything but verified
    it stops and prints the first failing check, unless -AllowLoadMismatch is
    given. Auto-analysis and recovery run after that, on bytes known to be
    the file's.

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

.PARAMETER NoLoadCorrection
    Skip CorrectMzLoad.java and verify Ghidra's own load as it stands, to
    compare with the corrected one. A file Ghidra loads wrong then stops at
    the load-image check, as it did before the corrector existed.

.PARAMETER View
    The record tools/overlays.py writes beside an overlay view, VIEW.view.json:
    which overlay the view holds, of which file, built how. Found without
    being given when it sits beside -Exe under that name. It is checked
    against -Exe before anything runs -- a record of another file stops the
    run -- copied into the results as overlay-view.json, and carried in
    loadimage.json, so the verified load says which overlay it is.

.EXAMPLE
    .\pipeline.ps1 -Exe C:\games\GAME.EXE

.EXAMPLE
    python tools\overlays.py UNPACKED.EXE --views views
    .\pipeline.ps1 -Exe views\UNPACKED-overlay1.exe -OutDir out-overlay1
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [string]$OutDir,
    [string]$Ghidra   = $env:GHIDRA_HOME,
    [string]$JavaHome = $env:JAVA_HOME,
    [switch]$SkipRecovery,
    [switch]$AllowLoadMismatch,
    [switch]$NoLoadCorrection,
    [string]$View
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
    $out | Select-String -Pattern 'RecoverFunctions:|ExportDecompiledC:|DumpLoadImage:|CorrectMzLoad:|Using Language/Compiler|Import succeeded' |
        ForEach-Object { Write-Host "    $_" -ForegroundColor DarkCyan }
}

Write-Host "`n[1/6] Structure" -ForegroundColor Cyan
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

# An overlay view: the record overlays.py wrote beside it says which overlay
# this is. A record of another file is worse than none -- every result would
# be filed under the wrong overlay -- so it stops the run.
if (-not $View) {
    $beside = [IO.Path]::ChangeExtension($exeItem.FullName, '.view.json')
    if (Test-Path -LiteralPath $beside) { $View = $beside }
}
if ($View) {
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $viewCheck = & $python (Join-Path $toolDir 'overlays.py') --check-view $View $exeItem.FullName 2>&1 |
            ForEach-Object { "$_" }
        $viewCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($viewCode -ne 0) { throw "the view record does not describe $($exeItem.Name): $viewCheck" }
    Write-Host "  $viewCheck" -ForegroundColor DarkCyan
    Copy-Item -LiteralPath $View -Destination (Join-Path $OutDir 'overlay-view.json') -Force
}

Write-Host "`n[2/6] Import" -ForegroundColor Cyan
# The settings this run expects Ghidra to use, written down before import so
# the export can be held to them afterwards. Ghidra still chooses; the
# handshake in step 6 checks that it chose these (tools/analysis_profile.py).
$profileJson = Join-Path $OutDir 'profile.json'
$profileArgs = @('write', '--exe', $exeItem.FullName, '--ghidra', $Ghidra, '--out', $profileJson)
if ($SkipRecovery) { $profileArgs += '--skip-recovery' }
if ($NoLoadCorrection) { $profileArgs += '--no-load-correction' }
& $python (Join-Path $toolDir 'analysis_profile.py') @profileArgs
if ($LASTEXITCODE -ne 0) { throw "analysis_profile.py could not write $profileJson" }

# Imported without analysis. Auto-analysis reads the program's bytes, and
# they are not to be trusted until the load has been corrected and verified;
# it runs in stage 5 instead, on the program stage 4 verified.
#
# Ghidra 12.1.2's MZ loader is measured to get two kinds of file wrong: a
# full last page is dropped, and a duplicated relocation takes effect once.
# CorrectMzLoad.java puts those right, and nothing else; stage 4 then checks
# the result against the file without believing anything the corrector says
# it did. It runs as a -postScript of the import itself, which saves one
# Ghidra start. Measured in prompt 06 on seven fixture builds -- a full last
# page, a duplicated relocation and both among them, each corrected -- and two
# real games: the load-image dump, the export and load-corrections.json came
# out byte-identical either way, and the run 4.9 to 9.9 s shorter on all but
# the largest fixture, where the import itself dominates.
$correctionsJson = Join-Path $OutDir 'load-corrections.json'
Remove-Item -LiteralPath $correctionsJson -ErrorAction SilentlyContinue
$importArgs = @($projDir, $projName, '-import', $exeItem.FullName, '-overwrite', '-noanalysis')
$correctTimer = [Diagnostics.Stopwatch]::StartNew()
if (-not $NoLoadCorrection) {
    $expectedJson = Join-Path $OutDir 'loadimage-expected.json'
    & $python (Join-Path $toolDir 'loadimage.py') expected $exeItem.FullName `
        --profile $profileJson --evidence $expectedJson | Out-Null
    $importArgs += @('-scriptPath', $scripts, '-postScript', 'CorrectMzLoad.java',
                     $expectedJson, $OutDir)
    Invoke-Headless -HeadlessArgs $importArgs 'importing, and correcting what the loader is known to get wrong'
} else {
    Invoke-Headless -HeadlessArgs $importArgs 'importing'
}
$correctTimer.Stop()

if (-not $NoLoadCorrection) {
    Write-Host "`n[3/6] Correct the load" -ForegroundColor Cyan
    Write-Host ("    corrected during the import ({0:N1} s for both); the record is {1}" -f $correctTimer.Elapsed.TotalSeconds, $correctionsJson) -ForegroundColor DarkGray
} else {
    Write-Host "`n[3/6] Load correction skipped (-NoLoadCorrection): verifying Ghidra's own load" -ForegroundColor DarkYellow
}

# Everything after this trusts that the program is the file: the same bytes,
# at the addresses the header implies, every relocation applied once per
# entry. Check it before anything is built on it. Read-only: the dump changes
# nothing in the project.
Write-Host "`n[4/6] Verify the load image" -ForegroundColor Cyan
$loadTimer = [Diagnostics.Stopwatch]::StartNew()
Invoke-Headless -HeadlessArgs @($projDir, $projName, '-process', $exeItem.Name, '-noanalysis',
                  '-readOnly', '-scriptPath', $scripts, '-postScript', 'DumpLoadImage.java',
                  $OutDir) 'dumping what Ghidra loaded'
$loadJson = Join-Path $OutDir 'loadimage.json'
$verifyArgs = @('verify', $exeItem.FullName, (Join-Path $OutDir 'loadimage-observed'),
                '--profile', $profileJson, '--evidence', $loadJson)
if (-not $NoLoadCorrection) { $verifyArgs += @('--corrections', $correctionsJson) }
if ($View) { $verifyArgs += @('--view', $View) }
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $verify = & $python (Join-Path $toolDir 'loadimage.py') @verifyArgs 2>&1 |
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

# Auto-analysis, now that the bytes are known to be the file's, in a run of
# its own; then recovery in a run without analysis, as before. Running
# recovery in the same, analysing, run was measured to change the export of a
# clean 51,904-byte game -- one function more, eleven records different --
# because Ghidra then analyses what the script creates. Kept apart, the export
# of a clean file is what it was before the corrector existed.
Write-Host "`n[5/6] Analyse and recover missed functions" -ForegroundColor Cyan
Invoke-Headless -HeadlessArgs @($projDir, $projName, '-process', $exeItem.Name) 'analysing'
if (-not $SkipRecovery) {
    Invoke-Headless -HeadlessArgs @($projDir, $projName, '-process', $exeItem.Name, '-noanalysis',
                      '-scriptPath', $scripts, '-postScript', 'RecoverFunctions.java') 'recovering'
} else {
    Write-Host '  recovery skipped' -ForegroundColor DarkYellow
}

Write-Host "`n[6/6] Decompile and fingerprint" -ForegroundColor Cyan
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
