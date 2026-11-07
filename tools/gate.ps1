#requires -Version 7
<#
.SYNOPSIS
  The base gate of docs/program-design.md section 9, plus the slice's extras. Writes docs\_runs\<date>-<Slice>.md with each command's
  exit code and last lines. The exit code is nonzero when any step fails. A step that cannot run yet says so by name, and never counts as a pass.
.PARAMETER Clauses
  The acceptance clauses to run, as a list or one comma-separated text. The gate always adds A9, because any change to a test or to shared code can break the CF build's proof.
.PARAMETER HangLimit
  The longest one test may run in a dotnet test step. Past it, the test host ends, the step fails, and the output names the test. The default is
  3 minutes: the slowest test takes 11.4 s at 100% CPU, and a test that fails on its own 20 s waits takes about 1 minute.
.PARAMETER SkipApp
  Skips the app steps (npm, Playwright). The report names the skip. With no app/package.json the app steps are skipped by the same rule.
.PARAMETER Lesson
  The lesson whose app/e2e/lesson-<n>.spec.ts the gate runs. Default: none.
.EXAMPLE
  pwsh tools/gate.ps1 -Slice S0 -Clauses A9
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Slice,
    [string[]]$Clauses = @(),
    [string]$NetCFRefDir = 'E:\dev\tools\netcf35-ref',
    [string]$HangLimit = '3m',
    [string]$Lesson,
    [switch]$SkipApp
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$date = Get-Date -Format 'yyyy-MM-dd'
$trx = "docs/_runs/trx/$Slice"
$report = "docs/_runs/$date-$Slice.md"
New-Item -ItemType Directory -Force -Path 'docs/_runs' | Out-Null
$cf = "-p:NetCFRefDir=$NetCFRefDir"
$hang = @('--blame-hang-timeout', $HangLimit, '--blame-hang-dump-type', 'none')

# A merge left half done builds something other than either side, and every step after it reports false results.
$unmerged = @(git diff --name-only --diff-filter=U)
if ($unmerged.Count -gt 0) {
    Write-Host "gate ${Slice}: GATE_TREE_UNMERGED: resolve these files first, nothing ran: $($unmerged -join ', ')"
    exit 2
}
$rows = [System.Collections.Generic.List[object]]::new()
$failed = 0
$Clauses = @($Clauses | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
if ($Clauses -notcontains 'A9' -and $Clauses -notcontains 'All') { $Clauses += 'A9' }

function Step([string]$name, [scriptblock]$body) {
    Write-Host "== $name"
    $output = & $body 2>&1 | ForEach-Object { "$_" }
    $code = $LASTEXITCODE
    $output | Select-Object -Last 12 | ForEach-Object { Write-Host $_ }
    $rows.Add([pscustomobject]@{ Name = $name; Status = $(if ($code -eq 0) { 'PASS' } else { 'FAIL' }); Exit = $code; Tail = (($output | Select-Object -Last 6) -join "`n") })
    if ($code -ne 0) { $script:failed++ }
}

function Skip([string]$name, [string]$why) {
    Write-Host "== ${name}: SKIPPED ($why)"
    $rows.Add([pscustomobject]@{ Name = $name; Status = 'SKIPPED'; Exit = ''; Tail = $why })
}

$hasApp = Test-Path 'app/package.json'
$appWhy = if ($SkipApp) { 'the -SkipApp switch' } elseif (-not $hasApp) { 'app/package.json is absent; Nancy owns app/ and her PR has not landed' } else { '' }

# ---------------------------------------------------------------- slice extras
switch ($Slice) {
    'S0' {
        Step 'dotnet build src/NetSec.Host' { dotnet build src/NetSec.Host -c Release --nologo -v q }
        Step 'dotnet build src/NetSec.CeDevice' { dotnet build src/NetSec.CeDevice -c Release --nologo -v q $cf }
        if ($appWhy) { Skip 'npm ci; npm run build (app)' $appWhy }
        else { Step 'npm ci; npm run build (app)' { Push-Location app; npm ci; if ($LASTEXITCODE -eq 0) { npm run build }; Pop-Location } }
    }
    'S1' { Step 'dotnet build acceptance/referees/bcl' { dotnet build acceptance/referees/bcl -c Release --nologo -v q } }
    { $_ -in 'S3', 'S4', 'S5', 'S6' } { Step 'go build referees' { Push-Location acceptance/referees/go; go build -o bin/ ./...; Pop-Location } }
    'S7' { Step 'native build' { & cmd /c native\build.cmd } }
    'S8' { Step 'dotnet build src/NetSec.Host' { dotnet build src/NetSec.Host -c Release --nologo -v q } }
}

# ---------------------------------------------------------------- base gate
Step 'layer_check' { python tools/layer_check.py src/NetSec.Core }
Step 'secret_guard' { python -I tools/secret_guard.py }

# >>> walk-routes-listed
# A19.repo.walk-routes-listed went red on main after builder PRs added a walk route with no row in Echo's list (checks/walk_routes.json).
# The check is fast and needs no build, so the builder's own gate runs it here. Builders do not write acceptance/, so the red sends them to Echo.
$walkRoutes = @(python -I acceptance/checks/docs_checks.py --root $root --ids A19.repo.walk-routes-listed 2>&1 | ForEach-Object { "$_" } |
    Where-Object { $_ -like '@@CLAUSE *' } | ForEach-Object { ($_ -replace '^@@CLAUSE ', '') | ConvertFrom-Json }) | Select-Object -First 1
if ($walkRoutes -and $walkRoutes.status -eq 'NOT RUN') { Skip 'A19.repo.walk-routes-listed' "$($walkRoutes.reason): $($walkRoutes.detail)" }
else {
    Step 'A19.repo.walk-routes-listed' {
        if (-not $walkRoutes) { 'GATE_WALK_ROUTES_NO_RESULT: acceptance/checks/docs_checks.py printed no clause line'; $global:LASTEXITCODE = 1 }
        elseif ($walkRoutes.status -ne 'PASS') {
            "FAIL $($walkRoutes.reason): $($walkRoutes.detail)"
            'Ask Echo for the list row before filing. Builders do not write acceptance/.'
            $global:LASTEXITCODE = 1
        }
        else { $walkRoutes.detail; $global:LASTEXITCODE = 0 }
    }
}
# <<< walk-routes-listed
Step 'dotnet build src/NetSec.Core' { dotnet build src/NetSec.Core -c Release --nologo -v q }
Step 'dotnet build src/NetSec.Core.NetCF' { dotnet build src/NetSec.Core.NetCF -c Release --nologo -v q $cf }
Step 'dotnet test net10.0' { dotnet test tests/NetSec.Tests -c Release -f net10.0 $cf --nologo --logger trx --results-directory "$trx-net10" @hang }
Step 'dotnet test net48 (CF binaries)' { dotnet test tests/NetSec.Tests -c Release -f net48 $cf --nologo --logger trx --results-directory "$trx-cf" @hang }
Step 'dotnet test Host (live process)' { dotnet test tests/NetSec.Host.Tests -c Release $cf --nologo --logger trx --results-directory "$trx-host" @hang }
Step "acceptance $($Clauses -join ',')" { pwsh -NoProfile -File acceptance/run.ps1 -Clauses ($Clauses -join ',') -NetCFRefDir $NetCFRefDir }
Step 'tour_lint' { python tools/tour_lint.py app/src/tours --max-grade 8.9 --max-concept 0.30 }

$tours = @(Get-ChildItem 'app/src/tours/lesson-*.json' -ErrorAction SilentlyContinue)
if ($tours.Count -eq 0) { Skip 'tic-gate on tours' 'no tour file in this tree yet' }
foreach ($tour in $tours) { Step "tic-gate $($tour.Name)" { python (Join-Path $HOME '.claude/hooks/tic-gate.py') $tour.FullName } }

if ($appWhy) { Skip 'playwright lesson spec' $appWhy }
elseif (-not $Lesson) { Skip 'playwright lesson spec' 'no -Lesson given' }
else { Step "playwright lesson $Lesson" { Push-Location app; npx playwright test "e2e/lesson-$Lesson.spec.ts"; Pop-Location } }

Step 'lessons_status' { python tools/lessons_status.py docs/_runs }

# ---------------------------------------------------------------- report
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# Gate $Slice, $date")
$lines.Add('')
$lines.Add("Result: $(@($rows | Where-Object Status -eq 'PASS').Count) of $(@($rows | Where-Object Status -ne 'SKIPPED').Count) steps passed. Skipped: $(@($rows | Where-Object Status -eq 'SKIPPED').Count).")
$lines.Add('')
$lines.Add('| Step | Status | Exit |')
$lines.Add('|---|---|---|')
foreach ($row in $rows) { $lines.Add("| $($row.Name) | $($row.Status) | $($row.Exit) |") }
$lines.Add('')
foreach ($row in $rows) {
    $lines.Add("## $($row.Name)")
    $lines.Add('')
    $lines.Add('```')
    $lines.Add($row.Tail)
    $lines.Add('```')
    $lines.Add('')
}
Set-Content -Path $report -Value ($lines -join "`n") -Encoding utf8
Write-Host "gate $Slice`: $(@($rows | Where-Object Status -eq 'PASS').Count) of $(@($rows | Where-Object Status -ne 'SKIPPED').Count) steps passed; report at $report"
exit $(if ($failed -gt 0) { 1 } else { 0 })
