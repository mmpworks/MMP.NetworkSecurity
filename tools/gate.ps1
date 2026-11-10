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
  Skips the app steps (typecheck, build, Playwright). The report names the skip. With no app/package.json the app steps are skipped by the same rule.
  When code under app/ differs from origin/main (committed or not), -SkipApp fails the gate with APP_PROOF_SKIPPED, and there is no override.
  The one automatic skip: when every changed file under app/ is a Markdown file or an image in a screens folder, the gate skips app proof on its own
  (with or without -SkipApp) and prints the file list. Anything else under app/ counts as code (tools/gate_app.ps1, Test-NonCodeAppFile).
.PARAMETER Lesson
  The lesson whose app/e2e/lesson-<n>.spec.ts the gate runs. Default: none. When app/ changed and no lesson is named, the gate runs typecheck, build
  and the full Playwright suite on NETSEC_PORT_BASE=auto. Naming a lesson narrows that suite to the one spec, and the report says "narrowed".
  The gate never installs packages: a missing node_modules or Electron binary stops with TOOL_MISSING and the command to run yourself.
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
# A full gate is a heavy run: one at a time on the machine (tools/heavy_lock.py). Re-run this script under the lock, with the same parameters, and pass its
# exit code through. A run started inside a holder skips this, but only when `heavy_lock.py holds` says so (NETSEC_HEAVY_LOCK_HELD names the live
# holder of a lock that is really held); a stale inherited variable does not count. NETSEC_LOCK_WAIT_MINUTES limits the wait (exit 75).
python -I (Join-Path $PSScriptRoot 'heavy_lock.py') holds | Out-Null
if ($LASTEXITCODE -ne 0) {
    $again = foreach ($name in $PSBoundParameters.Keys) {
        $value = $PSBoundParameters[$name]
        if ($value -is [System.Management.Automation.SwitchParameter]) { if ($value.IsPresent) { "-$name" } }
        else { "-$name"; ($value -join ',') }
    }
    $wait = if ($env:NETSEC_LOCK_WAIT_MINUTES) { @('--wait-minutes', $env:NETSEC_LOCK_WAIT_MINUTES) } else { @() }
    python -I (Join-Path $PSScriptRoot 'heavy_lock.py') run --label "gate $Slice" @wait -- pwsh -NoProfile -File $PSCommandPath @again
    exit $LASTEXITCODE
}
. (Join-Path $PSScriptRoot 'gate_app.ps1')
# Every run log names the commit it ran on, first (tools/run_status.py prints it).
$head = Get-HeadLine $root
Write-Host "gate $Slice @ $head"
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
    # A failing test's name sits above the traceback, outside the last 12 lines: print every FAIL:/ERROR: line so a red names itself.
    $failedTests = @($output | Where-Object { $_ -match '^(FAIL|ERROR): ' })
    if ($code -ne 0 -and $failedTests.Count -gt 0) { $failedTests | ForEach-Object { Write-Host $_ } }
    $output | Select-Object -Last 12 | ForEach-Object { Write-Host $_ }
    $status = Get-StepStatus -Code $code -Output $output          # exit 0 with a first line PIN_OFF or SKIP: reads SKIPPED, not PASS
    $rows.Add([pscustomobject]@{ Name = $name; Status = $status; Exit = $code; Tail = (($output | Select-Object -Last 6) -join "`n") })
    if ($status -eq 'FAIL') { $script:failed++ }
}

function Skip([string]$name, [string]$why) {
    Write-Host "== ${name}: SKIPPED ($why)"
    $rows.Add([pscustomobject]@{ Name = $name; Status = 'SKIPPED'; Exit = ''; Tail = $why })
}

$hasApp = Test-Path 'app/package.json'
$appDiffFiles = if ($hasApp) { @(Get-AppDiffFiles $root) } else { @() }
$toolsPresent = (-not $hasApp) -or (@(Test-AppTools 'app').Count -eq 0)
$appPlan = Get-AppProofPlan -HasApp $hasApp -SkipApp ([bool]$SkipApp) -Lesson $Lesson -AppDiffFiles $appDiffFiles -ToolsPresent $toolsPresent
$appWhy = if ($appPlan.Mode -in 'none', 'skip', 'docs') { $appPlan.Why } else { '' }

# One app step, with the gate's rule that it never installs: a missing tool stops with TOOL_MISSING and the command to run yourself.
function Step-App([string]$name, [scriptblock]$body) {
    $wrapped = {
        $tools = @(Test-AppTools 'app')
        if ($tools.Count -gt 0) { $tools; $global:LASTEXITCODE = 1; return }
        Push-Location app
        try { & $body } finally { Pop-Location }
    }.GetNewClosure()
    Step $name $wrapped
}

# ---------------------------------------------------------------- slice extras
switch ($Slice) {
    'S0' {
        Step 'dotnet build src/NetSec.Host' { dotnet build src/NetSec.Host -c Release --nologo -v q }
        if ($appWhy) { Skip 'npm run build (app)' $appWhy }
        else { Step-App 'npm run build (app)' { npm run build } }
    }
    'S1' { Step 'dotnet build acceptance/referees/bcl' { dotnet build acceptance/referees/bcl -c Release --nologo -v q } }
    { $_ -in 'S3', 'S4', 'S5', 'S6' } { Step 'go build referees' { Push-Location acceptance/referees/go; go build -o bin/ ./...; Pop-Location } }
    'S7' { Step 'native build' { & cmd /c native\build.cmd } }
    'S8' { Step 'dotnet build src/NetSec.Host' { dotnet build src/NetSec.Host -c Release --nologo -v q } }
}

# ---------------------------------------------------------------- base gate
Step 'layer_check' { python tools/layer_check.py src/NetSec.Core }
Step 'secret_guard' { python -I tools/secret_guard.py }
Step 'no package-runner calls in tools and app scripts' { python -I tools/no_npx.py }
Step 'no package-runner check tests' { python -I tools/test_no_npx.py }
Step 'app names the os transport os' { python -I tools/transport_name_lint.py }
Step 'transport name lint tests' { python -I tools/test_transport_name_lint.py }
Step 'run_status tests' { python -I tools/test_run_status.py }
Step 'electron dist tests' { python -I tools/test_electron_dist.py }
Step 'gate app decision tests' { python -I tools/test_gate_app.py }
Step 'dist stamp tests' { python -I tools/test_dist_stamp.py }
Step 'every tools test has a gate step' { python -I tools/check_tests_wired.py }
Step 'tests-wired check tests' { python -I tools/test_check_tests_wired.py }
# A change to acceptance/ may touch only acceptance/ and docs/ (tools/check_acceptance_scope.py names each other path).
Step 'acceptance scope (acceptance/ and docs/ only)' { python -I tools/check_acceptance_scope.py }
Step 'acceptance scope check tests' { python -I tools/test_check_acceptance_scope.py }
# A PR that changes acceptance/ bumps acceptance/PIN in the same PR (python -I acceptance/tools/pin.py --write).
Step 'acceptance PIN current' { python -W ignore -I acceptance/tools/pin.py --check }       # -W ignore keeps a Python warning off line 1, where PIN_OFF must stay
Step 'acceptance PIN tests' { python -I acceptance/tools/test_pin.py }
Step 'heavy-run lock tests' { python -I tools/test_heavy_lock.py }
Step 'gate lock tests' { python -I tools/test_gate_lock.py }
Step 'pre-push guard tests' { python -I tools/githooks/test_pre_push_guard.py }
Step 'pre-push hook installed and current' { pwsh -NoProfile -File tools/githooks/check-installed.ps1 }

# >>> walk-routes-listed
# A19.repo.walk-routes-listed went red on main after builder PRs added a walk route with no row in Echo's list (checks/walk_routes.json).
# The check is fast and needs no build, so the builder's own gate runs it here. Builders do not write acceptance/, so the red sends them to Echo.
$walkRoutes = @(python -I acceptance/checks/docs_checks.py --root $root --ids A19.repo.walk-routes-listed 2>&1 | ForEach-Object { "$_" } |
    Where-Object { $_ -like '@@CLAUSE *' } | ForEach-Object { ($_ -replace '^@@CLAUSE ', '') | ConvertFrom-Json }) | Select-Object -First 1
# Only PRODUCT_MISSING (the walk is not built in this tree yet) may skip. Any other NOT RUN, such as NOT_IN_GROUP after a clause rename, fails the step,
# so the gate cannot skip forever without a word.
if ($walkRoutes -and $walkRoutes.status -eq 'NOT RUN' -and $walkRoutes.reason -eq 'PRODUCT_MISSING') { Skip 'A19.repo.walk-routes-listed' "$($walkRoutes.reason): $($walkRoutes.detail)" }
else {
    Step 'A19.repo.walk-routes-listed' {
        if (-not $walkRoutes) { 'GATE_WALK_ROUTES_NO_RESULT: acceptance/checks/docs_checks.py printed no clause line'; $global:LASTEXITCODE = 1 }
        elseif ($walkRoutes.status -eq 'NOT RUN') { "GATE_WALK_ROUTES_UNEXPECTED: $($walkRoutes.reason): $($walkRoutes.detail)"; $global:LASTEXITCODE = 1 }
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
# Every gate builds the CE device first: a custom -Slice name used to skip the slice-only build, and CfBinaryTests then ran an old CE binary.
Step 'dotnet build src/NetSec.CeDevice' { dotnet build src/NetSec.CeDevice -c Release --nologo -v q $cf }
Step 'dotnet test net48 (CF binaries)' { dotnet test tests/NetSec.Tests -c Release -f net48 $cf --nologo --logger trx --results-directory "$trx-cf" @hang }
Step 'dotnet test Host (live process)' { dotnet test tests/NetSec.Host.Tests -c Release $cf --nologo --logger trx --results-directory "$trx-host" @hang }
Step "acceptance $($Clauses -join ',')" { pwsh -NoProfile -File acceptance/run.ps1 -Clauses ($Clauses -join ',') -NetCFRefDir $NetCFRefDir }
Step 'tour_lint' { python tools/tour_lint.py app/src/tours --max-grade 8.9 --max-concept 0.30 }

$tours = @(Get-ChildItem 'app/src/tours/lesson-*.json' -ErrorAction SilentlyContinue)
if ($tours.Count -eq 0) { Skip 'tic-gate on tours' 'no tour file in this tree yet' }
foreach ($tour in $tours) { Step "tic-gate $($tour.Name)" { python (Join-Path $HOME '.claude/hooks/tic-gate.py') $tour.FullName } }

# ---------------------------------------------------------------- app proof (tools/gate_app.ps1 decides; docs/program-design.md section 9)
# An app/ change gets typecheck + build + the full Playwright suite on its own port block. -Lesson narrows the suite and the step says so.
# The gate never installs: a missing tool is a TOOL_MISSING step with the command to run yourself.
switch ($appPlan.Mode) {
    { $_ -in 'none', 'skip', 'docs' } {
        Skip 'typecheck (app/src and app/e2e)' $appPlan.Why
        Skip 'playwright' $appPlan.Why
    }
    'refuse' { Step 'app proof' { $appPlan.Why; $global:LASTEXITCODE = 1 } }
    default {
        # One named failure when the tools are absent, instead of a failure per step.
        $appTools = @(Test-AppTools 'app')
        if ($appTools.Count -gt 0) { Step 'app tools present' { $appTools; $global:LASTEXITCODE = 1 }; break }
        # app/e2e had no tsconfig, so "npm run typecheck" checked app/src only; it checks both now.
        if ($appPlan.Typecheck) { Step-App 'typecheck (app/src and app/e2e)' { npm run typecheck } }
        if ($appPlan.Build) { Step-App 'npm run build (app)' { npm run build } }
        if ($appPlan.Mode -eq 'check') { Skip 'playwright' $appPlan.Why }
        else {
            # Real-Electron specs are part of the full suite and need the Electron binary, which npm ci can skip.
            if ($appPlan.Mode -eq 'suite') {
                Step 'Electron binary present' { $missing = @(Test-ElectronBinary 'app'); if ($missing.Count -gt 0) { $missing; $global:LASTEXITCODE = 1 } else { 'Electron loads'; $global:LASTEXITCODE = 0 } }
            }
            # The suite runs the Release Host; build it from this tree so the run cannot test an older Host.
            Step 'dotnet build src/NetSec.Host (Release, for the app run)' { dotnet build src/NetSec.Host -c Release --nologo -v q }
            $spec = if ($appPlan.Lesson) { "e2e/lesson-$($appPlan.Lesson).spec.ts" } else { '' }
            # The local Playwright CLI, never the package runner: it can run a package of the same name from outside this repo (tools/no_npx.py guards this).
            Step-App $appPlan.Label {
                if (-not $env:NETSEC_PORT_BASE) { $env:NETSEC_PORT_BASE = 'auto' }
                if ($spec) { node node_modules/@playwright/test/cli.js test $spec } else { node node_modules/@playwright/test/cli.js test }
            }
        }
    }
}

Step 'lessons_status' { python tools/lessons_status.py docs/_runs }

# ---------------------------------------------------------------- report
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add("# Gate $Slice, $date")
$lines.Add('')
$lines.Add("Head: $head")
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
$passedCount = @($rows | Where-Object Status -eq 'PASS').Count
$ranCount = @($rows | Where-Object Status -ne 'SKIPPED').Count
$skippedCount = @($rows | Where-Object Status -eq 'SKIPPED').Count
Write-Host (Format-GateFinal -Slice $Slice -Passed $passedCount -Ran $ranCount -Skipped $skippedCount -Report $report)
exit $(if ($failed -gt 0) { 1 } else { 0 })
