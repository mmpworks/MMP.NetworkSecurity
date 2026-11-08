#requires -Version 7
<#
.SYNOPSIS
  The decisions behind the gate's app steps, kept apart from tools/gate.ps1 so tools/test_gate_app.py can test each one with plain inputs.
  Dot-sourced by gate.ps1. Nothing here installs a package: a missing tool is a named TOOL_MISSING and the agent runs the fix as its own step.
#>

function Get-HeadLine([string]$Repo) {
    # The commit a run was made on: short sha, plus "+dirty" when a tracked file differs from it. Untracked files do not count.
    $sha = (git -C $Repo rev-parse --short HEAD 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $sha) { return 'unknown' }
    $changed = @(git -C $Repo status --porcelain --untracked-files=no 2>$null)
    if ($changed.Count -gt 0) { return "$sha+dirty" }
    return "$sha"
}

function Get-AppDiffCount([string]$Repo, [string]$Base = 'origin/main') {
    # How many files under app/ differ from main, committed or not. When main is unknown the answer is "changed", so a gate cannot skip app proof by accident.
    git -C $Repo rev-parse --verify -q $Base *> $null
    if ($LASTEXITCODE -ne 0) { return 1 }
    $names = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($n in @(git -C $Repo diff --name-only "$Base...HEAD" -- app 2>$null)) { if ($n) { [void]$names.Add($n) } }
    foreach ($line in @(git -C $Repo status --porcelain -- app 2>$null)) { if ($line.Length -gt 3) { [void]$names.Add($line.Substring(3).Trim('"')) } }
    return [int]$names.Count
}

function Get-AppProofPlan([bool]$HasApp, [bool]$SkipApp, [string]$SkipAppReason, [string]$Lesson, [int]$AppDiffCount) {
    # Mode: none (no app folder), skip (named), refuse (app changed, skipped with no reason), suite, narrowed (suite cut to one lesson),
    # lesson (no app change, one lesson spec), check (no app change: typecheck only).
    $plan = [ordered]@{ Mode = ''; Typecheck = $false; Build = $false; Suite = $false; Lesson = ''; Label = ''; Why = '' }
    if (-not $HasApp) {
        $plan.Mode = 'none'; $plan.Why = 'app/package.json is absent; Nancy owns app/ and her PR has not landed'
    } elseif ($SkipApp -and $AppDiffCount -gt 0 -and -not $SkipAppReason) {
        $plan.Mode = 'refuse'
        $plan.Why = "APP_PROOF_SKIPPED: app/ changed in $AppDiffCount files, so -SkipApp leaves them with no proof. Run without -SkipApp, or pass -SkipAppReason `"<why>`"."
    } elseif ($SkipApp) {
        $plan.Mode = 'skip'
        $plan.Why = $(if ($SkipAppReason) { "the -SkipApp switch: $SkipAppReason" } else { 'the -SkipApp switch' })
    } elseif ($AppDiffCount -gt 0 -and $Lesson) {
        $plan.Mode = 'narrowed'; $plan.Typecheck = $true; $plan.Build = $true; $plan.Suite = $true; $plan.Lesson = $Lesson
        $plan.Label = "playwright lesson $Lesson (narrowed by -Lesson $Lesson; app/ changed in $AppDiffCount files)"
    } elseif ($AppDiffCount -gt 0) {
        $plan.Mode = 'suite'; $plan.Typecheck = $true; $plan.Build = $true; $plan.Suite = $true
        $plan.Label = "playwright full suite (app/ changed in $AppDiffCount files)"
    } elseif ($Lesson) {
        $plan.Mode = 'lesson'; $plan.Typecheck = $true; $plan.Lesson = $Lesson; $plan.Label = "playwright lesson $Lesson"
    } else {
        $plan.Mode = 'check'; $plan.Typecheck = $true; $plan.Why = 'no -Lesson given'
    }
    return [pscustomobject]$plan
}

function Test-AppTools([string]$AppDir) {
    # Messages for tools the app steps need and the folder lacks. Empty means ready. Never installs.
    if (-not (Test-Path (Join-Path $AppDir 'node_modules'))) {
        return @('TOOL_MISSING: app/node_modules is absent. The gate never installs; run this yourself: cd app; npm ci')
    }
    $missing = @()
    foreach ($rel in 'vite/bin/vite.js', '@playwright/test/cli.js') {
        if (-not (Test-Path (Join-Path $AppDir "node_modules/$rel"))) { $missing += "TOOL_MISSING: app/node_modules/$rel is absent. Run this yourself: cd app; npm ci" }
    }
    return $missing
}

function Test-ElectronBinary([string]$AppDir) {
    # The real-Electron specs need the Electron binary, which npm ci can skip. Probe it the way the app loads it.
    Push-Location $AppDir
    try { node -e "require('electron')" 2>$null *> $null; $code = $LASTEXITCODE } finally { Pop-Location }
    if ($code -eq 0) { return @() }
    return @('TOOL_MISSING: the Electron binary is missing or broken in app/node_modules/electron. Set ELECTRON_OVERRIDE_DIST_PATH to another checkout''s node_modules/electron/dist, or run this yourself: cd app; node node_modules/electron/install.js')
}
