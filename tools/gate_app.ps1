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

function Get-AppDiffFiles([string]$Repo, [string]$Base = 'origin/main') {
    # The files under app/ that differ from main, committed or not. When main is unknown the answer is one code-like entry, so a gate cannot
    # skip app proof by accident.
    git -C $Repo rev-parse --verify -q $Base *> $null
    if ($LASTEXITCODE -ne 0) { return @('(origin/main unknown)') }
    $names = [System.Collections.Generic.SortedSet[string]]::new()
    # --no-renames lists a rename as a delete of the old path plus an add of the new one, so foo.ts renamed to foo.md still shows foo.ts (code).
    foreach ($n in @(git -C $Repo diff --name-only --no-renames "$Base...HEAD" -- app 2>$null)) { if ($n) { [void]$names.Add($n) } }
    foreach ($line in @(git -C $Repo status --porcelain --no-renames -- app 2>$null)) { if ($line.Length -gt 3) { [void]$names.Add($line.Substring(3).Trim('"')) } }
    return @($names)
}

function Test-NonCodeAppFile([string]$Path) {
    # The one rule that lets app proof be skipped without a human: a Markdown file, or an image in a screens folder. Everything else under app/
    # (source, specs, config, JSON, lockfiles, other images) is code and gets proof.
    $p = $Path.Replace('\', '/').ToLowerInvariant()
    if ($p.EndsWith('.md')) { return $true }
    return ($p -match '/screens/' -and $p -match '\.(png|jpe?g|gif|svg|webp)$')
}

function Get-AppProofPlan([bool]$HasApp, [bool]$SkipApp, [string]$Lesson, [string[]]$AppDiffFiles) {
    # Mode: none (no app folder), docs (every changed file under app/ is non-code: skipped on its own, the files printed), refuse (code changed
    # and -SkipApp was given; there is no override), skip (-SkipApp, nothing changed), suite, narrowed (suite cut to one lesson),
    # lesson (no app change, one lesson spec, typecheck and build first), check (no app change: typecheck only).
    $files = @($AppDiffFiles | Where-Object { $_ })
    $code = @($files | Where-Object { -not (Test-NonCodeAppFile $_) })
    $plan = [ordered]@{ Mode = ''; Typecheck = $false; Build = $false; Suite = $false; Lesson = ''; Label = ''; Why = '' }
    if (-not $HasApp) {
        $plan.Mode = 'none'; $plan.Why = 'app/package.json is absent; Nancy owns app/ and her PR has not landed'
    } elseif ($files.Count -gt 0 -and $code.Count -eq 0) {
        $plan.Mode = 'docs'
        $plan.Why = "app/ changed only in non-code files ($($files.Count)), so app proof does not apply: $($files -join ', ')"
    } elseif ($SkipApp -and $code.Count -gt 0) {
        $shown = ($code | Select-Object -First 10) -join ', '
        $more = if ($code.Count -gt 10) { ", and $($code.Count - 10) more" } else { '' }
        $plan.Mode = 'refuse'
        $plan.Why = "APP_PROOF_SKIPPED: -SkipApp cannot skip app proof because code under app/ changed ($($code.Count) files): $shown$more. Run without -SkipApp."
    } elseif ($SkipApp) {
        $plan.Mode = 'skip'; $plan.Why = 'the -SkipApp switch'
    } elseif ($code.Count -gt 0 -and $Lesson) {
        $plan.Mode = 'narrowed'; $plan.Typecheck = $true; $plan.Build = $true; $plan.Suite = $true; $plan.Lesson = $Lesson
        $plan.Label = "playwright lesson $Lesson (narrowed by -Lesson $Lesson; code under app/ changed in $($code.Count) files)"
    } elseif ($code.Count -gt 0) {
        $plan.Mode = 'suite'; $plan.Typecheck = $true; $plan.Build = $true; $plan.Suite = $true
        $plan.Label = "playwright full suite (code under app/ changed in $($code.Count) files)"
    } elseif ($Lesson) {
        # Build too: the preview serves app/dist, so a stale dist could otherwise pass a lesson spec.
        $plan.Mode = 'lesson'; $plan.Typecheck = $true; $plan.Build = $true; $plan.Lesson = $Lesson; $plan.Label = "playwright lesson $Lesson"
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
    # The real-Electron specs need the Electron binary, which npm ci can skip. require('electron') only RETURNS a path (from path.txt, or from
    # ELECTRON_OVERRIDE_DIST_PATH); it never checks the file exists, so the probe checks that too.
    Push-Location $AppDir
    # With the override and no path.txt, index.js returns <dist>/electron with no extension and Windows starts <dist>/electron.exe, so both count.
    try { node -e "const p = require('electron'); const fs = require('fs'); const isFile = f => fs.existsSync(f) && fs.statSync(f).isFile(); if (typeof p !== 'string' || !(isFile(p) || isFile(p + '.exe'))) process.exit(3)" 2>$null *> $null; $code = $LASTEXITCODE } finally { Pop-Location }
    if ($code -eq 0) { return @() }
    return @('TOOL_MISSING: the Electron binary is missing or broken in app/node_modules/electron. Set ELECTRON_OVERRIDE_DIST_PATH to another checkout''s node_modules/electron/dist, or run this yourself: cd app; node node_modules/electron/install.js')
}
