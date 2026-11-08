#requires -Version 7
<#
.SYNOPSIS
  Fails when the installed pre-push hook is missing or differs from the files on main. A gate step runs it, so a changed guard cannot sit
  uninstalled behind a green gate (Jared, #257).
.DESCRIPTION
  The reference is main (origin/main), never the working tree. The installed copy is shared by every worktree, so a builder on an older
  branch must not be told to install an older guard over a newer one (Jared, #261). A PR that changes the guard gates against main's copy;
  the new guard becomes the installed one once it merges and install.ps1 runs.
.PARAMETER Repo
  The clone to check. Default: the clone this script sits in.
.PARAMETER Ref
  The ref that holds the reference files. Default: origin/main (fetched first, best effort). Tests pass a branch.
#>
[CmdletBinding()]
param(
    [string]$Repo = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$Ref = 'origin/main'
)
$ErrorActionPreference = 'Stop'
$fix = 'Run: pwsh tools/githooks/install.ps1'
function Fail([string]$why) { Write-Host "HOOK_NOT_CURRENT: $why. $fix"; exit 1 }

$common = (git -C $Repo rev-parse --path-format=absolute --git-common-dir).Trim()
$expected = ((Join-Path $common 'netsec-hooks') -replace '\\', '/').TrimEnd('/')
$path = (git -C $Repo config core.hooksPath)
if (-not $path) { Fail 'core.hooksPath is not set, so no pre-push guard runs in this clone' }
if (($path -replace '\\', '/').TrimEnd('/') -ne $expected) { Fail "core.hooksPath is '$path', not the installed copy at $expected" }
if ($Ref -eq 'origin/main') { git -C $Repo fetch -q origin main 2>$null }
foreach ($name in 'pre-push', 'pre_push_guard.py') {
    $want = (git -C $Repo rev-parse --verify -q "${Ref}:tools/githooks/$name")
    if ($LASTEXITCODE -ne 0 -or -not $want) { Fail "$Ref has no tools/githooks/$name (fetch origin, or the guard is not merged yet)" }
    $installed = Join-Path $expected $name
    if (-not (Test-Path $installed)) { Fail "$name is missing from $expected" }
    $have = (git -C $Repo hash-object --no-filters $installed)
    if ($have -ne $want) { Fail "$name differs from $Ref" }
}
Write-Host "pre-push hook installed and current with $Ref ($expected)"
