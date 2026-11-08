#requires -Version 7
<#
.SYNOPSIS
  Fails when the installed pre-push hook is missing or differs from the files in tools/githooks. A gate step runs it, so a changed guard cannot
  sit uninstalled behind a green gate (Jared, #257).
.PARAMETER Repo
  The clone to check. Default: the clone this script sits in.
.PARAMETER Source
  The folder holding the files that should be installed. Default: the folder this script sits in.
#>
[CmdletBinding()]
param(
    [string]$Repo = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$Source = $PSScriptRoot
)
$ErrorActionPreference = 'Stop'
$fix = 'Run: pwsh tools/githooks/install.ps1'
function Fail([string]$why) { Write-Host "HOOK_NOT_CURRENT: $why. $fix"; exit 1 }

$common = (git -C $Repo rev-parse --path-format=absolute --git-common-dir).Trim()
$expected = ((Join-Path $common 'netsec-hooks') -replace '\\', '/').TrimEnd('/')
$path = (git -C $Repo config core.hooksPath)
if (-not $path) { Fail 'core.hooksPath is not set, so no pre-push guard runs in this clone' }
if (($path -replace '\\', '/').TrimEnd('/') -ne $expected) { Fail "core.hooksPath is '$path', not the installed copy at $expected" }
foreach ($name in 'pre-push', 'pre_push_guard.py') {
    $installed = Join-Path $expected $name
    if (-not (Test-Path $installed)) { Fail "$name is missing from $expected" }
    if ((Get-FileHash $installed).Hash -ne (Get-FileHash (Join-Path $Source $name)).Hash) { Fail "$name differs from $Source" }
}
Write-Host "pre-push hook installed and current ($expected)"
