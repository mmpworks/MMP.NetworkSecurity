#requires -Version 7
<#
.SYNOPSIS
  Installs the pre-push guard for a clone and every worktree of it. Run by tools/bootstrap.ps1; safe to run again (it refreshes the copy).
.DESCRIPTION
  Copies pre-push and pre_push_guard.py into <git common dir>/netsec-hooks and sets core.hooksPath to that absolute path.
  A relative core.hooksPath would resolve against the checked-out tree, so a worktree on a branch made before the hook files existed would run
  no hook and the push would go through silently (Jared, #257). The common git folder is shared by all worktrees, whatever branch each one has.
  After you change a file in tools/githooks, run this again to refresh the copy.
.PARAMETER Repo
  The clone to install into. Default: the clone this script sits in.
#>
[CmdletBinding()]
param([string]$Repo = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
$ErrorActionPreference = 'Stop'
$common = (git -C $Repo rev-parse --path-format=absolute --git-common-dir).Trim()
if ($LASTEXITCODE -ne 0 -or -not $common) { throw "not a git clone: $Repo" }
$target = Join-Path $common 'netsec-hooks'
New-Item -ItemType Directory -Force -Path $target | Out-Null
foreach ($name in 'pre-push', 'pre_push_guard.py') { Copy-Item -Force -Path (Join-Path $PSScriptRoot $name) -Destination (Join-Path $target $name) }
$hooksPath = $target -replace '\\', '/'
git -C $Repo config core.hooksPath $hooksPath
if ($LASTEXITCODE -ne 0) { throw 'git config core.hooksPath failed' }
Write-Host "== git hooks: core.hooksPath = $hooksPath"
