#requires -Version 7
<#
.SYNOPSIS
  Installs the pre-push guard for a clone and every worktree of it. Run by tools/bootstrap.ps1; safe to run again (it refreshes the copy).
.DESCRIPTION
  Copies pre-push and pre_push_guard.py, as they are on main, into <git common dir>/netsec-hooks and sets core.hooksPath to that absolute path.
  Two rules, both from Jared's reviews (#257, #261):
  1. The path is absolute and outside the working tree. A relative core.hooksPath resolves against the checked-out tree, so a worktree on a
     branch made before the hook files existed would run no hook and the push would go through silently.
  2. The files come from main (origin/main), never from the folder this script sits in. The installed copy is shared by every worktree, so a
     builder on an older branch must not install an older guard over a newer one. A change to the guard takes effect for everyone once it is
     merged and this script runs again.
.PARAMETER Repo
  The clone to install into. Default: the clone this script sits in.
.PARAMETER Ref
  The ref that holds the files. Default: origin/main (fetched first, best effort). Tests pass a branch.
#>
[CmdletBinding()]
param(
    [string]$Repo = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string]$Ref = 'origin/main'
)
$ErrorActionPreference = 'Stop'
$files = 'pre-push', 'pre_push_guard.py'

function Save-Blob([string]$Spec, [string]$Dest) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new('git')
    foreach ($a in '-C', $Repo, 'show', $Spec) { $psi.ArgumentList.Add($a) }
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = [System.IO.File]::Create($Dest)
    try { $p.StandardOutput.BaseStream.CopyTo($out) } finally { $out.Dispose() }
    $p.WaitForExit()
    if ($p.ExitCode -ne 0) { throw "git show $Spec failed" }
}

$common = (git -C $Repo rev-parse --path-format=absolute --git-common-dir).Trim()
if ($LASTEXITCODE -ne 0 -or -not $common) { throw "not a git clone: $Repo" }
if ($Ref -eq 'origin/main') { git -C $Repo fetch -q origin main 2>$null }
foreach ($name in $files) {
    git -C $Repo cat-file -e "${Ref}:tools/githooks/$name" 2>$null
    if ($LASTEXITCODE -ne 0) { throw "$Ref has no tools/githooks/$name. Fetch origin, or the guard is not merged into $Ref yet." }
}
$target = Join-Path $common 'netsec-hooks'
New-Item -ItemType Directory -Force -Path $target | Out-Null
foreach ($name in $files) { Save-Blob "${Ref}:tools/githooks/$name" (Join-Path $target $name) }
$hooksPath = $target -replace '\\', '/'
git -C $Repo config core.hooksPath $hooksPath
if ($LASTEXITCODE -ne 0) { throw 'git config core.hooksPath failed' }
Write-Host "== git hooks: core.hooksPath = $hooksPath (files from $Ref)"
