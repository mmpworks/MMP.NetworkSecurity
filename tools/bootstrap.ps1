#requires -Version 7
<#
.SYNOPSIS
  Builds every product piece from a fresh clone, in Release. Node and the app join when their slices land.
.EXAMPLE
  pwsh tools/bootstrap.ps1
  pwsh tools/bootstrap.ps1 -AsyncProxyRoot E:\dev\MMP.AsyncProxy
#>
[CmdletBinding()]
param(
    [string]$AsyncProxyRoot = $env:AsyncProxyRoot,
    [string]$NetCFRefDir = 'E:\dev\tools\netcf35-ref'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
# Repo hooks: the pre-push guard refuses a push to a branch whose pull requests are all merged or closed (tools/githooks/pre_push_guard.py).
# core.hooksPath is repo-level, so every worktree of this clone uses it.
git -C $root config core.hooksPath tools/githooks
Write-Host "== git hooks: core.hooksPath = tools/githooks"
if (-not (Test-Path (Join-Path $NetCFRefDir 'mscorlib.dll'))) { throw "CF 3.5 reference assemblies missing at $NetCFRefDir" }
if (-not $AsyncProxyRoot) { $AsyncProxyRoot = Join-Path (Split-Path -Parent $root) 'MMP.AsyncProxy' }
if (-not (Test-Path (Join-Path $AsyncProxyRoot 'src\MMP.AsyncProxy'))) { throw "MMP.AsyncProxy not found at $AsyncProxyRoot. Pass -AsyncProxyRoot." }

Write-Host "== native\build.cmd"
& cmd /c (Join-Path $root 'native\build.cmd')
if ($LASTEXITCODE -ne 0) { throw "native build failed with exit code $LASTEXITCODE" }

$props = @("-p:NetCFRefDir=$NetCFRefDir", "-p:AsyncProxyRoot=$AsyncProxyRoot")
foreach ($project in 'src\NetSec.Core', 'src\NetSec.Core.NetCF', 'src\NetSec.CeDevice', 'src\NetSec.Host') {
    $path = Join-Path $root $project
    Write-Host "== dotnet build $project"
    dotnet build $path -c Release --nologo -v q @props
    if ($LASTEXITCODE -ne 0) { throw "build failed: $project" }
}
$optional = Join-Path $root 'src\NetSec.Node'
if (Test-Path $optional) {
    Write-Host "== dotnet build src\NetSec.Node"
    dotnet build $optional -c Release --nologo -v q @props
    if ($LASTEXITCODE -ne 0) { throw "build failed: src\NetSec.Node" }
}
$app = Join-Path $root 'app\package.json'
if (Test-Path $app) {
    Write-Host "== npm ci and npm run build in app"
    Push-Location (Join-Path $root 'app')
    try {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
        npm run build
        if ($LASTEXITCODE -ne 0) { throw "npm run build failed" }
    } finally { Pop-Location }
}
Write-Host "bootstrap: done"
