#requires -Version 7
<#
.SYNOPSIS
  Runs the under-load half of issue #309's side property: each side test 20 times, the second half beside a CPU burner on every core
  (NETSEC_LOAD_RUNS=1, read by tests/NetSec.Tests/Tls13Tests.cs). The shared suite runs these tests 6 times with no burner, so this script is
  the one committed place where "20 of 20 under load" is measured. Writes docs\_runs\<date>-load-runs.md with the commit and each framework's result.
.DESCRIPTION
  A burner loads the whole machine, so the run takes the machine-wide heavy lock (tools/heavy_lock.py) and never starts beside a gate.
  With no lock script the run stops with LOAD_RUNS_NO_LOCK and runs nothing.
.PARAMETER HeavyLock
  The heavy-lock script. Default: tools/heavy_lock.py in this repo.
.PARAMETER WaitMinutes
  How long to wait for the lock. Default: 60.
.EXAMPLE
  pwsh tools/load_runs.ps1
#>
[CmdletBinding()]
param(
    [string]$HeavyLock,
    [int]$WaitMinutes = 60
)
$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
if (-not $HeavyLock) { $HeavyLock = Join-Path $root 'tools/heavy_lock.py' }
if (-not (Test-Path $HeavyLock)) {
    Write-Host "LOAD_RUNS_NO_LOCK: $HeavyLock is missing. A burner run must hold the heavy lock; pass -HeavyLock <path to heavy_lock.py>."
    exit 2
}

# The side tests: the whole drop fork, the drop fork right after a reply, and the record length fork. Their names all end this way.
$filter = 'FullyQualifiedName~_in_every_run'
$head = (git rev-parse HEAD).Trim()
$date = Get-Date -Format 'yyyy-MM-dd'
$log = "docs/_runs/trx/load-runs/$date-load-runs.log"   # the full output; docs/_runs/trx is not tracked
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null

$env:NETSEC_LOAD_RUNS = '1'
python -I $HeavyLock run --wait-minutes $WaitMinutes --label "load runs $($head.Substring(0, 7))" -- dotnet test tests/NetSec.Tests --filter $filter *> $log
$code = $LASTEXITCODE
Remove-Item Env:NETSEC_LOAD_RUNS

$results = @(Select-String -Path $log -Pattern '^(Passed|Failed)!' | ForEach-Object { $_.Line.Trim() })
$report = @("# Load runs, $date", '', "HEAD $head", '', 'Command: `pwsh tools/load_runs.ps1` (NETSEC_LOAD_RUNS=1, filter `' + $filter + '`, under the heavy lock)', '', "Exit code: $code", '')
if ($results.Count -eq 0) { $report += 'LOAD_RUNS_NO_RESULT: dotnet test printed no result line. Read ' + $log + '.' }
else { $report += $results | ForEach-Object { "- $_" } }
$report | Set-Content "docs/_runs/$date-load-runs.md"
$report | ForEach-Object { Write-Host $_ }
exit $code
