#requires -Version 7
<#
.SYNOPSIS
  Runs the acceptance suite for MMP.NetworkSecurity (D11). Every clause ends PASS, FAIL or NOT RUN, with a reason.

.DESCRIPTION
  Builds the product pieces that exist, builds the clause groups, runs the named clauses, and writes
  docs\_runs\acceptance-<timestamp>.json and .md with N of M, where M comes from acceptance\clauses.json.
  A clause whose product code is missing is NOT RUN PRODUCT_MISSING. It is never PASS.
  A clause that passes while the product is missing is a bug in the suite: it is reported FAIL SUITE_BUG_VACUOUS_PASS.

.PARAMETER Clauses
  What to run. Default All. Accepts clause ids, an assertion (A5), a slice (S3), a group name (tls13live), or a prefix (A5.client).
  Comma-separated or as a list.

.PARAMETER Fresh
  Clone the product (committed state only) into a temp folder that sits beside the sibling MMP.AsyncProxy folder, run the clone's own
  acceptance\run.ps1 there, and check acceptance\PIN with acceptance\tools\pin.py. A missing, stale or old-form PIN is a FAIL of
  A13.fresh-clone.acceptance-unchanged. Use AsyncProxyRoot (parameter or environment variable) to say where the sibling is.

.PARAMETER Contract
  Compile-check mode. Builds every clause group against the contract stub (acceptance\contract) and runs nothing. Proves the suite
  compiles against the signatures in program-design.md section 2.

.PARAMETER SelfTest
  Also run the SELF clauses (the suite's checks on itself). They are listed apart from M.

.EXAMPLE
  pwsh acceptance/run.ps1 -Clauses A1,A2
  pwsh acceptance/run.ps1 -Clauses All -Fresh
#>
[CmdletBinding()]
param(
    [string[]]$Clauses = @('All'),
    [switch]$Fresh,
    [string]$ProductRoot,
    [string]$AsyncProxyRoot,
    [string]$NetCFRefDir = 'E:\dev\tools\netcf35-ref',
    [string]$OutDir,
    [switch]$SelfTest,
    [switch]$RecordGolden,
    [switch]$Contract,
    [switch]$FreshChild,
    # The Algorithm-Optimization slice this run judges against acceptance/ao-rows.tsv (S0 to S7). No default: a default goes stale.
    [string]$AoSlice,
    # The S0 benchmark report (acceptance/ao-bench-schema.md). With none, the bench rows of the row list read as absent.
    [string]$AoBenchReport
)

# An explicit -NetCFRefDir that holds no mscorlib.dll stops the run here with one named error, before it queues for the lock.
# Git Bash strips the backslashes of an unquoted Windows path (E:devtoolsnetcf35-ref), and that path once gave 118
# PRODUCT_BUILD_FAILED rows. The default path keeps its NOT RUN CF_REFERENCES_MISSING rows, so a machine with no CF
# references still runs every other clause.
if ($PSBoundParameters.ContainsKey('NetCFRefDir') -and -not (Test-Path -LiteralPath (Join-Path $NetCFRefDir 'mscorlib.dll'))) {
    Write-Host "[acceptance] NETCF_REF_DIR_BAD: -NetCFRefDir '$NetCFRefDir' holds no mscorlib.dll. Quote Windows paths in Git Bash ('E:\dev\tools\netcf35-ref'), or omit the flag to use the default."
    exit 2
}

# Every run takes the machine-wide heavy-run lock first (tools/heavy_lock.py, #320), so acceptance runs queue behind gates and app suites
# instead of loading a busy machine. A run inside the live holder (a gate, a -Fresh parent, or this wrapper) goes straight on. A missing lock
# tool fails the run by name; it never skips the lock.
$lockTool = Join-Path $PSScriptRoot '..\tools\heavy_lock.py'
if (-not (Test-Path $lockTool)) { Write-Host "[acceptance] LOCK_MISSING: $lockTool is absent, so this run cannot queue behind other heavy runs"; exit 3 }
# `heavy_lock.py holds` exits 0 only inside the live holder, so a NETSEC_HEAVY_LOCK_HELD left over in a shell does not skip the lock (Jared on
# #334). A tool from before `holds` (#335) exits 2 on the unknown action; then the variable decides, or every child would wrap again forever.
python -I $lockTool holds *> $null
$holdsCode = $LASTEXITCODE
$insideHolder = $holdsCode -eq 0 -or ($holdsCode -eq 2 -and $env:NETSEC_HEAVY_LOCK_HELD)
if (-not $insideHolder) {
    # param() binds every argument, so $args is empty: forward the bound parameters, switches as bare names.
    $forward = @()
    foreach ($p in $PSBoundParameters.GetEnumerator()) {
        if ($p.Value -is [System.Management.Automation.SwitchParameter]) { if ($p.Value.IsPresent) { $forward += "-$($p.Key)" } }
        else { $forward += "-$($p.Key)"; $forward += (@($p.Value) -join ',') }
    }
    $label = 'acceptance ' + (@($Clauses) -join ',')
    if ($label.Length -gt 80) { $label = $label.Substring(0, 77) + '...' }
    python -I $lockTool run --label $label -- pwsh -NoProfile -File $PSCommandPath @forward
    exit $LASTEXITCODE
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$acc = $PSScriptRoot
if (-not $ProductRoot) { $ProductRoot = Split-Path -Parent $acc }
$ProductRoot = (Resolve-Path $ProductRoot).Path
if (-not $AsyncProxyRoot) { $AsyncProxyRoot = $env:AsyncProxyRoot }
if (-not $AsyncProxyRoot) { $AsyncProxyRoot = Join-Path (Split-Path -Parent $ProductRoot) 'MMP.AsyncProxy' }
$env:AsyncProxyRoot = $AsyncProxyRoot
if (-not $OutDir) { $OutDir = Join-Path $ProductRoot 'docs\_runs' }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Clauses = @($Clauses | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

function Say([string]$m) { Write-Host ("[acceptance] " + $m) }

# ------------------------------------------------------------------ fresh clone: run the clone's own script
if ($Fresh -and -not $FreshChild) {
    $parent = Split-Path -Parent $AsyncProxyRoot
    $clone = Join-Path $parent ("ns-fresh-" + $stamp)
    Say "cloning $ProductRoot to $clone (committed state only, beside the sibling at $AsyncProxyRoot)"
    git clone --quiet $ProductRoot $clone
    if ($LASTEXITCODE -ne 0) { throw "git clone failed" }
    $childArgs = @('-NoProfile', '-File', (Join-Path $clone 'acceptance\run.ps1'), '-Clauses', ($Clauses -join ','), '-ProductRoot', $clone,
                   '-AsyncProxyRoot', $AsyncProxyRoot, '-OutDir', $OutDir, '-FreshChild')
    # Only an explicit -NetCFRefDir goes to the child. The child's own default then keeps its NOT RUN CF_REFERENCES_MISSING rows (Jared on #385).
    if ($PSBoundParameters.ContainsKey('NetCFRefDir')) { $childArgs += @('-NetCFRefDir', $NetCFRefDir) }
    if ($SelfTest) { $childArgs += '-SelfTest' }
    & pwsh @childArgs
    $code = $LASTEXITCODE
    Say "the fresh clone stays at $clone for inspection"
    exit $code
}

$work = Join-Path $acc ".work\run-$stamp"
New-Item -ItemType Directory -Force -Path $work | Out-Null
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# ------------------------------------------------------------------ tools
function Invoke-Tool {
    param([string]$Exe, [string[]]$ToolArgs, [string]$Dir = $null, [int]$TimeoutSec = 1800)
    $stdout = Join-Path $work ("tool-" + [guid]::NewGuid().ToString('N') + ".out")
    $stderr = $stdout + '.err'
    if ($Exe -eq 'dotnet' -and $ToolArgs.Count -gt 0 -and $ToolArgs[0] -eq 'build') { $ToolArgs = @($ToolArgs) + @('-nodeReuse:false', '-p:UseSharedCompilation=false') }   # a private build, so a stuck shared build server of another session cannot hang this run
    if ($Exe -eq 'npm') { $Exe = 'npm.cmd' }      # the extensionless npm is a shell script, not a Win32 program
    $psi = @{ FilePath = $Exe; ArgumentList = $ToolArgs; NoNewWindow = $true; PassThru = $true; RedirectStandardOutput = $stdout; RedirectStandardError = $stderr }
    if ($Dir) { $psi.WorkingDirectory = $Dir }
    try { $p = Start-Process @psi }
    catch { return [pscustomobject]@{ ExitCode = -998; Output = "TOOL_MISSING: $Exe could not start: $($_.Exception.Message)" } }
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        & taskkill /T /F /PID $p.Id *> $null
        return [pscustomobject]@{ ExitCode = -999; Output = "timeout after $TimeoutSec s`n" + (Get-Content $stdout -Raw -ErrorAction SilentlyContinue) }
    }
    $p.WaitForExit()
    $text = ((Get-Content $stdout -Raw -ErrorAction SilentlyContinue) + "`n" + (Get-Content $stderr -Raw -ErrorAction SilentlyContinue))
    return [pscustomobject]@{ ExitCode = $p.ExitCode; Output = $text }
}

# An npm ci when node_modules is missing, when -Force, or when package-lock.json changed since the last good install. A tree that kept
# node_modules across a lockfile change built against old packages, and the app build failed on a missing import (#288's run, 2026-11-08).
# After a good install the lockfile's SHA-256 goes into node_modules/.netsec-lock.sha256; a missing or different stamp means install again.
# Returns the tool run, or $null when node_modules is current.
function Invoke-NpmCiIfStale([string]$Dir, [switch]$Force) {
    $modules = Join-Path $Dir 'node_modules'
    $stamp = Join-Path $modules '.netsec-lock.sha256'
    $lock = Join-Path $Dir 'package-lock.json'
    $want = if (Test-Path $lock) { (Get-FileHash -Algorithm SHA256 $lock).Hash } else { 'no-lockfile' }
    $have = if (Test-Path $stamp) { (Get-Content $stamp -Raw).Trim() } else { $null }
    if (-not $Force -and (Test-Path $modules) -and $have -eq $want) { return $null }
    $run = Invoke-Tool 'npm' @('ci', '--no-audit', '--no-fund') $Dir -TimeoutSec 1200
    if ($run.ExitCode -eq 0) { Set-Content -Path $stamp -Value $want -NoNewline }
    return $run
}

function Tail([string]$s, [int]$n = 600) { $s = ($s ?? '').Trim(); if ($s.Length -gt $n) { return $s.Substring($s.Length - $n) } else { return $s } }

# ------------------------------------------------------------------ load the clause list
# clauses.json is generated, never committed (#343): every run writes it from the clause code first, so a stale or missing file cannot change
# a result, and no open PR conflicts on it. A failed generation stops the run by name.
$gen = Invoke-Tool 'python' @('-I', (Join-Path $acc 'tools\gen_clauses.py'), '--write') $acc -TimeoutSec 300
if ($gen.ExitCode -ne 0) { Write-Host ("[acceptance] GEN_FAILED: tools/gen_clauses.py --write exit $($gen.ExitCode): " + (Tail $gen.Output 600)); exit 2 }
Say ($gen.Output.Trim() -split "`n" | Select-Object -Last 1)
$doc = Get-Content (Join-Path $acc 'clauses.json') -Raw | ConvertFrom-Json
$roles = (Get-Content (Join-Path $acc 'roles.json') -Raw | ConvertFrom-Json).roles
$all = @($doc.clauses)
$M = @($all | Where-Object { $_.counts }).Count

# ------------------------------------------------------------------ contract (compile-check) mode
function Get-AsyncProxyDlls {
    # The sibling MMP.AsyncProxy is shared by every lane. Builds that write into it can collide (CS2012). When the product holds its own
    # AsyncProxy.Local projects (src/AsyncProxy.Local and src/AsyncProxy.Local.NetCF, which compile the sibling's sources into the product's own bin
    # folders), the suite builds those. Without them it builds the sibling, as before. The assembly versions are the same either way.
    $r = [ordered]@{ ns2 = $null; cf = $null; error = $null }
    if (-not (Test-Path (Join-Path $AsyncProxyRoot 'src\MMP.AsyncProxy'))) { $r.error = "MMP.AsyncProxy not found at $AsyncProxyRoot (set AsyncProxyRoot)"; return $r }
    $localNs = Join-Path $ProductRoot 'src\AsyncProxy.Local'
    $localCf = Join-Path $ProductRoot 'src\AsyncProxy.Local.NetCF'
    if (@(Get-ChildItem $localNs -Filter *.csproj -ErrorAction SilentlyContinue).Count -gt 0) {
        $b = Invoke-Tool 'dotnet' @('build', $localNs, '-c', 'Release', "-p:AsyncProxyRoot=$AsyncProxyRoot", '--nologo', '-v', 'q') -TimeoutSec 600
        $ns2 = Join-Path $localNs 'bin\Release\netstandard2.0\MMP.AsyncProxy.dll'
    } else {
        $b = Invoke-Tool 'dotnet' @('build', (Join-Path $AsyncProxyRoot 'src\MMP.AsyncProxy'), '-c', 'Release', '-f', 'netstandard2.0', '--nologo', '-v', 'q') -TimeoutSec 600
        $ns2 = Join-Path $AsyncProxyRoot 'src\MMP.AsyncProxy\bin\Release\netstandard2.0\MMP.AsyncProxy.dll'
    }
    if ($b.ExitCode -eq 0 -and (Test-Path $ns2)) { $r.ns2 = $ns2 } else { $r.error = "MMP.AsyncProxy netstandard2.0 build failed: " + (Tail $b.Output) }
    if (Test-Path (Join-Path $NetCFRefDir 'mscorlib.dll')) {
        if (@(Get-ChildItem $localCf -Filter *.csproj -ErrorAction SilentlyContinue).Count -gt 0) {
            $c = Invoke-Tool 'dotnet' @('build', $localCf, '-c', 'Release', "-p:AsyncProxyRoot=$AsyncProxyRoot", "-p:NetCFRefDir=$NetCFRefDir", '--nologo', '-v', 'q') -TimeoutSec 600
            $cf = Join-Path $localCf 'bin\Release\net35\MMP.AsyncProxy.dll'
        } else {
            $c = Invoke-Tool 'dotnet' @('build', (Join-Path $AsyncProxyRoot 'src\MMP.AsyncProxy.NetCF'), '-c', 'Release', "-p:NetCFRefDir=$NetCFRefDir", '--nologo', '-v', 'q') -TimeoutSec 600
            $cf = Join-Path $AsyncProxyRoot 'src\MMP.AsyncProxy.NetCF\bin\Release\net35\MMP.AsyncProxy.dll'
        }
        if ($c.ExitCode -eq 0 -and (Test-Path $cf)) { $r.cf = $cf } else { $r.error = "MMP.AsyncProxy CF build failed: " + (Tail $c.Output) }
    } else { $r.error = "CF references not found at $NetCFRefDir" }
    return $r
}

if ($Contract) {
    Say "contract mode: building each clause group against the contract stub; nothing runs"
    $ap = Get-AsyncProxyDlls
    if (-not $ap.ns2) { throw $ap.error }
    $stubProj = Join-Path $acc 'contract\NetSec.Core.Contract.csproj'
    $b = Invoke-Tool 'dotnet' @('build', $stubProj, '-c', 'Release', "-p:AsyncProxyDll=$($ap.ns2)", '--nologo', '-v', 'q')
    if ($b.ExitCode -ne 0) { throw "contract stub does not build: " + (Tail $b.Output) }
    $stub = Join-Path $acc 'contract\bin\Release\netstandard2.0\NetSec.Core.dll'
    $failed = 0
    foreach ($name in $doc.groups.PSObject.Properties.Name) {
        $g = $doc.groups.$name
        if ($g.kind -ne 'csharp') { continue }
        foreach ($build in $g.builds) {
            $tfm = if ($build -eq 'cf') { 'net48' } else { 'net10.0' }
            $apDll = if ($build -eq 'cf') { $ap.cf } else { $ap.ns2 }
            $r = Invoke-Tool 'dotnet' @('build', (Join-Path $acc $g.project), '-c', 'Release', '-f', $tfm, "-p:NetSecCoreDll=$stub", "-p:AsyncProxyDll=$apDll", '--nologo', '-v', 'q') -TimeoutSec 900
            $ok = $r.ExitCode -eq 0
            if (-not $ok) { $failed++ }
            Say ("{0,-11} {1,-5} {2}" -f $name, $build, $(if ($ok) { 'compiles against the contract' } else { 'DOES NOT COMPILE: ' + (Tail $r.Output 400) }))
        }
    }
    if ($failed -gt 0) { exit 1 } else { Say "all groups compile against the contract stub"; exit 0 }
}

# ------------------------------------------------------------------ select clauses
function Select-Clauses {
    $sel = @()
    foreach ($tok in $Clauses) {
        if ($tok -eq 'All') { $sel += $all | Where-Object { $_.counts }; continue }
        $sel += $all | Where-Object {
            $_.id -eq $tok -or $_.id.StartsWith($tok + '.') -or $_.base -eq $tok -or $_.assertion -eq $tok -or $_.slice -eq $tok -or $_.group -eq $tok
        }
    }
    if ($SelfTest) { $sel += $all | Where-Object { -not $_.counts } }
    # AO-1 and AO-8 (docs/algorithm-optimization-prd.md section 3) read the results of other clauses in the same run, so they bring them in.
    if ($sel | Where-Object { $_.id -like 'AO-0.*' }) { $sel += $all | Where-Object { $_.assertion -like 'AO-*' } }
    if ($sel | Where-Object { $_.id -like 'AO-1.*' }) { $sel += $all | Where-Object { $_.assertion -eq 'A1' -or $_.id -like 'A3.vec.*' -or $_.id -like 'A3.pinblock.*' } }
    if ($sel | Where-Object { $_.id -like 'AO-8.*' }) { $sel += $all | Where-Object { $_.assertion -eq 'A9' -or $_.id -eq 'A17.mock.golden-trace-equal.cf' } }
    $sel = @($sel | Sort-Object -Property id -Unique)
    return $sel
}

# AO-1 and AO-8 verdicts: PASS when every named row in this run passed, NOT RUN when none ran, else FAIL with the rows that did not pass.
function Get-RowsVerdict([object[]]$ids, [string]$what, [hashtable]$table) {
    $have = @($ids | Where-Object { $table.ContainsKey($_) })
    if ($have.Count -eq 0) { return @('NOT RUN', 'AO_ROWS_ABSENT', "no $what row ran in this run") }
    $notPass = @($have | Where-Object { $table[$_].status -ne 'PASS' })
    if ($notPass.Count -gt 0) {
        return @('FAIL', 'AO_ROW_NOT_PASS', ("{0} of {1} {2} rows pass. Not PASS: {3}" -f ($have.Count - $notPass.Count), $have.Count, $what, (($notPass | ForEach-Object { "$_ ($($table[$_].status) $($table[$_].reason))" }) -join '; ')))
    }
    return @('PASS', '', ("{0} of {0} {1} rows pass: {2}" -f $have.Count, $what, ($have -join ', ')))
}
# ---- the AO row list (docs/algorithm-optimization-prd.md section 4) ----
$AoSlices = @('S0', 'S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7')
function Read-AoRowList([string]$path) {
    $list = [ordered]@{}
    foreach ($line in (Get-Content -LiteralPath $path -Encoding utf8)) {
        if ($line -match '^\s*#' -or $line -match '^id\t' -or -not $line.Trim()) { continue }
        $f = $line -split "`t"
        if ($f.Count -ne 5) { throw "ao-rows.tsv: a line needs 5 tab-separated fields: $line" }
        if ($AoSlices -notcontains $f[3]) { throw "ao-rows.tsv: unknown slice '$($f[3])' in: $line" }
        if ($list.Contains($f[0])) { throw "ao-rows.tsv: the id $($f[0]) is listed twice" }
        $list[$f[0]] = [pscustomobject]@{ id = $f[0]; state = $f[1]; reason = $f[2]; from = $f[3]; source = $f[4] }
    }
    return $list
}
# The code the benchmark builds from: the product projects it references, the frozen original it compiles, the shared build file, and
# its own code (each entry of bench/ but bench/files). A bench report is valid on a head whose content at these paths equals the content
# at the report's commit (acceptance/ao-bench-schema.md rule 6). A bare commit id cannot be the rule: the commit that adds the report
# changes the head. bench/files is data, judged by content: each file that acceptance/ao9-files.tsv names must have, at the head, bytes
# that are in bench/files at the report's commit. A data file may get a new name; its bytes may not change.
$AoBenchMeasuredPaths = 'src/NetSec.Core', 'src/NetSec.Core.NetCF', 'src/AsyncProxy.Local', 'src/AsyncProxy.Local.NetCF', 'acceptance/groups/algo/Frozen', 'Directory.Build.props'

# The id of a git object (a commit, or the tree or blob at commit:path), or '' when the repository does not hold it.
function Get-GitObjectId([string]$repo, [string]$rev) {
    $id = (git -C $repo rev-parse --verify --quiet $rev 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $id) { return '' }
    return ([string]$id).Trim()
}

# The entries of a tree as name -> object id (with -r: every blob under it as path -> id). Empty when the tree does not exist.
function Get-GitTreeEntries([string]$repo, [string]$rev, [switch]$Recurse) {
    $map = @{}
    $listed = if ($Recurse) { @(git -C $repo ls-tree -r $rev 2>$null) } else { @(git -C $repo ls-tree $rev 2>$null) }
    if ($LASTEXITCODE -ne 0) { return $map }
    foreach ($line in $listed) {
        $m = [regex]::Match([string]$line, '^\S+ \S+ (?<id>[0-9a-f]{40,64})\t(?<name>.+)$')
        if ($m.Success) { $map[$m.Groups['name'].Value] = $m.Groups['id'].Value }
    }
    return $map
}

# $null when the measured code and data are the same at the report's commit and at the head of $repo. Else an object with reason and detail.
function Get-AoBenchCodeVerdict([string]$repo, [string]$commit) {
    $full = if ($commit -match '^[0-9a-fA-F]{7,40}$') { Get-GitObjectId $repo ($commit + '^{commit}') } else { '' }
    if (-not $full) {
        return [pscustomobject]@{ reason = 'AO_BENCH_COMMIT_UNKNOWN'; detail = "the repository does not hold the commit '$commit' that the bench report names: fetch it, or keep a tag on the measured commit" }
    }
    $short = $full.Substring(0, 7)
    $thenBench = Get-GitTreeEntries $repo ($full + ':bench')
    $nowBench = Get-GitTreeEntries $repo 'HEAD:bench'
    $paths = @($AoBenchMeasuredPaths) + @(@($thenBench.Keys) + @($nowBench.Keys) | Where-Object { $_ -ne 'files' } | Sort-Object -Unique | ForEach-Object { "bench/$_" })
    foreach ($p in $paths) {
        if ((Get-GitObjectId $repo ($full + ':' + $p)) -ne (Get-GitObjectId $repo ('HEAD:' + $p))) {
            return [pscustomobject]@{ reason = 'AO_BENCH_OTHER_COMMIT'; detail = "the measured code differs between the bench report's commit $short and the head: $p" }
        }
    }
    $thenBytes = @((Get-GitTreeEntries $repo ($full + ':bench/files') -Recurse).Values)
    foreach ($line in @(git -C $repo show 'HEAD:acceptance/ao9-files.tsv' 2>$null)) {
        if ($line -match '^\s*#' -or $line -match '^name\t' -or -not ([string]$line).Trim()) { continue }
        $name = ([string]$line -split "`t")[0]
        $now = Get-GitObjectId $repo ("HEAD:bench/files/$name")
        if (-not $now) { return [pscustomobject]@{ reason = 'AO_BENCH_OTHER_COMMIT'; detail = "the head has no bench/files/$name, a file of acceptance/ao9-files.tsv" } }
        if ($thenBytes -notcontains $now) {
            return [pscustomobject]@{ reason = 'AO_BENCH_OTHER_COMMIT'; detail = "the bytes of bench/files/$name at the head are in no file of bench/files at the bench report's commit $short" }
        }
    }
    $dirty = @(git -C $repo status --porcelain -- (@($AoBenchMeasuredPaths) + 'bench') 2>$null)
    if ($dirty.Count -gt 0) {
        return [pscustomobject]@{ reason = 'AO_BENCH_OTHER_COMMIT'; detail = "the working tree has uncommitted changes in the measured code: " + (($dirty | Select-Object -First 3) -join '; ') }
    }
    return $null
}

# The bench rows, judged by the suite from the numbers (acceptance/ao-bench-schema.md). Returns id -> result. $codeJudge takes the report's
# commit and gives $null (the measured code is the head's) or an object with reason and detail; then every bench row reads that FAIL.
$script:aoBenchCommitNote = ''
function Read-AoBench([string]$path, $list, [string]$slice, [scriptblock]$codeJudge) {
    $out = @{}
    if (-not $path) { return $out }
    $doc = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json
    $byId = @{}
    foreach ($r in @($doc.rows)) { $byId[[string]$r.id] = $r }
    $stale = & $codeJudge ([string]$doc.commit)
    $script:aoBenchCommitNote = if ($stale) { "$($stale.reason): $($stale.detail)" } else { "the report's commit $($doc.commit) has the measured code and data of the head (" + ($AoBenchMeasuredPaths -join ', ') + ", bench; bench/files by content)" }
    foreach ($e in @($list.Values | Where-Object { $_.source -eq 'bench' })) {
        $r = $byId[$e.id]
        if ($stale) { $out[$e.id] = [pscustomobject]@{ status = 'FAIL'; reason = $stale.reason; detail = $stale.detail }; continue }
        if (-not $r) { $out[$e.id] = [pscustomobject]@{ status = 'FAIL'; reason = 'AO_BENCH_ROW_BAD'; detail = 'no row in the bench report' }; continue }
        if ($e.id -like 'AO-5.*') {
            $b = $r.PSObject.Properties['bytesPerOp']
            if (-not $b -or $b.Value -isnot [ValueType]) { $out[$e.id] = [pscustomobject]@{ status = 'FAIL'; reason = 'AO_BENCH_ROW_BAD'; detail = 'bytesPerOp is missing or not a number' }; continue }
            $v = [double]$b.Value
            $out[$e.id] = if ($v -eq 0) { [pscustomobject]@{ status = 'PASS'; reason = ''; detail = "0 B per op ($($r.op))" } } else { [pscustomobject]@{ status = 'FAIL'; reason = 'AO5_ALLOCATES'; detail = "$v B per op ($($r.op))" } }
        } elseif ($e.id -like 'AO-9.*') {
            # PRD 3.3: outputs byte-equal on the frozen original and the head, and both numbers recorded. Five operations sum over the 7 files.
            $q = $r.PSObject.Properties['outputsEqual']; $a0 = $r.PSObject.Properties['originalNsPerOp']; $a1 = $r.PSObject.Properties['newNsPerOp']; $nf = $r.PSObject.Properties['files']
            $needSeven = @('gcm', 'cbc', 'ctr', 'sha256', 'hmac') -contains ($e.id.Split('.')[1])
            $okShape = $q -and $q.Value -is [bool] -and $a0 -and $a1 -and $a0.Value -is [ValueType] -and $a1.Value -is [ValueType] -and [double]$a0.Value -gt 0 -and [double]$a1.Value -gt 0 -and $nf -and $nf.Value -is [ValueType] -and [double]$nf.Value -ge 0 -and [double]$nf.Value -eq [math]::Floor([double]$nf.Value)
            if (-not $okShape -or ($needSeven -and [double]$nf.Value -ne 7)) { $out[$e.id] = [pscustomobject]@{ status = 'FAIL'; reason = 'AO_BENCH_ROW_BAD'; detail = 'outputsEqual (boolean), originalNsPerOp, newNsPerOp (above 0) and files (whole number; 7 for gcm, cbc, ctr, sha256, hmac) are needed' }; continue }
            # The .time row records the numbers. Output equality is the suite's own AO-9 row; the bench outputsEqual is a second record (Get-AoBenchDisagreements).
            $out[$e.id] = [pscustomobject]@{ status = 'PASS'; reason = ''; detail = ("recorded over {0} files: original {1} ns, new {2} ns ({3})" -f $nf.Value, $a0.Value, $a1.Value, $r.op) }
        } else {
            $p0 = $r.PSObject.Properties['baselineNsPerOp']; $p1 = $r.PSObject.Properties['newNsPerOp']
            if (-not $p0 -or -not $p1 -or $p0.Value -isnot [ValueType] -or $p1.Value -isnot [ValueType] -or [double]$p0.Value -le 0 -or [double]$p1.Value -le 0) { $out[$e.id] = [pscustomobject]@{ status = 'FAIL'; reason = 'AO_BENCH_ROW_BAD'; detail = 'baselineNsPerOp or newNsPerOp is missing, not a number, or not above 0' }; continue }
            $ratio = [double]$p0.Value / [double]$p1.Value
            $judge = $e.id -eq 'AO-6.aes-block.net10' -and [array]::IndexOf($AoSlices, $slice) -ge 1
            if ($judge -and $ratio -lt 5) { $out[$e.id] = [pscustomobject]@{ status = 'FAIL'; reason = 'AO6_BELOW_TARGET'; detail = ("{0:N2} x baseline, target 5 x" -f $ratio) }; continue }
            $out[$e.id] = [pscustomobject]@{ status = 'PASS'; reason = ''; detail = ("recorded: baseline {0} ns, new {1} ns, {2:N2} x" -f $p0.Value, $p1.Value, $ratio) }
        }
    }
    return $out
}
# acceptance/ao-budgets.tsv (PRD 7.4 rule 3; Jared's 3 conditions in its header). Returns one red text for each bad line: an id that
# is not in the row list, a second line for one id, a budget above 0 with no tradeoff PR, a malformed line.
function Get-AoBudgetReds([string]$path, $list) {
    $reds = @(); $seen = @{}
    if (-not (Test-Path -LiteralPath $path)) { return @('acceptance/ao-budgets.tsv is missing') }
    foreach ($line in (Get-Content -LiteralPath $path -Encoding utf8)) {
        if ($line -match '^\s*#' -or $line -match '^id\t' -or -not $line.Trim()) { continue }
        $f = $line -split "`t"
        if ($f.Count -ne 5) { $reds += "ao-budgets.tsv: a line needs 5 tab-separated fields: $line"; continue }
        $id = $f[0]
        if (-not $list.Contains($id)) { $reds += "ao-budgets.tsv: ${id} is not a row of ao-rows.tsv" }
        if ($seen.ContainsKey($id)) { $reds += "ao-budgets.tsv: ${id} has a second line" }
        $seen[$id] = $true
        $b = 0.0
        if (-not [double]::TryParse($f[1], [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$b) -or $b -lt 0) { $reds += "ao-budgets.tsv: ${id} budget_bytes '$($f[1])' is not a number of 0 or more" }
        elseif ($b -gt 0 -and -not $f[4].Trim()) { $reds += "ao-budgets.tsv: ${id} has a budget above 0 and no tradeoff PR" }
    }
    return $reds
}

# Jared on #405 (B1): the suite measures AO-5 and computes AO-9 equality itself. The bench numbers are a second record, and a
# disagreement is a red: an AO-5 bench row whose bytesPerOp is 0 while the suite row FAILs (or above 0 while it PASSes), and an AO-9 .time
# row whose outputsEqual differs from the suite's AO-9 row. A suite row that did not run (NOT RUN) is not compared.
function Get-AoBenchDisagreements([string]$path, [hashtable]$run) {
    $out = @()
    if (-not $path) { return $out }
    $doc = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json
    foreach ($r in @($doc.rows)) {
        $id = [string]$r.id
        if ($id -like 'AO-5.*') {
            $b = $r.PSObject.Properties['bytesPerOp']; $s = $run[$id]
            if (-not $b -or $b.Value -isnot [ValueType] -or -not $s -or $s.status -eq 'NOT RUN') { continue }
            $benchZero = [double]$b.Value -eq 0; $suiteZero = $s.status -eq 'PASS'
            if ($benchZero -ne $suiteZero) { $out += "${id}: AO5_BENCH_DISAGREES (bench $($b.Value) B per op, suite $($s.status) $($s.reason))" }
        } elseif ($id -like 'AO-9.*.time') {
            $q = $r.PSObject.Properties['outputsEqual']; $sid = $id.Substring(0, $id.Length - 5); $s = $run[$sid]
            if (-not $q -or $q.Value -isnot [bool] -or -not $s -or $s.status -eq 'NOT RUN') { continue }
            if ([bool]$q.Value -ne ($s.status -eq 'PASS')) { $out += "${id}: AO9_BENCH_DISAGREES (bench outputsEqual $($q.Value), suite $sid $($s.status) $($s.reason))" }
        }
    }
    return $out
}

# PRD 4.2: before its slice a row shows its listed state and reason; from its slice on, PASS. Anything else, a missing row and an
# unlisted row are each a red. Returns status, reason, detail; the detail starts with N of M (M = lines in the list).
function Get-AoRowListVerdict($list, [hashtable]$run, [string]$slice) {
    if (-not $slice) { return @('FAIL', 'AO_SLICE_MISSING', 'run with -AoSlice S0 (or the current slice); the check has no default') }
    if ($AoSlices -notcontains $slice) { return @('FAIL', 'AO_SLICE_UNKNOWN', "-AoSlice '$slice' is not one of $($AoSlices -join ', ')") }
    $at = [array]::IndexOf($AoSlices, $slice)
    $reds = @(); $ok = 0
    foreach ($e in $list.Values) {
        $r = $run[$e.id]
        $wantPass = $at -ge [array]::IndexOf($AoSlices, $e.from)
        if (-not $r) { $reds += "$($e.id): absent from the run"; continue }
        if ($wantPass) {
            if ($r.status -eq 'PASS') { $ok++ } else { $reds += "$($e.id): $($r.status) $($r.reason), wanted PASS from $($e.from)" }
            continue
        }
        if ($r.status -eq $e.state -and $r.reason -eq $e.reason) { $ok++ } else { $reds += "$($e.id): $($r.status) $($r.reason), wanted $($e.state) $($e.reason) before $($e.from)" }
    }
    foreach ($id in @($run.Keys | Sort-Object)) { if (-not $list.Contains($id)) { $reds += "${id}: in the run, not in the row list" } }
    $m = $list.Count
    $detail = "$ok of $m rows match the row list for slice $slice" + $(if ($reds) { '. Red: ' + ($reds -join '; ') } else { '' })
    if ($reds) { return @('FAIL', 'AO_ROW_LIST_RED', $detail) }
    return @('PASS', '', $detail)
}

function Set-FromRows([string]$id, [object[]]$ids, [string]$what) {
    $v = Get-RowsVerdict $ids $what $results
    Set-Result $id $v[0] $v[1] $v[2]
}
$sel = Select-Clauses
if ($sel.Count -eq 0) { throw "no clause matches: $($Clauses -join ', ')" }
Say ("{0} clauses selected of M = {1} (+ {2} self-checks in the file)" -f @($sel | Where-Object { $_.counts }).Count, $M, @($all | Where-Object { -not $_.counts }).Count)

# ------------------------------------------------------------------ results
$results = @{}
function Set-Result([string]$id, [string]$status, [string]$reason = '', [string]$detail = '', [long]$ms = 0, [int]$budgetSec = 0) {
    $results[$id] = [pscustomobject]@{ id = $id; status = $status; reason = $reason; detail = $detail; ms = $ms; budgetSec = $budgetSec }
}
# A clause line's own time budget (#327). A line from a group that sends none reads 0, which the slow warning takes as 900 s.
function BudgetOf($line) { $p = $line.PSObject.Properties['budgetSec']; if ($p) { [int]$p.Value } else { 0 } }
function Set-All($clauseList, [string]$status, [string]$reason, [string]$detail) {
    foreach ($c in $clauseList) { if (-not $results.ContainsKey($c.id)) { Set-Result $c.id $status $reason $detail } }
}

# cut roles first: a clause that needs a cut role is NOT RUN, by role name
foreach ($c in $sel) {
    foreach ($r in @($c.roles)) {
        if ($r -and $roles.$r.state -eq 'cut') { Set-Result $c.id 'NOT RUN' "ROLE_CUT:$r" "role '$r' is cut ($($roles.$r.reason)); see acceptance/roles.json"; break }
    }
}
$pending = @($sel | Where-Object { -not $results.ContainsKey($_.id) })

# ------------------------------------------------------------------ vectors made at run time
# The X9.24-3 test vectors stay out of git (prd.md licence checklist item 1). fetch-x9.ps1 downloads the PDF into the ignored _cache folder and
# records its SHA-256; extract_x9.py writes the vector file next to it. If either step fails, the clauses that need the file say VECTORS_MISSING.
$needX9 = @($sel | Where-Object { $_.id -like 'A3.vec.*' -or $_.id -like 'A3.pinblock.*' -or $_.id -like 'A3.sales1000.*' -or $_.id -like 'A3.erasure.*' -or $_.id -eq 'A17.payment.known-answer-vectors-through-flow-code' -or $_.id -eq 'SELF.dukpt-vectors-pass' -or $_.id -eq 'SELF.a17-clauses-pass-and-bite-rest' -or $_.id -eq 'SELF.vector-provenance' }).Count -gt 0
$x9Out = Join-Path $acc 'vectors\_cache\x9-24-3-aes-dukpt.nsv'
if ($needX9 -and -not (Test-Path $x9Out)) {
    Say "fetching the X9.24-3 test vectors (ignored by git) and extracting them"
    $f = Invoke-Tool 'pwsh' @('-NoProfile', '-File', (Join-Path $acc 'vectors\fetch-x9.ps1')) -TimeoutSec 300
    $pdf = Join-Path $acc 'vectors\_cache\X9.24-3-2017-Test-Vectors-20180129-1.pdf'
    if ($f.ExitCode -eq 0 -and (Test-Path $pdf)) {
        $x = Invoke-Tool 'python' @('-I', (Join-Path $acc 'vectors\tools\extract_x9.py'), $pdf, $x9Out) -TimeoutSec 300
        if ($x.ExitCode -ne 0) { Say ("X9 extraction failed: " + (Tail $x.Output 300)) }
    } else { Say ("X9 fetch failed: " + (Tail $f.Output 300)) }
}

# ------------------------------------------------------------------ prepare: product pieces, sibling, referees
$productExists = Test-Path (Join-Path $ProductRoot 'src\NetSec.Core\NetSec.Core.csproj')
$prep = [ordered]@{ core10 = $null; coreCf = $null; ce = $null; node = $null; host = $null; ap = $null; errors = [ordered]@{} }
$groupsNeeded = @($pending | ForEach-Object { $_.group } | Sort-Object -Unique)
$needsProductGroups = @('prim', 'walk', 'dukpt', 'kschedule', 'tls13live', 'tls11', 'ssh', 'auth', 'nativeprod', 'bridge', 'host', 'a17', 'a17probe', 'golden', 'keys', 'binproof', 'e2e', 'algo')
$wantProduct = @($groupsNeeded | Where-Object { $needsProductGroups -contains $_ }).Count -gt 0

function Build-Piece([string]$key, [string]$projRel, [string[]]$extra, [string[]]$outRels) {
    $proj = Join-Path $ProductRoot $projRel
    if (-not (Test-Path $proj)) { $prep.errors[$key] = "PRODUCT_MISSING:$projRel does not exist yet"; return }
    $r = Invoke-Tool 'dotnet' (@('build', $proj, '-c', 'Release', '--nologo', '-v', 'q') + $extra) -TimeoutSec 1800
    # The first output that exists wins. Design section 11 names the .exe outputs of Node and Host. The .dll is the fallback.
    $out = $null
    foreach ($rel in $outRels) { $cand = Join-Path $ProductRoot $rel; if (Test-Path $cand) { $out = $cand; break } }
    if ($r.ExitCode -eq 0 -and $out) { $prep[$key] = $out }
    else { $prep.errors[$key] = "PRODUCT_BUILD_FAILED:dotnet build $projRel exited $($r.ExitCode): " + (Tail $r.Output) }
}

if ($wantProduct -and -not $FreshChild -or ($wantProduct -and $FreshChild)) {
    Say "preparing: MMP.AsyncProxy builds, product builds"
    $prep.ap = Get-AsyncProxyDlls
    if ($productExists) {
        $cfProps = @("-p:NetCFRefDir=$NetCFRefDir")
        Build-Piece 'core10' 'src\NetSec.Core\NetSec.Core.csproj' @() 'src\NetSec.Core\bin\Release\net10.0\NetSec.Core.dll'
        Build-Piece 'coreCf' 'src\NetSec.Core.NetCF\NetSec.Core.NetCF.csproj' $cfProps 'src\NetSec.Core.NetCF\bin\Release\net35\NetSec.Core.dll'
        Build-Piece 'ce' 'src\NetSec.CeDevice\NetSec.CeDevice.csproj' $cfProps 'src\NetSec.CeDevice\bin\Release\net35\NetSec.CeDevice.exe'
        Build-Piece 'node' 'src\NetSec.Node\NetSec.Node.csproj' @() @('src\NetSec.Node\bin\Release\net10.0\NetSec.Node.exe', 'src\NetSec.Node\bin\Release\net10.0\NetSec.Node.dll')
        Build-Piece 'host' 'src\NetSec.Host\NetSec.Host.csproj' @() @('src\NetSec.Host\bin\Release\net10.0\NetSec.Host.exe', 'src\NetSec.Host\bin\Release\net10.0\NetSec.Host.dll')
    } else {
        foreach ($k in 'core10', 'coreCf', 'ce', 'node', 'host') { $prep.errors[$k] = 'PRODUCT_MISSING:src/NetSec.Core does not exist yet' }
    }
}

# referees: Jared's programs under acceptance\referees are built into the work folder
$refGo = $null; $refBcl = $null; $refErr = @{}
$goDir = Join-Path $acc 'referees\go'; $bclDir = Join-Path $acc 'referees\bcl'
if (Test-Path (Join-Path $goDir 'go.mod')) {
    $bin = Join-Path $work 'referees\go\bin'
    New-Item -ItemType Directory -Force -Path $bin | Out-Null
    $r = Invoke-Tool 'go' @('build', '-o', "$bin\", './...') $goDir -TimeoutSec 900
    if ($r.ExitCode -eq 0) { $refGo = $bin } else { $refErr.go = "REFEREE_BUILD_FAILED:go build exited $($r.ExitCode): " + (Tail $r.Output) }
}
if (Test-Path $bclDir) {
    $bin = Join-Path $work 'referees\bcl'
    $proj = Get-ChildItem $bclDir -Filter *.csproj -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($proj) {
        $r = Invoke-Tool 'dotnet' @('build', $proj.FullName, '-c', 'Release', '-o', $bin, '--nologo', '-v', 'q') -TimeoutSec 900
        $rc = Get-ChildItem $bin -Filter *.runtimeconfig.json -ErrorAction SilentlyContinue | Select-Object -First 1
        $dll = if ($rc) { Join-Path $bin ($rc.Name -replace ".runtimeconfig.json$", ".dll") } else { Join-Path $bin ($proj.BaseName + ".dll") }
        if ($r.ExitCode -eq 0 -and (Test-Path $dll)) { $refBcl = $dll } else { $refErr.bcl = "REFEREE_BUILD_FAILED:dotnet build exited $($r.ExitCode): " + (Tail $r.Output) }
    }
}

function Get-Props([string]$build) {
    $p = [System.Collections.Generic.List[string]]::new()
    function Add-Prop($k, $v) { if ($v) { $p.Add('--prop'); $p.Add("$k=$v") } }
    Add-Prop 'referee.go' $refGo
    Add-Prop 'referee.bcl' $refBcl
    Add-Prop 'node' $prep.node
    Add-Prop 'ce' $prep.ce
    Add-Prop 'host' $prep.host
    Add-Prop 'core.net10' $prep.core10
    Add-Prop 'asyncproxy.ns2' $(if ($prep.ap) { $prep.ap.ns2 })
    Add-Prop 'asyncproxy.cf' $(if ($prep.ap) { $prep.ap.cf })
    Add-Prop 'netcf' $NetCFRefDir
    if ($RecordGolden) { Add-Prop 'golden.record' '1' }
    return , $p.ToArray()
}

# ------------------------------------------------------------------ C# groups
function Read-ClauseLines([string]$text) {
    $found = @()
    foreach ($line in ($text -split "`n")) {
        if ($line.StartsWith('@@CLAUSE ')) { try { $found += ($line.Substring(9) | ConvertFrom-Json) } catch { } }
    }
    return $found
}

$missingSymbolCodes = 'CS0246', 'CS0234', 'CS0103', 'CS1061', 'CS0117', 'CS0122', 'CS1503', 'CS1729', 'CS7036', 'CS0070', 'CS0200', 'CS0535', 'CS0305', 'CS0308', 'CS0266', 'CS0029', 'CS1579'

# CONTRACT.md rule 4: only a missing type or member OF NetSec.Core is NOT RUN PRODUCT_MISSING. The compiler gives the same error codes
# when the missing name is the suite's own (for example a file that a group project does not link). That is a break in acceptance/, so
# it is a FAIL in every slice, never a NOT RUN that a row list can expect.
$missingNameCodes = 'CS0246', 'CS0234', 'CS0103', 'CS1061', 'CS0117'
$script:suiteTypeNames = $null

# The type names that the clause groups and the shared library declare themselves (acceptance/groups and acceptance/lib). A name that
# contract/ or a Frozen/ folder also declares is left out: those folders hold copies of product names, and a product name must stay
# NOT RUN PRODUCT_MISSING. selftest/ is not read: it holds stand-ins with product names on purpose.
function Get-SuiteTypeNames {
    if ($null -eq $script:suiteTypeNames) {
        $set = [System.Collections.Generic.HashSet[string]]::new()
        $product = [System.Collections.Generic.HashSet[string]]::new()
        $decl = [regex]'\b(?:class|interface|struct|enum)\s+(?<name>[A-Za-z_]\w*)'
        foreach ($rootName in 'groups', 'lib', 'contract') {
            $rootDir = Join-Path $acc $rootName
            if (-not (Test-Path -LiteralPath $rootDir)) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $rootDir -Recurse -Filter *.cs -File)) {
                if ($f.FullName -match '[\\/](?:bin|obj)[\\/]') { continue }
                # No "$x = if (...) { $set }": PowerShell unrolls an empty set to $null there.
                $isProduct = $rootName -eq 'contract' -or $f.FullName -match '[\\/]Frozen[\\/]'
                foreach ($m in $decl.Matches([System.IO.File]::ReadAllText($f.FullName))) {
                    if ($isProduct) { [void]$product.Add($m.Groups['name'].Value) } else { [void]$set.Add($m.Groups['name'].Value) }
                }
            }
        }
        $set.ExceptWith($product)
        $script:suiteTypeNames = $set
    }
    return , $script:suiteTypeNames
}

# The verdict for a clause group whose build failed, from the compiler output: status, reason, detail.
function Get-GroupBuildVerdict([string]$output) {
    $lines = @([regex]::Matches($output, '(?m)^.*error (?<code>CS\d{4}):.*$') | ForEach-Object { ($_.Value -replace '\[.*\]\s*$', '').Trim() } | Sort-Object -Unique)
    $codes = @($lines | ForEach-Object { [regex]::Match($_, 'error (?<code>CS\d{4}):').Groups['code'].Value } | Sort-Object -Unique)
    $firstErrors = @($lines | Select-Object -First 3) -join ' | '
    $surface = $codes.Count -gt 0 -and (@($codes | Where-Object { $missingSymbolCodes -notcontains $_ }).Count -eq 0)
    if (-not $surface) { return @('FAIL', 'ACCEPTANCE_COMPILE_ERROR', ("the group failed to build for a reason outside the product surface: " + $firstErrors + " " + (Tail $output 300))) }
    $names = Get-SuiteTypeNames
    $own = @()
    foreach ($line in $lines) {
        $code = [regex]::Match($line, 'error (?<code>CS\d{4}):').Groups['code'].Value
        if ($missingNameCodes -notcontains $code) { continue }
        # The first quoted text is the missing name (CS0246, CS0234, CS0103) or the type that lacks the member (CS1061, CS0117).
        $quoted = [regex]::Match($line.Substring($line.IndexOf("error $code")), "'(?<quoted>[^']+)'").Groups['quoted'].Value
        $simple = (($quoted -replace '<.*$', '') -split '\.')[-1]
        if ($simple -and $names.Contains($simple) -and $own -notcontains $simple) { $own += $simple }
    }
    if ($own.Count -gt 0) { return @('FAIL', 'ACCEPTANCE_COMPILE_ERROR', ("the group does not compile, and the name it lacks is the suite's own (" + ($own -join ', ') + "): a file is not linked into the group project, or the suite code is wrong. " + $firstErrors)) }
    return @('NOT RUN', 'PRODUCT_MISSING', ("the group does not compile against the built NetSec.Core: a type or member the contract names is missing or differs. " + $firstErrors))
}

function Run-CSharpGroup($name, $g, $build, $ids) {
    $list = @($pending | Where-Object { $ids -contains $_.id })
    $tfm = if ($build -eq 'cf') { 'net48' } else { 'net10.0' }
    $buildArgs = @('build', (Join-Path $acc $g.project), '-c', 'Release', '-f', $tfm, '--nologo', '-v', 'q')
    if ($g.needsCore) {
        $coreDll = if ($build -eq 'cf') { $prep.coreCf } else { $prep.core10 }
        $key = if ($build -eq 'cf') { 'coreCf' } else { 'core10' }
        if (-not $coreDll) {
            $why = if ($prep.errors.Contains($key)) { $prep.errors[$key] } else { 'PRODUCT_MISSING:NetSec.Core was not built' }
            $reason, $detail = $why -split ':', 2
            Set-All $list $(if ($reason -eq 'PRODUCT_BUILD_FAILED') { 'FAIL' } else { 'NOT RUN' }) $reason $detail
            return
        }
        $apDll = if ($prep.ap) { if ($build -eq 'cf') { $prep.ap.cf } else { $prep.ap.ns2 } }
        if (-not $apDll) { Set-All $list 'NOT RUN' 'SIBLING_MISSING' ($prep.ap.error ?? 'MMP.AsyncProxy was not built'); return }
        $buildArgs += @("-p:NetSecCoreDll=$coreDll", "-p:AsyncProxyDll=$apDll")
    }
    $b = Invoke-Tool 'dotnet' $buildArgs -TimeoutSec 1200
    if ($b.ExitCode -ne 0) {
        $verdict = Get-GroupBuildVerdict $b.Output
        Set-All $list $verdict[0] $verdict[1] $verdict[2]
        return
    }
    $outDir = Join-Path $acc ("groups\" + (Split-Path (Split-Path $g.project -Parent) -Leaf) + "\bin\Release\$tfm")
    if ($g.kind -eq 'selftest') { $outDir = Join-Path $acc "selftest\bin\Release\$tfm" }
    $runArgs = @('--build', $build, '--ids', ($ids -join ','), '--acceptance', $acc, '--vectors', (Join-Path $acc 'vectors'), '--root', $ProductRoot, '--work', $work) + (Get-Props $build)
    if ($build -eq 'cf') { $exe = Join-Path $outDir ($g.assembly + '.exe'); $argv = $runArgs }
    else { $exe = 'dotnet'; $argv = @((Join-Path $outDir ($g.assembly + '.dll'))) + $runArgs }
    # The group process may run as long as its selected clauses' budgets together, plus 300 s to start: each clause then hits its own
    # budget and fails by name before this cap can stop the group (Jared on #342). A clause row with no budgetSec has the runner's 900 s.
    $groupCap = 300 + (@($list | ForEach-Object { $p = $_.PSObject.Properties['budgetSec']; if ($p) { [int]$p.Value } else { 900 } }) | Measure-Object -Sum).Sum
    $r = Invoke-Tool $exe $argv -TimeoutSec $groupCap
    foreach ($line in (Read-ClauseLines $r.Output)) { Set-Result $line.id $line.status $line.reason $line.detail ([long]$line.ms) (BudgetOf $line) }
    foreach ($c in $list) {
        if (-not $results.ContainsKey($c.id)) {
            $why = if ($r.ExitCode -eq -999) { 'TIMEOUT' } else { 'NO_RESULT' }
            Set-Result $c.id 'FAIL' $why ("group $name ($build) gave no result line for this clause (exit $($r.ExitCode); the group cap is $groupCap s, the sum of its clauses' budgets plus 300 s). " + (Tail $r.Output 300))
        }
    }
}

foreach ($name in ($doc.groups.PSObject.Properties.Name)) {
    $g = $doc.groups.$name
    if ($g.kind -notin 'csharp', 'selftest') { continue }
    $mine = @($pending | Where-Object { $_.group -eq $name -and -not $results.ContainsKey($_.id) })
    if ($mine.Count -eq 0) { continue }
    foreach ($build in $g.builds) {
        $ids = @($mine | Where-Object { $_.build -eq $build -or ($_.build -eq 'host' -and $build -eq $g.builds[0]) } | ForEach-Object { $_.id })
        if ($ids.Count -eq 0) { continue }
        Say ("group {0} ({1}): {2} clauses" -f $name, $build, $ids.Count)
        # product pieces that a group needs besides NetSec.Core
        if ($name -eq 'bridge' -and (-not $prep.node -or -not $prep.ce)) {
            $why = if (-not $prep.node) { $prep.errors['node'] } else { $prep.errors['ce'] }
            $reason, $detail = ($why ?? 'PRODUCT_MISSING:NetSec.Node or NetSec.CeDevice not built') -split ':', 2
            # the group still runs when only the referees are missing; with no Node or CE it cannot start the lab
            Set-All @($pending | Where-Object { $ids -contains $_.id }) $(if ($reason -eq 'PRODUCT_BUILD_FAILED') { 'FAIL' } else { 'NOT RUN' }) $reason $detail
            continue
        }
        if ($name -in 'host', 'a17' -and -not $prep.host) {
            $reason, $detail = (($prep.errors['host']) ?? 'PRODUCT_MISSING:NetSec.Host not built') -split ':', 2
            Set-All @($pending | Where-Object { $ids -contains $_.id }) $(if ($reason -eq 'PRODUCT_BUILD_FAILED') { 'FAIL' } else { 'NOT RUN' }) $reason $detail
            continue
        }
        if ($name -eq 'keys' -and -not $prep.core10) {
            $reason, $detail = (($prep.errors['core10']) ?? 'PRODUCT_MISSING:NetSec.Core not built') -split ':', 2
            Set-All @($pending | Where-Object { $ids -contains $_.id }) $(if ($reason -eq 'PRODUCT_BUILD_FAILED') { 'FAIL' } else { 'NOT RUN' }) $reason $detail
            continue
        }
        Run-CSharpGroup $name $g $build $ids
    }
}

# ------------------------------------------------------------------ python text clauses
$docsMine = @($pending | Where-Object { $_.group -eq 'docs' -and -not $results.ContainsKey($_.id) })
if ($docsMine.Count -gt 0) {
    Say "group docs: $($docsMine.Count) clauses"
    $r = Invoke-Tool 'python' @('-I', (Join-Path $acc 'checks\docs_checks.py'), '--root', $ProductRoot, '--ids', (($docsMine | ForEach-Object { $_.id }) -join ',')) -TimeoutSec 600
    foreach ($line in (Read-ClauseLines $r.Output)) { Set-Result $line.id $line.status $line.reason $line.detail }
    Set-All $docsMine 'FAIL' 'NO_RESULT' ("docs_checks.py gave no result: " + (Tail $r.Output 300))
}

# ------------------------------------------------------------------ Playwright
$e2eMine = @($pending | Where-Object { $_.group -eq 'e2e' -and -not $results.ContainsKey($_.id) })
if ($e2eMine.Count -gt 0) {
    Say "group e2e: $($e2eMine.Count) clauses"
    $e2e = Join-Path $acc 'e2e'
    $out = Join-Path $work 'e2e'
    New-Item -ItemType Directory -Force -Path $out | Out-Null
    $reasonMissing = $null
    if (-not (Test-Path (Join-Path $ProductRoot 'app\package.json'))) { $reasonMissing = 'app/package.json does not exist yet (slice S0)' }
    elseif (-not $prep.host) { $reasonMissing = ($prep.errors['host'] ?? 'NetSec.Host is not built') }
    if ($reasonMissing) {
        Set-All $e2eMine 'NOT RUN' 'PRODUCT_MISSING' $reasonMissing
    } else {
      try {
        $app = Join-Path $ProductRoot 'app'
        $toolRuns = @()
        $appCi = Invoke-NpmCiIfStale $app -Force:$FreshChild
        if ($appCi) { $toolRuns += $appCi }
        $appBuild = Invoke-Tool 'npm' @('run', 'build') $app -TimeoutSec 1200
        $toolRuns += $appBuild
        $e2eCi = Invoke-NpmCiIfStale $e2e
        if ($e2eCi) { $toolRuns += $e2eCi }
        $missing = @($toolRuns | Where-Object { $_.ExitCode -eq -998 })
        # A failed build leaves the last good app/dist in place, so the specs would judge an old screen and could pass (#288's red run did,
        # 2026-11-08). A failed build or install fails every selected e2e clause by name, and no spec runs.
        $failedPrep = @($toolRuns | Where-Object { $_.ExitCode -ne 0 -and $_.ExitCode -ne -998 })
        if ($missing.Count -gt 0) { Set-All $e2eMine 'NOT RUN' 'TOOL_MISSING' (Tail $missing[0].Output 300) }
        elseif ($appBuild.ExitCode -ne 0) { Set-All $e2eMine 'FAIL' 'APP_BUILD_FAILED' ("npm run build in app exit $($appBuild.ExitCode): " + (Tail $appBuild.Output 600)) }
        elseif ($failedPrep.Count -gt 0) { Set-All $e2eMine 'FAIL' 'E2E_PREP_FAILED' ("an npm ci before the e2e run exit $($failedPrep[0].ExitCode): " + (Tail $failedPrep[0].Output 600)) } else {
        $env:ACC_ROOT = $ProductRoot; $env:ACC_HOST = $prep.host; $env:ACC_OUT = $out
        # Other sessions on this machine run Hosts and vite previews too. A fixed port that is already taken would connect the tests to
        # somebody else's server, so the run picks free ports.
        $listening = @([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | ForEach-Object { $_.Port })
        if (Test-Path (Join-Path $ProductRoot 'src/NetSec.Host/ExtraOrigins.cs')) {
            # The Host reads NETSEC_ORIGINS (design D14 amendment, #225), so the preview may use any port the Host is told to trust.
            # Acceptance takes its own block, 36800 to 36899 (ACC_PORT_BASE moves it), and leaves 4180 and 5173 to the builders' suites.
            $portBase = if ($env:ACC_PORT_BASE) { [int]$env:ACC_PORT_BASE } else { 36800 }
            $previewPort = $portBase..($portBase + 98) | Where-Object { $listening -notcontains $_ } | Select-Object -First 1
            $hostPort = if ($previewPort) { ($previewPort + 1)..($portBase + 99) | Where-Object { $listening -notcontains $_ } | Select-Object -First 1 }
            if (-not $hostPort) { $previewPort = $null }
            $env:ACC_ORIGINS = if ($previewPort) { "http://localhost:$previewPort" } else { '' }
        }
        else {
            # A product tree from before #225: the Host trusts only its built-in origins (design section 5: localhost:4180 and localhost:5173).
            $previewPort = @(4180, 5173) | Where-Object { $listening -notcontains $_ } | Select-Object -First 1
            $hostPort = 5180; while ($listening -contains $hostPort) { $hostPort++ }
            $env:ACC_ORIGINS = ''
        }
        $env:ACC_HOST_PORT = [string]$hostPort
        # Playwright strips the types and runs a spec that tsc would refuse, so a type error never failed a run. The specs are type-checked
        # first (acceptance/e2e/tsconfig.json), and a type error fails every selected e2e clause by name before any spec runs.
        # tsc and Playwright run from this folder's own node_modules under node, never through the package runner, so a missing tool reads TOOL_MISSING and
        # nothing is fetched from a registry or found elsewhere on the machine (Jared, #269).
        $tscJs = Join-Path $e2e 'node_modules/typescript/bin/tsc'
        $playwrightJs = Join-Path $e2e 'node_modules/@playwright/test/cli.js'
        $noTool = { param($p) [pscustomobject]@{ ExitCode = -998; Output = "no local tool at $p. Run npm ci in acceptance/e2e" } }
        $tc = if (Test-Path $tscJs) { Invoke-Tool 'node' @($tscJs, '-p', 'tsconfig.json', '--pretty', 'false') $e2e -TimeoutSec 300 } else { & $noTool $tscJs }
        $typeBroken = $tc.ExitCode -ne 0
        # Run only the selected clauses. Before this, every spec ran, and a failure outside the selection never reached the report.
        $env:ACC_E2E_GREP = if ($Clauses -contains 'All') { '' } else { (@($e2eMine | ForEach-Object { '\[' + [regex]::Escape($_.id) + '\]' }) -join '|') }
        if ($typeBroken -and $tc.ExitCode -eq -998) { Set-All $e2eMine 'NOT RUN' 'TOOL_MISSING' (Tail $tc.Output 300) }
        elseif ($typeBroken) { Set-All $e2eMine 'FAIL' 'E2E_TYPE_ERROR' ("tsc -p acceptance/e2e/tsconfig.json exit $($tc.ExitCode): " + (Tail $tc.Output 600)) }
        elseif ($previewPort) { $env:ACC_PREVIEW_PORT = [string]$previewPort }
        else { Set-All $e2eMine 'NOT RUN' 'PORT_BUSY' 'no free preview port: the acceptance block (36800 to 36899, or ACC_PORT_BASE) is full, or, on a tree from before #225, ports 4180 and 5173 are both in use. The UI cannot be served here without testing against a stranger.' }
        $r = if (-not $previewPort -or $typeBroken) { [pscustomobject]@{ ExitCode = -997; Output = '' } }
             elseif (Test-Path $playwrightJs) { Invoke-Tool 'node' @($playwrightJs, 'test') $e2e -TimeoutSec 1800 }
             else { & $noTool $playwrightJs }
        $json = Join-Path $out 'playwright.json'
        if ($r.ExitCode -eq -997) { }      # E2E_TYPE_ERROR, TOOL_MISSING or PORT_BUSY was recorded above
        elseif ($r.ExitCode -eq -998) { Set-All $e2eMine 'NOT RUN' 'TOOL_MISSING' (Tail $r.Output 300) }
        elseif (-not (Test-Path $json)) { Set-All $e2eMine 'FAIL' 'NO_RESULT' ("Playwright wrote no JSON report. " + (Tail $r.Output 400)) }
        else {
            $rep = Get-Content $json -Raw | ConvertFrom-Json
            $tests = [System.Collections.Generic.List[object]]::new()
            function Walk-Suite($s) { if ($s.PSObject.Properties["specs"]) { foreach ($sp in @($s.specs)) { $tests.Add($sp) } }; if ($s.PSObject.Properties["suites"]) { foreach ($c in @($s.suites)) { Walk-Suite $c } } }
            foreach ($s in @($rep.suites)) { Walk-Suite $s }
            foreach ($sp in $tests) {
                $titleMatch = [regex]::Match($sp.title, '^\[(?<id>[^\]]+)\]')      # not $m: PowerShell names are case-insensitive and $M is the clause count
                if (-not $titleMatch.Success) { continue }
                $id = $titleMatch.Groups['id'].Value
                $t = @($sp.tests)[0]; $res = @($t.results)[0]
                $err = if ($res.PSObject.Properties.Name -contains 'error' -and $res.error) { [string]$res.error.message } else { '' }
                if ($t.status -eq 'skipped') {
                    $annProp = $t.PSObject.Properties["annotations"]; $annList = if ($annProp) { @($annProp.Value) } else { @() }
                    $ann = @($annList | Where-Object { $_.type -eq "notrun" } | ForEach-Object { $_.description })[0]
                    $rs, $dt = (($ann ?? 'SKIPPED: skipped by the spec') -split ':', 2)
                    Set-Result $id 'NOT RUN' $rs.Trim() ($dt ?? '').Trim()
                } elseif ($res.status -eq 'passed') { Set-Result $id 'PASS' '' 'Playwright test passed' }
                elseif ($err -match 'NOTRUN (?<r>[A-Z_]+): (?<d>.*)') { Set-Result $id 'NOT RUN' $Matches.r (($Matches.d -split "`n")[0]) }
                else { Set-Result $id 'FAIL' 'ASSERTION' (Tail ($err -replace '\x1b\[[0-9;]*m', '') 600) }
            }
            Set-All $e2eMine 'FAIL' 'NO_RESULT' 'Playwright did not report this test'
        }
        }
      } catch { Set-All $e2eMine 'FAIL' 'RUNNER_ERROR' ("the e2e step stopped: " + $_.Exception.Message) }
    }
}

# ------------------------------------------------------------------ driver clauses
foreach ($c in @($pending | Where-Object { $_.group -eq 'driver' -and -not $results.ContainsKey($_.id) })) {
    switch ($c.id) {
        'A13.fresh-clone.acceptance-unchanged' {
            if (-not $FreshChild) { Set-Result $c.id 'NOT RUN' 'NOT_A_FRESH_RUN' 'run with -Fresh; the diff of acceptance/ against the pin only means something in a fresh clone'; break }
            # acceptance/tools/pin.py is the one rule for PIN: the gate runs the same --check on every PR, so a stale PIN stops there first.
            $pinOut = (python -I (Join-Path $acc 'tools/pin.py') --root $ProductRoot --check 2>&1 | ForEach-Object { "$_" }) -join ' '
            $pinCode = $LASTEXITCODE
            $pinReason = if ($pinOut -match '^(?<code>[A-Z_]+):') { $Matches['code'] } else { 'PIN_CHECK_FAILED' }
            # Only the committed setting (acceptance/settings.json "pin": false) turns the check off. A missing PIN with the setting on is PIN_MISSING, a FAIL.
            if ($pinReason -eq 'PIN_OFF') { Set-Result $c.id 'NOT RUN' 'PIN_OFF' $pinOut; break }
            if ($pinCode -ne 0) { Set-Result $c.id 'FAIL' $pinReason $pinOut; break }
            if (-not $productExists) { Set-Result $c.id "NOT RUN" "PRODUCT_MISSING" "$pinOut. The clause waits for a product to clone: src/NetSec.Core is absent." }
            else { Set-Result $c.id "PASS" "" "in this clone, $pinOut (PIN file excluded)" }
        }
        'A13.fresh-clone.sibling-layout' {
            $problems = @()
            if (-not (Test-Path (Join-Path $AsyncProxyRoot 'src\MMP.AsyncProxy'))) { $problems += "sibling MMP.AsyncProxy not found at $AsyncProxyRoot" }
            if (-not (Test-Path (Join-Path $NetCFRefDir 'mscorlib.dll'))) { $problems += "CF references not found at $NetCFRefDir" }
            $dirty = git -C $ProductRoot status --porcelain 2>$null
            if ($FreshChild -and $dirty) { $problems += "the clone is not clean: " + (($dirty | Select-Object -First 3) -join '; ') }
            $parent = Split-Path -Parent $ProductRoot
            if ($FreshChild -and ((Split-Path -Parent $AsyncProxyRoot) -ne $parent)) { $problems += "the clone ($ProductRoot) does not sit beside the sibling ($AsyncProxyRoot)" }
            if (-not $productExists) { Set-Result $c.id 'NOT RUN' 'PRODUCT_MISSING' 'the product has no src/NetSec.Core yet, so there is no layout to check'; break }
            if ($problems) { Set-Result $c.id 'FAIL' 'LAYOUT' ($problems -join '; ') } else { Set-Result $c.id 'PASS' '' "sibling at $AsyncProxyRoot, CF references at $NetCFRefDir" }
        }
        'SELF.clauses-json-matches-code' {
            $r = Invoke-Tool 'python' @('-I', (Join-Path $acc 'tools\gen_clauses.py'), '--check') -TimeoutSec 120
            Set-Result $c.id $(if ($r.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }) $(if ($r.ExitCode -eq 0) { '' } else { 'DRIFT' }) (Tail $r.Output 400)
        }
        'SELF.tool-cannot-start-still-reports' {
            $r = Invoke-Tool 'acceptance-no-such-tool' @('x') -TimeoutSec 30
            $np = Get-Command npm.cmd -ErrorAction SilentlyContinue
            if ($r.ExitCode -eq -998 -and $r.Output -match '^TOOL_MISSING' -and $np) { Set-Result $c.id 'PASS' '' "a tool that cannot start gives TOOL_MISSING and the run goes on; npm.cmd resolves to $($np.Source)" }
            else { Set-Result $c.id 'FAIL' 'ASSERTION' ("exit $($r.ExitCode), output '$((Tail $r.Output 120))', npm.cmd found: $([bool]$np)") }
        }
        'SELF.summary-m-stays-a-count' {
            # PowerShell variable names are case-insensitive, so a loop variable $m silently replaces $M. The summary line then prints a clause id for M.
            $self = Get-Content (Join-Path $acc 'run.ps1') -Raw
            $assign = [regex]::Matches($self, '(?im)^\s*(?:foreach\s*\(\s*)?\$m\s*(?:=|\bin\b)')
            if ($assign.Count -eq 1 -and $M -is [int] -and $M -gt 0) { Set-Result $c.id 'PASS' '' "M is assigned once and is the integer $M" }
            else { Set-Result $c.id 'FAIL' 'ASSERTION' "run.ps1 assigns `$m $($assign.Count) times (must be 1), M is of type $($M.GetType().Name)" }
        }
        'SELF.vectors-python' {
            $r = Invoke-Tool 'python' @('-I', (Join-Path $acc 'vectors\tools\selfcheck_vectors.py'), (Join-Path $acc 'vectors')) -TimeoutSec 300
            Set-Result $c.id $(if ($r.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }) $(if ($r.ExitCode -eq 0) { '' } else { 'ASSERTION' }) (Tail $r.Output 400)
        }
        { $_ -in @('AO-1.vectors-pass.net10', 'AO-1.vectors-pass.cf') } {
            $b = $c.id.Substring($c.id.LastIndexOf('.') + 1)
            $vec = @($all | Where-Object { ($_.assertion -eq 'A1' -or $_.id -like 'A3.vec.*' -or $_.id -like 'A3.pinblock.*') -and $_.build -eq $b } | ForEach-Object { $_.id })
            Set-FromRows $c.id $vec "known-answer ($b)"
        }
        'AO-8.cf-compiles-and-golden-pass' {
            $cf = @($all | Where-Object { $_.assertion -eq 'A9' -or $_.id -eq 'A17.mock.golden-trace-equal.cf' } | ForEach-Object { $_.id })
            Set-FromRows $c.id $cf 'CF build and CF golden'
        }
        'AO-0.row-list-matches' { }   # judged after this loop, when every other row has its result
        'SELF.ao-row-list-bites' {
            # The row-list check against a 3-line list: a matching run PASSes; a wrong reason, a deleted row, an extra row and a FAIL after
            # its slice each go red; a bench row that claims PASS with bytes allocated is judged FAIL from its number.
            New-Item -ItemType Directory -Force -Path $work | Out-Null
            $tsv = Join-Path $work ("ao-rows-self-{0}.tsv" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
            Set-Content -LiteralPath $tsv -Encoding utf8 -Value @("id`tstate_before`treason_before`tpass_from`tsource", "X.a`t-`t-`tS0`tsuite", "X.b`tFAIL`tCODE_B`tS1`tsuite", "X.c`tNOT RUN`tPRODUCT_MISSING`tS2`tsuite")
            $l = Read-AoRowList $tsv
            # Not "R": that name is the built-in alias of Invoke-History, and an alias wins over a function.
            function New-AoRow($s, $why) { [pscustomobject]@{ status = $s; reason = $why } }
            $good = @{ 'X.a' = (New-AoRow 'PASS' ''); 'X.b' = (New-AoRow 'FAIL' 'CODE_B'); 'X.c' = (New-AoRow 'NOT RUN' 'PRODUCT_MISSING') }
            $cases = [ordered]@{
                'matching run at S0'        = @($good, 'S0', 'PASS')
                'wrong reason code'         = @(@{ 'X.a' = (New-AoRow 'PASS' ''); 'X.b' = (New-AoRow 'FAIL' 'OTHER'); 'X.c' = (New-AoRow 'NOT RUN' 'PRODUCT_MISSING') }, 'S0', 'FAIL')
                'deleted row'               = @(@{ 'X.a' = (New-AoRow 'PASS' ''); 'X.c' = (New-AoRow 'NOT RUN' 'PRODUCT_MISSING') }, 'S0', 'FAIL')
                'extra row'                 = @(($good + @{ 'X.d' = (New-AoRow 'PASS' '') }), 'S0', 'FAIL')
                'FAIL after its slice'      = @($good, 'S1', 'FAIL')
                'no slice given'            = @($good, '', 'FAIL')
                'all PASS at S2'            = @(@{ 'X.a' = (New-AoRow 'PASS' ''); 'X.b' = (New-AoRow 'PASS' ''); 'X.c' = (New-AoRow 'PASS' '') }, 'S2', 'PASS')
            }
            $bad = @(); $seen = @()
            foreach ($k in $cases.Keys) {
                $v = Get-AoRowListVerdict $l $cases[$k][0] $cases[$k][1]
                $seen += "${k}: $($v[0])"
                if ($v[0] -ne $cases[$k][2]) { $bad += "${k}: got $($v[0]) ($($v[2])), wanted $($cases[$k][2])" }
            }
            $bl = Read-AoRowList $tsv
            $bl['AO-5.x.net10'] = [pscustomobject]@{ id = 'AO-5.x.net10'; state = 'FAIL'; reason = 'AO5_ALLOCATES'; from = 'S1'; source = 'bench' }
            $bj = Join-Path $work ("ao-bench-self-{0}.json" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
            Set-Content -LiteralPath $bj -Encoding utf8 -Value '{"schema":1,"commit":"HEADX","rows":[{"id":"AO-5.x.net10","status":"PASS","bytesPerOp":16,"op":"block"}]}'
            $bv = Read-AoBench $bj $bl 'S0' { param($commit) $null }
            if ($bv['AO-5.x.net10'].status -ne 'FAIL' -or $bv['AO-5.x.net10'].reason -ne 'AO5_ALLOCATES') { $bad += "a bench row with 16 B that says PASS read $($bv['AO-5.x.net10'].status) $($bv['AO-5.x.net10'].reason)" }
            $bl['AO-9.pool-25.net10.time'] = [pscustomobject]@{ id = 'AO-9.pool-25.net10.time'; state = '-'; reason = '-'; from = 'S0'; source = 'bench' }
            $bl['AO-9.gcm.net10.time'] = [pscustomobject]@{ id = 'AO-9.gcm.net10.time'; state = '-'; reason = '-'; from = 'S0'; source = 'bench' }
            Set-Content -LiteralPath $bj -Encoding utf8 -Value '{"schema":1,"commit":"HEADX","rows":[{"id":"AO-5.x.net10","bytesPerOp":0,"op":"block"},{"id":"AO-9.gcm.net10.time","outputsEqual":false,"originalNsPerOp":10,"newNsPerOp":5,"files":7,"op":"seal+open"},{"id":"AO-9.pool-25.net10.time","outputsEqual":true,"originalNsPerOp":10,"newNsPerOp":5,"files":1,"op":"25 workers"},{"id":"AO-9.gcm.net10.time.extra","outputsEqual":true}]}'
            $b9 = Read-AoBench $bj $bl 'S0' { param($commit) $null }
            if ($b9['AO-9.pool-25.net10.time'].status -ne 'PASS') { $bad += "a good AO-9 pool-25 timing row with files 1 read $($b9['AO-9.pool-25.net10.time'].status) $($b9['AO-9.pool-25.net10.time'].reason)" }
            # Second record against the suite's own rows: the suite FAILs AO-5.x while the bench says 0 B; the suite PASSes AO-9.gcm while the bench says outputs differ.
            $suiteRun = @{ 'AO-5.x.net10' = (New-AoRow 'FAIL' 'AO5_ALLOCATES'); 'AO-9.gcm.net10' = (New-AoRow 'PASS' ''); 'AO-9.pool-25.net10' = (New-AoRow 'PASS' '') }
            $dis = @(Get-AoBenchDisagreements $bj $suiteRun)
            if ($dis.Count -ne 2 -or -not ($dis -match 'AO5_BENCH_DISAGREES') -or -not ($dis -match 'AO9_BENCH_DISAGREES')) { $bad += "the second-record check gave " + ($dis -join ' | ') + ", wanted one AO5_BENCH_DISAGREES and one AO9_BENCH_DISAGREES" }
            $agree = @(Get-AoBenchDisagreements $bj @{ 'AO-5.x.net10' = (New-AoRow 'PASS' ''); 'AO-9.gcm.net10' = (New-AoRow 'FAIL' 'AO9_OUTPUT_DIFFERS'); 'AO-9.pool-25.net10' = (New-AoRow 'PASS' '') })
            if ($agree.Count -ne 0) { $bad += "the second-record check flagged agreeing rows: " + ($agree -join ' | ') }
            # The budget file: a good line passes; an unknown id, a second line and a budget with no tradeoff PR each go red.
            $bt = Join-Path $work ("ao-budgets-self-{0}.tsv" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
            Set-Content -LiteralPath $bt -Encoding utf8 -Value @("id`tbudget_bytes`tunit`tfrom_slice`ttradeoff_pr", "X.a`t64`tmessage`tS1`t#420")
            $budOk = @(Get-AoBudgetReds $bt $l)
            if ($budOk.Count -ne 0) { $bad += "a good budget line went red: " + ($budOk -join ' | ') }
            Set-Content -LiteralPath $bt -Encoding utf8 -Value @("id`tbudget_bytes`tunit`tfrom_slice`ttradeoff_pr", "X.a`t64`tmessage`tS1`t#420", "X.a`t32`tmessage`tS1`t#421", "X.z`t0`tmessage`tS1`t", "X.b`t16`tblock`tS1`t ")
            $budBad = @(Get-AoBudgetReds $bt $l)
            if (-not ($budBad -match 'second line') -or -not ($budBad -match 'not a row') -or -not ($budBad -match 'no tradeoff PR')) { $bad += "the budget check missed a bad line: " + ($budBad -join ' | ') }
            $bo = Read-AoBench $bj $bl 'S0' { param($commit) [pscustomobject]@{ reason = 'AO_BENCH_OTHER_COMMIT'; detail = "the measured code differs from $commit" } }
            if ($bo['AO-5.x.net10'].reason -ne 'AO_BENCH_OTHER_COMMIT') { $bad += "a bench report for another commit read $($bo['AO-5.x.net10'].reason)" }
            if ($bad) { Set-Result $c.id 'FAIL' 'ASSERTION' ($bad -join '; ') }
            else { Set-Result $c.id 'PASS' '' (($seen -join '; ') + '; bench 16 B claiming PASS -> FAIL AO5_ALLOCATES; AO-9 timing row -> PASS; bench 0 B against a suite FAIL -> AO5_BENCH_DISAGREES; bench outputsEqual false against a suite PASS -> AO9_BENCH_DISAGREES; agreeing records -> no red; bench for another commit -> AO_BENCH_OTHER_COMMIT; budget file: a good line passes, an unknown id, a second line and a budget with no tradeoff PR each go red') }
        }
        'SELF.ao-bench-same-code-rule-bites' {
            # A small git repository with the measured paths and 2 paths that are not measured. The bench report names commit A.
            $bad = @(); $seen = @()
            $repo = Join-Path $work ("bench-code-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Force -Path $repo | Out-Null
            $git = { git -C $repo @args 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') failed in the self-check repository" } }
            $put = { param([string]$rel, [string]$text)
                $full = Join-Path $repo $rel
                New-Item -ItemType Directory -Force -Path (Split-Path -Parent $full) | Out-Null
                Set-Content -LiteralPath $full -Encoding utf8 -Value $text }
            $commitAll = { param([string]$message) & $git add -A; & $git commit -q -m $message; return (Get-GitObjectId $repo 'HEAD') }
            $expect = { param([string]$case, [string]$commit, [string]$wantReason, [string]$wantText)
                $v = Get-AoBenchCodeVerdict $repo $commit
                $got = if ($v) { $v.reason } else { 'valid' }
                if ($got -ne $wantReason -or ($wantText -and $v.detail -notmatch [regex]::Escape($wantText))) { $script:benchSelfBad += "${case}: read $got$(if ($v) { ' (' + $v.detail + ')' }), wanted $wantReason $wantText" }
                $script:benchSelfSeen += "$case -> $wantReason" }
            $script:benchSelfBad = @(); $script:benchSelfSeen = @()
            try {
                & $git init -q
                & $git config user.email 'self-check@example.invalid'; & $git config user.name 'self-check'
                & $git config commit.gpgsign false; & $git config core.autocrlf false; & $git config core.hooksPath 'no-hooks'
                & $put 'src/NetSec.Core/A.cs' 'a'; & $put 'src/NetSec.Core.NetCF/N.csproj' 'n'; & $put 'bench/B.cs' 'b'
                & $put 'acceptance/groups/algo/Frozen/F.cs' 'f'; & $put 'Directory.Build.props' 'p'; & $put 'docs/d.md' 'd'; & $put 'acceptance/README.md' 'r'
                & $put 'bench/files/one.bin' 'bytes of one'; & $put 'bench/files/two.txt' 'bytes of two'; & $put 'bench/files/files.tsv' 'one.bin, two.txt'
                & $put 'acceptance/ao9-files.tsv' "# the file set`nname`tbytes`tsha256`none.bin`t12`tx`ntwo.txt`t12`ty"
                $a = & $commitAll 'A'
                & $expect 'the report commit is the head' $a 'valid' ''
                & $expect 'a short id of the report commit' $a.Substring(0, 7) 'valid' ''
                & $put 'docs/d.md' 'the report'; & $put 'acceptance/README.md' 'rows'; $docs = & $commitAll 'docs and acceptance text only'
                & $expect 'a report commit on top (docs and acceptance text only)' $a 'valid' ''
                $tree = Get-GitObjectId $repo 'HEAD^{tree}'
                $rebased = ([string](git -C $repo commit-tree $tree -m 'the same content on another parent')).Trim()
                & $git checkout -q --detach $rebased
                & $expect 'the same content after a rebase (another parent)' $a 'valid' ''
                foreach ($change in @(@('src/NetSec.Core/A.cs', 'src/NetSec.Core'), @('src/NetSec.Core.NetCF/N.csproj', 'src/NetSec.Core.NetCF'), @('bench/B.cs', 'bench'),
                                      @('acceptance/groups/algo/Frozen/F.cs', 'acceptance/groups/algo/Frozen'), @('Directory.Build.props', 'Directory.Build.props'))) {
                    & $put $change[0] 'changed'; $null = & $commitAll "change $($change[0])"
                    & $expect "a change under $($change[1])" $a 'AO_BENCH_OTHER_COMMIT' $change[1]
                    & $git checkout -q --detach $rebased
                }
                # bench/files is data, judged by content: a new name with the same bytes is valid; other bytes and a missing file are not.
                & $git mv 'bench/files/one.bin' 'bench/files/one.dat'; & $put 'bench/files/files.tsv' 'one.dat, two.txt'
                & $put 'acceptance/ao9-files.tsv' "# the file set`nname`tbytes`tsha256`none.dat`t12`tx`ntwo.txt`t12`ty"
                $null = & $commitAll 'a data file gets a new name'
                & $expect 'a data file with a new name and the same bytes' $a 'valid' ''
                & $put 'bench/files/two.txt' 'other bytes'; $null = & $commitAll 'a data file changes'
                & $expect 'a data file with other bytes' $a 'AO_BENCH_OTHER_COMMIT' 'bench/files/two.txt'
                & $git checkout -q --detach $rebased
                & $git rm -q 'bench/files/two.txt'; $null = & $commitAll 'a data file goes'
                & $expect 'a data file that the head lacks' $a 'AO_BENCH_OTHER_COMMIT' 'bench/files/two.txt'
                & $git checkout -q --detach $rebased
                & $put 'src/NetSec.Core/A.cs' 'not committed'
                & $expect 'an uncommitted change in the measured code' $a 'AO_BENCH_OTHER_COMMIT' 'uncommitted'
                & $git checkout -q -- .
                & $expect 'a commit the repository does not hold' ('0123456789abcdef0123456789abcdef01234567') 'AO_BENCH_COMMIT_UNKNOWN' ''
                & $expect 'a commit field that is no id' 'HEAD' 'AO_BENCH_COMMIT_UNKNOWN' ''
                # End to end through Read-AoBench: the report of commit A, read on the rebased head, is judged from its numbers.
                $bl2 = [ordered]@{ 'AO-6.x.net10' = [pscustomobject]@{ id = 'AO-6.x.net10'; state = '-'; reason = '-'; from = 'S0'; source = 'bench' } }
                $bj2 = Join-Path $work ("ao-bench-code-{0}.json" -f [guid]::NewGuid().ToString('N').Substring(0, 8))
                Set-Content -LiteralPath $bj2 -Encoding utf8 -Value ('{"schema":1,"commit":"' + $a + '","rows":[{"id":"AO-6.x.net10","baselineNsPerOp":10,"newNsPerOp":5,"op":"block"}]}')
                $rows = Read-AoBench $bj2 $bl2 'S0' { param($commit) Get-AoBenchCodeVerdict $repo $commit }
                if ($rows['AO-6.x.net10'].status -ne 'PASS') { $script:benchSelfBad += "a valid report read $($rows['AO-6.x.net10'].status) $($rows['AO-6.x.net10'].reason)" }
                & $put 'bench/B.cs' 'changed again'; $null = & $commitAll 'change bench'
                $rows = Read-AoBench $bj2 $bl2 'S0' { param($commit) Get-AoBenchCodeVerdict $repo $commit }
                if ($rows['AO-6.x.net10'].reason -ne 'AO_BENCH_OTHER_COMMIT') { $script:benchSelfBad += "a stale report read $($rows['AO-6.x.net10'].status) $($rows['AO-6.x.net10'].reason) through Read-AoBench" }
            } catch { $script:benchSelfBad += "the self-check stopped: $($_.Exception.Message)" }
            if ($script:benchSelfBad.Count -gt 0) { Set-Result $c.id 'FAIL' 'ASSERTION' ($script:benchSelfBad -join '; ') }
            else { Set-Result $c.id 'PASS' '' (($script:benchSelfSeen -join '; ') + '; through Read-AoBench: a valid report is judged from its numbers, a stale one reads AO_BENCH_OTHER_COMMIT') }
        }
        'SELF.suite-compile-break-is-a-fail' {
            # A real break: a project that names a suite type (AoStreamSeam) and does not compile its file. This is the break that made
            # the thread group read NOT RUN PRODUCT_MISSING on 2026-11-11. The verdict must be FAIL ACCEPTANCE_COMPILE_ERROR.
            $bad = @()
            $probe = Join-Path $work ("suite-break-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Force -Path $probe | Out-Null
            Set-Content -LiteralPath (Join-Path $probe 'Directory.Build.props') -Encoding utf8 -Value '<Project />'
            Set-Content -LiteralPath (Join-Path $probe 'Directory.Build.targets') -Encoding utf8 -Value '<Project />'
            Set-Content -LiteralPath (Join-Path $probe 'probe.csproj') -Encoding utf8 -Value '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework><Nullable>disable</Nullable></PropertyGroup></Project>'
            Set-Content -LiteralPath (Join-Path $probe 'Probe.cs') -Encoding utf8 -Value 'namespace Acceptance { public static class Probe { public static AoStreamSeam Seam; } }'
            $pb = Invoke-Tool 'dotnet' @('build', (Join-Path $probe 'probe.csproj'), '-c', 'Release', '--nologo', '-v', 'q') -TimeoutSec 600
            if ($pb.ExitCode -eq 0) { $bad += 'the broken project built' }
            else {
                $v = Get-GroupBuildVerdict $pb.Output
                if ($v[0] -ne 'FAIL' -or $v[1] -ne 'ACCEPTANCE_COMPILE_ERROR' -or $v[2] -notmatch 'AoStreamSeam') { $bad += "a real break of the suite read $($v[0]) $($v[1]): $($v[2])" }
            }
            # Recorded compiler lines, one verdict each.
            $cases = @(
                @('suite type not linked', "AoSide.Product.cs(217,23): error CS0246: The type or namespace name 'AoStreamSeam' could not be found (are you missing a using directive or an assembly reference?)", 'FAIL', 'ACCEPTANCE_COMPILE_ERROR'),
                @('member missing on a suite type', "X.cs(1,1): error CS1061: 'FrozenChain' does not contain a definition for 'Reset' and no accessible extension method 'Reset' accepting a first argument of type 'FrozenChain' could be found", 'FAIL', 'ACCEPTANCE_COMPILE_ERROR'),
                @('product type missing', "X.cs(1,1): error CS0246: The type or namespace name 'CbcChain' could not be found (are you missing a using directive or an assembly reference?)", 'NOT RUN', 'PRODUCT_MISSING'),
                @('product member missing', "X.cs(1,1): error CS1061: 'AesKey' does not contain a definition for 'EncryptBlocks' and no accessible extension method 'EncryptBlocks' accepting a first argument of type 'AesKey' could be found", 'NOT RUN', 'PRODUCT_MISSING'),
                @('product and suite names together', "X.cs(1,1): error CS0246: The type or namespace name 'CbcChain' could not be found`nY.cs(2,2): error CS0234: The type or namespace name 'AoStreamSeam' does not exist in the namespace 'Acceptance'", 'FAIL', 'ACCEPTANCE_COMPILE_ERROR'),
                @('syntax error', "X.cs(1,1): error CS1002: ; expected", 'FAIL', 'ACCEPTANCE_COMPILE_ERROR')
            )
            $seen = @()
            foreach ($case in $cases) {
                $v = Get-GroupBuildVerdict $case[1]
                if ($v[0] -ne $case[2] -or $v[1] -ne $case[3]) { $bad += "$($case[0]) read $($v[0]) $($v[1]), wanted $($case[2]) $($case[3])" }
                $seen += "$($case[0]) -> $($case[2]) $($case[3])"
            }
            if ($bad) { Set-Result $c.id 'FAIL' 'ASSERTION' ($bad -join '; ') }
            else { Set-Result $c.id 'PASS' '' ('a real project that names AoStreamSeam without its file -> FAIL ACCEPTANCE_COMPILE_ERROR; ' + ($seen -join '; ')) }
        }
        'SELF.ao-row-verdicts-bite' {
            # AO-1 and AO-8 read other rows. All PASS must PASS; one FAIL or one NOT RUN must FAIL; no row at all must be NOT RUN.
            $ok = @{ 'x.a' = [pscustomobject]@{ status = 'PASS'; reason = '' }; 'x.b' = [pscustomobject]@{ status = 'PASS'; reason = '' } }
            $oneFail = @{ 'x.a' = [pscustomobject]@{ status = 'PASS'; reason = '' }; 'x.b' = [pscustomobject]@{ status = 'FAIL'; reason = 'ASSERTION' } }
            $oneNotRun = @{ 'x.a' = [pscustomobject]@{ status = 'NOT RUN'; reason = 'PRODUCT_MISSING' }; 'x.b' = [pscustomobject]@{ status = 'PASS'; reason = '' } }
            $got = @((Get-RowsVerdict @('x.a', 'x.b') 'self' $ok)[0], (Get-RowsVerdict @('x.a', 'x.b') 'self' $oneFail)[0], (Get-RowsVerdict @('x.a', 'x.b') 'self' $oneNotRun)[0], (Get-RowsVerdict @('x.a', 'x.b') 'self' @{})[0])
            $want = @('PASS', 'FAIL', 'FAIL', 'NOT RUN')
            if ((Compare-Object $got $want -SyncWindow 0)) { Set-Result $c.id 'FAIL' 'ASSERTION' ("verdicts were " + ($got -join ', ') + "; wanted " + ($want -join ', ')) }
            else { Set-Result $c.id 'PASS' '' 'all PASS -> PASS; one FAIL -> FAIL; one NOT RUN -> FAIL; no rows -> NOT RUN' }
        }
        'AO-2.reference-frozen-from-git' {
            $r = Invoke-Tool 'python' @('-I', (Join-Path $acc 'tools\freeze_ref.py'), '--check', '--repo', $ProductRoot) -TimeoutSec 120
            Set-Result $c.id $(if ($r.ExitCode -eq 0) { 'PASS' } else { 'FAIL' }) $(if ($r.ExitCode -eq 0) { '' } else { 'FROZEN_DIFFERS' }) (Tail $r.Output 400)
        }
        default { Set-Result $c.id 'FAIL' 'NO_RESULT' 'driver has no code for this clause' }
    }
}

# ------------------------------------------------------------------ AO-0: the run against the row list
if ($sel | Where-Object { $_.id -eq 'AO-0.row-list-matches' }) {
    try {
        $aoList = Read-AoRowList (Join-Path $acc 'ao-rows.tsv')
        $aoRun = @{}
        foreach ($k in @($results.Keys | Where-Object { $_ -like 'AO-*' -and $_ -ne 'AO-0.row-list-matches' })) { $aoRun[$k] = $results[$k] }
        $bench = Read-AoBench $AoBenchReport $aoList $AoSlice { param($commit) Get-AoBenchCodeVerdict $ProductRoot $commit }
        foreach ($k in $bench.Keys) { $aoRun[$k] = $bench[$k] }
        $v = Get-AoRowListVerdict $aoList $aoRun $AoSlice
        $dis = @(Get-AoBenchDisagreements $AoBenchReport $aoRun)
        $bud = @(Get-AoBudgetReds (Join-Path $acc 'ao-budgets.tsv') $aoList)
        $benchNote = if ($AoBenchReport) { " Bench report: $AoBenchReport ($script:aoBenchCommitNote)." } else { ' No bench report (-AoBenchReport), so the bench rows are absent.' }
        $extra = ''
        if ($dis.Count -gt 0) { $extra += '. Bench disagrees with the suite: ' + ($dis -join '; ') }
        if ($bud.Count -gt 0) { $extra += '. Budget file: ' + ($bud -join '; ') }
        if ($extra) { Set-Result 'AO-0.row-list-matches' 'FAIL' 'AO_ROW_LIST_RED' ($v[2] + $extra + '.' + $benchNote) }
        else { Set-Result 'AO-0.row-list-matches' $v[0] $v[1] ($v[2] + $benchNote) }
    } catch { Set-Result 'AO-0.row-list-matches' 'FAIL' 'AO_ROW_LIST_UNREADABLE' $_.Exception.Message }
}

# ------------------------------------------------------------------ the suite must not pass while the product is missing
if (-not $productExists) {
    foreach ($c in $sel) {
        if ($c.counts -and $results.ContainsKey($c.id) -and $results[$c.id].status -eq 'PASS') {
            $results[$c.id] = [pscustomobject]@{ id = $c.id; status = 'FAIL'; reason = 'SUITE_BUG_VACUOUS_PASS'; detail = "this clause passed with no product in the repo (src/NetSec.Core is absent). A clause that holds with nothing built is vacuous. Original detail: " + $results[$c.id].detail; ms = $results[$c.id].ms }
        }
    }
}
Set-All $sel 'FAIL' 'NO_RESULT' 'no group produced a result for this clause'

# ------------------------------------------------------------------ report
function Git-Head([string]$dir) { try { return (git -C $dir rev-parse --short HEAD 2>$null) } catch { return '' } }
$counted = @($sel | Where-Object { $_.counts })
$rows = foreach ($c in $sel) {
    $r = $results[$c.id]
    [pscustomobject][ordered]@{ id = $c.id; assertion = $c.assertion; slice = $c.slice; group = $c.group; build = $c.build; referee = $c.referee; status = $r.status; reason = $r.reason; detail = $r.detail; ms = $r.ms; budgetSec = $r.budgetSec }
}
# One selected clause makes foreach return a single object. The report keeps results as an array, so a reader never has to guess the shape.
$rows = @($rows)
$prodRows = @($rows | Where-Object { $_.assertion -ne 'SELF' })
$selfRows = @($rows | Where-Object { $_.assertion -eq 'SELF' })
$nPass = @($prodRows | Where-Object { $_.status -eq 'PASS' }).Count
$nFail = @($prodRows | Where-Object { $_.status -eq 'FAIL' }).Count
$nNot = @($prodRows | Where-Object { $_.status -eq 'NOT RUN' }).Count
$mSel = $prodRows.Count
$reasons = @($prodRows | Where-Object { $_.status -ne 'PASS' } | Group-Object -Property { "$($_.status) $($_.reason)" } | ForEach-Object { [pscustomobject]@{ key = $_.Name; count = $_.Count } })

# Test settings that change what a run proves, so a reader sees them in the report itself.
$activeEnv = [ordered]@{}
foreach ($name in @('ACC_E2E_DEFECT', 'ACC_SELF_ONLY')) { $v = [Environment]::GetEnvironmentVariable($name); if ($v) { $activeEnv[$name] = $v } }
# A clause near its time budget is a timeout waiting to happen. Each clause has its own budget (900 s unless its [Clause] names another,
# #327), and the warning line is 75% of it. ACC_SLOW_WARN_SEC sets one line for every clause, for a test of this warning.
$slowSec = if ($env:ACC_SLOW_WARN_SEC) { [int]$env:ACC_SLOW_WARN_SEC } else { $null }
$slow = @($sel | ForEach-Object {
    $r = $results[$_.id]
    $budget = if ($r -and $r.budgetSec) { [int]$r.budgetSec } else { 900 }
    $line = if ($slowSec) { $slowSec } else { [int]($budget * 0.75) }
    if ($r -and $r.ms -and ([double]$r.ms / 1000) -gt $line) { [pscustomobject]@{ id = $_.id; seconds = [math]::Round([double]$r.ms / 1000); line = $line; budget = $budget } }
})

# Uncommitted changes under a product path mean the commits the report names do not hold all of what ran. The report says so, so no
# report can pass for a run of a clean commit. The paths are every place a clause runs from: the suite, the engine, the app, the native
# library and the tools. docs/ stays out, because the runner writes its own reports there. Ignored files (.work, the vector cache,
# node_modules, dist) do not count. A failed git status reads as unknown, never as clean.
$dirtyPaths = @('acceptance', 'src', 'app', 'native', 'tools')
$statusOut = @(git -C $ProductRoot status --porcelain --untracked-files=normal -- @dirtyPaths 2>$null)
$dirtyKnown = ($LASTEXITCODE -eq 0)
# @( ) around the whole if: an if expression turns an empty list into $null, and strict mode then has no Count to read.
$dirty = @(if ($dirtyKnown) { $statusOut | ForEach-Object { "$_".Substring(3) } | Where-Object { $_ } })

$jsonPath = Join-Path $OutDir "acceptance-$stamp.json"
$mdPath = Join-Path $OutDir "acceptance-$stamp.md"
$summary = [ordered]@{
    schema = 1; timestamp = (Get-Date).ToString('o'); machine = $env:COMPUTERNAME; command = ('run.ps1 -Clauses ' + ($Clauses -join ',') + $(if ($Fresh -or $FreshChild) { ' -Fresh' } else { '' }) + $(if ($SelfTest) { ' -SelfTest' } else { '' }))
    productRoot = $ProductRoot; productCommit = (Git-Head $ProductRoot); acceptanceCommit = (git -C $ProductRoot log -1 --format=%h -- acceptance 2>$null)
    freshClone = [bool]$FreshChild; productPresent = $productExists
    M = $M; selected = $mSel; pass = $nPass; fail = $nFail; notRun = $nNot; reasons = $reasons
    activeEnv = $activeEnv; slowWarnSeconds = $slowSec; slow = $slow
    dirtyKnown = $dirtyKnown; dirtyCount = $(if ($dirtyKnown) { $dirty.Count } else { $null }); dirty = @($dirty | Select-Object -First 20)
    selfChecks = [ordered]@{ selected = $selfRows.Count; pass = @($selfRows | Where-Object { $_.status -eq 'PASS' }).Count; fail = @($selfRows | Where-Object { $_.status -eq 'FAIL' }).Count; notRun = @($selfRows | Where-Object { $_.status -eq 'NOT RUN' }).Count }
}
([ordered]@{ summary = $summary; results = $rows } | ConvertTo-Json -Depth 6) | Set-Content -Path $jsonPath -Encoding utf8

$md = [System.Text.StringBuilder]::new()
$null = $md.AppendLine("# Acceptance run $stamp")
$null = $md.AppendLine()
$null = $md.AppendLine(("**{0} of {1} clauses PASS** ({2} FAIL, {3} NOT RUN). M = {4} comes from acceptance/clauses.json; {5} of them were selected." -f $nPass, $mSel, $nFail, $nNot, $M, $mSel))
$null = $md.AppendLine()
$null = $md.AppendLine("Command: ``$($summary.command)``. Product commit: $($summary.productCommit). Acceptance commit: $($summary.acceptanceCommit). Fresh clone: $($summary.freshClone). Product present: $productExists.")
$null = $md.AppendLine()
if (-not $dirtyKnown) {
    $null = $md.AppendLine("Warning: could not read the tree's status (git status failed in $ProductRoot), so this report cannot say the commits above hold all of what ran.")
    $null = $md.AppendLine()
}
elseif ($dirty.Count -gt 0) {
    $null = $md.AppendLine("Warning: $($dirty.Count) uncommitted paths under " + (($dirtyPaths | ForEach-Object { "$_/" }) -join ', ') + ", for example " + ((@($dirty | Select-Object -First 3) | ForEach-Object { "``$_``" }) -join ', ') + ". The commits above do not hold all of what ran.")
    $null = $md.AppendLine()
}
if ($activeEnv.Count -gt 0) {
    $null = $md.AppendLine("Active test settings: " + (($activeEnv.Keys | ForEach-Object { "``$_=$($activeEnv[$_])``" }) -join ', ') + ". They change what this run proves.")
    $null = $md.AppendLine()
}
foreach ($s in $slow) {
    $null = $md.AppendLine("Warning: ``$($s.id)`` took $($s.seconds) s, past the $($s.line) s warning line. The runner stops this clause at $($s.budget) s.")
}
if ($slow.Count -gt 0) { $null = $md.AppendLine() }
$null = $md.AppendLine('## N of M per assertion')
$null = $md.AppendLine()
$null = $md.AppendLine('| Assertion | M | PASS | FAIL | NOT RUN | Slice | Referee |')
$null = $md.AppendLine('|---|---|---|---|---|---|---|')
foreach ($g in ($prodRows | Group-Object assertion | Sort-Object { [regex]::Replace($_.Name, '\d+', { $args[0].Value.PadLeft(3, '0') }) })) {
    $sl = ($g.Group | ForEach-Object { $_.slice } | Sort-Object -Unique) -join ', '
    $rf = ($g.Group | ForEach-Object { $_.referee } | Sort-Object -Unique) -join '; '
    $null = $md.AppendLine(("| {0} | {1} | {2} | {3} | {4} | {5} | {6} |" -f $g.Name, $g.Count, @($g.Group | Where-Object status -eq 'PASS').Count, @($g.Group | Where-Object status -eq 'FAIL').Count, @($g.Group | Where-Object status -eq 'NOT RUN').Count, $sl, $rf))
}
$null = $md.AppendLine()
$null = $md.AppendLine('## Why a clause is not PASS')
$null = $md.AppendLine()
$null = $md.AppendLine('| Status and reason | Clauses |')
$null = $md.AppendLine('|---|---|')
foreach ($r in $reasons) { $null = $md.AppendLine("| $($r.key) | $($r.count) |") }
$odd = @($prodRows | Where-Object { $_.status -eq 'NOT RUN' -and $_.reason -ne 'PRODUCT_MISSING' })
$null = $md.AppendLine()
$null = $md.AppendLine('## NOT RUN for a reason other than PRODUCT_MISSING')
$null = $md.AppendLine()
if ($odd.Count -eq 0) { $null = $md.AppendLine('None.') } else {
    $null = $md.AppendLine('| Clause | Reason | Detail |'); $null = $md.AppendLine('|---|---|---|')
    foreach ($o in $odd) { $null = $md.AppendLine(("| {0} | {1} | {2} |" -f $o.id, $o.reason, (($o.detail ?? '') -replace '\|', '/' -replace "`r?`n", ' ')).Substring(0)) }
}
$bad = @($prodRows | Where-Object { $_.status -eq 'FAIL' })
$null = $md.AppendLine()
$null = $md.AppendLine('## FAIL')
$null = $md.AppendLine()
if ($bad.Count -eq 0) { $null = $md.AppendLine('None.') } else {
    $null = $md.AppendLine('| Clause | Reason | Detail |'); $null = $md.AppendLine('|---|---|---|')
    foreach ($o in $bad) { $null = $md.AppendLine(("| {0} | {1} | {2} |" -f $o.id, $o.reason, (($o.detail ?? '') -replace '\|', '/' -replace "`r?`n", ' '))) }
}
if ($selfRows.Count -gt 0) {
    $null = $md.AppendLine()
    $null = $md.AppendLine('## Harness self-checks (not part of M)')
    $null = $md.AppendLine()
    $null = $md.AppendLine('| Check | Status | Detail |'); $null = $md.AppendLine('|---|---|---|')
    foreach ($o in $selfRows) { $null = $md.AppendLine(("| {0} | {1} | {2} |" -f $o.id, $o.status, (($o.detail ?? '') -replace '\|', '/' -replace "`r?`n", ' '))) }
}
$null = $md.AppendLine()
$null = $md.AppendLine('## Every clause')
$null = $md.AppendLine()
$null = $md.AppendLine('| Clause | Status | Reason |'); $null = $md.AppendLine('|---|---|---|')
foreach ($o in $prodRows) { $null = $md.AppendLine("| $($o.id) | $($o.status) | $($o.reason) |") }
$md.ToString() | Set-Content -Path $mdPath -Encoding utf8

Say ("{0} of {1} clauses PASS ({2} FAIL, {3} NOT RUN); M = {4}" -f $nPass, $mSel, $nFail, $nNot, $M)
if ($selfRows.Count -gt 0) { Say ("self-checks: {0} of {1} PASS" -f $summary.selfChecks.pass, $selfRows.Count) }
Say "report: $mdPath"
Say "json:   $jsonPath"
if (($nFail -gt 0) -or ($nNot -gt 0) -or ($summary.selfChecks.fail -gt 0)) { exit 1 } else { exit 0 }
