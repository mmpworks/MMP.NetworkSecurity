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
  acceptance\run.ps1 there, and check acceptance\PIN with acceptance\tools\pin.py. A stale or old-form PIN is a FAIL of
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
    [switch]$FreshChild
)

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
                   '-AsyncProxyRoot', $AsyncProxyRoot, '-NetCFRefDir', $NetCFRefDir, '-OutDir', $OutDir, '-FreshChild')
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
    $sel = @($sel | Sort-Object -Property id -Unique)
    return $sel
}
$sel = Select-Clauses
if ($sel.Count -eq 0) { throw "no clause matches: $($Clauses -join ', ')" }
Say ("{0} clauses selected of M = {1} (+ {2} self-checks in the file)" -f @($sel | Where-Object { $_.counts }).Count, $M, @($all | Where-Object { -not $_.counts }).Count)

# ------------------------------------------------------------------ results
$results = @{}
function Set-Result([string]$id, [string]$status, [string]$reason = '', [string]$detail = '', [long]$ms = 0) {
    $results[$id] = [pscustomobject]@{ id = $id; status = $status; reason = $reason; detail = $detail; ms = $ms }
}
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
$needsProductGroups = @('prim', 'walk', 'dukpt', 'kschedule', 'tls13live', 'tls11', 'ssh', 'auth', 'nativeprod', 'bridge', 'host', 'a17', 'a17probe', 'golden', 'keys', 'binproof', 'e2e')
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
        $codes = @([regex]::Matches($b.Output, 'error (CS\d{4})') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $firstErrors = @([regex]::Matches($b.Output, '(?m)^.*error CS\d{4}:.*$') | Select-Object -First 3 | ForEach-Object { ($_.Value -replace '\[.*\]\s*$', '').Trim() }) -join ' | '
        $surface = $codes.Count -gt 0 -and (@($codes | Where-Object { $missingSymbolCodes -notcontains $_ }).Count -eq 0)
        if ($surface) { Set-All $list 'NOT RUN' 'PRODUCT_MISSING' ("the group does not compile against the built NetSec.Core: a type or member the contract names is missing or differs. " + $firstErrors) }
        else { Set-All $list 'FAIL' 'ACCEPTANCE_COMPILE_ERROR' ("the group failed to build for a reason outside the product surface: " + $firstErrors + " " + (Tail $b.Output 300)) }
        return
    }
    $outDir = Join-Path $acc ("groups\" + (Split-Path (Split-Path $g.project -Parent) -Leaf) + "\bin\Release\$tfm")
    if ($g.kind -eq 'selftest') { $outDir = Join-Path $acc "selftest\bin\Release\$tfm" }
    $runArgs = @('--build', $build, '--ids', ($ids -join ','), '--acceptance', $acc, '--vectors', (Join-Path $acc 'vectors'), '--root', $ProductRoot, '--work', $work) + (Get-Props $build)
    if ($build -eq 'cf') { $exe = Join-Path $outDir ($g.assembly + '.exe'); $argv = $runArgs }
    else { $exe = 'dotnet'; $argv = @((Join-Path $outDir ($g.assembly + '.dll'))) + $runArgs }
    $r = Invoke-Tool $exe $argv -TimeoutSec 3000
    foreach ($line in (Read-ClauseLines $r.Output)) { Set-Result $line.id $line.status $line.reason $line.detail ([long]$line.ms) }
    foreach ($c in $list) {
        if (-not $results.ContainsKey($c.id)) {
            $why = if ($r.ExitCode -eq -999) { 'TIMEOUT' } else { 'NO_RESULT' }
            Set-Result $c.id 'FAIL' $why ("group $name ($build) gave no result line for this clause (exit $($r.ExitCode)). " + (Tail $r.Output 300))
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
            if ($pinCode -ne 0 -and $pinReason -eq 'PIN_UNSET') { Set-Result $c.id 'NOT RUN' 'PIN_UNSET' $pinOut; break }
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
        default { Set-Result $c.id 'FAIL' 'NO_RESULT' 'driver has no code for this clause' }
    }
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
    [pscustomobject][ordered]@{ id = $c.id; assertion = $c.assertion; slice = $c.slice; group = $c.group; build = $c.build; referee = $c.referee; status = $r.status; reason = $r.reason; detail = $r.detail; ms = $r.ms }
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
# A clause near the runner's 900 s budget is a timeout waiting to happen. ACC_SLOW_WARN_SEC lowers the line, for a test of this warning.
$slowSec = 600; if ($env:ACC_SLOW_WARN_SEC) { $slowSec = [int]$env:ACC_SLOW_WARN_SEC }
$slow = @($sel | ForEach-Object { $r = $results[$_.id]; if ($r -and $r.ms -and ([double]$r.ms / 1000) -gt $slowSec) { [pscustomobject]@{ id = $_.id; seconds = [math]::Round([double]$r.ms / 1000) } } })

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
    $null = $md.AppendLine("Warning: ``$($s.id)`` took $($s.seconds) s, past the $slowSec s warning line. The runner stops a clause at 900 s.")
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
