#requires -Version 7
<#
.SYNOPSIS
  Opens the Network Security Lab app. Builds what is missing, checks the Electron binary, and launches.
.DESCRIPTION
  Steps, each one skipped when its result already exists:
    1. Host build      src\NetSec.Host\bin\Release\net10.0\NetSec.Host.dll, and netsec_ct.dll beside it (the Host's build makes it, for lesson 11).
                       With no C compiler the script warns and goes on: lesson 11 reads a named error, and every other lesson opens.
    2. app packages    app\node_modules (npm ci)
    3. app build       app\dist\index.html (npm run build)
    4. Electron binary app\node_modules\electron\dist\electron.exe. If it is absent, the script repairs it from the cached official zip
                       after a SHA-256 check against node_modules\electron\checksums.json. With no cached zip it runs the official
                       installer (node_modules\electron\install.js). If the binary is still absent it stops with a named error.
    5. launch          electron.exe in app\. main.cjs starts the Host with a fresh token.
  Every failure stops with a line of the form `open-app: ERROR <CODE>: <what> Fix: <what to do>`.
.PARAMETER AsyncProxyRoot
  Path of MMP.AsyncProxy. Default: the folder beside this repo, or the AsyncProxyRoot environment variable.
.PARAMETER Check
  Builds and checks everything and stops before the launch.
.PARAMETER Smoke
  Launches, waits for the window titled "Network Security Lab", reports the result, and closes the app. For proof runs.
.PARAMETER Wait
  Keeps the shell attached until the app closes.
.PARAMETER Rebuild
  Rebuilds the Host and the app even when their outputs exist.
.EXAMPLE
  pwsh tools/open-app.ps1
#>
[CmdletBinding()]
param(
    [string]$AsyncProxyRoot = $env:AsyncProxyRoot,
    [switch]$Check,
    [switch]$Smoke,
    [switch]$Wait,
    [switch]$Rebuild
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$app = Join-Path $root 'app'
$hostDll = Join-Path $root 'src\NetSec.Host\bin\Release\net10.0\NetSec.Host.dll'
$nativeDll = Join-Path (Split-Path -Parent $hostDll) 'netsec_ct.dll'
$electronDir = Join-Path $app 'node_modules\electron'
$electronExe = Join-Path $electronDir 'dist\electron.exe'

function Fail([string]$code, [string]$what, [string]$fix) {
    Write-Host "open-app: ERROR ${code}: $what Fix: $fix" -ForegroundColor Red
    exit 1
}
function Say([string]$text) { Write-Host "open-app: $text" }

function Need-Tool([string]$name, [string]$fix) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { Fail 'TOOL_MISSING' "$name is not on PATH." $fix }
}

# ---------------------------------------------------------------- tools
Need-Tool 'dotnet' 'Install the .NET 10 SDK from https://dotnet.microsoft.com/download.'
Need-Tool 'node' 'Install Node.js 20 or newer from https://nodejs.org.'
Need-Tool 'npm' 'Install Node.js 20 or newer from https://nodejs.org.'
if (-not (Test-Path (Join-Path $app 'package.json'))) { Fail 'APP_MISSING' "app\package.json is not in $root." 'Run this script from a full clone of MMP.NetworkSecurity.' }

# ---------------------------------------------------------------- 1 Host
if ($Rebuild -or -not (Test-Path $hostDll) -or -not (Test-Path $nativeDll)) {
    if (-not $AsyncProxyRoot) { $AsyncProxyRoot = Join-Path (Split-Path -Parent $root) 'MMP.AsyncProxy' }
    if (-not (Test-Path (Join-Path $AsyncProxyRoot 'src\MMP.AsyncProxy'))) {
        Fail 'ASYNCPROXY_MISSING' "MMP.AsyncProxy is not at $AsyncProxyRoot." 'Clone MMP.AsyncProxy beside this repo, or pass -AsyncProxyRoot <path>.'
    }
    Say "building the Host (AsyncProxy at $AsyncProxyRoot)"
    dotnet build (Join-Path $root 'src\NetSec.Host') -c Release --nologo -v q "-p:AsyncProxyRoot=$AsyncProxyRoot"
    if ($LASTEXITCODE -ne 0) { Fail 'HOST_BUILD_FAILED' 'dotnet build of src\NetSec.Host failed.' 'Read the build output above. Run `dotnet --list-sdks` and confirm a 10.x SDK.' }
    if (-not (Test-Path $hostDll)) { Fail 'HOST_BUILD_FAILED' "The build passed but $hostDll is absent." 'Run the build again with -Rebuild and read the output.' }
} else { Say 'Host already built' }
if (Test-Path $nativeDll) { Say 'netsec_ct.dll is beside the Host' }
else { Write-Host "open-app: WARNING NATIVE_LIB_NOT_BUILT: netsec_ct.dll is not beside the Host. Lesson 11 will end in NATIVE_LIB_MISSING. Every other lesson works. Fix: install the C++ tools of Visual Studio 2022, then run this script again." -ForegroundColor Yellow }

# ---------------------------------------------------------------- 2 and 3 app
Push-Location $app
try {
    if ($Rebuild -or -not (Test-Path 'node_modules\.package-lock.json')) {
        Say 'npm ci'
        npm ci
        if ($LASTEXITCODE -ne 0) { Fail 'NPM_CI_FAILED' 'npm ci failed.' 'Close every program that holds files in app\node_modules (a running vite or Electron), then run again. EPERM means a file is locked.' }
    } else { Say 'app packages already installed' }
    if ($Rebuild -or -not (Test-Path 'dist\index.html')) {
        Say 'npm run build'
        npm run build
        if ($LASTEXITCODE -ne 0) { Fail 'APP_BUILD_FAILED' 'npm run build failed.' 'Read the TypeScript output above. Run `npm ci` again if packages look wrong.' }
    } else { Say 'app already built' }
} finally { Pop-Location }

# ---------------------------------------------------------------- 4 Electron binary
function Test-ElectronBinary { (Test-Path $electronExe) -and (Test-Path (Join-Path $electronDir 'path.txt')) }

function Repair-ElectronFromCache([string]$version) {
    $zipName = "electron-v$version-win32-x64.zip"
    $cacheRoot = Join-Path $env:LOCALAPPDATA 'electron\Cache'
    $zip = if (Test-Path $cacheRoot) { Get-ChildItem $cacheRoot -Recurse -Filter $zipName -ErrorAction SilentlyContinue | Select-Object -First 1 } else { $null }
    if (-not $zip) { return $false }
    $sums = Get-Content (Join-Path $electronDir 'checksums.json') -Raw | ConvertFrom-Json
    $want = $sums.$zipName
    if (-not $want) { Fail 'ELECTRON_CHECKSUM_UNKNOWN' "checksums.json has no entry for $zipName." 'Run `npm ci` in app\ again so the package and its checksums match.' }
    $got = (Get-FileHash $zip.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -ne $want.ToLowerInvariant()) {
        Fail 'ELECTRON_ZIP_HASH_MISMATCH' "The cached $($zip.FullName) has SHA-256 $got. checksums.json expects $want." "Delete that zip, then run this script again so the installer downloads a fresh copy."
    }
    Say "repairing Electron from the cached zip (SHA-256 matches checksums.json)"
    $dist = Join-Path $electronDir 'dist'
    if (Test-Path $dist) { Remove-Item $dist -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $dist | Out-Null
    $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
    if (Test-Path $tar) { & $tar -xf $zip.FullName -C $dist } else { Expand-Archive -Path $zip.FullName -DestinationPath $dist -Force }
    if (-not (Test-Path $electronExe)) { Fail 'ELECTRON_EXTRACT_FAILED' "Extracting $($zip.FullName) did not produce dist\electron.exe." 'Free disk space and check that antivirus is not removing electron.exe, then run again.' }
    Set-Content -Path (Join-Path $electronDir 'path.txt') -Value 'electron.exe' -NoNewline
    return $true
}

if (-not (Test-Path $electronDir)) { Fail 'ELECTRON_PACKAGE_MISSING' 'app\node_modules\electron is absent.' 'Run `npm ci` in app\.' }
if (-not (Test-ElectronBinary)) {
    $version = (Get-Content (Join-Path $electronDir 'package.json') -Raw | ConvertFrom-Json).version
    Say "Electron $version binary is missing"
    $fixed = Repair-ElectronFromCache $version
    if (-not $fixed) {
        Say 'no cached zip, running the official installer'
        node (Join-Path $electronDir 'install.js')
    }
    if (-not (Test-ElectronBinary)) {
        $fixText = 'Connect to the internet and run `node app\node_modules\electron\install.js`, or copy electron-v' + $version + '-win32-x64.zip into %LOCALAPPDATA%\electron\Cache\<any folder>\ and run this script again.'
        Fail 'ELECTRON_BINARY_MISSING' 'app\node_modules\electron\dist has no electron.exe and no cached zip exists.' $fixText
    }
}
# electron.exe is a GUI program and prints nothing to a pipe, so the version comes from dist\version (the file the official zip ships).
$versionFile = Join-Path $electronDir 'dist\version'
$reported = if (Test-Path $versionFile) { 'v' + (Get-Content $versionFile -Raw).Trim() } else { '' }
$expected = 'v' + (Get-Content (Join-Path $electronDir 'package.json') -Raw | ConvertFrom-Json).version
if ($reported -ne $expected) { Fail 'ELECTRON_VERSION_MISMATCH' "electron.exe reports $reported and the package expects $expected." 'Delete app\node_modules\electron\dist and run this script again.' }
Say "Electron binary ok ($reported)"

if ($Check) { Say 'check passed, not launching (-Check)'; exit 0 }

# ---------------------------------------------------------------- 5 launch
Remove-Item Env:NETSEC_HOST -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $electronExe -ArgumentList '.' -WorkingDirectory $app -PassThru
Say "launched Electron, pid $($p.Id)"
if ($Smoke) {
    $deadline = (Get-Date).AddSeconds(60)
    $title = ''
    while ((Get-Date) -lt $deadline) {
        $title = (Get-Process -Id $p.Id -ErrorAction SilentlyContinue).MainWindowTitle
        if ($title -eq 'Network Security Lab') { break }
        Start-Sleep -Milliseconds 500
    }
    $ok = $title -eq 'Network Security Lab'
    Say "window title: '$title'"
    Start-Sleep -Seconds 3
    # taskkill /T ends the Host that main.cjs started as well
    taskkill /PID $p.Id /T /F | Out-Null
    if (-not $ok) { Fail 'WINDOW_NOT_SHOWN' 'Electron started and no window titled Network Security Lab appeared in 60 seconds.' 'Run `app\node_modules\electron\dist\electron.exe app` in a terminal and read its output.' }
    Say 'smoke ok'
    exit 0
}
if ($Wait) { $p.WaitForExit() }
