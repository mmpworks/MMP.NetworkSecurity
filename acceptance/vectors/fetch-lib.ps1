# Shared download helper for the vector sources. Dot-source it: . "$PSScriptRoot\fetch-lib.ps1"
# Each source lands in _cache\ (git-ignored). The first fetch records a SHA-256 in sources.lock.json.
# A later fetch that hashes differently is a STOP: the source changed, so a human re-reads it.
$ErrorActionPreference = "Stop"
$script:Cache = Join-Path $PSScriptRoot "_cache"
$script:Lock  = Join-Path $PSScriptRoot "sources.lock.json"

function Get-VectorSource {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Url)
    New-Item -ItemType Directory -Force -Path $script:Cache | Out-Null
    $dest = Join-Path $script:Cache $Name
    if (-not (Test-Path $dest)) {
        Invoke-WebRequest -Uri $Url -OutFile $dest -UseBasicParsing
    }
    $sha = (Get-FileHash -Algorithm SHA256 -Path $dest).Hash.ToLowerInvariant()
    $lock = @{}
    if (Test-Path $script:Lock) {
        (Get-Content -Raw $script:Lock | ConvertFrom-Json).PSObject.Properties | ForEach-Object { $lock[$_.Name] = $_.Value }
    }
    if ($lock.ContainsKey($Name)) {
        if ($lock[$Name].sha256 -ne $sha) {
            throw "SOURCE_CHANGED: $Name hashes to $sha, lock says $($lock[$Name].sha256). Read the new source before you accept it."
        }
    } else {
        $lock[$Name] = [ordered]@{ url = $Url; sha256 = $sha; bytes = (Get-Item $dest).Length; fetched = (Get-Date -Format "yyyy-MM-dd") }
        ($lock.GetEnumerator() | Sort-Object Name | ForEach-Object -Begin { $o = [ordered]@{} } -Process { $o[$_.Name] = $_.Value } -End { $o }) |
            ConvertTo-Json -Depth 4 | Set-Content -Encoding utf8 $script:Lock
    }
    Write-Host ("{0,-44} {1}  {2:N0} bytes" -f $Name, $sha, (Get-Item $dest).Length)
    return $dest
}
