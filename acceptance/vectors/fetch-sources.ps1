# Downloads every published source the vector files come from. The commands that rebuild the vector files are in SOURCES.md.
. "$PSScriptRoot\fetch-lib.ps1"
$rfc = "https://www.rfc-editor.org/rfc"
$cavp = "https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents"
$list = [ordered]@{
    "rfc1321.txt" = "$rfc/rfc1321.txt"; "rfc2202.txt" = "$rfc/rfc2202.txt"; "rfc3526.txt" = "$rfc/rfc3526.txt"; "rfc4231.txt" = "$rfc/rfc4231.txt"
    "rfc4493.txt" = "$rfc/rfc4493.txt"; "rfc5869.txt" = "$rfc/rfc5869.txt"; "rfc7748.txt" = "$rfc/rfc7748.txt"
    "rfc8032.txt" = "$rfc/rfc8032.txt"; "rfc8448.txt" = "$rfc/rfc8448.txt"
    "fips-197-2001.pdf" = "https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf"
    "shakebytetestvectors.zip" = "$cavp/sha3/shakebytetestvectors.zip"
    "sp800-38a.pdf" = "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf"
    "shabytetestvectors.zip" = "$cavp/shs/shabytetestvectors.zip"
    "sha-3bytetestvectors.zip" = "$cavp/sha3/sha-3bytetestvectors.zip"
    "gcmtestvectors.zip" = "$cavp/mac/gcmtestvectors.zip"
    "KAT_TDES.zip" = "$cavp/des/KAT_TDES.zip"
    "tdesmmt.zip" = "$cavp/des/tdesmmt.zip"
}
foreach ($k in $list.Keys) { $null = Get-VectorSource -Name $k -Url $list[$k] }
& "$PSScriptRoot\fetch-x9.ps1"
