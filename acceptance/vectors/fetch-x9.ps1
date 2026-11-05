# Downloads the ANSI X9.24-3-2017 AES DUKPT test vectors (free from x9.org) and records the SHA-256.
# The PDF stays in _cache\ (git-ignored). extract_vectors.py reads it with pdftotext (poppler, on PATH).
. "$PSScriptRoot\fetch-lib.ps1"
$null = Get-VectorSource -Name "X9.24-3-2017-Test-Vectors-20180129-1.pdf" -Url "https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Test-Vectors-20180129-1.pdf"
