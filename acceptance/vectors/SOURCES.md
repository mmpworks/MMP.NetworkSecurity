# Vector provenance

Conclusion: every vector in `acceptance/vectors` is read from a named source or produced by a named referee. Nothing is typed from memory.
Each `.nsv` group carries a `# source:` line, and `SELF.vector-provenance` fails when a group has none.

## Files

| File | Holds | Source | How it was read | Second check |
|---|---|---|---|---|
| `aes-fips197.nsv` | AES-128/192/256 block examples | FIPS 197 (2001 edition) appendix C, fips-197-2001.pdf | pdftotext, final round output of each trace | BCL AES in SELF.reference-passes |
| `aes-fips197-rounds.nsv` | AES-128/192/256 round states, key rows and both S-box tables (A19) | FIPS 197 (2001 edition) appendices A and C, figures 7 and 14, fips-197-2001.pdf | pdftotext, every value of the CIPHER and INVERSE CIPHER runs by position | RefAes in SELF.walk-reference-matches-fips, BCL output in the same check |
| `aes-modes-sp800-38a.nsv` | AES ECB, CBC (128, 192), CTR examples | SP 800-38A appendix F, sp800-38a.pdf | pdftotext, four blocks per example. CBC-AES256 (F.2.5) is left out: the PDF text scrambles its key, IV and plaintext rows at a page break, and the extractor does not guess | BCL AES in SELF.reference-passes |
| `sha-cavp.nsv` | SHA-1, SHA-256, SHA-384, SHA-512 short messages and the first 3 long messages | NIST CAVP shabytetestvectors.zip | parse of the .rsp files, bit length checked against the message | BCL hashes |
| `sha3-cavp.nsv` | SHA3-256, SHA3-512, SHAKE128, SHAKE256 short messages, first 3 long, first 40 variable-output | NIST CAVP sha-3bytetestvectors.zip, shakebytetestvectors.zip | parse of the .rsp files | BCL SHA-3 and SHAKE |
| `gcm-cavp.nsv` | AES-GCM seal and open, 96-bit IV, 128-bit tag, first 2 records per (key size, text length, AAD length) group, plus the FAIL records | NIST CAVP gcmtestvectors.zip | parse of the .rsp files | BCL AesGcm |
| `tdes-cavp.nsv` | Triple DES ECB known answers (single-key KAT files, and multi-block 2-key and 3-key files, first 25 each) | NIST CAVP KAT_TDES.zip and tdesmmt.zip | parse of the .rsp files | python cryptography TripleDES (selfcheck_vectors.py) |
| `md5-rfc1321.nsv` | MD5 test suite | RFC 1321 appendix A.5 | text parse, wrapped lines joined | BCL MD5 |
| `hmac-rfc2202.nsv` | HMAC-MD5 and HMAC-SHA-1 test cases | RFC 2202 sections 2 and 3 | text parse, key and data lengths checked against the RFC's own key_len and data_len | BCL HMAC |
| `hmac-rfc4231.nsv` | HMAC-SHA-256, SHA-384, SHA-512 test cases 1 to 7 | RFC 4231 section 4 | text parse, byte counts checked against the RFC's own '(N bytes)'; case 5 is the truncated one | BCL HMAC |
| `cmac-rfc4493.nsv` | AES-CMAC examples 1 to 4 | RFC 4493 section 4 | text parse, message length checked | a CMAC written for the self-test |
| `hkdf-rfc5869.nsv` | HKDF test cases 1 to 7 (SHA-256 and SHA-1) | RFC 5869 appendix A | text parse | BCL HKDF |
| `ecdsa-rfc6979.nsv` | ECDSA P-256 with SHA-256: the key pair, and k, r and s for the messages "sample" and "test" | RFC 6979 appendix A.2.5, rfc6979.txt | text parse; each of the 12 values checked against the RFC text by a script (2026-11-08) | P-256 arithmetic on .NET's own curve parameters, .NET ECDsa verify, and OpenSSL `dgst -verify` (A19.host.ecdsa-walk-open-and-rfc6979) |
| `x25519-rfc7748.nsv` | X25519 scalar multiplication, 1 and 1,000 iterations, Diffie-Hellman | RFC 7748 sections 5.2 and 6.1 | text parse (the 1,000,000 iteration value is not used) | python cryptography X25519 |
| `ed25519-rfc8032.nsv` | Ed25519 tests 1, 2, 3, 1024 and SHA(abc) | RFC 8032 section 7.1 | text parse, message length checked | python cryptography Ed25519 |
| `dh-group14-rfc3526.nsv` | MODP group 14 prime and generator | RFC 3526 section 3 | text parse, 512 hex digits | python pow() with the DH vectors |
| `dh-group14-openssl.nsv` | Diffie-Hellman group 14 public values and shared secrets for fixed 512-bit private values | produced by the OpenSSL 3.5.7 referee (openssl pkey, openssl pkeyutl -derive); command list is the header of the file | extract_openssl.py | python pow() against RFC 3526 |
| `rsa-openssl.nsv` | RSA PKCS#1 v1.5 signatures (SHA-1, SHA-256) and decryption known answers, 1024 and 2048 bit keys | produced by the OpenSSL 3.5.7 referee (openssl genpkey, dgst -sign, pkeyutl -encrypt) | extract_openssl.py | python cryptography (verify, recover primes, decrypt) |
| `tls13-rfc8448.nsv` | TLS 1.3 key schedule trace, simple 1-RTT handshake | RFC 8448 section 3 | text parse, every value's octet count checked against the RFC | an RFC 8446 section 7.1 key schedule on BCL HKDF in SELF.kschedule-rfc8448-pass; transcript hashes recomputed |
| `x9-24-3-aes-dukpt.nsv (made at run time, not committed)` | AES DUKPT initial keys, derivation keys, PIN, MAC and data keys for 17 counters in three families, all usages for 9 counters, 9 format 4 PIN blocks | ANSI X9.24-3-2017 supplement, X9.24-3-2017-Test-Vectors-20180129-1.pdf from x9.org (fetch-x9.ps1) | extract_x9.py: every value is recomputed with an AES-ECB key derivation and must also appear in the PDF text (four consecutive words, or each word of a column-split PIN block). A value the PDF lacks stops the script | BCL AES (SELF.dukpt-vectors-pass) |

## Downloaded documents

The documents stay in `vectors/_cache` (ignored by git). `fetch-sources.ps1` and `fetch-x9.ps1` download them and compare each SHA-256 with `sources.lock.json`.
A different hash stops the fetch with SOURCE_CHANGED. A person reads the new document before the lock changes.

| Document | SHA-256 | Bytes | URL |
|---|---|---|---|
| `KAT_TDES.zip` | `19d8841f84ae3415350b069a4768bd416c05a0533ee43e905ab099adb8ccb374` | 118,218 | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/KAT_TDES.zip |
| `X9.24-3-2017-Test-Vectors-20180129-1.pdf` | `ae9bb01d76eda32018332f1202a9c2010097abf0d17d753612b7e612ddd9c4cc` | 531,149 | https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Test-Vectors-20180129-1.pdf |
| `fips-197-2001.pdf` | `89c6da9e6cb81ffb7c115752b789ff3dc205acb2b13d6a36ff55acc79e87f61e` | 1,184,869 | https://csrc.nist.gov/files/pubs/fips/197/final/docs/fips-197.pdf |
| `gcmtestvectors.zip` | `f9fc479e134cde2980b3bb7cddbcb567b2cd96fd753835243ed067699f26a023` | 9,154,174 | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip |
| `rfc1321.txt` | `284a79d148400d9cd2a423211d1103b5cef0fb9256a4cbe6d7ebe5197c3149dd` | 35,222 | https://www.rfc-editor.org/rfc/rfc1321.txt |
| `rfc2202.txt` | `c19effeca47e801be304460da3b2fb05f595e2309abceb050e40e024868fe483` | 11,942 | https://www.rfc-editor.org/rfc/rfc2202.txt |
| `rfc3526.txt` | `6c95b231eb1c2d9ffa480efbe3ae53477231271f3438570a3af370b2aa4a968b` | 19,166 | https://www.rfc-editor.org/rfc/rfc3526.txt |
| `rfc4231.txt` | `72178527ce93500e730bc8eb182b857e583096d652b64ece0879c52ba1df973b` | 17,725 | https://www.rfc-editor.org/rfc/rfc4231.txt |
| `rfc4493.txt` | `252850ac038a44e931fdce6cb02b444a18ed1da0c9e212bfdd1da0ed3366fc1c` | 38,751 | https://www.rfc-editor.org/rfc/rfc4493.txt |
| `rfc5869.txt` | `7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c` | 25,854 | https://www.rfc-editor.org/rfc/rfc5869.txt |
| `rfc7748.txt` | `279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3` | 39,298 | https://www.rfc-editor.org/rfc/rfc7748.txt |
| `rfc8032.txt` | `ed63657ff389301282b169b0abde9b5dd2c7e4d524fdfa5da6ff3094fc93c4c3` | 103,210 | https://www.rfc-editor.org/rfc/rfc8032.txt |
| `rfc8448.txt` | `6564d1376d1ec744fc7a9993da15ebc1b9be361908b166091f47ef605c537fba` | 159,343 | https://www.rfc-editor.org/rfc/rfc8448.txt |
| `sha-3bytetestvectors.zip` | `cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c` | 2,801,880 | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip |
| `shabytetestvectors.zip` | `929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8` | 4,909,729 | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip |
| `shakebytetestvectors.zip` | `debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7` | 2,116,268 | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip |
| `sp800-38a.pdf` | `66821162de1e7130c5fb5eedb22140d8d6d013ec51af4550bb095c2a9481a00e` | 378,266 | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf |
| `tdesmmt.zip` | `04db93728ebf994330b0ba4555d397f8f03c29fd8547d9d586219fabe00e8c78` | 61,614 | https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/des/tdesmmt.zip |

## Rebuild

```
pwsh vectors/fetch-sources.ps1
python -I vectors/tools/extract_rfc.py vectors/_cache vectors
python -I vectors/tools/extract_nist.py vectors/_cache vectors
python -I vectors/tools/extract_rfc8448.py vectors/_cache/rfc8448.txt vectors/tls13-rfc8448.nsv
python -I vectors/tools/extract_openssl.py "C:\Program Files\Git\mingw64\bin\openssl.exe" vectors/dh-group14-rfc3526.nsv vectors   # new RSA keys: renews the file
python -I vectors/tools/selfcheck_vectors.py vectors
```

## Licence

RFC text: IETF Trust. NIST publications and CAVP files: US government work. OpenSSL output: produced here.
The X9.24-3 supplement is copyrighted by ASC X9 and free to download. The PDF and the vector file made from it stay out of git (prd.md licence checklist item 1).
Dave decides if the vector file may ever be committed.
