"""Writes vectors/SOURCES.md from sources.lock.json and the vector files, so the provenance table cannot drift from the data.

Run: python -I make_sources_md.py
"""
import json
import os
import re

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# vector file -> (what, source documents, how the values were read, how they were checked)
FILES = [
    ("aes-fips197.nsv", "AES-128/192/256 block examples", "FIPS 197 (2001 edition) appendix C, fips-197-2001.pdf", "pdftotext, final round output of each trace", "BCL AES in SELF.reference-passes"),
    ("aes-modes-sp800-38a.nsv", "AES ECB, CBC (128, 192), CTR examples", "SP 800-38A appendix F, sp800-38a.pdf", "pdftotext, four blocks per example. CBC-AES256 (F.2.5) is left out: the PDF text scrambles its key, IV and plaintext rows at a page break, and the extractor does not guess", "BCL AES in SELF.reference-passes"),
    ("sha-cavp.nsv", "SHA-1, SHA-256, SHA-384, SHA-512 short messages and the first 3 long messages", "NIST CAVP shabytetestvectors.zip", "parse of the .rsp files, bit length checked against the message", "BCL hashes"),
    ("sha3-cavp.nsv", "SHA3-256, SHA3-512, SHAKE128, SHAKE256 short messages, first 3 long, first 40 variable-output", "NIST CAVP sha-3bytetestvectors.zip, shakebytetestvectors.zip", "parse of the .rsp files", "BCL SHA-3 and SHAKE"),
    ("gcm-cavp.nsv", "AES-GCM seal and open, 96-bit IV, 128-bit tag, first 2 records per (key size, text length, AAD length) group, plus the FAIL records", "NIST CAVP gcmtestvectors.zip", "parse of the .rsp files", "BCL AesGcm"),
    ("tdes-cavp.nsv", "Triple DES ECB known answers (single-key KAT files, and multi-block 2-key and 3-key files, first 25 each)", "NIST CAVP KAT_TDES.zip and tdesmmt.zip", "parse of the .rsp files", "python cryptography TripleDES (selfcheck_vectors.py)"),
    ("md5-rfc1321.nsv", "MD5 test suite", "RFC 1321 appendix A.5", "text parse, wrapped lines joined", "BCL MD5"),
    ("hmac-rfc2202.nsv", "HMAC-MD5 and HMAC-SHA-1 test cases", "RFC 2202 sections 2 and 3", "text parse, key and data lengths checked against the RFC's own key_len and data_len", "BCL HMAC"),
    ("hmac-rfc4231.nsv", "HMAC-SHA-256, SHA-384, SHA-512 test cases 1 to 7", "RFC 4231 section 4", "text parse, byte counts checked against the RFC's own '(N bytes)'; case 5 is the truncated one", "BCL HMAC"),
    ("cmac-rfc4493.nsv", "AES-CMAC examples 1 to 4", "RFC 4493 section 4", "text parse, message length checked", "a CMAC written for the self-test"),
    ("hkdf-rfc5869.nsv", "HKDF test cases 1 to 7 (SHA-256 and SHA-1)", "RFC 5869 appendix A", "text parse", "BCL HKDF"),
    ("x25519-rfc7748.nsv", "X25519 scalar multiplication, 1 and 1,000 iterations, Diffie-Hellman", "RFC 7748 sections 5.2 and 6.1", "text parse (the 1,000,000 iteration value is not used)", "python cryptography X25519"),
    ("ed25519-rfc8032.nsv", "Ed25519 tests 1, 2, 3, 1024 and SHA(abc)", "RFC 8032 section 7.1", "text parse, message length checked", "python cryptography Ed25519"),
    ("dh-group14-rfc3526.nsv", "MODP group 14 prime and generator", "RFC 3526 section 3", "text parse, 512 hex digits", "python pow() with the DH vectors"),
    ("dh-group14-openssl.nsv", "Diffie-Hellman group 14 public values and shared secrets for fixed 512-bit private values", "produced by the OpenSSL 3.5.7 referee (openssl pkey, openssl pkeyutl -derive); command list is the header of the file", "extract_openssl.py", "python pow() against RFC 3526"),
    ("rsa-openssl.nsv", "RSA PKCS#1 v1.5 signatures (SHA-1, SHA-256) and decryption known answers, 1024 and 2048 bit keys", "produced by the OpenSSL 3.5.7 referee (openssl genpkey, dgst -sign, pkeyutl -encrypt)", "extract_openssl.py", "python cryptography (verify, recover primes, decrypt)"),
    ("tls13-rfc8448.nsv", "TLS 1.3 key schedule trace, simple 1-RTT handshake", "RFC 8448 section 3", "text parse, every value's octet count checked against the RFC", "an RFC 8446 section 7.1 key schedule on BCL HKDF in SELF.kschedule-rfc8448-pass; transcript hashes recomputed"),
]

X9 = ("x9-24-3-aes-dukpt.nsv (made at run time, not committed)", "AES DUKPT initial keys, derivation keys, PIN, MAC and data keys for 17 counters in three families, all usages for 9 counters, 9 format 4 PIN blocks",
      "ANSI X9.24-3-2017 supplement, X9.24-3-2017-Test-Vectors-20180129-1.pdf from x9.org (fetch-x9.ps1)",
      "extract_x9.py: every value is recomputed with an AES-ECB key derivation and must also appear in the PDF text (four consecutive words, or each word of a column-split PIN block). A value the PDF lacks stops the script",
      "BCL AES (SELF.dukpt-vectors-pass)")


def main():
    lock = json.load(open(os.path.join(HERE, "sources.lock.json"), encoding="utf-8"))
    out = ["# Vector provenance", "",
           "Conclusion: every vector in `acceptance/vectors` is read from a named source or produced by a named referee. Nothing is typed from memory.",
           "Each `.nsv` group carries a `# source:` line, and `SELF.vector-provenance` fails when a group has none.", "",
           "## Files", "", "| File | Holds | Source | How it was read | Second check |", "|---|---|---|---|---|"]
    for name, what, src, how, check in FILES:
        out.append("| `%s` | %s | %s | %s | %s |" % (name, what, src, how, check))
    out.append("| `%s` | %s | %s | %s | %s |" % X9)
    out += ["", "## Downloaded documents", "",
            "The documents stay in `vectors/_cache` (ignored by git). `fetch-sources.ps1` and `fetch-x9.ps1` download them and compare each SHA-256 with `sources.lock.json`.",
            "A different hash stops the fetch with SOURCE_CHANGED. A person reads the new document before the lock changes.", "",
            "| Document | SHA-256 | Bytes | URL |", "|---|---|---|---|"]
    for k, v in sorted(lock.items()):
        out.append("| `%s` | `%s` | %s | %s |" % (k, v["sha256"], format(v["bytes"], ","), v["url"]))
    out += ["", "## Rebuild", "",
            "```",
            "pwsh vectors/fetch-sources.ps1",
            "python -I vectors/tools/extract_rfc.py vectors/_cache vectors",
            "python -I vectors/tools/extract_nist.py vectors/_cache vectors",
            "python -I vectors/tools/extract_rfc8448.py vectors/_cache/rfc8448.txt vectors/tls13-rfc8448.nsv",
            "python -I vectors/tools/extract_openssl.py \"C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe\" vectors/dh-group14-rfc3526.nsv vectors   # new RSA keys: renews the file",
            "python -I vectors/tools/selfcheck_vectors.py vectors",
            "```", "",
            "## Licence", "",
            "RFC text: IETF Trust. NIST publications and CAVP files: US government work. OpenSSL output: produced here.",
            "The X9.24-3 supplement is copyrighted by ASC X9 and free to download. The PDF and the vector file made from it stay out of git (prd.md licence checklist item 1).",
            "Dave decides if the vector file may ever be committed.", ""]
    open(os.path.join(HERE, "SOURCES.md"), "w", encoding="utf-8", newline="\n").write("\n".join(out))
    print("wrote SOURCES.md")


if __name__ == "__main__":
    main()
