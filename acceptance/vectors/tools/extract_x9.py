"""Builds vectors/x9-24-3-aes-dukpt.nsv from the X9.24-3-2017 test-vector PDF, or checks the committed file against it.

Source: https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Test-Vectors-20180129-1.pdf
(the PDF is fetched by fetch-x9.ps1 into _cache, hash recorded in sources.lock.json).

Why recompute? pdftotext cannot keep the two-column pages in order, so a 32-byte key can
come out as two halves in separate places. This script recomputes each value with an
independent AES-ECB implementation (python "cryptography"), then REQUIRES that every
16-byte half of every written value appears in the PDF text as four consecutive words.
A value that the PDF does not contain stops the script. So each byte written here is both
read from the source and reproduced by a second implementation.

The committed file holds only the inputs and expected outputs that the A3 and A17 clauses read (Steve's decision of
2026-11-11, on Dave's memo: the middle route). The PIN field and PAN field of each PIN block are still checked against
the PDF, but they are not written. Section 2.3 (the full internal-state traces) is never written to the file.

Run: python -I extract_x9.py <pdf> <out.nsv>
     python -I extract_x9.py --check <pdf> <committed.nsv>   # the true-copy check: exit 0 when the committed file equals a fresh extraction
"""
import hashlib
import os
import re
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ALG = {16: (2, 128), 32: (4, 256)}          # key bytes -> (algorithm id, bit length) in the derivation data
USAGE = {
    "kek": 0x0002, "pin": 0x1000, "mac-gen": 0x2000, "mac-ver": 0x2001, "mac-both": 0x2002,
    "data-enc": 0x3000, "data-dec": 0x3001, "data-both": 0x3002,
}
COUNTERS = [1, 2, 3, 4, 5, 6, 7, 8, 0x1FFFE, 0x1FFFF, 0x20000, 0x20001, 0x845FED,
            0xFFFE2000, 0xFFFE4000, 0xFFFE8000, 0xFFFF0000]
IKID = bytes.fromhex("1234567890123456")
BDK128 = bytes.fromhex("FEDCBA9876543210F1F1F1F1F1F1F1F1")
BDK256 = BDK128 + BDK128
PDF_URL = "https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Test-Vectors-20180129-1.pdf"
SOURCE = "ANSI X9.24-3-2017 supplement (X9.24-3-2017-Test-Vectors-20180129-1.pdf, ASC X9), section 2.2"


def ecb(key, block):
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


def kdf(key, usage, out_bytes, tail, counter4):
    alg, bits = ALG[out_bytes]
    out = b""
    for i in range(1, (out_bytes + 15) // 16 + 1):
        data = bytes([1, i]) + usage.to_bytes(2, "big") + alg.to_bytes(2, "big") + bits.to_bytes(2, "big") + tail + counter4
        out += ecb(key, data)
    return out[:out_bytes]


def derivation_key(initial_key, counter):
    key, working = initial_key, 0
    for bit in range(31, -1, -1):
        mask = 1 << bit
        if counter & mask:
            working |= mask
            key = kdf(key, 0x8000, len(initial_key), IKID[4:], working.to_bytes(4, "big"))
    return key


def groups_in(text):
    """Every run of four 8-hex-digit words on one line, as 16 bytes."""
    found = set()
    for line in text.splitlines():
        words = re.findall(r"\b[0-9A-F]{8}\b", line)
        for i in range(len(words) - 3):
            found.add(bytes.fromhex("".join(words[i:i + 4])))
    return found


def need(value, groups, what):
    for i in range(0, len(value), 16):
        if value[i:i + 16] not in groups:
            sys.exit("NOT IN PDF: %s half %d = %s" % (what, i // 16, value[i:i + 16].hex().upper()))
    return value.hex()


def need_words(value, block_text, what):
    """For a value the page layout splits across columns: each 4-byte word must appear in the example's text."""
    for i in range(0, len(value), 4):
        if value[i:i + 4].hex().upper() not in block_text:
            sys.exit("NOT IN PDF: %s word %d = %s" % (what, i // 4, value[i:i + 4].hex().upper()))
    return value.hex()


def header(pdf):
    with open(pdf, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    return [
        "# AES DUKPT test vectors from the Supplement to ANSI X9.24-3-2017, Test Vectors, dated 2018-01-29.",
        "# Source PDF: X9.24-3-2017-Test-Vectors-20180129-1.pdf",
        "# SHA-256: " + sha,
        "# URL: " + PDF_URL,
        "# The values are facts taken from that supplement. The supplement is copyright ASC X9, Inc.",
        "# ASC X9 has not reviewed or endorsed this project.",
        "# The MIT licence of this repository covers MMPWorks' code. This file claims no ownership of the values.",
        "# The values are test data. The keys protect nothing.",
        "# The file holds inputs and expected outputs only. It holds no text, tables or internal-state traces from the PDF.",
        "# Every value below was recomputed (AES-ECB key derivation) and found in the PDF text.",
        "# Initial key id 1234567890123456. BDK-128 and BDK-256 as printed in section 2.2.",
        "# Made by acceptance/vectors/tools/extract_x9.py. The true-copy check (SELF.x9-vectors-true-copy) compares this file with a fresh extraction.",
        "",
    ]


def build(pdf):
    """The file text and the count of PIN blocks. A value the PDF lacks stops the script."""
    text = subprocess.run(["pdftotext", "-layout", pdf, "-"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=True).stdout
    groups = groups_in(text)
    lines = header(pdf)
    families = [("aes128-from-aes128", BDK128, 16), ("aes128-from-aes256", BDK256, 16), ("aes256-from-aes256", BDK256, 32)]
    for name, bdk, out_len in families:
        ik = kdf(bdk, 0x8001, len(bdk), IKID, b"")
        lines += ["[dukpt-%s]" % name, "# source: %s (%s)" % (SOURCE, name.replace("-", " ")), ""]
        for c in COUNTERS:
            dk = derivation_key(ik, c)
            rec = ["bdk = " + bdk.hex(), "ikid = " + IKID.hex(), "counter = %d" % c,
                   "initial_key = " + need(ik, groups, name + " initial key"),
                   "derivation_key = " + need(dk, groups, "%s ctr %d derivation key" % (name, c))]
            for use in ("pin", "mac-gen", "data-enc"):
                key = kdf(dk, USAGE[use], out_len, IKID[4:], c.to_bytes(4, "big"))
                rec.append("%s = %s" % (use, need(key, groups, "%s ctr %d %s" % (name, c, use))))
            lines += rec + [""]
    # All key usages, AES-128 under AES-128 BDK: counters 1..8 and 8675309 (section "All Key Usages").
    ik = kdf(BDK128, 0x8001, 16, IKID, b"")
    lines += ["[dukpt-all-usages]", "# source: %s, 'All Key Usages for Transaction N (AES-128 under AES-128 BDK)'" % SOURCE, ""]
    for c in [1, 2, 3, 4, 5, 6, 7, 8, 0x845FED]:
        dk = derivation_key(ik, c)
        rec = ["bdk = " + BDK128.hex(), "ikid = " + IKID.hex(), "counter = %d" % c]
        for use, code in USAGE.items():
            key = kdf(dk, code, 16, IKID[4:], c.to_bytes(4, "big"))
            rec.append("%s = %s" % (use, need(key, groups, "usage %s ctr %d" % (use, c))))
        lines += rec + [""]
    # PIN block format 4 examples. Plaintext PIN field and PAN field are printed; recompute and check.
    lines += ["[dukpt-pinblock-format4]", "# source: %s, 'Calculation of AES PIN Block (Format 4)', PAN 4111111111111111" % SOURCE, ""]
    blocks = re.split(r"Calculation of AES PIN Block \(Format 4\)", text)[1:]
    done = 0
    for blk in blocks:
        pin = re.search(r"PIN = (\d+)", blk)
        rnd = re.search(r"Random Number = ([0-9A-F]{16})", blk)
        key_m = re.search(r"PIN Encryption Key:\s*\n((?:[0-9A-F]{8} ?){4})", blk)
        if not (pin and rnd and key_m):
            continue
        key = bytes.fromhex(key_m.group(1).replace(" ", ""))
        pin_s = pin.group(1)
        pin_field = bytes.fromhex(("4%x" % len(pin_s)) + pin_s + "A" * (14 - len(pin_s)) + rnd.group(1))
        pan_field = bytes.fromhex("44111111111111111" + "0" * 15)
        block_a = ecb(key, pin_field)
        block_b = bytes(x ^ y for x, y in zip(block_a, pan_field))
        enc = ecb(key, block_b)
        # The PIN field and PAN field are intermediate values. No clause reads them, so they are checked here and not written.
        need(pin_field, groups, "pin field")
        need(pan_field, groups, "pan field")
        lines += ["pan = 4111111111111111", "pin = " + pin_s, "random = " + rnd.group(1).lower(),
                  "pin_key = " + need(key, groups, "pin block key"),
                  "encrypted = " + need_words(enc, blk, "encrypted pin block"), ""]
        done += 1
    if done == 0:
        sys.exit("no PIN block examples recovered")
    return "\n".join(lines).rstrip() + "\n", done


def main(pdf, out_path):
    body, done = build(pdf)
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    print("wrote", out_path, "pin blocks:", done)


def check(pdf, committed):
    """The true-copy check. Exit 0 when the committed file equals a fresh extraction, 1 when it differs. Line ends compare as LF."""
    fresh, _ = build(pdf)
    with open(committed, encoding="utf-8") as f:
        held = f.read().replace("\r\n", "\n")
    if held == fresh:
        print("TRUE_COPY: %s equals a fresh extraction from %s (%d lines)" % (os.path.basename(committed), os.path.basename(pdf), fresh.count("\n")))
        return 0
    a, b = held.split("\n"), fresh.split("\n")
    n = next((i for i in range(min(len(a), len(b))) if a[i] != b[i]), min(len(a), len(b)))
    print("NOT_A_TRUE_COPY: line %d differs. committed: %r, fresh: %r" % (n + 1, a[n] if n < len(a) else "<end>", b[n] if n < len(b) else "<end>"))
    return 1


if __name__ == "__main__":
    if sys.argv[1] == "--check":
        try:
            sys.exit(check(sys.argv[2], sys.argv[3]))
        except FileNotFoundError as e:          # pdftotext is not on PATH
            print("TOOL_MISSING: " + str(e))
            sys.exit(3)
    main(sys.argv[1], sys.argv[2])
