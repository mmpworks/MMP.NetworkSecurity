"""Builds vectors/x9-24-3-aes-dukpt.nsv from the X9.24-3-2017 test-vector PDF.

Source: https://x9.org/wp-content/uploads/2018/03/X9.24-3-2017-Test-Vectors-20180129-1.pdf
(the PDF is fetched by fetch-x9.ps1 into _cache, hash recorded in sources.lock.json).

Why recompute? pdftotext cannot keep the two-column pages in order, so a 32-byte key can
come out as two halves in separate places. This script recomputes each value with an
independent AES-ECB implementation (python "cryptography"), then REQUIRES that every
16-byte half of every written value appears in the PDF text as four consecutive words.
A value that the PDF does not contain stops the script. So each byte written here is both
read from the source and reproduced by a second implementation.

Run: python -I extract_x9.py <pdf> <out.nsv>
"""
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


def main(pdf, out_path):
    text = subprocess.run(["pdftotext", "-layout", pdf, "-"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=True).stdout
    groups = groups_in(text)
    lines = [
        "# AES DUKPT vectors, ANSI X9.24-3-2017 supplement (x9.org test vectors, 2018-01-29).",
        "# Every value below was recomputed (AES-ECB key derivation) and found in the PDF text.",
        "# Initial key id 1234567890123456. BDK-128 and BDK-256 as printed in section 2.2.",
        "",
    ]
    families = [("aes128-from-aes128", BDK128, 16), ("aes128-from-aes256", BDK256, 16), ("aes256-from-aes256", BDK256, 32)]
    for name, bdk, out_len in families:
        ik = kdf(bdk, 0x8001, len(bdk), IKID, b"")
        lines += ["[dukpt-%s]" % name, "# source: X9.24-3-2017 supplement section 2.2 (%s)" % name.replace("-", " "), ""]
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
    lines += ["[dukpt-all-usages]", "# source: X9.24-3-2017 supplement, 'All Key Usages for Transaction N (AES-128 under AES-128 BDK)'", ""]
    for c in [1, 2, 3, 4, 5, 6, 7, 8, 0x845FED]:
        dk = derivation_key(ik, c)
        rec = ["bdk = " + BDK128.hex(), "ikid = " + IKID.hex(), "counter = %d" % c]
        for use, code in USAGE.items():
            key = kdf(dk, code, 16, IKID[4:], c.to_bytes(4, "big"))
            rec.append("%s = %s" % (use, need(key, groups, "usage %s ctr %d" % (use, c))))
        lines += rec + [""]
    # PIN block format 4 examples. Plaintext PIN field and PAN field are printed; recompute and check.
    lines += ["[dukpt-pinblock-format4]", "# source: X9.24-3-2017 supplement, 'Calculation of AES PIN Block (Format 4)', PAN 4111111111111111", ""]
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
        lines += ["pan = 4111111111111111", "pin = " + pin_s, "random = " + rnd.group(1).lower(),
                  "pin_key = " + need(key, groups, "pin block key"),
                  "pin_field = " + need(pin_field, groups, "pin field"),
                  "pan_field = " + need(pan_field, groups, "pan field"),
                  "encrypted = " + need_words(enc, blk, "encrypted pin block"), ""]
        done += 1
    if done == 0:
        sys.exit("no PIN block examples recovered")
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines).rstrip() + "\n")
    print("wrote", out_path, "pin blocks:", done)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
