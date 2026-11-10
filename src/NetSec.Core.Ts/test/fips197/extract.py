"""Transcribe the FIPS 197 example values from the PDF text into fips197-vectors.json.

This script reads the standard and nothing else. It imports no part of the TypeScript engine.

Sources (both from NIST):
  Appendix A (key expansion): FIPS 197-upd1 (2023), https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
  Appendix C (cipher and inverse cipher traces): FIPS 197 (2001), https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
  The 2023 update removed Appendix C (its change log, item 23), so the traces come from the 2001 text.

Steps:
  curl -sSL -o upd1.pdf https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
  curl -sSL -o orig.pdf https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
  pdftotext -layout upd1.pdf upd1.txt
  pdftotext -raw orig.pdf orig.txt
  python -I extract.py upd1.txt orig.txt <sha256 of upd1.pdf> <sha256 of orig.pdf> > fips197-vectors.json

Appendix C uses -raw: -layout misplaces some values by one line at a page break in C.2 and C.3.
The script checks each value set against the others, with XOR and byte moves only (check_* below), and stops on a mismatch.
No S-box and no field multiply runs here, so the checks cannot share a fault with an engine.
"""
import json
import re
import sys

HEX8 = re.compile(r"^[0-9a-f]{8}$")
ROW = re.compile(r"^\s*(\d+)\s+((?:[0-9a-f]{8}\s+)*[0-9a-f]{8})\s*$")
KEY_WORD = re.compile(r"w(\d+)\s*=\s*([0-9a-f]{8})")
TRACE = re.compile(r"round\[\s*(\d+)\]\.(\w+)\s+([0-9a-f]{32})")


def read(path):
    with open(path, "rb") as f:
        return f.read().decode("latin-1").splitlines()


def section(lines, start, stop):
    """The lines after the first line holding `start`, up to the next line holding `stop`. Runs of spaces count as one."""
    flat = [" ".join(line.split()) for line in lines]
    begin = next(i for i, line in enumerate(flat) if start in line)
    end = next((i for i in range(begin + 1, len(flat)) if stop and stop in flat[i]), len(flat))
    return lines[begin + 1:end]


def expansion_row(index, words):
    """One table row. 7 words: a RotWord row. 4 words: the AES-256 SubWord-only row. 3 words: a plain row."""
    if len(words) == 7:
        temp, rot, sub, rcon, after_rcon, back, w = words
        return {"i": index, "temp": temp, "afterRotWord": rot, "afterSubWord": sub, "rcon": rcon,
                "afterXorWithRcon": after_rcon, "wBack": back, "w": w}
    if len(words) == 4:
        temp, sub, back, w = words
        return {"i": index, "temp": temp, "afterSubWord": sub, "wBack": back, "w": w}
    if len(words) == 3:
        temp, back, w = words
        return {"i": index, "temp": temp, "wBack": back, "w": w}
    raise ValueError(f"row {index} has {len(words)} words")


def key_expansion(lines, title, stop, nk):
    body = section(lines, title, stop)
    key_words = {}
    rows = []
    for line in body:
        for m in KEY_WORD.finditer(line):
            key_words[int(m.group(1))] = m.group(2)
        m = ROW.match(line)
        if m:
            rows.append(expansion_row(int(m.group(1)), m.group(2).split()))
    words = [key_words[i] for i in range(nk)] + [r["w"] for r in rows]
    return {"nk": nk, "key": "".join(key_words[i] for i in range(nk)),
            "keyWords": [key_words[i] for i in range(nk)], "rows": rows, "words": words}


def trace(lines):
    return [{"round": int(m.group(1)), "tag": m.group(2), "hex": m.group(3)}
            for line in lines for m in [TRACE.search(line)] if m]


def cipher_example(lines, title, stop):
    body = section(lines, title, stop)
    plaintext = next(re.search(r"[0-9a-f]{32}", l).group(0) for l in body if l.strip().startswith("PLAINTEXT"))
    key = next(re.search(r"[0-9a-f]{32,64}", l).group(0) for l in body if l.strip().startswith("KEY:"))
    encrypt = section(body, "CIPHER (ENCRYPT)", "INVERSE CIPHER (DECRYPT)")
    decrypt = section(body, "INVERSE CIPHER (DECRYPT)", "EQUIVALENT")
    return {"plaintext": plaintext, "key": key, "encrypt": trace(encrypt), "decrypt": trace(decrypt)}


def xor(a, b):
    return "%0*x" % (len(a), int(a, 16) ^ int(b, 16))


def shift_rows(h):
    """FIPS 197 5.1.2 as a byte move: out[r + 4c] = in[r + 4((c + r) mod 4)]."""
    b = [h[2 * i:2 * i + 2] for i in range(16)]
    return "".join(b[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4))


def require(ok, what):
    if not ok:
        raise SystemExit("FIPS text check failed: " + what)


def check_expansion(e):
    """Each row agrees with its neighbours: temp = w[i-1], wBack = w[i-Nk], w = wBack XOR the last stage."""
    w, nk = e["words"], e["nk"]
    for r in e["rows"]:
        i = r["i"]
        require(r["temp"] == w[i - 1] and r["wBack"] == w[i - nk], f"A row {i} neighbours")
        last = r.get("afterXorWithRcon") or r.get("afterSubWord") or r["temp"]
        require(xor(r["wBack"], last) == r["w"], f"A row {i} final XOR")
        if "rcon" in r:
            require(r["afterRotWord"] == r["temp"][2:] + r["temp"][:2], f"A row {i} RotWord")
            require(xor(r["afterSubWord"], r["rcon"]) == r["afterXorWithRcon"], f"A row {i} Rcon XOR")


def check_cipher(c, nr):
    """Count each tag, then link the values: start = state XOR k_sch, s_row = ShiftRows(s_box), and the inverse mirrors it."""
    enc = {(t["round"], t["tag"]): t["hex"] for t in c["encrypt"]}
    dec = {(t["round"], t["tag"]): t["hex"] for t in c["decrypt"]}
    require(len(enc) == len(c["encrypt"]) == 5 * nr + 2, "C encrypt count")
    require(len(dec) == len(c["decrypt"]) == 5 * nr + 2, "C decrypt count")
    require(enc[(0, "input")] == c["plaintext"] and enc[(0, "k_sch")] == c["key"][:32], "C input and first round key")
    state = xor(enc[(0, "input")], enc[(0, "k_sch")])
    for r in range(1, nr + 1):
        require(enc[(r, "start")] == state, f"C encrypt round {r} start")
        require(shift_rows(enc[(r, "s_box")]) == enc[(r, "s_row")], f"C encrypt round {r} ShiftRows")
        last = enc[(r, "m_col")] if r < nr else enc[(r, "s_row")]
        state = xor(last, enc[(r, "k_sch")])
    require(enc[(nr, "output")] == state, "C encrypt output")
    require(dec[(0, "iinput")] == state, "C decrypt input")
    for r in range(0, nr + 1):
        require(dec[(r, "ik_sch")] == enc[(nr - r, "k_sch")], f"C decrypt round {r} key")
    require(dec[(1, "istart")] == xor(dec[(0, "iinput")], dec[(0, "ik_sch")]), "C decrypt round 1 start")
    for r in range(1, nr + 1):
        require(shift_rows(dec[(r, "is_row")]) == dec[(r, "istart")], f"C decrypt round {r} InvShiftRows")
        require(dec[(r, "is_box")] == enc[(nr - r + 1, "start")], f"C decrypt round {r} InvSubBytes mirrors encrypt")
        added = xor(dec[(r, "is_box")], dec[(r, "ik_sch")])
        if r < nr:
            require(dec[(r, "ik_add")] == added == enc[(nr - r, "m_col")], f"C decrypt round {r} AddRoundKey")
            require(dec[(r + 1, "istart")] == enc[(nr - r, "s_row")], f"C decrypt round {r + 1} start mirrors encrypt")
        else:
            require(dec[(r, "ioutput")] == added == c["plaintext"], "C decrypt output")


def main(upd1_txt, orig_txt, upd1_sha, orig_sha):
    a = read(upd1_txt)
    start = max(i for i, l in enumerate(a) if l.startswith("Appendix A -- Key Expansion Examples"))
    a = a[start:]
    c = read(orig_txt)
    start = max(i for i, l in enumerate(c) if l.startswith("Appendix C - Example Vectors"))
    c = c[start:]
    out = {
        "source": {
            "appendixA": {"document": "NIST FIPS 197-upd1 (2023-05-09)", "url": "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf", "sha256": upd1_sha},
            "appendixC": {"document": "NIST FIPS 197 (2001-11-26)", "url": "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf", "sha256": orig_sha,
                          "note": "FIPS 197-upd1 removed Appendix C (change log item 23). Only CIPHER and INVERSE CIPHER are taken; EQUIVALENT INVERSE CIPHER is left out."},
            "method": "pdftotext 4.06 (xpdf): -layout for Appendix A, -raw for Appendix C. Then test/fips197/extract.py, which links the values with XOR and byte moves only. No value comes from the engine.",
        },
        "keyExpansion": {
            "128": key_expansion(a, "A.1 Expansion of a 128-bit Key", "A.2 Expansion", 4),
            "192": key_expansion(a, "A.2 Expansion of a 192-bit Key", "A.3 Expansion", 6),
            "256": key_expansion(a, "A.3 Expansion of a 256-bit Key", "Appendix B", 8),
        },
        "cipher": {
            "128": cipher_example(c, "C.1 AES-128 (Nk=4, Nr=10)", "C.2 AES-192"),
            "192": cipher_example(c, "C.2 AES-192 (Nk=6, Nr=12)", "C.3 AES-256"),
            "256": cipher_example(c, "C.3 AES-256 (Nk=8, Nr=14)", None),
        },
    }
    for size, nr in (("128", 10), ("192", 12), ("256", 14)):
        check_expansion(out["keyExpansion"][size])
        check_cipher(out["cipher"][size], nr)
    json.dump(out, sys.stdout, indent=1)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main(*sys.argv[1:5])
