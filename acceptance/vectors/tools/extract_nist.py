"""Builds the NIST-sourced vector files from the files kept in vectors/_cache.

Sources (all fetched by fetch-sources.ps1, hashes in sources.lock.json):
  fips-197-2001.pdf        FIPS 197 appendix C, AES-128/192/256 example vectors
  sp800-38a.pdf            SP 800-38A appendix F, ECB, CBC and CTR examples
  shabytetestvectors.zip   CAVP SHA-1 and SHA-2 byte-oriented vectors
  sha-3bytetestvectors.zip CAVP SHA-3 byte-oriented vectors
  shakebytetestvectors.zip CAVP SHAKE byte-oriented vectors
  gcmtestvectors.zip       CAVP AES-GCM vectors
  KAT_TDES.zip             CAVP TDES known-answer tests, ECB mode

Run: python -I extract_nist.py <cache dir> <out dir>
"""
import os
import re
import subprocess
import sys
import zipfile

LONG_KEEP = 3          # long-message records kept per file. The full files run to megabytes.
GCM_PER_GROUP = 2      # records kept per (key length, text length, aad length) group


def write(path, header, groups):
    out = ["# " + header, ""]
    for name, source, records in groups:
        out += ["[%s]" % name, "# source: " + source, ""]
        for rec in records:
            out += ["%s = %s" % (k, v) for k, v in rec] + [""]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out).rstrip() + "\n")
    print("wrote", os.path.basename(path), sum(len(g[2]) for g in groups), "records")


def pdf_text(path):
    out = subprocess.run(["pdftotext", "-layout", path, "-"], capture_output=True, text=True, encoding="utf-8", errors="replace", check=True).stdout
    return out.replace(chr(12), chr(10))


def zip_member(cache, zip_name, member):
    with zipfile.ZipFile(os.path.join(cache, zip_name)) as z:
        names = [n for n in z.namelist() if n.endswith("/" + member) or n == member]
        if len(names) != 1:
            sys.exit("%s: member %s matched %s" % (zip_name, member, names))
        return z.read(names[0]).decode("ascii").replace("\r\n", "\n")


def aes_fips197(cache, out):
    text = pdf_text(os.path.join(cache, "fips-197-2001.pdf"))
    recs = []
    parts = re.split(r"\n(?=C\.\d AES-\d+ \(Nk=)", text)[1:]
    for part in parts:
        head = re.match(r"C\.(\d) AES-(\d+)", part)
        pt = re.search(r"PLAINTEXT:\s*([0-9a-f]{32})", part).group(1)
        key = re.search(r"KEY:\s*([0-9a-f]{32,64})", part).group(1)
        cipher_part = part.split("INVERSE CIPHER")[0]
        final = re.findall(r"round\[\s*\d+\]\.output\s+([0-9a-f]{32})", cipher_part)[-1]
        if len(key) * 4 != int(head.group(2)):
            sys.exit("fips197: key length does not match header " + head.group(0))
        recs.append([("example", "C." + head.group(1)), ("key", key), ("plaintext", pt), ("ciphertext", final)])
    if len(recs) != 3:
        sys.exit("fips197: expected 3 examples, got %d" % len(recs))
    write(os.path.join(out, "aes-fips197.nsv"), "AES block examples, FIPS 197 (2001) appendix C",
          [("aes-block", "FIPS 197 appendix C.1 to C.3", recs)])


def fips197_box(text, figure):
    """The 16 rows above a figure caption: a row label, then 16 hex bytes."""
    head = text[:text.index(figure, text.index("5.1 Cipher"))]
    rows = re.findall(r"^\s*(?P<row>[0-9a-f])\s+(?P<cells>(?:[0-9a-f]{2}\s+){15}[0-9a-f]{2})\s*$", head, re.M)[-16:]
    if [r[0] for r in rows] != list("0123456789abcdef"):
        sys.exit("fips197: bad table above " + figure)
    return "".join("".join(r[1].split()) for r in rows)


def fips197_key_rows(section, nk, name):
    """One record per word w[i] with i >= Nk. A row prints w[i] on a neighbouring line, so w[i] is read as the temp of row i+1. The last word is temp xor w[i-Nk]."""
    rows = {}
    for m in re.finditer(r"^\s*(?P<i>\d{1,2}) (?P<words>[0-9a-f]{8}(?:\s+[0-9a-f]{8})*)\s*$", section, re.M):
        rows[int(m.group("i"))] = m.group("words").split()
    first, last = nk, max(rows)
    if sorted(rows) != list(range(first, last + 1)):
        sys.exit("fips197: %s rows are not contiguous" % name)
    recs = []
    for i in range(first, last + 1):
        w = rows[i]
        rec = [("example", name), ("nk", str(nk)), ("i", str(i)), ("temp", w[0])]
        if i % nk == 0:
            rec += [("rot", w[1]), ("sub", w[2]), ("rcon", w[3]), ("after", w[4])]
            before, back = w[4], w[5]
        elif nk > 6 and i % nk == 4:
            rec += [("sub", w[1])]
            before, back = w[1], w[2]
        else:
            before, back = w[0], w[1]
        word = rows[i + 1][0] if i < last else "%08x" % (int(before, 16) ^ int(back, 16))
        if int(word, 16) != int(before, 16) ^ int(back, 16):
            sys.exit("fips197: %s row %d does not add up" % (name, i))
        if i == last and word not in section:
            sys.exit("fips197: %s last word %s is not in the text" % (name, word))
        recs.append(rec + [("keyback", back), ("word", word)])
    return recs


def aes_fips197_rounds(cache, out):
    """Every listed value of the CIPHER and INVERSE CIPHER runs (appendix C), the key rows (appendix A), and both S-box tables (figures 7 and 14). The EQUIVALENT INVERSE CIPHER runs hold another order and stay out."""
    text = pdf_text(os.path.join(cache, "fips-197-2001.pdf"))
    groups = []
    rounds = []
    for part in re.split(r"\n(?=C\.\d AES-\d+ \(Nk=)", text)[1:]:
        example = "C." + part[2]
        key = re.search(r"KEY:\s*(?P<key>[0-9a-f]{32,64})", part).group("key")
        # pdftotext prints some values one line above their label (C.2 and C.3 start on the CIPHER heading line). So the n-th value belongs to the n-th label, read by position.
        start = re.search(r"CIPHER\s+\(ENCRYPT\):", part).start()
        encrypt = part[start:part.index("INVERSE CIPHER (DECRYPT)")]
        inverse = part[part.index("INVERSE CIPHER (DECRYPT)"):re.search(r"EQUIVALENT\s+INVERSE", part).start()]
        for direction, body in (("encrypt", encrypt), ("inverse", inverse)):
            labels = re.findall(r"round\[\s*(?P<r>\d+)\]\.(?P<label>\w+)", body)
            values = re.findall(r"\b[0-9a-f]{32}\b", body)
            if len(labels) != len(values):
                sys.exit("fips197: %s %s has %d labels and %d values" % (example, direction, len(labels), len(values)))
            for (r, label), value in zip(labels, values):
                rounds.append([("example", example), ("key", key), ("direction", direction), ("round", r), ("label", label), ("value", value)])
    if len(rounds) != 372:
        sys.exit("fips197: expected 372 round values, got %d" % len(rounds))
    groups.append(("round-values", "FIPS 197 (2001) appendix C.1 to C.3, CIPHER and INVERSE CIPHER runs", rounds))
    words = []
    a1, a2, a3 = text.index("\nA.1 Expansion"), text.index("\nA.2 Expansion"), text.index("\nA.3 Expansion")
    end = text.index("Appendix B - Cipher Example", a3)
    for name, nk, section in (("A.1", 4, text[a1:a2]), ("A.2", 6, text[a2:a3]), ("A.3", 8, text[a3:end])):
        key = "".join(re.search(r"Cipher Key =\s*(?P<k>(?:[0-9a-f]{2}\s+)+)", section).group("k").split())
        rows = fips197_key_rows(section, nk, name)
        words += [[("key", key)] + r for r in rows]
    groups.append(("key-rows", "FIPS 197 (2001) appendix A.1 to A.3", words))
    sbox = fips197_box(text, "Figure 7. S-box:")
    inverse = fips197_box(text, "Figure 14. Inverse S-box:")
    groups.append(("tables", "FIPS 197 (2001) figures 7 and 14", [[("table", "sbox"), ("value", sbox)], [("table", "inverse"), ("value", inverse)]]))
    write(os.path.join(out, "aes-fips197-rounds.nsv"), "AES round values, key rows and S-box tables, FIPS 197 (2001). Data only: no product code computes a value here", groups)


def aes_modes(cache, out):
    text = pdf_text(os.path.join(cache, "sp800-38a.pdf"))
    groups = {"ecb": [], "cbc": [], "ctr": []}
    pat = re.compile(r"^F\.\d\.\d\s+(ECB|CBC|CTR)-AES(\d+)\.Encrypt\s*$", re.M)
    marks = list(pat.finditer(text))
    for n, m in enumerate(marks):
        end = marks[n + 1].start() if n + 1 < len(marks) else len(text)
        # the section ends at the matching Decrypt header
        body = text[m.end():end]
        body = re.split(r"^F\.\d\.\d\s+\w+-AES\d+\.Decrypt", body, flags=re.M)[0]
        mode = m.group(1).lower()
        if mode == "cbc" and m.group(2) == "256":
            # pdftotext scrambles the page break inside F.2.5 (key, IV and plaintext rows trade places).
            # No value is guessed. CBC-AES256 stays out; ECB-256, CTR-256 and FIPS 197 C.3 cover the AES-256 core.
            print("skip F.2.5 CBC-AES256: page layout scrambled in the PDF text")
            continue
        key = ""
        rows = body.splitlines()
        for idx, row in enumerate(rows):
            km = re.match(r"^Key\s+([0-9a-f]+)\s*$", row)
            if km:
                key = km.group(1)
                for nxt in rows[idx + 1:]:      # a 256-bit key wraps onto an indented second line
                    if not nxt.strip():
                        continue
                    if re.match(r"^\s+[0-9a-f]{16,}\s*$", nxt):
                        key += nxt.strip()
                    else:
                        break
                break
        iv = None
        if mode == "cbc":
            iv = re.search(r"^IV\s+([0-9a-f]{32})", body, re.M).group(1)
        if mode == "ctr":
            iv = re.search(r"^Init\. Counter\s+([0-9a-f]{32})", body, re.M).group(1)
        pts = re.findall(r"^Plaintext\s+([0-9a-f]{32})", body, re.M)
        cts = re.findall(r"^Ciphertext\s+([0-9a-f]{32})", body, re.M)
        if len(pts) != 4 or len(cts) != 4 or len(key) * 4 != int(m.group(2)):
            sys.exit("sp800-38a: odd section %s-AES%s: key bits %d, %d plaintexts, %d ciphertexts" % (m.group(1), m.group(2), len(key) * 4, len(pts), len(cts)))
        rec = [("key", key)] + ([("iv", iv)] if iv else []) + [("plaintext", "".join(pts)), ("ciphertext", "".join(cts))]
        groups[mode].append(rec)
    if {k: len(v) for k, v in groups.items()} != {"ecb": 3, "cbc": 2, "ctr": 3}:
        sys.exit("sp800-38a: expected 3 key sizes per mode, got %s" % {k: len(v) for k, v in groups.items()})
    write(os.path.join(out, "aes-modes-sp800-38a.nsv"), "AES ECB, CBC and CTR examples, SP 800-38A appendix F",
          [("aes-" + k, "SP 800-38A appendix F.%s (AES-128, AES-192, AES-256)" % {"ecb": "1", "cbc": "2", "ctr": "5"}[k], v) for k, v in groups.items()])


def parse_rsp(text):
    """Records of a CAVP .rsp file: list of (header dict, record dict)."""
    header, rec, out = {}, {}, []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            if rec:
                out.append((dict(header), rec))
                rec = {}
            continue
        m = re.match(r"^\[(.+?)\s*=\s*(.+?)\]$", ln)
        if m:
            if rec:
                out.append((dict(header), rec))
                rec = {}
            header[m.group(1)] = m.group(2)
            continue
        m = re.match(r"^\[(\w+)\]$", ln)
        if m:
            if rec:
                out.append((dict(header), rec))
                rec = {}
            header = {"section": m.group(1)}
            continue
        if ln.startswith("["):
            continue
        k, _, v = ln.partition("=")
        rec[k.strip()] = v.strip()
    if rec:
        out.append((dict(header), rec))
    return out


def sha(cache, out):
    groups = []
    for name, fname in (("sha1", "SHA1"), ("sha256", "SHA256"), ("sha384", "SHA384"), ("sha512", "SHA512")):
        recs = []
        for kind, keep in (("ShortMsg", None), ("LongMsg", LONG_KEEP)):
            data = parse_rsp(zip_member(cache, "shabytetestvectors.zip", "%s%s.rsp" % (fname, kind)))
            for i, (_, r) in enumerate(data):
                if keep is not None and i >= keep:
                    break
                msg = "" if r["Len"] == "0" else r["Msg"]
                if len(msg) * 4 != int(r["Len"]):
                    sys.exit("%s%s: Len %s but Msg has %d bits" % (fname, kind, r["Len"], len(msg) * 4))
                recs.append([("set", kind), ("bits", r["Len"]), ("msg", msg), ("digest", r["MD"])])
        groups.append((name, "NIST CAVP SHA byte-oriented vectors, %sShortMsg and %sLongMsg (first %d)" % (fname, fname, LONG_KEEP), recs))
    write(os.path.join(out, "sha-cavp.nsv"), "SHA-1 and SHA-2 vectors, NIST CAVP shabytetestvectors", groups)


def sha3(cache, out):
    groups = []
    for name, fname in (("sha3-256", "SHA3_256"), ("sha3-512", "SHA3_512")):
        recs = []
        for kind, keep in (("ShortMsg", None), ("LongMsg", LONG_KEEP)):
            for i, (_, r) in enumerate(parse_rsp(zip_member(cache, "sha-3bytetestvectors.zip", "%s%s.rsp" % (fname, kind)))):
                if keep is not None and i >= keep:
                    break
                msg = "" if r["Len"] == "0" else r["Msg"]
                recs.append([("set", kind), ("bits", r["Len"]), ("msg", msg), ("digest", r["MD"])])
        groups.append((name, "NIST CAVP SHA-3 byte-oriented vectors, %sShortMsg and %sLongMsg" % (fname, fname), recs))
    for name, fname in (("shake128", "SHAKE128"), ("shake256", "SHAKE256")):
        recs = []
        for i, (_, r) in enumerate(parse_rsp(zip_member(cache, "shakebytetestvectors.zip", fname + "ShortMsg.rsp"))):
            msg = "" if r["Len"] == "0" else r["Msg"]
            recs.append([("set", "ShortMsg"), ("bits", r["Len"]), ("msg", msg), ("out_bytes", str(len(r["Squeezed" if "Squeezed" in r else "Output"]) // 2)),
                         ("output", r["Squeezed" if "Squeezed" in r else "Output"])])
        for i, (h, r) in enumerate(parse_rsp(zip_member(cache, "shakebytetestvectors.zip", fname + "VariableOut.rsp"))):
            if i >= 40:
                break
            bits = h["Input Length"]
            msg = "" if bits == "0" else r["Msg"]
            out_key = "Squeezed" if "Squeezed" in r else "Output"
            recs.append([("set", "VariableOut"), ("bits", bits), ("msg", msg), ("out_bytes", str(len(r[out_key]) // 2)), ("output", r[out_key])])
        groups.append((name, "NIST CAVP SHAKE byte-oriented vectors, %sShortMsg and %sVariableOut (first 40)" % (fname, fname), recs))
    write(os.path.join(out, "sha3-cavp.nsv"), "SHA-3 and SHAKE vectors, NIST CAVP", groups)


def gcm(cache, out):
    seal, fail = [], []
    for size in (128, 192, 256):
        seen = {}
        for h, r in parse_rsp(zip_member(cache, "gcmtestvectors.zip", "gcmEncryptExtIV%d.rsp" % size)):
            if h.get("IVlen") != "96" or h.get("Taglen") != "128":
                continue
            grp = (size, h["PTlen"], h["AADlen"])
            if seen.get(grp, 0) >= GCM_PER_GROUP:
                continue
            seen[grp] = seen.get(grp, 0) + 1
            seal.append([("key", r["Key"]), ("iv", r["IV"]), ("aad", r.get("AAD", "")), ("plaintext", r.get("PT", "")), ("ciphertext", r.get("CT", "")), ("tag", r["Tag"])])
        seen_ok, seen_bad = {}, {}
        for h, r in parse_rsp(zip_member(cache, "gcmtestvectors.zip", "gcmDecrypt%d.rsp" % size)):
            if h.get("IVlen") != "96" or h.get("Taglen") != "128":
                continue
            grp = (size, h["PTlen"], h["AADlen"])
            bad = "FAIL" in r
            bucket = seen_bad if bad else seen_ok
            if bucket.get(grp, 0) >= GCM_PER_GROUP:
                continue
            bucket[grp] = bucket.get(grp, 0) + 1
            if bad:
                fail.append([("key", r["Key"]), ("iv", r["IV"]), ("aad", r.get("AAD", "")), ("ciphertext", r.get("CT", "")), ("tag", r["Tag"])])
            else:
                seal.append([("key", r["Key"]), ("iv", r["IV"]), ("aad", r.get("AAD", "")), ("plaintext", r.get("PT", "")), ("ciphertext", r.get("CT", "")), ("tag", r["Tag"])])
    write(os.path.join(out, "gcm-cavp.nsv"), "AES-GCM vectors, NIST CAVP gcmtestvectors (IV 96 bits, tag 128 bits)",
          [("gcm-seal", "NIST CAVP gcmEncryptExtIV and gcmDecrypt (valid records), first %d per group" % GCM_PER_GROUP, seal),
           ("gcm-open-fail", "NIST CAVP gcmDecrypt, records marked FAIL", fail)])


def tdes_records(text, fname, keep):
    """ENCRYPT and DECRYPT records of one TDES ECB file. A KEYs field is one DES key used three times."""
    enc, dec, section, rec, seen = [], [], None, {}, {"ENCRYPT": 0, "DECRYPT": 0}

    def flush():
        if not (rec and section):
            return
        if keep is not None and seen[section] >= keep:
            return
        seen[section] += 1
        key = rec["KEYs"] * 3 if "KEYs" in rec else rec["KEY1"] + rec["KEY2"] + rec["KEY3"]
        if section == "ENCRYPT":
            enc.append([("file", fname), ("key", key), ("plaintext", rec["PLAINTEXT"]), ("ciphertext", rec["CIPHERTEXT"])])
        else:
            dec.append([("file", fname), ("key", key), ("ciphertext", rec["CIPHERTEXT"]), ("plaintext", rec["PLAINTEXT"])])

    for ln in text.splitlines() + [""]:
        ln = ln.strip()
        if ln in ("[ENCRYPT]", "[DECRYPT]"):
            flush()
            rec = {}
            section = ln.strip("[]")
            continue
        if not ln or ln.startswith("#"):
            flush()
            rec = {}
            continue
        k, _, v = ln.partition("=")
        rec[k.strip()] = v.strip()
    return enc, dec


def tdes(cache, out):
    enc, dec = [], []
    for fname in ("TECBvarkey", "TECBvartext", "TECBpermop", "TECBsubtab", "TECBinvperm"):
        e, d = tdes_records(zip_member(cache, "KAT_TDES.zip", fname + ".rsp"), fname, None)
        enc += e
        dec += d
    mmt_enc, mmt_dec = [], []
    for fname in ("TECBMMT2", "TECBMMT3"):
        e, d = tdes_records(zip_member(cache, "tdesmmt.zip", fname + ".rsp"), fname, 25)
        mmt_enc += e
        mmt_dec += d
    write(os.path.join(out, "tdes-cavp.nsv"), "Triple DES ECB known answers, NIST CAVP (key = KEY1|KEY2|KEY3, 24 bytes; text is one or more 8-byte blocks)",
          [("tdes-ecb-encrypt-kat", "NIST CAVP KAT_TDES TECB*.rsp [ENCRYPT] (one DES key used three times)", enc),
           ("tdes-ecb-decrypt-kat", "NIST CAVP KAT_TDES TECB*.rsp [DECRYPT] (one DES key used three times)", dec),
           ("tdes-ecb-encrypt-mmt", "NIST CAVP tdesmmt TECBMMT2.rsp and TECBMMT3.rsp [ENCRYPT], first 25 each", mmt_enc),
           ("tdes-ecb-decrypt-mmt", "NIST CAVP tdesmmt TECBMMT2.rsp and TECBMMT3.rsp [DECRYPT], first 25 each", mmt_dec)])


if __name__ == "__main__":
    cache, out = sys.argv[1], sys.argv[2]
    for fn in (aes_fips197, aes_fips197_rounds, aes_modes, sha, sha3, gcm, tdes):
        fn(cache, out)
