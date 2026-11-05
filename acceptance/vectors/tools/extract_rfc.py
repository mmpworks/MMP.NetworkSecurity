"""Builds the RFC-sourced vector files from the RFC text kept in vectors/_cache.

Writes md5-rfc1321.nsv, hmac-rfc4231.nsv, cmac-rfc4493.nsv, hkdf-rfc5869.nsv,
x25519-rfc7748.nsv, ed25519-rfc8032.nsv and dh-group14-rfc3526.nsv.
The RFC text comes from rfc-editor.org (see fetch-sources.ps1 and sources.lock.json).
Only values printed in the RFC go in. Nothing is typed from memory.

Run: python -I extract_rfc.py <cache dir> <out dir>
"""
import os
import re
import sys

HEX = re.compile(r"^[0-9a-fA-F]+$")
CHROME = re.compile(r"\[Page \d+\]|^RFC \d+ |^Nystrom |^Song, |^Krawczyk |^Langley, |^Josefsson |^Rivest |^Kivinen ")


def lines_of(path):
    with open(path, encoding="utf-8") as f:
        return [ln.rstrip("\n").rstrip("\f") for ln in f]


def section(lines, start_pat, end_pat):
    out, on = [], False
    for ln in lines:
        if not on and re.search(start_pat, ln):
            on = True
        elif on and re.search(end_pat, ln):
            break
        if on:
            out.append(ln)
    if not out:
        sys.exit("section not found: " + start_pat)
    return out


def hex_after(lines, i):
    """Hex on the lines after lines[i], up to the first line that is not pure hex (page chrome is skipped)."""
    acc = ""
    j = i + 1
    while j < len(lines):
        s = lines[j].strip()
        if not s or CHROME.search(s):
            if acc and not s:
                # a blank line inside a run only ends it when the next real line is not hex
                k = j + 1
                while k < len(lines) and (not lines[k].strip() or CHROME.search(lines[k].strip())):
                    k += 1
                if k < len(lines) and HEX.match(lines[k].strip().replace(" ", "")) and len(lines[k].strip()) >= 8:
                    j = k
                    continue
                break
            j += 1
            continue
        t = s.replace(" ", "")
        if not HEX.match(t):
            break
        acc += t
        j += 1
    return acc.lower()


def inline_hex(text):
    """Hex tokens on the right of an '=' sign, dropping a trailing (comment)."""
    text = re.sub(r"\(.*?\)", "", text)
    text = text.replace("0x", "")
    return "".join(t for t in text.split() if HEX.match(t)).lower()


def write(path, header, groups):
    out = ["# " + header, ""]
    for name, source, records in groups:
        out += ["[%s]" % name, "# source: " + source, ""]
        for rec in records:
            out += ["%s = %s" % (k, v) for k, v in rec] + [""]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out).rstrip() + "\n")
    print("wrote", os.path.basename(path), sum(len(g[2]) for g in groups), "records")


def md5(cache, out):
    raw = lines_of(os.path.join(cache, "rfc1321.txt"))
    block = section(raw, r"^MD5 test suite:", r"^Security Considerations")[1:]
    joined = "".join(ln for ln in block if ln.strip() and not CHROME.search(ln))
    recs = []
    for piece in joined.split('MD5 ("')[1:]:
        m = re.match(r'^(.*?)"\)\s*=\s*([0-9a-f]{32})', piece)
        if not m:
            sys.exit("md5: cannot parse " + piece[:40])
        recs.append([("msg_ascii_hex", m.group(1).encode("ascii").hex()), ("digest", m.group(2))])
    if len(recs) != 7:
        sys.exit("md5: expected 7 records, got %d" % len(recs))
    write(os.path.join(out, "md5-rfc1321.nsv"), "MD5 test suite, RFC 1321 appendix A.5",
          [("md5", "RFC 1321 appendix A.5", recs)])


def hmac(cache, out):
    lines = lines_of(os.path.join(cache, "rfc4231.txt"))
    groups = {"sha256": [], "sha384": [], "sha512": []}
    starts = [i for i, ln in enumerate(lines) if re.match(r"^4\.\d+\.\s+Test Case \d+", ln)][7:]
    starts = [i for i, ln in enumerate(lines) if re.match(r"^4\.\d+\.\s+Test Case \d+\s*$", ln)]
    for n, s in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else len(lines)
        blk = lines[s:e]
        case = re.search(r"Test Case (\d+)", blk[0]).group(1)

        def field(label, blk=blk):
            for i, ln in enumerate(blk):
                m = re.match(r"^\s+%s(?:\s*=)?\s+(\S.*)$" % re.escape(label), ln)
                if m:
                    acc = inline_hex(m.group(1))
                    declared = re.findall(r"\((\d+) bytes?\)", m.group(1))
                    j = i + 1
                    while j < len(blk) and re.match(r"^\s{10,}\S", blk[j]) and not re.match(r"^\s+(HMAC|Key|Data)", blk[j]):
                        acc += inline_hex(blk[j])
                        declared += re.findall(r"\((\d+) bytes?\)", blk[j])
                        j += 1
                    if declared and len(acc) // 2 != int(declared[-1]):
                        sys.exit("hmac case %s %s: %d bytes read, RFC says %s" % (case, label, len(acc) // 2, declared[-1]))
                    return acc
            return None

        key, data = field("Key"), field("Data")
        for hname, label in (("sha256", "HMAC-SHA-256"), ("sha384", "HMAC-SHA-384"), ("sha512", "HMAC-SHA-512")):
            mac = field(label)
            if mac is None:
                sys.exit("hmac: missing %s in case %s" % (label, case))
            size = {"sha256": 32, "sha384": 48, "sha512": 64}[hname]
            rec = [("key", key), ("data", data), ("truncated_prefix_bytes" if len(mac) // 2 < size else "mac_bytes", str(len(mac) // 2)), ("mac", mac)]
            rec = [r for r in rec if r[0] != "mac_bytes"]
            groups[hname].append([("case", case)] + rec)
    write(os.path.join(out, "hmac-rfc4231.nsv"), "HMAC-SHA-2 test cases, RFC 4231 section 4",
          [("hmac-" + k, "RFC 4231 section 4.2 to 4.8", v) for k, v in groups.items()])


def cmac(cache, out):
    lines = lines_of(os.path.join(cache, "rfc4493.txt"))
    sec = section(lines, r"^4\.  Test Vectors", r"^5\.  Acknowledgement")
    key = None
    for ln in sec:
        m = re.match(r"^   K\s+([0-9a-f ]+)$", ln)
        if m:
            key = m.group(1).replace(" ", "")
            break
    recs = []
    i = 0
    while i < len(sec):
        m = re.match(r"^   Example (\d+): len = (\d+)", sec[i])
        if m:
            msg = ""
            j = i + 1
            while not sec[j].lstrip().startswith("AES-CMAC"):
                row = sec[j]
                if "<empty string>" not in row and row.strip() and not CHROME.search(row):
                    msg += inline_hex(re.sub(r"^\s*M\s+", "", row))
                j += 1
            mac = inline_hex(sec[j].split("AES-CMAC", 1)[1])
            if len(msg) // 2 != int(m.group(2)):
                sys.exit("cmac length mismatch in example " + m.group(1))
            recs.append([("example", m.group(1)), ("key", key), ("msg", msg), ("mac", mac)])
            i = j
        i += 1
    if len(recs) != 4:
        sys.exit("cmac: expected 4 examples")
    write(os.path.join(out, "cmac-rfc4493.nsv"), "AES-CMAC examples, RFC 4493 section 4",
          [("cmac-aes128", "RFC 4493 section 4", recs)])


def hkdf(cache, out):
    lines = lines_of(os.path.join(cache, "rfc5869.txt"))
    sec = section(lines, r"^Appendix A\.  Test Vectors", r"^Appendix B|^Authors")
    groups = {"sha256": [], "sha1": []}
    starts = [i for i, ln in enumerate(sec) if re.match(r"^A\.\d+\.  Test Case \d+", ln)]
    for n, s in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else len(sec)
        blk = sec[s:e]
        vals = {}
        for i, ln in enumerate(blk):
            m = re.match(r"^   (Hash|IKM|salt|info|L|PRK|OKM)\s*=\s*(.*)$", ln)
            if not m:
                continue
            k, rest = m.group(1), m.group(2)
            if k == "Hash":
                vals[k] = rest.strip()
            elif k == "L":
                vals[k] = rest.split()[0]
            else:
                acc = inline_hex(rest.replace("(", " (")) if rest.strip() else ""
                j = i + 1
                while j < len(blk) and re.match(r"^\s{10,}0?x?[0-9a-f]", blk[j]) and not re.match(r"^   [A-Za-z]", blk[j]):
                    acc += inline_hex(blk[j])
                    j += 1
                vals[k] = acc
        if len(vals) != 7:
            sys.exit("hkdf case %d incomplete: %s" % (n + 1, sorted(vals)))
        g = "sha256" if vals["Hash"] == "SHA-256" else "sha1"
        groups[g].append([("case", str(n + 1)), ("ikm", vals["IKM"]), ("salt", vals["salt"]), ("info", vals["info"]),
                          ("length", vals["L"]), ("prk", vals["PRK"]), ("okm", vals["OKM"])])
    write(os.path.join(out, "hkdf-rfc5869.nsv"), "HKDF test cases, RFC 5869 appendix A",
          [("hkdf-" + k, "RFC 5869 appendix A", v) for k, v in groups.items()])


def x25519(cache, out):
    lines = lines_of(os.path.join(cache, "rfc7748.txt"))
    sec = section(lines, r"^5\.2\.  Test Vectors", r"^6\.  Diffie-Hellman")
    recs = []
    i = 0
    while i < len(sec):
        if sec[i].strip() == "X25519:":
            i += 1
            vals = {}
            while i < len(sec) and sec[i].strip() != "X448:":
                t = sec[i].strip()
                if t in ("Input scalar:", "Input u-coordinate:", "Output u-coordinate:"):
                    vals.setdefault(t, []).append(hex_after(sec, i))
                i += 1
            for a, b, c in zip(vals.get("Input scalar:", []), vals.get("Input u-coordinate:", []), vals.get("Output u-coordinate:", [])):
                recs.append([("scalar", a), ("u", b), ("out", c)])
        i += 1
    if len(recs) != 2:
        sys.exit("x25519: expected 2 scalar-mult vectors, got %d" % len(recs))
    iter_text = " ".join(sec)
    one = re.search(r"After one iteration:\s*([0-9a-f ]{64,80})", iter_text)
    thousand = re.search(r"After 1,000 iterations:\s*([0-9a-f ]{64,80})", iter_text)
    start = re.search(r"For X25519:\s*(09[0-9a-f]{62})", iter_text)
    iters = []
    if one and thousand and start:
        k0 = start.group(1)
        iters = [[("k_start", k0), ("u_start", k0), ("iterations", "1"), ("out", one.group(1).replace(" ", "")[:64])],
                 [("k_start", k0), ("u_start", k0), ("iterations", "1000"), ("out", thousand.group(1).replace(" ", "")[:64])]]
    else:
        sys.exit("x25519: iteration vectors not found")
    sec61 = section(lines, r"^6\.1\.  Curve25519", r"^6\.2\.  Curve448")
    dh = {}
    for i, ln in enumerate(sec61):
        for label, name in (("Alice's private key, a:", "a"), ("Alice's public key, X25519(a, 9):", "a_pub"),
                            ("Bob's private key, b:", "b"), ("Bob's public key, X25519(b, 9):", "b_pub"),
                            ("Their shared secret, K:", "k")):
            if ln.strip() == label:
                dh[name] = hex_after(sec61, i)
    if len(dh) != 5:
        sys.exit("x25519: DH vector incomplete")
    write(os.path.join(out, "x25519-rfc7748.nsv"), "X25519, RFC 7748 sections 5.2 and 6.1",
          [("x25519-scalarmult", "RFC 7748 section 5.2", recs), ("x25519-iterated", "RFC 7748 section 5.2", iters),
           ("x25519-dh", "RFC 7748 section 6.1", [[(k, dh[k]) for k in ("a", "a_pub", "b", "b_pub", "k")]])])


def ed25519(cache, out):
    lines = lines_of(os.path.join(cache, "rfc8032.txt"))
    sec = section(lines, r"^7\.1\.  Test Vectors for Ed25519", r"^7\.2\.  Test Vectors for Ed25519ctx")
    recs = []
    starts = [i for i, ln in enumerate(sec) if ln.strip().startswith("-----TEST")]
    for n, s in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else len(sec)
        blk = sec[s:e]
        name = blk[0].strip().replace("-----", "")
        vals = {"message": ""}
        for i, ln in enumerate(blk):
            t = ln.strip()
            if t == "SECRET KEY:":
                vals["seed"] = hex_after(blk, i)
            elif t == "PUBLIC KEY:":
                vals["public"] = hex_after(blk, i)
            elif t == "SIGNATURE:":
                vals["signature"] = hex_after(blk, i)
            elif t.startswith("MESSAGE (length"):
                n_bytes = int(re.search(r"length (\d+) byte", t).group(1))
                vals["message"] = hex_after(blk, i) if n_bytes else ""
                vals["message_bytes"] = n_bytes
        if len(vals["message"]) // 2 != vals["message_bytes"]:
            sys.exit("ed25519 %s: message is %d bytes, header says %d" % (name, len(vals["message"]) // 2, vals["message_bytes"]))
        recs.append([("test", name), ("seed", vals["seed"]), ("public", vals["public"]), ("message", vals["message"]), ("signature", vals["signature"])])
    if len(recs) < 5:
        sys.exit("ed25519: expected 5 tests, got %d" % len(recs))
    write(os.path.join(out, "ed25519-rfc8032.nsv"), "Ed25519 test vectors, RFC 8032 section 7.1",
          [("ed25519", "RFC 8032 section 7.1", recs)])


def modp14(cache, out):
    lines = lines_of(os.path.join(cache, "rfc3526.txt"))
    sec = section(lines, r"^3\.  2048-bit MODP Group", r"^4\.  3072-bit MODP Group")
    i = next(k for k, ln in enumerate(sec) if "Its hexadecimal value is:" in ln)
    prime = ""
    for ln in sec[i + 1:]:
        if "The generator is" in ln:
            break
        if CHROME.search(ln) or not ln.strip():
            continue
        prime += ln.replace(" ", "").strip()
    if len(prime) != 512 or not HEX.match(prime):
        sys.exit("modp14 prime has %d hex digits" % len(prime))
    write(os.path.join(out, "dh-group14-rfc3526.nsv"), "Diffie-Hellman group 14 parameters, RFC 3526 section 3",
          [("dh-group14-params", "RFC 3526 section 3 (2048-bit MODP group, id 14)", [[("p", prime.lower()), ("g", "02")]])])


def hmac2202(cache, out):
    """HMAC-MD5 and HMAC-SHA-1 test cases of RFC 2202. Values are hex, quoted text, or 'hex repeated N times'."""
    lines = lines_of(os.path.join(cache, "rfc2202.txt"))
    groups = {"md5": [], "sha1": []}
    cur = None
    cases = {"md5": [], "sha1": []}
    body = {}
    for ln in lines:
        if re.match(r"^2\. Test Cases for HMAC-MD5", ln):
            cur = "md5"
        elif re.match(r"^3\. Test Cases for HMAC-SHA-1", ln):
            cur = "sha1"
        elif re.match(r"^4\. ", ln):
            cur = None
        if cur is None or CHROME.search(ln) or ln.startswith("Cheng"):
            continue
        if re.match(r"^test_case\s*=", ln):
            body = {"text": []}
            cases[cur].append(body)
        elif cases[cur]:
            cases[cur][-1]["text"].append(ln)

    def value(text_lines, name):
        joined = " ".join(l.strip() for l in text_lines)
        m = re.search(r"\b%s\s*=?\s+(.*?)(?=\s+(?:key_len|data|data_len|digest|digest-96)\b|$)" % name, joined)
        if not m:
            return None
        raw = m.group(1).strip()
        rep = re.match(r"^0x([0-9a-f]{2}) repeated (\d+) times$", raw)
        if rep:
            return rep.group(1) * int(rep.group(2))
        if raw.startswith('"'):
            return raw.strip('"').encode("ascii").hex()
        if raw.startswith("0x"):
            return raw[2:].lower()
        return None

    for kind in ("md5", "sha1"):
        for n, case in enumerate(cases[kind]):
            t = case["text"]
            key, data, digest = value(t, "key"), value(t, "data"), value(t, "digest")
            joined = " ".join(l.strip() for l in t)
            key_len = int(re.search(r"key_len\s*=?\s+(\d+)", joined).group(1))
            data_len = int(re.search(r"data_len\s*=?\s+(\d+)", joined).group(1))
            if len(key) // 2 != key_len or len(data) // 2 != data_len:
                sys.exit("rfc2202 %s case %d: length mismatch (key %d vs %d, data %d vs %d)" % (kind, n + 1, len(key) // 2, key_len, len(data) // 2, data_len))
            rec = [("case", str(n + 1)), ("key", key), ("data", data), ("mac", digest)]
            groups[kind].append(rec)
    write(os.path.join(out, "hmac-rfc2202.nsv"), "HMAC-MD5 and HMAC-SHA-1 test cases, RFC 2202 sections 2 and 3",
          [("hmac-" + k, "RFC 2202 section %s" % ("2" if k == "md5" else "3"), v) for k, v in groups.items()])


if __name__ == "__main__":
    cache, out = sys.argv[1], sys.argv[2]
    hmac2202(cache, out)
    for fn in (md5, hmac, cmac, hkdf, x25519, ed25519, modp14):
        fn(cache, out)
