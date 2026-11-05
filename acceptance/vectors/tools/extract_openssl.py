"""Builds rsa-openssl.nsv and dh-group14-openssl.nsv from the OpenSSL referee.

These known answers come from OpenSSL 3.5.7 (C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe), the
referee named in the PRD (D10). PKCS#1 v1.5 signatures are deterministic, so a signature made by
OpenSSL is a known answer for our signer. An RSA ciphertext made by OpenSSL is a known answer for our
decryptor. Diffie-Hellman group 14 values come from `openssl pkey` and `openssl pkeyutl -derive`
with fixed private values. The group prime itself is in dh-group14-rfc3526.nsv (RFC 3526, section 3).

The output files are committed. Re-running makes new RSA keys, so do it only to renew the vectors.

Run: python -I extract_openssl.py <openssl.exe> <rfc3526 vectors file> <out dir>
"""
import hashlib
import os
import re
import subprocess
import sys
import tempfile


def run(openssl, args, **kw):
    r = subprocess.run([openssl] + args, capture_output=True, **kw)
    if r.returncode != 0:
        sys.exit("openssl %s failed: %s" % (" ".join(args), r.stderr.decode("utf-8", "replace")))
    return r.stdout


def hexdump_field(text, label):
    """Hex bytes printed under 'label:' in `openssl pkey -text` output (colon separated, wrapped)."""
    text = text.replace("\r", "")
    m = re.search(r"^%s:\s*\n((?:\s+[0-9a-f:]+\n)+)" % re.escape(label), text, re.M)
    if not m:
        sys.exit("field not found: " + label)
    return "".join(m.group(1).split()).replace(":", "")


def strip_zero(h):
    return h[2:] if h.startswith("00") and len(h) % 2 == 0 and len(h) > 2 else h


def write(path, header, groups):
    out = ["# " + header, ""]
    for name, source, records in groups:
        out += ["[%s]" % name, "# source: " + source, ""]
        for rec in records:
            out += ["%s = %s" % (k, v) for k, v in rec] + [""]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out).rstrip() + "\n")
    print("wrote", os.path.basename(path), sum(len(g[2]) for g in groups), "records")


def rsa(openssl, out_dir, tmp):
    version = run(openssl, ["version"]).decode().strip()
    messages = [b"abc", b"MMP.NetworkSecurity acceptance message", bytes(range(100))]
    sign_recs, dec_recs = [], []
    for bits in (1024, 2048):
        key = os.path.join(tmp, "rsa%d.pem" % bits)
        run(openssl, ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:%d" % bits, "-out", key])
        text = run(openssl, ["pkey", "-in", key, "-text", "-noout"]).decode()
        n = strip_zero(hexdump_field(text, "modulus"))
        d = strip_zero(hexdump_field(text, "privateExponent"))
        e = "010001"
        if "65537" not in text:
            sys.exit("unexpected public exponent")
        for i, msg in enumerate(messages):
            mpath = os.path.join(tmp, "m%d.bin" % i)
            with open(mpath, "wb") as f:
                f.write(msg)
            for h in ("sha1", "sha256"):
                sig = run(openssl, ["dgst", "-" + h, "-sign", key, mpath])
                sign_recs.append([("bits", str(bits)), ("n", n), ("e", e), ("d", d), ("hash", h), ("message", msg.hex()), ("signature", sig.hex())])
            if len(msg) < bits // 8 - 11:
                ct = run(openssl, ["pkeyutl", "-encrypt", "-inkey", key, "-pkeyopt", "rsa_padding_mode:pkcs1", "-in", mpath])
                dec_recs.append([("bits", str(bits)), ("n", n), ("e", e), ("d", d), ("ciphertext", ct.hex()), ("plaintext", msg.hex())])
    cmd = "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:N; openssl dgst -sha1|-sha256 -sign key m; openssl pkeyutl -encrypt -pkeyopt rsa_padding_mode:pkcs1"
    write(os.path.join(out_dir, "rsa-openssl.nsv"), "RSA PKCS#1 v1.5 known answers produced by " + version,
          [("rsa-sign", "produced by " + version + " (" + cmd + ")", sign_recs),
           ("rsa-decrypt", "produced by " + version + " (" + cmd + ")", dec_recs)])


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der(tag, body):
    return bytes([tag]) + der_len(len(body)) + body


def der_int(v):
    b = v.to_bytes((v.bit_length() + 8) // 8, "big")
    return der(0x02, b)


def dh(openssl, rfc_file, out_dir, tmp):
    version = run(openssl, ["version"]).decode().strip()
    text = open(rfc_file, encoding="utf-8").read()
    p = int(re.search(r"^p = ([0-9a-f]+)$", text, re.M).group(1), 16)
    g = 2
    oid = bytes.fromhex("06092a864886f70d010301")
    params = der(0x30, der_int(p) + der_int(g))
    recs = []
    labels = [b"MMP.NetworkSecurity acceptance dh a", b"MMP.NetworkSecurity acceptance dh b", b"MMP.NetworkSecurity acceptance dh c"]
    xs = [int(hashlib.sha512(l).hexdigest(), 16) for l in labels]        # 512-bit private values, like the device
    keys = []
    for i, x in enumerate(xs):
        pk = der(0x30, der_int(0) + der(0x30, oid + params) + der(0x04, der_int(x)))
        path = os.path.join(tmp, "dh%d.der" % i)
        with open(path, "wb") as f:
            f.write(pk)
        pub_pem = os.path.join(tmp, "dh%d_pub.pem" % i)
        run(openssl, ["pkey", "-in", path, "-inform", "DER", "-pubout", "-out", pub_pem])
        info = run(openssl, ["pkey", "-in", path, "-inform", "DER", "-text", "-noout"]).decode()
        pub = hexdump_field(info, "public-key")
        keys.append((x, path, pub_pem, strip_zero(pub)))
    for a, b in ((0, 1), (1, 2), (2, 0)):
        xa, pa, _, ya = keys[a]
        xb, pb, pub_b, yb = keys[b]
        shared = run(openssl, ["pkeyutl", "-derive", "-inkey", pa, "-keyform", "DER", "-peerkey", pub_b])
        recs.append([("x_a", "%0128x" % xa), ("y_a", ya.rjust(512, "0")), ("y_b", yb.rjust(512, "0")), ("shared", shared.hex())])
    write(os.path.join(out_dir, "dh-group14-openssl.nsv"), "Diffie-Hellman group 14 known answers produced by " + version,
          [("dh-group14", "produced by " + version + " (openssl pkey -pubout/-text; openssl pkeyutl -derive); p and g from RFC 3526 section 3", recs)])


if __name__ == "__main__":
    openssl, rfc_file, out_dir = sys.argv[1], sys.argv[2], sys.argv[3]
    with tempfile.TemporaryDirectory() as tmp:
        rsa(openssl, out_dir, tmp)
        dh(openssl, rfc_file, out_dir, tmp)
