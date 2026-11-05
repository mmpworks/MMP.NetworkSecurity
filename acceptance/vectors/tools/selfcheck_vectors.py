"""Checks the vector files that the BCL cannot check, with a second implementation (python "cryptography").

Covers X25519, Ed25519, TDES, RSA (public side) and Diffie-Hellman group 14. If a vector fails here, the
extraction is wrong, not the product. run.ps1 runs this as clause SELF.vectors-python.

Run: python -I selfcheck_vectors.py <vectors dir>
"""
import os
import re
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers import Cipher, modes

try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:                                    # older cryptography
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES


def load(directory, name):
    """Returns {group: [record dict, ...]} for one .nsv file."""
    groups, cur, rec = {}, None, None
    for raw in open(os.path.join(directory, name), encoding="utf-8").read().split("\n"):
        ln = raw.strip()
        if not ln:
            rec = None
        elif ln.startswith("["):
            cur = ln[1:-1]
            groups[cur] = []
            rec = None
        elif ln.startswith("#"):
            continue
        else:
            k, _, v = ln.partition("=")
            if rec is None:
                rec = {}
                groups[cur].append(rec)
            rec[k.strip()] = v.strip()
    return groups


def main(d):
    checked = {}

    def ok(name):
        checked[name] = checked.get(name, 0) + 1

    g = load(d, "x25519-rfc7748.nsv")
    for r in g["x25519-scalarmult"]:
        priv = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(r["scalar"]))
        out = priv.exchange(x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(r["u"])))
        assert out.hex() == r["out"], "x25519 scalarmult"
        ok("x25519")
    for r in g["x25519-dh"]:
        a = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(r["a"]))
        b = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(r["b"]))
        from cryptography.hazmat.primitives import serialization as s
        raw = lambda k: k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex()
        assert raw(a) == r["a_pub"] and raw(b) == r["b_pub"], "x25519 dh public"
        assert a.exchange(b.public_key()).hex() == r["k"], "x25519 dh secret"
        ok("x25519")
    for r in g["x25519-iterated"]:
        k = u = bytes.fromhex(r["k_start"])
        for _ in range(int(r["iterations"])):
            nxt = x25519.X25519PrivateKey.from_private_bytes(k).exchange(x25519.X25519PublicKey.from_public_bytes(u))
            u, k = k, nxt
        assert k.hex() == r["out"], "x25519 iterated"
        ok("x25519")

    from cryptography.hazmat.primitives import serialization as ser
    for r in load(d, "ed25519-rfc8032.nsv")["ed25519"]:
        key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(r["seed"]))
        assert key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw).hex() == r["public"], "ed25519 public"
        msg = bytes.fromhex(r["message"])
        assert key.sign(msg).hex() == r["signature"], "ed25519 signature"
        key.public_key().verify(bytes.fromhex(r["signature"]), msg)
        ok("ed25519")

    t = load(d, "tdes-cavp.nsv")
    for grp, enc in (("tdes-ecb-encrypt-kat", True), ("tdes-ecb-encrypt-mmt", True), ("tdes-ecb-decrypt-kat", False), ("tdes-ecb-decrypt-mmt", False)):
        for r in t[grp]:
            c = Cipher(TripleDES(bytes.fromhex(r["key"])), modes.ECB())
            if enc:
                x = c.encryptor()
                assert (x.update(bytes.fromhex(r["plaintext"])) + x.finalize()).hex() == r["ciphertext"], "tdes encrypt " + r["file"]
            else:
                x = c.decryptor()
                assert (x.update(bytes.fromhex(r["ciphertext"])) + x.finalize()).hex() == r["plaintext"], "tdes decrypt " + r["file"]
            ok("tdes")

    for r in load(d, "rsa-openssl.nsv")["rsa-sign"]:
        pub = rsa.RSAPublicNumbers(int(r["e"], 16), int(r["n"], 16)).public_key()
        h = hashes.SHA1() if r["hash"] == "sha1" else hashes.SHA256()
        pub.verify(bytes.fromhex(r["signature"]), bytes.fromhex(r["message"]), padding.PKCS1v15(), h)
        ok("rsa-verify")
    # RSA private side: rebuild the key from n, e, d (cryptography derives p and q) and decrypt.
    for r in load(d, "rsa-openssl.nsv")["rsa-decrypt"]:
        n, e, dd = int(r["n"], 16), int(r["e"], 16), int(r["d"], 16)
        p, q = rsa.rsa_recover_prime_factors(n, e, dd)
        priv = rsa.RSAPrivateNumbers(p, q, dd, rsa.rsa_crt_dmp1(dd, p), rsa.rsa_crt_dmq1(dd, q), rsa.rsa_crt_iqmp(p, q),
                                     rsa.RSAPublicNumbers(e, n)).private_key()
        assert priv.decrypt(bytes.fromhex(r["ciphertext"]), padding.PKCS1v15()).hex() == r["plaintext"], "rsa decrypt"
        ok("rsa-decrypt")

    p = int(load(d, "dh-group14-rfc3526.nsv")["dh-group14-params"][0]["p"], 16)
    for r in load(d, "dh-group14-openssl.nsv")["dh-group14"]:
        x = int(r["x_a"], 16)
        assert pow(2, x, p) == int(r["y_a"], 16), "dh public"
        assert pow(int(r["y_b"], 16), x, p) == int(r["shared"], 16), "dh shared"
        ok("dh14")

    print("python cross-check: " + ", ".join("%s %d" % kv for kv in sorted(checked.items())))


if __name__ == "__main__":
    main(sys.argv[1])
