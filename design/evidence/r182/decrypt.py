"""Decrypts each hidden wire range with the run's own keys, using no course code. If the range is right, the readable bytes come out."""
import hashlib
import hmac
import json
import pathlib
import sys

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ev = pathlib.Path(sys.argv[1])


def load(lesson):
    return json.loads((ev / f"lesson{lesson}.txt").read_text(encoding="utf-8"))


def secrets(rows):
    out = {}
    for e in rows:
        for s in e.get("secrets") or []:
            if s.get("hex"):
                out.setdefault(s["name"], bytes.fromhex(s["hex"]))
    return out


def sent(rows):
    return [e for e in rows if e["type"] == "wire.sent" and e.get("wire") and e.get("plain") and any(not f["visibleToWire"] for f in e.get("fields") or [])]


def span(e, kind="cipher"):
    f = next(f for f in e["fields"] if not f["visibleToWire"] and f["kind"] == kind)
    return f["offset"], f["length"]


def field(e, name, w):
    f = next(f for f in e["fields"] if f["name"] == name)
    return w[f["offset"]:f["offset"] + f["length"]]


def report(name, ok, total, sample=""):
    print(f"{name}: {ok} of {total} ranges decrypt to the readable bytes {sample}")


def lesson1():
    rows = load(1)
    key = secrets(rows)["aes.key"]
    ok, n, notes = 0, 0, {}
    for e in sent(rows):
        w, p = bytes.fromhex(e["wire"]), bytes.fromhex(e["plain"])
        o, l = span(e)
        c = w[o:o + l]
        n += 1
        msg = e["message"]
        if "Gcm" in msg:
            tag = field(e, "tag", w)
            nonce = field(e, "nonce", w)
            good = False
            for aad in (b"", w[:4]):
                try:
                    good = AESGCM(key).decrypt(nonce, c + tag, aad or None) == p
                except Exception:
                    good = False
                if good:
                    notes[msg] = "aad=" + aad.hex()
                    break
        elif "Cbc" in msg:
            d = Cipher(algorithms.AES(key), modes.CBC(field(e, "iv", w))).decryptor()
            good = (d.update(c) + d.finalize()).startswith(p)
        else:
            d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
            good = (d.update(c) + d.finalize()).startswith(p)
        ok += good
        if not good:
            print("  MISS", msg)
    report("lesson 1 AES", ok, n, str(notes))


def lesson6():
    rows = load(6)
    s = secrets(rows)
    msgs = sent(rows)
    ok = 0
    for i, e in enumerate(msgs):
        w, p = bytes.fromhex(e["wire"]), bytes.fromhex(e["plain"])
        o, l = span(e)
        found = None
        for name, key in s.items():
            if not name.startswith("dukpt.pinKey"):
                continue
            d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
            out = d.update(w[o:o + l]) + d.finalize()
            print("  ", e["message"], name, "ecb", out.hex()[:32], "plain", p.hex(), repr(p))
            if p in out or p.hex() in out.hex():
                found = name
        print("  fields", [(f["name"], f["offset"], f["length"]) for f in e["fields"]], "wire", len(w), "|", found)
        ok += bool(found)
    report("lesson 6 pinBlock", ok, len(msgs))


def tls11(lesson, client_only=False):
    rows = load(lesson)
    s = secrets(rows)
    ok, n = 0, 0
    for e in sent(rows):
        names = [f["name"] for f in e["fields"]]
        if "iv" not in names or "version" not in names:
            continue
        w, p = bytes.fromhex(e["wire"]), bytes.fromhex(e["plain"])
        o, l = span(e)
        side = "client" if e["actor"] == "client" else "server"
        key, mackey = s[f"tls11.{side}_write_key"], s[f"tls11.{side}_write_mac"]
        d = Cipher(algorithms.AES(key), modes.CBC(field(e, "iv", w))).decryptor()
        out = d.update(w[o:o + l]) + d.finalize()
        pad = out[-1]
        good = out.startswith(p) and out[-pad - 1:] == bytes([pad]) * (pad + 1) and len(out) == len(p) + 20 + pad + 1
        n += 1
        ok += good
        if not good:
            print("  MISS", e["message"], out.hex()[:80], "plain", p.hex()[:40])
    report(f"lesson {lesson} TLS 1.1 (plain + 20-byte MAC + padding)", ok, n)


def ssh(lesson):
    rows = load(lesson)
    s = secrets(rows)
    counters = {}
    ok, n = 0, 0
    client_actors = {"client", "ce"}
    for e in sent(rows):
        if not any(f["name"] == "encryptedPacket" for f in e["fields"]):
            continue
        w, p = bytes.fromhex(e["wire"]), bytes.fromhex(e["plain"])
        o, l = span(e)
        c2s = e["actor"] in client_actors
        tag = "c2s" if c2s else "s2c"
        key, iv = s[f"ssh.key.{tag}"], s[f"ssh.iv.{tag}"]
        blocks = counters.get(tag, 0)
        ctr = (int.from_bytes(iv, "big") + blocks).to_bytes(16, "big")
        d = Cipher(algorithms.AES(key), modes.CTR(ctr)).decryptor()
        out = d.update(w[o:o + l]) + d.finalize()
        counters[tag] = blocks + l // 16
        plen = int.from_bytes(out[:4], "big")
        pad = out[4]
        good = plen == l - 4 and out[5:5 + len(p)] == p and plen == 1 + len(p) + pad
        n += 1
        ok += good
        if not good and n < 4:
            print("  MISS", e["message"], "len", plen, "pad", pad, out.hex()[:60], "plain", p.hex()[:40])
    report(f"lesson {lesson} SSH CTR (4-byte length, padding length, payload, padding)", ok, n)


lesson1()
lesson6()
tls11(7)
ssh(8)
