"""Generates every AES byte for the walk mock, checks FIPS 197, and fills the page template."""
import base64
import json
import pathlib

HERE = pathlib.Path(__file__).parent
POLY = 0x11B


def xtime(a):
    a <<= 1
    return a ^ POLY if a & 0x100 else a


def mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = xtime(a)
        b >>= 1
    return out


def inv(a):
    return next((x for x in range(256) if mul(a, x) == 1), 0)


def rotl(a, n):
    return ((a << n) | (a >> (8 - n))) & 0xFF


def sbox_entry(a):
    b = inv(a)
    return b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63


SBOX = [sbox_entry(a) for a in range(256)]
RCON = [1]
for _ in range(9):
    RCON.append(xtime(RCON[-1]))
MATRIX = [[2, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]]


def expand(key):
    nk = len(key) // 4
    total = 4 * (nk + 7)
    words = [list(key[i:i + 4]) for i in range(0, len(key), 4)]
    rows = [{"i": i, "key": True, "word": words[i]} for i in range(nk)]
    for i in range(nk, total):
        previous = words[i - 1]
        back = words[i - nk]
        row = {"i": i, "key": False, "previous": previous, "keyBack": back}
        temp = previous
        if i % nk == 0:
            rotated = previous[1:] + previous[:1]
            substituted = [SBOX[b] for b in rotated]
            rcon = RCON[i // nk - 1]
            after = [substituted[0] ^ rcon] + substituted[1:]
            row.update(rotated=rotated, substituted=substituted, rcon=rcon, afterRcon=after)
            temp = after
        elif nk > 6 and i % nk == 4:
            substituted = [SBOX[b] for b in previous]
            row.update(substituted=substituted)
            temp = substituted
        word = [a ^ b for a, b in zip(back, temp)]
        row["word"] = word
        words.append(word)
        rows.append(row)
    return words, rows


def term(factor, byte):
    doublings = []
    value = byte
    while (1 << len(doublings)) < factor:
        shifted = value << 1
        reduced = bool(shifted & 0x100)
        next_value = shifted ^ POLY if reduced else shifted
        doublings.append({"from": value, "shifted": shifted, "reduced": reduced, "to": next_value})
        value = next_value
    return {"factor": factor, "byte": byte, "result": mul(factor, byte),
            "ordinary": factor * byte, "doublings": doublings}


def mix(state):
    out = [0] * 16
    terms = []
    for c in range(4):
        column = state[4 * c:4 * c + 4]
        rows = []
        for r in range(4):
            parts = [term(MATRIX[r][i], column[i]) for i in range(4)]
            total = 0
            for part in parts:
                total ^= part["result"]
            out[r + 4 * c] = total
            rows.append({"parts": parts, "total": total})
        terms.append(rows)
    return out, terms


def walk(key, block):
    words, rows = expand(key)
    round_key = lambda n: [b for w in words[4 * n:4 * n + 4] for b in w]
    state = list(block)
    steps = [{"kind": "start", "round": 0, "state": state}]

    def add_key(n):
        nonlocal state
        k = round_key(n)
        state = [a ^ b for a, b in zip(state, k)]
        steps.append({"kind": "ark", "round": n, "state": state, "key": k})

    add_key(0)
    rounds = len(words) // 4 - 1
    for n in range(1, rounds + 1):
        state = [SBOX[b] for b in state]
        steps.append({"kind": "sub", "round": n, "state": state})
        state = [state[(r + 4 * ((c + r) % 4))] for c in range(4) for r in range(4)]
        steps.append({"kind": "shift", "round": n, "state": state})
        if n < rounds:
            state, terms = mix(state)
            steps.append({"kind": "mix", "round": n, "state": state, "terms": terms})
        add_key(n)
    return steps, rows


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
FIPS_IN = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
PUMP = b"Pump four is ok."

fips_steps, rows = walk(KEY, FIPS_IN)
assert bytes(fips_steps[-1]["state"]).hex() == "3925841d02dc09fb" + "dc118597196a0b32", "FIPS appendix B"
assert bytes(rows[4]["word"]).hex() == "a0fafe17", "FIPS appendix A w4"
assert bytes(rows[43]["word"]).hex() == "b6630ca6", "FIPS appendix A w43"
assert len(fips_steps) == 41

# All three sizes. Keys are FIPS 197 appendix A; each size is checked against appendix A and appendix C.
KEYS = {
    "128": KEY,
    "192": bytes.fromhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
    "256": bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),
}
LAST_WORD = {"128": "b6630ca6", "192": "01002202", "256": "706c631e"}
APPENDIX_C_IN = bytes.fromhex("00112233445566778899aabbccddeeff")
APPENDIX_C_OUT = {"128": "69c4e0d86a7b0430d8cdb78070b4c55a",
                  "192": "dda97ca4864cdfe06eaf70a0ec0d7191",
                  "256": "8ea2b7ca516745bfeafc49904b496089"}
SIZES = {}
for name, k in KEYS.items():
    size_steps, size_rows = walk(k, FIPS_IN)
    assert bytes(size_rows[-1]["word"]).hex() == LAST_WORD[name], "appendix A last word " + name
    c_steps, _ = walk(bytes(range(len(k))), APPENDIX_C_IN)
    assert bytes(c_steps[-1]["state"]).hex() == APPENDIX_C_OUT[name], "appendix C " + name
    pump, _ = walk(k, PUMP)
    SIZES[name] = {"nk": len(k) // 4, "nr": len(k) // 4 + 6, "words": size_rows,
                   "runs": {"pump": {"label": "Pump four is ok.", "steps": pump},
                            "fips": {"label": "FIPS 197 example", "steps": size_steps}}}
    print(name, "steps:", len(size_steps), " words:", len(size_rows), " appendix A and C match")



# Long text and picture. Fast AES for many blocks, checked against SP 800-38A.
MUL2 = [mul(2, b) for b in range(256)]
MUL3 = [mul(3, b) for b in range(256)]
WORDS, _ = expand(KEY)
ROUND_KEYS = [[b for w in WORDS[4 * n:4 * n + 4] for b in w] for n in range(11)]


def encrypt_block(block):
    s = [a ^ b for a, b in zip(block, ROUND_KEYS[0])]
    for n in range(1, 11):
        s = [SBOX[b] for b in s]
        s = [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]
        if n < 10:
            out = []
            for c in range(4):
                a, b, d, e = s[4 * c:4 * c + 4]
                out += [MUL2[a] ^ MUL3[b] ^ d ^ e, a ^ MUL2[b] ^ MUL3[d] ^ e,
                        a ^ b ^ MUL2[d] ^ MUL3[e], MUL3[a] ^ b ^ d ^ MUL2[e]]
            s = out
        s = [a ^ b for a, b in zip(s, ROUND_KEYS[n])]
    return bytes(s)


def split(data):
    return [data[i:i + 16] for i in range(0, len(data), 16)]


def ecb(data):
    return [encrypt_block(b) for b in split(data)]


def cbc(data, iv):
    out, last = [], iv
    for b in split(data):
        last = encrypt_block(bytes(x ^ y for x, y in zip(b, last)))
        out.append(last)
    return out


def pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


NIST_PLAIN = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
assert ecb(NIST_PLAIN)[0].hex() == "3ad77bb40d7a3660a89ecaf32466ef97", "SP 800-38A F.1.1"
assert cbc(NIST_PLAIN, bytes(range(16)))[0].hex() == "7649abac8119b246cee98e9b12e9197d", "SP 800-38A F.2.1"

IV = bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90")
LONG_TEXT = b"Pump four is ok.Pump four is ok.Pump nine stops.Pump four is ok.Pump four is ok.All done."
plain = pad(LONG_TEXT)
flipped = bytearray(plain)
FLIP_BLOCK = 1
flipped[16] ^= 0x01
flipped = bytes(flipped)


def hamming(a, b):
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


def rows_for(data, base_ecb, base_cbc):
    e, c = ecb(data), cbc(data, IV)
    return {"ecb": [b.hex() for b in e], "cbc": [b.hex() for b in c],
            "ecbBits": [hamming(x, y) for x, y in zip(e, base_ecb)],
            "cbcBits": [hamming(x, y) for x, y in zip(c, base_cbc)]}


base_e, base_c = ecb(plain), cbc(plain, IV)
blocks = split(plain)
SIZE = 128
image = bytearray([230]) * (SIZE * SIZE)


def rect(x0, y0, x1, y1, value):
    for y in range(y0, y1):
        for x in range(x0, x1):
            image[y * SIZE + x] = value


# Our own picture: a fuel pump with a hose, in two flat values.
rect(32, 16, 80, 112, 40)      # body
rect(40, 26, 72, 54, 230)      # display
rect(24, 112, 88, 120, 40)     # base
rect(80, 40, 96, 48, 40)       # hose top
rect(96, 40, 104, 96, 40)      # hose down
rect(88, 88, 96, 96, 40)       # nozzle
rect(48, 64, 64, 80, 230)      # badge
picture = bytes(image)
pic_ecb = b"".join(ecb(picture))
pic_cbc = b"".join(cbc(picture, IV))
all_blocks = split(picture)
distinct = lambda items: len(set(items))
LONG = {
    "text": LONG_TEXT.decode(), "iv": IV.hex(), "flipBlock": FLIP_BLOCK,
    "plain": [b.hex() for b in blocks], "base": rows_for(plain, base_e, base_c),
    "flip": rows_for(flipped, base_e, base_c), "flipPlain": [b.hex() for b in split(flipped)],
    "pic": {"size": SIZE, "plain": base64.b64encode(picture).decode(),
            "ecb": base64.b64encode(pic_ecb).decode(), "cbc": base64.b64encode(pic_cbc).decode(),
            "blocks": len(all_blocks), "plainDistinct": distinct(all_blocks),
            "ecbDistinct": distinct(split(pic_ecb)), "cbcDistinct": distinct(split(pic_cbc))},
}
print("long blocks:", len(blocks), " flip bits ECB:", LONG["flip"]["ecbBits"], " CBC:", LONG["flip"]["cbcBits"])
print("picture blocks:", len(all_blocks), " distinct plain/ecb/cbc:", LONG["pic"]["plainDistinct"],
      LONG["pic"]["ecbDistinct"], LONG["pic"]["cbcDistinct"])

# GCM, from SP 800-38D. Checked against the published GCM test cases below.
def gf128_mul(x, y):
    r = 0xE1 << 120
    z, v = 0, y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        v = (v >> 1) ^ r if v & 1 else v >> 1
    return z


def to_int(b):
    return int.from_bytes(b, "big")


def to_bytes16(n):
    return n.to_bytes(16, "big")


def gcm_seal(enc, nonce, plain, aad):
    h = to_int(enc(bytes(16)))
    j0 = nonce + bytes([0, 0, 0, 1])
    mask = enc(j0)
    blocks, cipher = [], b""
    for n, start in enumerate(range(0, len(plain), 16)):
        counter = nonce + (n + 2).to_bytes(4, "big")
        stream = enc(counter)
        chunk = plain[start:start + 16]
        out = bytes(a ^ b for a, b in zip(chunk, stream))
        blocks.append({"count": n + 2, "counter": counter.hex(), "stream": list(stream), "plain": list(chunk), "cipher": list(out)})
        cipher += out
    steps, x = [], 0
    def feed(label, data):
        nonlocal x
        for i in range(0, len(data), 16):
            part = data[i:i + 16].ljust(16, bytes(1))
            mixed = x ^ to_int(part)
            x = gf128_mul(mixed, h)
            steps.append({"label": label, "block": part.hex(), "xored": to_bytes16(mixed).hex(), "mulled": to_bytes16(x).hex()})
    if aad:
        feed("Other data", aad)
    feed("Sent bytes", cipher)
    feed("Lengths", (len(aad) * 8).to_bytes(8, "big") + (len(cipher) * 8).to_bytes(8, "big"))
    tag = to_bytes16(x ^ to_int(mask))
    return {"h": to_bytes16(h).hex(), "mask": mask.hex(), "blocks": blocks, "cipher": cipher, "ghash": steps, "tag": tag.hex()}


def make_enc(key):
    words, _ = expand(key)
    keys = [[b for w in words[4 * n:4 * n + 4] for b in w] for n in range(len(words) // 4)]
    last = len(keys) - 1

    def enc(block):
        s = [a ^ b for a, b in zip(block, keys[0])]
        for n in range(1, last + 1):
            s = [SBOX[b] for b in s]
            s = [s[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]
            if n < last:
                out = []
                for c in range(4):
                    a, b, d, e = s[4 * c:4 * c + 4]
                    out += [MUL2[a] ^ MUL3[b] ^ d ^ e, a ^ MUL2[b] ^ MUL3[d] ^ e, a ^ b ^ MUL2[d] ^ MUL3[e], MUL3[a] ^ b ^ d ^ MUL2[e]]
                s = out
            s = [a ^ b for a, b in zip(s, keys[n])]
        return bytes(s)
    return enc


TC1 = gcm_seal(make_enc(bytes(16)), bytes(12), b"", b"")
assert TC1["tag"] == "58e2fccefa7e3061367f1d57a4e7455a", "GCM test case 1"
TC3_KEY = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
TC3_IV = bytes.fromhex("cafebabefacedbaddecaf888")
TC3_PLAIN = bytes.fromhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                          "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
TC3 = gcm_seal(make_enc(TC3_KEY), TC3_IV, TC3_PLAIN, b"")
assert TC3["tag"] == "4d5c2af327cd64a62cf35abd2ba6fab4", "GCM test case 3"
print("GCM test case tags 1 and 3 match. TC3 cipher=" + TC3["cipher"].hex() + " tag=" + TC3["tag"])

GCM_NONCE = bytes.fromhex("a1b2c3d4e5f6071829303132")
GCM_AAD = b"pump-4"
GCM_TEXT = b"Pump four is ok. Pump nine stops now. All done."
GCM_ENC = make_enc(KEY)
sealed = gcm_seal(GCM_ENC, GCM_NONCE, GCM_TEXT, GCM_AAD)
assert len(GCM_TEXT) % 16 != 0
flip_at = 20
bad_cipher = bytearray(sealed["cipher"])
bad_cipher[flip_at] ^= 0x01
bad_tag = gcm_seal(GCM_ENC, GCM_NONCE, bytes(a ^ b for a, b in zip(bytes(bad_cipher), b"".join(bytes(bk["stream"][:len(bk["plain"])]) for bk in sealed["blocks"]))), GCM_AAD)["tag"]
assert bad_tag != sealed["tag"]
bad_text = bytes(a ^ b for a, b in zip(bytes(bad_cipher), b"".join(bytes(bk["stream"][:len(bk["plain"])]) for bk in sealed["blocks"])))
GCM_DATA = {"nonce": GCM_NONCE.hex(), "aad": GCM_AAD.decode(), "textBytes": list(GCM_TEXT), "h": sealed["h"], "mask": sealed["mask"],
            "blocks": sealed["blocks"], "ghash": sealed["ghash"], "tag": sealed["tag"],
            "flip": {"tag": bad_tag, "text": bad_text.decode("latin-1")}}
print("GCM demo:", len(GCM_TEXT), "bytes,", len(sealed["blocks"]), "counters, cipher=" + sealed["cipher"].hex() + " tag=" + sealed["tag"])

# HMAC and the chain. The chain's inputs and expected values are the spec's public test case 002.
import hashlib
import hmac as std_hmac


def sha(b):
    return hashlib.sha256(b).digest()


def hmac_parts(key, msg):
    k = key if len(key) <= 64 else sha(key)
    padded = k.ljust(64, bytes(1))
    inner = bytes(b ^ 0x36 for b in padded)
    outer = bytes(b ^ 0x5C for b in padded)
    inner_hash = sha(inner + msg)
    return {"padded": padded.hex(), "inner": inner.hex(), "outer": outer.hex(), "innerHash": inner_hash.hex(), "tag": sha(outer + inner_hash).hex()}


def hmac_tag(key, msg):
    return bytes.fromhex(hmac_parts(key, msg)["tag"])


assert hmac_tag(bytes([0x0b] * 20), b"Hi There").hex() == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "RFC 4231 case 1"
assert hmac_tag(b"Jefe", b"what do ya want for nothing?") == std_hmac.new(b"Jefe", b"what do ya want for nothing?", hashlib.sha256).digest()


def hkdf(ikm, salt, info, length):
    prk = hmac_tag(salt, ikm)
    out, last, n = b"", b"", 1
    while len(out) < length:
        last = hmac_tag(prk, last + info + bytes([n]))
        out += last
        n += 1
    return out[:length]


assert hkdf(bytes([0x0b] * 22), bytes(range(13)), bytes(range(0xF0, 0xFA)), 42).hex().startswith("3cb25f25faacd57a90434f64d0362f2a"), "RFC 5869 case 1"


def merkle_root(seals):
    def go(nodes):
        if len(nodes) == 1:
            return nodes[0]
        split = 1
        while split * 2 < len(nodes):
            split *= 2
        return sha(bytes([1]) + go(nodes[:split]) + go(nodes[split:]))
    return go([sha(bytes([0]) + s) for s in seals])


VECTOR = pathlib.Path("E:/dev/ffiec-public/spec/test-vectors/002-multi-event-same-run")
vector_in = json.loads((VECTOR / "input.json").read_text(encoding="utf-8"))
tenant = vector_in["inputs"]["tenant_id"]
ikm = bytes.fromhex(vector_in["inputs"]["ikm_v1_hex"])
session_key = hkdf(ikm, b"ffiec.chain-of-custody.v1.salt", b"ffiec.chain-of-custody.v1.info|" + tenant.encode(), 32)
canon = (VECTOR / "expected_canonical.txt").read_bytes().split(b"\n")
expected = vector_in["expected"]["chain"]


def seal_events(events):
    prev, rows = bytes(32), []
    for ev in events:
        seal = hmac_tag(session_key, prev + ev)
        rows.append((prev, seal))
        prev = seal
    return rows


base_rows = seal_events(canon)
assert len(canon) == 5 and len(expected) == 5
for row, want in zip(base_rows, expected):
    assert row[0].hex() == want["prev_hash_hex"] and row[1].hex() == want["payload_hash_hex"], "spec case 002 seal"
base_seals = [r[1] for r in base_rows]
assert merkle_root(base_seals).hex() == "927adc88e5d843c5847674f7245d1e3c762bacc3f0b225f3322300cddf4eefe9", "spec case 002 root"
print("Spec case 002: 5 of 5 seals and the Merkle root match")


def short_event(raw):
    doc = json.loads(raw)
    return doc["name"] + " " + json.dumps(doc["attributes"], separators=(",", ":"))


def entry(i, prev, seal, status, text=None, **extra):
    row = {"seq": i + 1, "text": text or short_event(canon[i]), "prev": prev.hex(), "seal": seal.hex(), "status": status}
    row.update(extra)
    return row


plain_entries = [entry(i, base_rows[i][0], base_rows[i][1], None) for i in range(5)]
for e in plain_entries:
    del e["status"]
changed_raw = canon[2].replace(b"payload-3", b"payload-9")
assert changed_raw != canon[2]
change_case = [entry(i, base_rows[i][0], base_rows[i][1], "ok" if i < 2 else ("bad" if i == 2 else "skip"), text=short_event(changed_raw) if i == 2 else None, changed=i == 2) for i in range(5)]
assert hmac_tag(session_key, base_rows[2][0] + changed_raw) != base_seals[2]
remove_case = [entry(i, base_rows[i][0], base_rows[i][1], "ok" if i < 2 else ("bad" if i == 3 else "skip")) for i in range(5) if i != 2]
assert base_rows[3][0] != base_seals[1]
cut_case = [entry(i, base_rows[i][0], base_rows[i][1], "ok") for i in range(4)]
cut_root = merkle_root(base_seals[:4])
assert cut_root != merkle_root(base_seals)
rewrite_events = list(canon)
rewrite_events[2] = changed_raw
rewrite_rows = seal_events(rewrite_events)
rewrite_case = [entry(i, rewrite_rows[i][0], rewrite_rows[i][1], "ok", text=short_event(rewrite_events[i]), changed=i == 2, oldSeal=base_seals[i].hex() if i >= 2 else None) for i in range(5)]
new_root = merkle_root([r[1] for r in rewrite_rows])
assert new_root != merkle_root(base_seals)
assert all(rewrite_rows[i][1] != base_seals[i] for i in range(2, 5)) and all(rewrite_rows[i][1] == base_seals[i] for i in range(2))
for row in rewrite_case:
    if row["oldSeal"] is None:
        del row["oldSeal"]
HDEMO_KEY = b"a shared key"
HDEMO_MSG = b"Pump four: pay 100 dollars"
HDEMO_BAD = b"Pump four: pay 900 dollars"
HMAC_DATA = {
    "attack": {"message": HDEMO_MSG.decode(), "changed": HDEMO_BAD.decode(),
               "messageHash": sha(HDEMO_MSG).hex(), "changedHash": sha(HDEMO_BAD).hex(),
               "messageTag": hmac_tag(HDEMO_KEY, HDEMO_MSG).hex(), "changedTag": hmac_tag(HDEMO_KEY, HDEMO_BAD).hex()},
    "build": dict(hmac_parts(HDEMO_KEY, HDEMO_MSG), keyText=HDEMO_KEY.decode()),
    "chain": {"tenant": tenant, "sessionKey": session_key.hex(), "root": merkle_root(base_seals).hex(), "entries": plain_entries,
              "cases": {
                  "change": {"entries": change_case, "caught": "chain",
                             "verdict": "The event's text changed, so its tag no longer matches. A verifier holding the key stops at the first failure and says: <b>payload_hash MAC mismatch at seq 3</b>. A verifier with no key cannot check tags, and it reads PASS-STRUCTURALLY, with key-bound verification skipped. Without the session key, an attacker cannot make a matching tag."},
                  "remove": {"entries": remove_case, "caught": "chain",
                             "verdict": "Event 4 now sits at position 3, and it names a tag the verifier has not seen. The verifier says: <b>chain link broken at seq 3</b>. It names the position it expected."},
                  "cut": {"entries": cut_case, "caught": "root", "root": cut_root.hex(),
                          "verdict": "Nothing after the cut names the missing event, so the chain cannot see this. With no daily seal to compare, the verifier reads PASS and warns: <b>no daily seal supplied: steps 10 and 11 did not run, so a cut at the end of the file cannot be detected</b>. With the seal, it fails: <b>merkle root mismatch — ledger contents do not produce sealed root</b>."},
                  "rewrite": {"entries": rewrite_case, "caught": "root", "root": new_root.hex(),
                              "verdict": "Someone holding the session key changed event 3 and made a new tag. Every tag after it had to change too, because each tag covers the last one. Each tag now checks out, so the chain alone cannot catch this. The signed root catches it: <b>merkle root mismatch — ledger contents do not produce sealed root</b>."}}}}

# A small teaching Feistel network. The test below proves decrypt works for every F offered.
def fxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


FEISTEL_FUNCS = {
    "hash": ("SHA-256, one way", lambda r, k: sha(k + r)[:4],
             "F here is SHA-256 cut to 4 bytes: there is no way to run it backward. The cipher still decrypts, because decrypting only ever runs F forward."),
    "and": ("AND with the key", lambda r, k: bytes(x & y for x, y in zip(r, k)),
            "F here is a bit AND, which throws bits away, so it has no inverse at all. The cipher still decrypts. But it is weak: the structure gives you decryption, and security has to come from F."),
    "zero": ("All zeros", lambda r, k: bytes(4),
             "F here always gives zeros, so the XOR changes nothing and the text comes out in plain view, with its halves swapped. The cipher still decrypts, and it hides nothing. The structure never promised secrecy."),
}
FEISTEL_KEYS = [sha(b"mock round key " + bytes([i]))[:4] for i in range(1, 5)]
FEISTEL_TEXT = b"Pump 4 !"
assert len(FEISTEL_TEXT) == 8


def feistel(block, keys, f):
    left, right = block[:4], block[4:]
    rounds = []
    for k in keys:
        out_f = f(right, k)
        out = fxor(left, out_f)
        rounds.append({"key": k.hex(), "left": left.hex(), "right": right.hex(), "f": out_f.hex(), "out": out.hex()})
        left, right = right, out
    return right + left, rounds


FEISTEL_DATA = {"functions": {}}
for name, (label, fn, says) in FEISTEL_FUNCS.items():
    cipher_out, enc_rounds = feistel(FEISTEL_TEXT, FEISTEL_KEYS, fn)
    plain_out, dec_rounds = feistel(cipher_out, list(reversed(FEISTEL_KEYS)), fn)
    assert plain_out == FEISTEL_TEXT, "Feistel decrypt " + name
    FEISTEL_DATA["functions"][name] = {"label": label, "says": says,
                                       "enc": {"input": FEISTEL_TEXT.hex(), "output": cipher_out.hex(), "rounds": enc_rounds},
                                       "dec": {"input": cipher_out.hex(), "output": plain_out.hex(), "rounds": dec_rounds}}
print("Feistel: decrypt returns the text for", len(FEISTEL_FUNCS), "of", len(FEISTEL_FUNCS), "functions")

# Diffie-Hellman. Small tables for the walk, then X25519 checked against RFC 7748 section 6.1.
DH_N = 23
DH_G = 5
assert sorted(pow(DH_G, e, DH_N) for e in range(1, DH_N)) == list(range(1, DH_N)), "g must reach every value"
DH_POW = [[pow(base, e, DH_N) for e in range(DH_N)] for base in range(DH_N)]
DH_MUL = [[(x * y) % DH_N for y in range(DH_N)] for x in range(DH_N)]
X_P = 2 ** 255 - 19


def x25519(scalar, point):
    k = bytearray(scalar)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    k = int.from_bytes(k, "little")
    u = int.from_bytes(point, "little") & ((1 << 255) - 1)
    x2, z2, x3, z3, swap_bit = 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        if swap_bit ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap_bit = bit
        a = (x2 + z2) % X_P
        aa = a * a % X_P
        b = (x2 - z2) % X_P
        bb = b * b % X_P
        e = (aa - bb) % X_P
        c = (x3 + z3) % X_P
        d = (x3 - z3) % X_P
        da = d * a % X_P
        cb = c * b % X_P
        x3 = (da + cb) ** 2 % X_P
        z3 = u * (da - cb) ** 2 % X_P
        x2 = aa * bb % X_P
        z2 = e * (aa + 121665 * e) % X_P
    if swap_bit:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, X_P - 2, X_P) % X_P).to_bytes(32, "little")


X_BASE = bytes([9]) + bytes(31)
X_A = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
X_B = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
X_PUB_A = x25519(X_A, X_BASE)
X_PUB_B = x25519(X_B, X_BASE)
assert X_PUB_A.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
assert X_PUB_B.hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
X_SHARED = x25519(X_A, X_PUB_B)
assert X_SHARED == x25519(X_B, X_PUB_A)
assert X_SHARED.hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
print("X25519: RFC 7748 section 6.1 holds: 2 of 2 public values, and the secret from both sides")
DH_DATA = {"n": DH_N, "g": DH_G, "pow": DH_POW, "mul": DH_MUL, "mitm": 9,
           "x25519": {"a": X_A.hex(), "b": X_B.hex(), "A": X_PUB_A.hex(), "B": X_PUB_B.hex(), "s": X_SHARED.hex(),
                      "key": hkdf(X_SHARED, b"", b"mock page: a key for AES", 16).hex()}}

RCON_STEPS = []
for value in RCON[:-1]:
    shifted = value << 1
    reduced_bit = bool(shifted & 0x100)
    RCON_STEPS.append({"from": value, "shifted": shifted, "reduced": reduced_bit, "to": xtime(value)})
assert [s["to"] for s in RCON_STEPS] == RCON[1:]

data = {
    "long": LONG,
    "gcm": GCM_DATA,
    "hmac": HMAC_DATA,
    "feistel": FEISTEL_DATA,
    "dh": DH_DATA,
    "rconSteps": RCON_STEPS,
    "sbox": SBOX,
    "rcon": RCON,
    "sizes": SIZES,
}
page = (HERE / "template.html").read_text(encoding="utf-8")
assert page.count("__DATA__") == 1
out = HERE / "aes-walk-mock.html"
out.write_text(page.replace("__DATA__", json.dumps(data, separators=(",", ":"))), encoding="utf-8")
print("FIPS output:", bytes(fips_steps[-1]["state"]).hex())
print("steps per run:", len(fips_steps), " page bytes:", out.stat().st_size)
