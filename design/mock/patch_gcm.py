"""Adds the GCM streaming tab to the mock, and the GCM data to the build, checked against NIST values."""
import pathlib

HERE = pathlib.Path(__file__).parent
path = HERE / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('''<button role="tab" id="tab-long" aria-selected="false">Long text</button>''',
     '''<button role="tab" id="tab-long" aria-selected="false">Long text</button>
      <button role="tab" id="tab-gcm" aria-selected="false">GCM stream</button>''')
assert text.count('["block", "keys", "field", "long"]') == 2
text = text.replace('["block", "keys", "field", "long"]', '["block", "keys", "field", "long", "gcm"]')
swap('''  <section id="view-field" class="card" hidden>''', '''  <section id="view-gcm" class="card" hidden>
    <h2>GCM: AES as a stream</h2>
    <p>In GCM, AES never locks your text. It locks a counter, and the answer is a key stream. Your text then XORs with that key stream one byte at a time. So the text can be any length, with no padding, and a byte can go out as soon as it is ready.</p>
    <p class="note" id="gkey"></p>
    <div class="controls">
      <button class="btn primary" id="gplay">Play the stream</button>
      <button class="btn" id="gnext">Next byte</button>
      <button class="btn" id="gall">Show all</button>
      <span class="seg" aria-label="Speed">
        <button data-speed="1.8" aria-pressed="false">Slow</button>
        <button data-speed="1" aria-pressed="true">Normal</button>
        <button data-speed="0.45" aria-pressed="false">Fast</button>
      </span>
    </div>
    <div class="mcap gcap" id="gcap" aria-live="polite"></div>
    <div class="gtape scroll" id="gtape"></div>
    <h2>The tag: why a stream needs a seal</h2>
    <p>A stream alone stops reading, and it does not stop changes: a flipped bit on the wire flips the same bit in the text. So GCM adds a tag. AES of 128 zero bits gives a secret value, H. Each block is XORed in and multiplied by H, in a 128-bit Galois field. AES of the first counter then masks the result.</p>
    <p class="mono longtext">H = <span id="gh"></span><br>Mask = <span id="gmask"></span></p>
    <div class="scroll"><table class="modes" id="gtable"></table></div>
    <div class="controls"><button class="btn" id="gflip">Flip one bit on the wire</button></div>
    <p class="mono longtext">Tag sent: <span id="gsent"></span><br>Tag the receiver works out: <span id="gcalc"></span></p>
    <p class="gverdict good" id="gverdict"></p>
  </section>

  <section id="view-field" class="card" hidden>''')
swap(".build .s1 { background: var(--accent-soft); }",
     """.gtape { display: grid; gap: 12px; }
.gblock { display: grid; gap: 4px; padding: 10px; border: 1px solid var(--line); border-radius: 10px; min-width: max-content; }
.gblock.on { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
.ghead { font-size: 13px; color: var(--muted); }
.ghead code { font: 600 13px var(--mono); color: var(--fg); }
.grow { display: grid; grid-template-columns: 86px auto; align-items: center; gap: 8px; }
.grow b { font-weight: 400; font-size: 13px; color: var(--muted); }
.gcells { display: grid; grid-template-columns: repeat(16, 30px); gap: 3px; }
.gc { height: 26px; display: grid; place-items: center; border-radius: 4px; background: var(--sunk); font: 600 12px var(--mono); padding: 0; }
.gc.now { outline: 2px solid var(--key); outline-offset: 1px; }
.gc.gdone { background: var(--flash-soft); }
.gc.unusedbyte { opacity: .35; text-decoration: line-through; }
.gbits { margin-top: 4px; }
.gcap { min-height: 118px; }
.gverdict { max-width: none; padding: 8px 12px; border-radius: 8px; font-weight: 700; overflow-wrap: anywhere; }
.gverdict.good { background: var(--flash-soft); }
.gverdict.bad { background: var(--key-soft); }
.build .s1 { background: var(--accent-soft); }""")
swap("/* Every named spec gets a hover card", (HERE / "gcm_view.js").read_text(encoding="utf-8") + "/* Every named spec gets a hover card")
swap("setupLong(); buildKeyTable();", "setupLong(); setupGcm(); buildKeyTable();")
swap('var TIP_TARGETS = ".kb, .cell,', 'var TIP_TARGETS = ".kb, .gc.kb, .cell,')
path.write_text(text, encoding="utf-8")

build = HERE / "build_mock.py"
source = build.read_text(encoding="utf-8")
old = 'RCON_STEPS = []'
assert source.count(old) == 1
source = source.replace(old, '''# GCM, from SP 800-38D. Checked against the published GCM test cases below.
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
assert TC3["cipher"].hex().startswith("42831ec2217774243b7261d5"), "GCM test case 3 cipher"
print("GCM test cases 1 and 3 match")

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
print("GCM demo:", len(GCM_TEXT), "bytes,", len(sealed["blocks"]), "counters, tag", sealed["tag"])

RCON_STEPS = []''')
old2 = '''    "long": LONG,
    "rconSteps": RCON_STEPS,'''
assert source.count(old2) == 1
source = source.replace(old2, '''    "long": LONG,
    "gcm": GCM_DATA,
    "rconSteps": RCON_STEPS,''')
build.write_text(source, encoding="utf-8")
print("patched")
