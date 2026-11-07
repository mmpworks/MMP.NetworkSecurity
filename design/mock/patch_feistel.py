"""Adds the Feistel tab to the mock, and its data to the build."""
import pathlib

HERE = pathlib.Path(__file__).parent
path = HERE / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('''<button role="tab" id="tab-hmac" aria-selected="false">HMAC and chain</button>''',
     '''<button role="tab" id="tab-hmac" aria-selected="false">HMAC and chain</button>
      <button role="tab" id="tab-feistel" aria-selected="false">Feistel</button>''')
assert text.count('["block", "keys", "field", "long", "gcm", "hmac"]') == 2
text = text.replace('["block", "keys", "field", "long", "gcm", "hmac"]', '["block", "keys", "field", "long", "gcm", "hmac", "feistel"]')
swap('''  <section id="view-field" class="card" hidden>''', '''  <section id="view-feistel" class="card" hidden>
    <h2>A Feistel network: another way to build a cipher</h2>
    <p>A Feistel network is a structure, and you choose what goes inside it. It splits the block in half and changes one half per round. To decrypt, you run the same steps with the keys in reverse order. So F never has to run backward, and F can even be a one-way hash. DES is built this way (<button class="spec" data-spec="fips46">FIPS 46-3</button>).</p>
    <p class="note">This tab is a small teaching cipher: 8 bytes, 4 rounds, with F chosen below. It is not DES, and it is not safe to use.</p>
    <div class="controls">
      <span class="seg" id="ffn" aria-label="The function F"></span>
      <span class="seg" id="fdir" aria-label="Direction"></span>
    </div>
    <p id="fsays"></p>
    <div class="controls">
      <button class="btn primary" id="fplay">Play the rounds</button>
      <button class="btn" id="fnext">Next</button>
      <button class="btn" id="fall">Show all</button>
      <span class="seg" aria-label="Speed">
        <button data-speed="1.8" aria-pressed="false">Slow</button>
        <button data-speed="1" aria-pressed="true">Normal</button>
        <button data-speed="0.45" aria-pressed="false">Fast</button>
      </span>
    </div>
    <div class="fline"><h3>Going in</h3><div id="fin"></div></div>
    <div class="mcap gcap" id="fcap" aria-live="polite"></div>
    <div class="scroll"><table class="modes ftable" id="ftable"></table></div>
    <div class="fline"><h3>Coming out</h3><div id="fout"></div></div>
    <p class="gverdict good" id="fback"></p>
    <h3>Feistel beside AES</h3>
    <div class="scroll"><table class="datatable">
      <tr><th></th><th>Feistel, such as DES</th><th>AES</th></tr>
      <tr><td>Each round changes</td><td>Half the block</td><td>The whole block</td></tr>
      <tr><td>Decrypt uses</td><td>The same steps, keys reversed</td><td>Inverse steps and an inverse table</td></tr>
      <tr><td>The inner function</td><td>Need not be reversible</td><td>Every step must be reversible</td></tr>
    </table></div>
  </section>

  <section id="view-field" class="card" hidden>''')
swap(".build .s1 { background: var(--accent-soft); }",
     """.fchips { display: inline-flex; gap: 2px; font: 600 12px var(--mono); }
.fchips .kb { padding: 1px 3px; background: var(--sunk); }
.fchips .kb.fkey { background: var(--key-soft); }
.fchips .kb.tagbyte { background: var(--flash-soft); }
.fchips .kb.pick { background: var(--fg); color: var(--bg); }
.ftable tr.fnow td { background: var(--accent-soft); }
.ftable tr.flater { opacity: .35; }
.ftable td { white-space: nowrap; }
.ftext { margin-left: 8px; }
.fline { display: grid; gap: 4px; }
.build .s1 { background: var(--accent-soft); }""")
swap("/* Every named spec gets a hover card", (HERE / "feistel_view.js").read_text(encoding="utf-8") + "/* Every named spec gets a hover card")
swap("setupLong(); setupGcm(); setupHmac(); buildKeyTable();", "setupLong(); setupGcm(); setupHmac(); setupFeistel(); buildKeyTable();")
swap('''var SPECS = {
  rfc2104:''', '''var SPECS = {
  fips46: { name: "FIPS 46-3", title: "Data Encryption Standard (DES)", says: "The US standard for DES, a Feistel cipher with 16 rounds, an 8-byte block and a 56-bit key. NIST has withdrawn it, and AES replaced it. Triple DES, built from it, still appears in older payment systems.", link: "https://csrc.nist.gov/pubs/fips/46-3/final", linkText: "Read FIPS 46-3 at NIST" },
  rfc2104:''')
path.write_text(text, encoding="utf-8")

build = HERE / "build_mock.py"
source = build.read_text(encoding="utf-8")
old = 'RCON_STEPS = []'
assert source.count(old) == 1
source = source.replace(old, '''# A small teaching Feistel network. The test below proves decrypt works for every F offered.
def fxor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


FEISTEL_FUNCS = {
    "hash": ("SHA-256, one way", lambda r, k: sha(k + r)[:4],
             "F here is a hash: it cannot be run backward, and nobody can work out its input from its output. The cipher still decrypts."),
    "and": ("AND with the key", lambda r, k: bytes(x & y for x, y in zip(r, k)),
            "F here is a bit AND, which throws bits away, so it has no inverse at all. The cipher still decrypts. But it is weak: the structure gives you decryption, and security has to come from F."),
    "zero": ("All zeros", lambda r, k: bytes(4),
             "F here always gives zeros, so the XOR changes nothing and the text comes out in plain view. The cipher still decrypts, and it hides nothing. The structure never promised secrecy."),
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

RCON_STEPS = []''')
old2 = '''    "hmac": HMAC_DATA,'''
assert source.count(old2) == 1
source = source.replace(old2, '''    "hmac": HMAC_DATA,
    "feistel": FEISTEL_DATA,''')
build.write_text(source, encoding="utf-8")
print("patched")
