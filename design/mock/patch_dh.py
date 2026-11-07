"""Adds the Diffie-Hellman tab to the mock, and its data to the build."""
import pathlib

HERE = pathlib.Path(__file__).parent
path = HERE / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('''<button role="tab" id="tab-feistel" aria-selected="false">Feistel</button>''',
     '''<button role="tab" id="tab-feistel" aria-selected="false">Feistel</button>
      <button role="tab" id="tab-dh" aria-selected="false">Diffie-Hellman</button>''')
assert text.count('"hmac", "feistel"]') == 2
text = text.replace('"hmac", "feistel"]', '"hmac", "feistel", "dh"]')
swap('''  <section id="view-field" class="card" hidden>''', '''  <section id="view-dh" class="card" hidden>
    <h2>Diffie-Hellman: agree on a secret in public</h2>
    <p>AES needs both sides to hold one key. So how do two strangers get that key when anyone can read the wire? They never send it. Each side keeps a private number and sends a public one. Then both work out the same secret. Published in 1976, this is how your browser starts a secure connection today.</p>
    <p class="note">These numbers are small so you can follow them, and they are not safe. The real thing is further down.</p>
    <div class="controls">
      <label>Client's private number <select id="da"></select></label>
      <label>Server's private number <select id="db"></select></label>
    </div>
    <div class="controls">
      <button class="btn primary" id="dplay">Play the exchange</button>
      <button class="btn" id="dnext">Next</button>
      <button class="btn" id="dall">Show all</button>
      <span class="seg" aria-label="Speed">
        <button data-speed="1.8" aria-pressed="false">Slow</button>
        <button data-speed="1" aria-pressed="true">Normal</button>
        <button data-speed="0.45" aria-pressed="false">Fast</button>
      </span>
    </div>
    <div class="mcap gcap" id="dcap" aria-live="polite"></div>
    <div class="dhgrid">
      <div class="dhside"><h3>Client</h3><div id="dclient"></div></div>
      <div class="dhside dhwire"><h3>On the wire: the listener reads all of this</h3><div id="dwire"></div></div>
      <div class="dhside"><h3>Server</h3><div id="dserver"></div></div>
    </div>
    <p id="dchain" class="dhchainline"></p>
    <h3>The same idea in paint</h3>
    <p>Mixing paint is easy, and unmixing it is hard. Each side adds its own private color to the shared one and sends the mix. Then each adds its private color to the other's mix. Both end with the same three colors in the pot. This is a picture of the idea, not the math.</p>
    <div class="dhpaint" id="dpaint"></div>
    <h2>The listener's turn</h2>
    <p>The listener has n, g and both public numbers. Try the two obvious attacks.</p>
    <div class="controls">
      <button class="btn" id="dmix">Combine the two public numbers</button>
      <button class="btn" id="dtry">Try every private number</button>
    </div>
    <p class="gverdict" id="dlisten" aria-live="polite"></p>
    <h3>So n must be huge</h3>
    <div class="scroll"><table class="datatable">
      <tr><th>Group</th><th>Strength</th><th>What that means</th></tr>
      <tr><td>n = 23, this page</td><td>Under 5 bits</td><td>22 tries at most</td></tr>
      <tr><td>2048-bit prime</td><td>About 112 bits (<button class="spec" data-spec="sp80057">SP 800-57</button>)</td><td>Better attacks than trying each number exist, so the strength is far below 2048</td></tr>
      <tr><td>3072-bit prime</td><td>About 128 bits (<button class="spec" data-spec="sp80057">SP 800-57</button>)</td><td>Secure, but with large numbers on the wire</td></tr>
      <tr><td>X25519</td><td>About 128 bits (<button class="spec" data-spec="rfc7748">RFC 7748</button>)</td><td>A curve in place of a prime, with 32-byte numbers</td></tr>
    </table></div>
    <p>Nobody has proved that this problem is hard. It is the best anyone has found in decades of trying. A large quantum computer would break both kinds, so lesson 3 also adds ML-KEM.</p>
    <h2>The attack it does not stop</h2>
    <p>The listener above can only read. What if someone can also change messages?</p>
    <div class="controls"><button class="btn" id="dmidbtn">Put someone in the middle</button></div>
    <div id="dmid" hidden></div>
    <h2>The real thing: X25519</h2>
    <p>This uses the same steps, with a curve in place of the powers and 32-byte numbers. These are the published test values from <button class="spec" data-spec="rfc7748">RFC 7748</button>, section 6.1. A script ran both sides and got this secret. The last row feeds the secret through <button class="spec" data-spec="rfc5869">HKDF</button> to make a key for AES, with a label made up for this page. TLS 1.3 does the same step with its own labels.</p>
    <div id="dreal"></div>
    <p>Real systems make new private numbers for every connection and then delete them. So if a server's long-term key leaks later, old recorded traffic stays locked. This is called forward secrecy.</p>
  </section>

  <section id="view-field" class="card" hidden>''')
swap(".build .s1 { background: var(--accent-soft); }",
     """.dhgrid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; margin: 10px 0; }
@media (max-width: 640px) { .dhgrid { grid-template-columns: minmax(0, 1fr); } }
.dhside { background: var(--sunk); border-radius: 10px; padding: 10px; min-height: 110px; }
.dhside h3 { margin-top: 0; }
.dhwire { background: var(--flash-soft); }
.dhattack { background: var(--key-soft); }
.dhrow { display: flex; justify-content: space-between; gap: 8px; align-items: baseline; padding: 2px 0; }
.dhlabel { font-size: 13px; }
.dhnum { font: 700 16px var(--mono); }
.dhnum.dhkey { color: var(--key, inherit); }
.dhnum.dhsecret { background: var(--fg); color: var(--bg); padding: 0 6px; border-radius: 4px; }
.dhchainline { min-height: 1.5em; }
.dhchain { flex-wrap: wrap; }
.dhpow { font: 600 13px var(--mono); }
.dhpaint { display: grid; gap: 6px; margin: 8px 0; }
.dhpaint b { display: inline-block; width: 56px; font-weight: 600; }
.pdot { display: inline-block; width: 20px; height: 20px; border-radius: 50%; vertical-align: middle; }
.pdot.pempty { background: var(--sunk); }
.seal-row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; padding: 3px 0; }
.seal-row > span:first-child { min-width: 150px; font-size: 13px; }
.seal-row .fchips { flex-wrap: wrap; }
.build .s1 { background: var(--accent-soft); }""")
swap("/* Every named spec gets a hover card", (HERE / "dh_view.js").read_text(encoding="utf-8") + "/* Every named spec gets a hover card")
swap("setupHmac(); setupFeistel(); buildKeyTable();", "setupHmac(); setupFeistel(); setupDh(); buildKeyTable();")
swap('''var SPECS = {
''', '''var SPECS = {
  rfc7748: { name: "RFC 7748", title: "Elliptic Curves for Security", says: "Defines X25519, the Diffie-Hellman function on Curve25519, with its test values. It gives about 128 bits of strength.", link: "https://www.rfc-editor.org/rfc/rfc7748", linkText: "Read RFC 7748" },
  rfc8446: { name: "RFC 8446", title: "The Transport Layer Security (TLS) Protocol Version 1.3", says: "The TLS 1.3 standard. Each handshake runs a key exchange, and the server signs the handshake with its certificate key in the CertificateVerify message.", link: "https://www.rfc-editor.org/rfc/rfc8446", linkText: "Read RFC 8446" },
  sp80057: { name: "SP 800-57 Part 1", title: "NIST Recommendation for Key Management", says: "Lists the comparable strength of key sizes. A 2048-bit Diffie-Hellman prime gives about 112 bits, and a 3072-bit prime gives about 128 bits.", link: "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final", linkText: "Read SP 800-57 Part 1 at NIST" },
''')
path.write_text(text, encoding="utf-8")

build = HERE / "build_mock.py"
source = build.read_text(encoding="utf-8")
old = "RCON_STEPS = []"
assert source.count(old) == 1
source = source.replace(old, '''# Diffie-Hellman. Small tables for the walk, then X25519 checked against RFC 7748 section 6.1.
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

RCON_STEPS = []''')
old2 = '''    "feistel": FEISTEL_DATA,'''
assert source.count(old2) == 1
source = source.replace(old2, '''    "feistel": FEISTEL_DATA,
    "dh": DH_DATA,''')
build.write_text(source, encoding="utf-8")
print("patched")
