"""Adds the HMAC and chain tab to the mock, and its data to the build, anchored on the spec's case 002."""
import pathlib

HERE = pathlib.Path(__file__).parent
path = HERE / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('''<button role="tab" id="tab-gcm" aria-selected="false">GCM stream</button>''',
     '''<button role="tab" id="tab-gcm" aria-selected="false">GCM stream</button>
      <button role="tab" id="tab-hmac" aria-selected="false">HMAC and chain</button>''')
assert text.count('["block", "keys", "field", "long", "gcm"]') == 2
text = text.replace('["block", "keys", "field", "long", "gcm"]', '["block", "keys", "field", "long", "gcm", "hmac"]')
swap('''  <section id="view-field" class="card" hidden>''', '''  <section id="view-hmac" class="card" hidden>
    <h2>HMAC: a seal, not a lock</h2>
    <p>AES hides bytes. HMAC hides nothing: it proves that a message was not changed, and that it came from someone holding the key. It is built from a plain hash and a key (<button class="spec" data-spec="rfc2104">RFC 2104</button>, <button class="spec" data-spec="fips198">FIPS 198-1</button>).</p>
    <h3>Why a plain hash is not a seal</h3>
    <p class="mono longtext" id="hmsg"></p>
    <div class="controls"><button class="btn" id="hattack"></button></div>
    <div class="hcompare">
      <div><h3>Plain SHA-256, no key</h3><p class="gverdict" id="hplain"></p></div>
      <div><h3>HMAC, with a key</h3><p class="gverdict" id="hkeyed"></p></div>
    </div>
    <h3>How HMAC is built</h3>
    <p class="note" id="hkeyline"></p>
    <div class="controls">
      <button class="btn primary" id="hplay">Play the steps</button>
      <button class="btn" id="hnext">Next</button>
      <button class="btn" id="hall">Show all</button>
      <span class="seg" aria-label="Speed">
        <button data-speed="1.8" aria-pressed="false">Slow</button>
        <button data-speed="1" aria-pressed="true">Normal</button>
        <button data-speed="0.45" aria-pressed="false">Fast</button>
      </span>
    </div>
    <div class="hsteps" id="hsteps"></div>
    <h2>The chain: each seal covers the last one</h2>
    <p>The Chain of Custody spec seals every event this way: <span class="mono">seal = HMAC-SHA-256(session key, previous seal + event)</span>. The first event uses 32 zero bytes as its previous seal. These 5 events and seals are the spec's own public test values, case 002.</p>
    <p class="mono longtext">Tenant: <span id="ctenant"></span><br>Session key, made with <button class="spec" data-spec="rfc5869">HKDF</button> from a test key: <span id="ckey"></span></p>
    <div class="controls">
      <button class="btn primary" id="cplay">Build the chain</button>
      <span class="seg" id="ccases" aria-label="What happens to the events"></span>
    </div>
    <p class="gverdict good" id="cverdict" hidden></p>
    <div class="clist" id="clist"></div>
    <h3>The daily seal</h3>
    <p>The seals go into a <button class="spec" data-spec="rfc6962">Merkle tree</button>, and its root gets signed in a hardware key store, which the mock does not run. Someone who holds the session key can rewrite the chain, but cannot sign a new root.</p>
    <p class="mono longtext" id="crootrow">Root of these events: <span id="croot"></span><br>Root that was signed: <span id="csealed"></span></p>
  </section>

  <section id="view-field" class="card" hidden>''')
swap(".build .s1 { background: var(--accent-soft); }",
     """.hcompare { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(280px, 100%), 1fr)); gap: 14px; }
.hcompare > div { display: grid; gap: 6px; align-content: start; min-width: 0; }
.hcompare .gverdict { font-weight: 400; }
.hsteps { display: grid; gap: 8px; }
.hstep { display: grid; gap: 4px; padding: 10px 12px; border-radius: 9px; background: var(--sunk); min-width: 0; }
.hstep.on { outline: 2px solid var(--accent); }
.hstep.later { opacity: .55; }
.hstep b { font-weight: 700; font-size: 14px; }
.hexchips { display: grid; grid-template-columns: repeat(var(--per), 26px); gap: 2px; font: 600 12px var(--mono); overflow-x: auto; }
.hexchips .kb { padding: 1px 0; text-align: center; }
.hexchips .kb.tagbyte { background: var(--flash-soft); }
.clist { display: grid; gap: 0; }
.cevent { display: grid; gap: 4px; padding: 10px 12px; border: 1px solid var(--line); border-radius: 9px; min-width: 0; }
.cevent.ok { background: var(--flash-soft); }
.cevent.bad { background: var(--key-soft); border-color: var(--key); }
.cevent.later, .cevent.skip { opacity: .55; }
.chead { display: flex; justify-content: space-between; gap: 10px; font-size: 13px; }
.ctext { font: 12px var(--mono); overflow-wrap: anywhere; }
.clinks { display: flex; flex-wrap: wrap; gap: 4px 18px; font-size: 13px; }
.seal { font: 600 12px var(--mono); }
.clink { width: 2px; height: 14px; background: var(--accent); margin-left: 24px; }
.rootbad { outline: 2px solid var(--key); }
.build .s1 { background: var(--accent-soft); }""")
swap("/* Every named spec gets a hover card", (HERE / "hmac_view.js").read_text(encoding="utf-8") + "/* Every named spec gets a hover card")
swap("setupLong(); setupGcm(); buildKeyTable();", "setupLong(); setupGcm(); setupHmac(); buildKeyTable();")
swap('''var SPECS = {
  fips197: {''', '''var SPECS = {
  rfc2104: { name: "RFC 2104", title: "HMAC: Keyed-Hashing for Message Authentication", says: "The 1997 paper that defines HMAC: two passes of a hash, each with the key mixed in by a different fixed pad.", link: "https://www.rfc-editor.org/rfc/rfc2104", linkText: "Read RFC 2104" },
  fips198: { name: "FIPS 198-1", title: "The Keyed-Hash Message Authentication Code", says: "The US government standard for HMAC, published by NIST in 2008.", link: "https://csrc.nist.gov/pubs/fips/198-1/final", linkText: "Read FIPS 198-1 at NIST" },
  rfc5869: { name: "RFC 5869", title: "HKDF: HMAC-based Key Derivation", says: "A way to stretch one secret into new keys using HMAC. The chain uses it so the master key never reaches the application host.", link: "https://www.rfc-editor.org/rfc/rfc5869", linkText: "Read RFC 5869" },
  rfc6962: { name: "RFC 6962", title: "Certificate Transparency", says: "Defines the Merkle tree the spec uses, with a different prefix byte for leaves and inner nodes, so one cannot pass as the other.", link: "https://www.rfc-editor.org/rfc/rfc6962", linkText: "Read RFC 6962" },
  fips197: {''')
path.write_text(text, encoding="utf-8")

build = HERE / "build_mock.py"
source = build.read_text(encoding="utf-8")
old = 'RCON_STEPS = []'
assert source.count(old) == 1
source = source.replace(old, '''# HMAC and the chain. The chain's inputs and expected values are the spec's public test case 002.
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
canon = (VECTOR / "expected_canonical.txt").read_bytes().split(b"\\n")
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
HDEMO_MSG = b"Send Mike 100 pounds"
HDEMO_BAD = b"Send Mike 900 pounds"
HMAC_DATA = {
    "attack": {"message": HDEMO_MSG.decode(), "changed": HDEMO_BAD.decode(),
               "messageHash": sha(HDEMO_MSG).hex(), "changedHash": sha(HDEMO_BAD).hex(),
               "messageTag": hmac_tag(HDEMO_KEY, HDEMO_MSG).hex(), "changedTag": hmac_tag(HDEMO_KEY, HDEMO_BAD).hex()},
    "build": dict(hmac_parts(HDEMO_KEY, HDEMO_MSG), keyText=HDEMO_KEY.decode()),
    "chain": {"tenant": tenant, "sessionKey": session_key.hex(), "root": merkle_root(base_seals).hex(), "entries": plain_entries,
              "cases": {
                  "change": {"entries": change_case, "caught": "chain",
                             "verdict": "The event's text changed, so its seal no longer matches. The verifier stops at the first failure and says: <b>payload_hash MAC mismatch at seq 3</b>. Without the session key, an attacker cannot make a matching seal."},
                  "remove": {"entries": remove_case, "caught": "chain",
                             "verdict": "Event 4 still names the seal of event 3 as its previous seal, and event 3 is gone. The verifier says: <b>chain link broken at seq 4</b>."},
                  "rewrite": {"entries": rewrite_case, "caught": "root", "root": new_root.hex(),
                              "verdict": "Someone holding the session key changed event 3 and resealed it. Every seal after it had to change too, because each seal covers the last one. Each seal now checks out, so the chain alone cannot catch this. The Merkle root catches it: <b>merkle root mismatch</b>. A new root would need the signing key, which stays in the hardware key store."}}}}

RCON_STEPS = []''')
old2 = '''    "gcm": GCM_DATA,'''
assert source.count(old2) == 1
source = source.replace(old2, '''    "gcm": GCM_DATA,
    "hmac": HMAC_DATA,''')
build.write_text(source, encoding="utf-8")
print("patched")
