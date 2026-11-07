"""Applies Jared's corrections to the HMAC and chain tab."""
import pathlib

HERE = pathlib.Path(__file__).parent
path = HERE / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


# Words: "seal" means the daily signed record, as in the spec. An event's MAC is its tag.
swap("<h2>HMAC: a seal, not a lock</h2>", "<h2>HMAC: proof, not a lock</h2>")
swap("<h3>Why a plain hash is not a seal</h3>", "<h3>Why a plain hash proves nothing</h3>")
swap("<h2>The tag: why a stream needs a seal</h2>", "<h2>The tag: why a stream needs one</h2>")
swap("<h2>The chain: each seal covers the last one</h2>", "<h2>The chain: each tag covers the last one</h2>")
swap('''The Chain of Custody spec seals every event this way: <span class="mono">seal = HMAC-SHA-256(session key, previous seal + event)</span>. The first event uses 32 zero bytes as its previous seal. These 5 events and seals are the spec's own public test values, case 002.''',
     '''The Chain of Custody spec tags every event this way: <span class="mono">tag = HMAC-SHA-256(session key, previous tag + event)</span>. The spec calls this tag <span class="mono">payload_hash</span>. The first event uses 32 zero bytes as its previous tag. These 5 events and tags are the spec's own public test values, case 002. The spec is a Public Review Draft.''')
swap('''<p>The seals go into a <button class="spec" data-spec="rfc6962">Merkle tree</button>, and its root gets signed in a hardware key store, which the mock does not run. Someone who holds the session key can rewrite the chain, but cannot sign a new root.</p>''',
     '''<p>Once a day, the tags go into a <button class="spec" data-spec="rfc6962">Merkle tree</button>, and its root gets signed in a hardware key store. The mock does not run that signature. A new root needs a new signature from that store. The signing key cannot leave it, and only the seal job may ask it to sign. This protects a day already sealed. Before the seal runs, the chain records whatever the key holder writes.</p>''')
swap('''var word = { ok: "Seal checks out",''', '''var word = { ok: "Tag checks out",''')
swap('''<span>Previous seal <code class="seal"''', '''<span>Previous tag <code class="seal"''')
swap('''</code></span><span>Seal <code class="seal sealout"''', '''</code></span><span>Tag <code class="seal sealout"''')
swap('''v.textContent = "All 5 seals check out, and the 5 seals make the sealed Merkle root.";''',
     '''v.textContent = "All 5 tags check out, and the 5 tags make the root that was signed.";''')
swap('''  remove: { label: "Remove event 3" },
''', '''  remove: { label: "Remove event 3" },
  cut: { label: "Remove the last event" },
''')
swap('''"This is the HMAC tag. Hashing a second time under the key stops an attacker from adding to the end of the message."''',
     '''"This is the HMAC tag. With a plain hash of key plus message, an attacker can add to the end and work out a valid tag with no key. The second hash under the key stops that."''')
# Spec cards.
swap('''says: "The 1997 paper that defines HMAC: two passes of a hash, each with the key mixed in by a different fixed pad."''',
     '''says: "The 1997 RFC that defines HMAC: two passes of a hash, each with the key mixed in by a different fixed pad."''')
swap('''title: "HKDF: HMAC-based Key Derivation", says: "A way to stretch one secret into new keys using HMAC. The chain uses it so the master key never reaches the application host."''',
     '''title: "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", says: "A way to make new keys from one secret, using HMAC. The chain uses it to make one session key per tenant from the master key."''')
swap('''title: "Certificate Transparency", says: "Defines the Merkle tree the spec uses, with a different prefix byte for leaves and inner nodes, so one cannot pass as the other."''',
     '''title: "Certificate Transparency", says: "Defines the Merkle tree the spec uses, with a different prefix byte for leaves and inner nodes, so one cannot pass as the other. It is an Experimental RFC from 2013, and RFC 9162 obsoletes it. The spec still names RFC 6962."''')
path.write_text(text, encoding="utf-8")

build = HERE / "build_mock.py"
source = build.read_text(encoding="utf-8")


def bswap(old, new):
    global source
    assert source.count(old) == 1, old
    source = source.replace(old, new)


bswap('''"verdict": "The event's text changed, so its seal no longer matches. The verifier stops at the first failure and says: <b>payload_hash MAC mismatch at seq 3</b>. Without the session key, an attacker cannot make a matching seal."''',
      '''"verdict": "The event's text changed, so its tag no longer matches. A verifier holding the key stops at the first failure and says: <b>payload_hash MAC mismatch at seq 3</b>. A verifier with no key cannot check tags, and it reads PASS-STRUCTURALLY, with key-bound verification skipped. Without the session key, an attacker cannot make a matching tag."''')
bswap('''"verdict": "Event 4 still names the seal of event 3 as its previous seal, and event 3 is gone. The verifier says: <b>chain link broken at seq 4</b>."''',
      '''"verdict": "Event 4 now sits at position 3, and it names a tag the verifier has not seen. The verifier says: <b>chain link broken at seq 3</b>. It names the position it expected."''')
bswap('''"verdict": "Someone holding the session key changed event 3 and resealed it. Every seal after it had to change too, because each seal covers the last one. Each seal now checks out, so the chain alone cannot catch this. The Merkle root catches it: <b>merkle root mismatch</b>. A new root would need the signing key, which stays in the hardware key store."''',
      '''"verdict": "Someone holding the session key changed event 3 and made a new tag. Every tag after it had to change too, because each tag covers the last one. Each tag now checks out, so the chain alone cannot catch this. The signed root catches it: <b>merkle root mismatch — ledger contents do not produce sealed root</b>."''')
bswap('''                  "rewrite": {"entries": rewrite_case,''', '''                  "cut": {"entries": cut_case, "caught": "root", "root": cut_root.hex(),
                          "verdict": "Nothing after the cut names the missing event, so the chain cannot see this. With no daily seal to compare, the verifier reads PASS and warns: <b>no daily seal supplied: steps 10 and 11 did not run, so a cut at the end of the file cannot be detected</b>. With the seal, it fails: <b>merkle root mismatch — ledger contents do not produce sealed root</b>."},
                  "rewrite": {"entries": rewrite_case,''')
bswap('''rewrite_events = list(canon)
''', '''cut_case = [entry(i, base_rows[i][0], base_rows[i][1], "ok") for i in range(4)]
cut_root = merkle_root(base_seals[:4])
assert cut_root != merkle_root(base_seals)
rewrite_events = list(canon)
''')
build.write_text(source, encoding="utf-8")

test = HERE.parent / "mock_hmac.cjs"
t = test.read_text(encoding="utf-8")
assert "['change', 'remove', 'rewrite', 'none']" in t
test.write_text(t.replace("['change', 'remove', 'rewrite', 'none']", "['change', 'remove', 'cut', 'rewrite', 'none']"), encoding="utf-8")
print("patched")
