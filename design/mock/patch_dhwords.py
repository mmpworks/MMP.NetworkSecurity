"""Applies Jared's Diffie-Hellman word corrections to the template and the view source."""
import pathlib

HERE = pathlib.Path(__file__).parent
PAIRS = [
    ("Pick another pair and it misses.", "Almost every other pair misses."),
    ("It is the best anyone has found in decades of trying.", "The evidence is only that decades of attacks have found no fast way at these sizes."),
    ("Secure, but with large numbers on the wire", "No practical attack is known, and the numbers on the wire are large"),
    ("Published in 1976, this is how your browser starts a secure connection today.", "Published in 1976, this idea still starts most of your browser's secure connections, in a newer form."),
    ("Real systems make new private numbers for every connection and then delete them. So if a server's long-term key leaks later, old recorded traffic stays locked. This is called forward secrecy.",
     "A full TLS 1.3 handshake makes new private numbers, then deletes them. So if a server's long-term key leaks later, old recorded traffic stays locked, unless someone later breaks the exchange itself. That risk is why lesson 3 adds ML-KEM. This is called forward secrecy."),
    ('''So TLS 1.3 has the server sign the exchange with its certificate key (<button class="spec" data-spec="rfc8446">RFC 8446</button>).''',
     '''So in a TLS 1.3 certificate handshake, the server signs a hash of the handshake so far, which holds both public numbers, and the client checks that key&#39;s certificate (<button class="spec" data-spec="rfc8446">RFC 8446</button>, section 4.4.3).'''),
    ("A curve in place of a prime, with 32-byte numbers", "A curve in place of powers of a number, with 32-byte numbers"),
    ("with a curve in place of the powers and 32-byte numbers", "with a curve in place of the powers, and with 32-byte numbers"),
    ("TLS 1.3 does the same step with its own labels.", "TLS 1.3 does the same step with its own labels, with more steps, and with a hash of the handshake."),
    ("for (var i = 1; i < D.dh.n; i++) html +=", "for (var i = 2; i < D.dh.n - 1; i++) html +="),
]

template = HERE / "template.html"
text = template.read_text(encoding="utf-8")
for old, new in PAIRS:
    assert text.count(old) == 1, old
    text = text.replace(old, new)
template.write_text(text, encoding="utf-8")

view = HERE / "dh_view.js"
source = view.read_text(encoding="utf-8")
hits = 0
for old, new in PAIRS:
    if old in source:
        source = source.replace(old, new)
        hits += 1
view.write_text(source, encoding="utf-8")

test = HERE.parent / "mock_dh.cjs"
t = test.read_text(encoding="utf-8")
old = "await page.selectOption('#da', '11');\n  await page.selectOption('#db', '2');"
assert t.count(old) == 1
t = t.replace(old, "await page.selectOption('#da', '2');\n  await page.selectOption('#db', '2');")
old2 = "console.log('real rows:'"
assert t.count(old2) == 1
t = t.replace(old2, "console.log('private choices:', await page.evaluate(() => [document.querySelector('#da').options[0].value, document.querySelector('#da').options[document.querySelector('#da').options.length - 1].value].join(' to ')));\n  console.log('real rows:'")
test.write_text(t, encoding="utf-8")
print("patched", len(PAIRS), "lines in the template,", hits, "in the view source")
