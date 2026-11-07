"""Applies Jared's Feistel word corrections."""
import pathlib

HERE = pathlib.Path(__file__).parent
path = HERE / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('''<span>A last swap puts the halves back in order.</span>''',
     '''<span>A last swap undoes the swap at the end of this round. DES does this too. It is why the same steps decrypt.</span>''')
swap('''says: "The US standard for DES, a Feistel cipher with 16 rounds, an 8-byte block and a 56-bit key. NIST has withdrawn it, and AES replaced it. Triple DES, built from it, still appears in older payment systems."''',
     '''says: "The US standard for DES, a Feistel cipher with 16 rounds, an 8-byte block and a 56-bit key stored in 8 bytes. NIST withdrew it on May 19, 2005."''')
path.write_text(text, encoding="utf-8")

build = HERE / "build_mock.py"
source = build.read_text(encoding="utf-8")
old = "so the XOR changes nothing and the text comes out in plain view."
assert source.count(old) == 1
source = source.replace(old, "so the XOR changes nothing and the text comes out in plain view, with its halves swapped.")
build.write_text(source, encoding="utf-8")
print("patched")
