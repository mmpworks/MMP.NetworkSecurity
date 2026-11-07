"""Adds the limit on where the signer's public key must come from."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")
old = "Before the seal runs, the chain records whatever the key holder writes.</p>"
assert text.count(old) == 1
text = text.replace(old, "Before the seal runs, the chain records whatever the key holder writes. The reader must also get the signer's public key from somewhere other than the file's holder: a rewriter who signs with their own key passes against their own public key.</p>")
path.write_text(text, encoding="utf-8")
print("patched")
