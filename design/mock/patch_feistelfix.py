"""Three small Feistel fixes: no spoiled rows, no empty bar, and a claim that holds for a 4-byte hash."""
import pathlib

HERE = pathlib.Path(__file__).parent
path = HERE / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('''"</td><td>" + fchips(r.left) + "</td><td>" + fchips(r.right, at === 1 && live ? "pick" : "") + "</td>" +''',
     '''"</td><td>" + (seenRow ? fchips(r.left) : "") + "</td><td>" + (seenRow ? fchips(r.right, at === 1 && live ? "pick" : "") : "") + "</td>" +''')
swap('''    : (finished ? "Switch to Decrypt to run the same steps with the keys reversed." : "");
''', '''    : (finished ? "Switch to Decrypt to run the same steps with the keys reversed." : "");
  $("fback").hidden = !$("fback").textContent;
''')
path.write_text(text, encoding="utf-8")

build = HERE / "build_mock.py"
source = build.read_text(encoding="utf-8")
old = '"F here is a hash: it cannot be run backward, and nobody can work out its input from its output. The cipher still decrypts."'
assert source.count(old) == 1
source = source.replace(old, '"F here is SHA-256 cut to 4 bytes: there is no way to run it backward. The cipher still decrypts, because decrypting only ever runs F forward."')
build.write_text(source, encoding="utf-8")
print("patched")
