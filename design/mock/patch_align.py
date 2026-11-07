"""Lines up the bit columns in the AddRoundKey panel and in the key schedule equation."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap("""d.innerHTML = '<div class="bits">  ' + bin(prev.state[i]) + "  " + hex(prev.state[i]) + '\\nXOR <span class="k">' + bin(s.key[i]) + "  " + hex(s.key[i]) + '</span>\\n= <span class="r">' + bin(s.state[i]) + "  " + hex(s.state[i]) + "</span></div>";""",
     """d.innerHTML = '<div class="bits">    ' + nibbles(prev.state[i]) + "  " + hex(prev.state[i]) + '\\nXOR <span class="k">' + nibbles(s.key[i]) + "  " + hex(s.key[i]) + '</span>\\n  = <span class="r">' + nibbles(s.state[i]) + "  " + hex(s.state[i]) + "</span></div>";""")
swap("""    "w" + (word - nk) + " byte " + j + "   " + nibbles(back) + "\\nXOR         " + nibbles(temp[j]) + "\\nw" + word + " byte " + j + "   " + nibbles(w.word[j]);""",
     """    ("w" + (word - nk) + " byte " + j).padEnd(13) + nibbles(back) + "\\n" + "XOR".padEnd(13) + nibbles(temp[j]) + "\\n" + ("w" + word + " byte " + j).padEnd(13) + nibbles(w.word[j]);""")
path.write_text(text, encoding="utf-8")
print("patched")
