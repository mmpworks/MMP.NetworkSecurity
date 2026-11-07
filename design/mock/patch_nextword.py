"""Stops the RotWord note naming a next word past the end of the table."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")
old = '''" then use this one finished copy. The next word that does this is w" + (chosen + nk) + "."'''
assert text.count(old) == 1
new = '''" then use this one finished copy." + (chosen + nk < S().words.length ? " The next word that does this is w" + (chosen + nk) + "." : " This is the last word that does this.")'''
path.write_text(text.replace(old, new), encoding="utf-8")
print("patched")
