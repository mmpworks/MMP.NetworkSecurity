"""Names the round key on the AddRoundKey step button."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")
old = 'var b = document.createElement("button"); b.textContent = NAMES[st.kind];'
assert text.count(old) == 1
text = text.replace(old, 'var b = document.createElement("button"); b.textContent = st.kind === "ark" ? "AddRoundKey " + st.round : NAMES[st.kind];')
path.write_text(text, encoding="utf-8")
print("patched")
