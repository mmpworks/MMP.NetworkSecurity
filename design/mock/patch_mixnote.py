"""Replaces the clipped MixColumns table in the side panel with a pointer to the matrix view."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")
start = text.index('  else if (s.kind === "mix") {\n    var col = Math.floor(i / 4)')
end_marker = 'd.innerHTML = h + "</table>";\n  }'
end = text.index(end_marker, start) + len(end_marker)
text = text[:start] + '''  else if (s.kind === "mix") {
    d.innerHTML = '<p class="note">The matrix view below shows each multiply, one pair at a time. Tap a byte to pick its column.</p>';
  }''' + text[end:]
path.write_text(text, encoding="utf-8")
print("patched")
